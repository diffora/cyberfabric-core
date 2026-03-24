"""Tests for cleanup — chat deletion, attachment cleanup, orphan watchdog, thread summary.

Most cleanup internals (background workers, file deletion timing, vector store ordering)
are not directly observable via HTTP. These tests verify the observable effects:
DELETE returns correct status codes, GET returns 404 after deletion, and turn states
transition correctly.

Covers:
- Cleanup worker observable effect (delete chat -> 404)
- Provider 404 idempotent (double delete)
- Vector store ordering (upload then delete)
- Attachment cleanup state machine
- Orphan watchdog detects stuck turn
- Orphan settlement estimated
- Thread summary trigger (P2 deferred)
- Thread summary worker (P2 deferred)
"""

import io
import time
import uuid

import httpx
import pytest

from .conftest import (
    API_PREFIX,
    DB_PATH,
    DEFAULT_MODEL,
    STANDARD_MODEL,
    expect_done,
    expect_stream_started,
    parse_sse,
    stream_message,
)
from .mock_provider.responses import MockEvent, Scenario, Usage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_chat(model: str | None = None) -> dict:
    body = {"model": model} if model else {}
    resp = httpx.post(f"{API_PREFIX}/chats", json=body, timeout=10)
    assert resp.status_code == 201, f"Create chat failed: {resp.status_code} {resp.text}"
    return resp.json()


def delete_chat(chat_id: str) -> httpx.Response:
    return httpx.delete(f"{API_PREFIX}/chats/{chat_id}", timeout=10)


def get_chat(chat_id: str) -> httpx.Response:
    return httpx.get(f"{API_PREFIX}/chats/{chat_id}", timeout=10)


def upload_file(
    chat_id: str,
    content: bytes = b"Hello, world!",
    filename: str = "test.txt",
    content_type: str = "text/plain",
) -> httpx.Response:
    return httpx.post(
        f"{API_PREFIX}/chats/{chat_id}/attachments",
        files={"file": (filename, io.BytesIO(content), content_type)},
        timeout=60,
    )


def poll_turn_terminal(chat_id: str, request_id: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    body = None
    while time.monotonic() < deadline:
        resp = httpx.get(
            f"{API_PREFIX}/chats/{chat_id}/turns/{request_id}", timeout=5
        )
        if resp.status_code == 200:
            body = resp.json()
            if body["state"] in ("done", "error", "cancelled"):
                return body
        elif resp.status_code != 404:
            raise AssertionError(
                f"Unexpected status {resp.status_code} polling turn {request_id}: {resp.text}"
            )
        time.sleep(0.3)
    state = body["state"] if body else "no response"
    raise AssertionError(
        f"Turn {request_id} did not reach terminal state within {timeout}s "
        f"(last state: {state})"
    )


def get_quota_status() -> dict:
    resp = httpx.get(f"{API_PREFIX}/quota/status", timeout=10)
    assert resp.status_code == 200
    return resp.json()


def has_stuck_reserves() -> bool:
    qs = get_quota_status()
    for tier in qs["tiers"]:
        for period in tier["periods"]:
            if period.get("reserved_credits_micro", 0) != 0:
                return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCleanup:
    """Cleanup — deletion, attachment cleanup, orphan handling."""

    def test_cleanup_worker_observable(self, server):
        # TODO: Background cleanup happens asynchronously. Cannot observe
        # file deletion timing. This test verifies the HTTP-observable effects.
        chat = create_chat()
        chat_id = chat["id"]

        # Upload an attachment
        upload_resp = upload_file(chat_id)
        assert upload_resp.status_code == 201

        # Delete the chat
        del_resp = delete_chat(chat_id)
        assert del_resp.status_code == 204

        # Verify chat is gone
        get_resp = get_chat(chat_id)
        assert get_resp.status_code == 404

    def test_provider_404_idempotent(self, server):
        # TODO: Provider cleanup internals not observable via HTTP.
        # Test idempotency by deleting the same chat twice.
        chat = create_chat()
        chat_id = chat["id"]

        # First delete
        resp1 = delete_chat(chat_id)
        assert resp1.status_code == 204

        # Second delete — should return 404 (already gone)
        resp2 = delete_chat(chat_id)
        assert resp2.status_code == 404

    def test_vector_store_ordering(self, server):
        # TODO: Vector store cleanup timing not observable via HTTP.
        # Verify that uploading a document (which creates a vector store)
        # and then deleting the chat produces correct HTTP responses.
        chat = create_chat()
        chat_id = chat["id"]

        # Upload a document (triggers vector store creation)
        doc_content = b"This is a document for vector store testing."
        upload_resp = upload_file(
            chat_id,
            content=doc_content,
            filename="vector_test.txt",
            content_type="text/plain",
        )
        assert upload_resp.status_code == 201

        # Delete chat — should succeed even with vector store
        del_resp = delete_chat(chat_id)
        assert del_resp.status_code == 204

        # Verify chat is gone
        get_resp = get_chat(chat_id)
        assert get_resp.status_code == 404

    def test_attachment_cleanup_state_machine(self, server):
        # TODO: Cleanup state not exposed in API. We verify the
        # observable transitions: upload -> delete chat -> 404.
        chat = create_chat()
        chat_id = chat["id"]

        upload_resp = upload_file(chat_id)
        assert upload_resp.status_code == 201
        attachment_id = upload_resp.json()["id"]

        # Attachment should be accessible before deletion
        att_resp = httpx.get(
            f"{API_PREFIX}/chats/{chat_id}/attachments/{attachment_id}",
            timeout=10,
        )
        assert att_resp.status_code == 200

        # Delete chat
        del_resp = delete_chat(chat_id)
        assert del_resp.status_code == 204

        # After deletion, chat and attachment should be inaccessible
        get_resp = get_chat(chat_id)
        assert get_resp.status_code == 404
        att_resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}/attachments/{attachment_id}", timeout=10)
        assert att_resp.status_code == 404

    def test_orphan_watchdog_detects_stuck_turn(self, chat, mock_provider):
        # TODO: Requires waiting for orphan timeout (5 min default). Too slow
        # for regular e2e tests. This test uses disconnect detection (faster)
        # as a proxy for orphan watchdog behavior.
        chat_id = chat["id"]
        request_id = str(uuid.uuid4())

        # Very slow scenario
        many_deltas = [
            MockEvent("response.output_text.delta", {"delta": f"w{i} "})
            for i in range(30)
        ]
        many_deltas.append(
            MockEvent("response.output_text.done", {"text": "done"})
        )
        mock_provider.set_next_scenario(Scenario(slow=1.0, events=many_deltas))

        url = f"{API_PREFIX}/chats/{chat_id}/messages:stream"
        body = {"content": "Stuck turn test.", "request_id": request_id}

        # Start stream and disconnect immediately
        with httpx.stream(
            "POST", url, json=body,
            headers={"Accept": "text/event-stream"},
            timeout=30,
        ) as resp:
            assert resp.status_code == 200
            # disconnect immediately

        # Poll until turn reaches terminal state
        turn = poll_turn_terminal(chat_id, request_id, timeout=30.0)
        assert turn["state"] in ("cancelled", "error"), f"Expected cancelled/error for orphan, got {turn['state']}"

    def test_orphan_settlement_estimated(self, chat, mock_provider):
        # TODO: Timing dependent on orphan watchdog interval. This test
        # uses disconnect detection as a proxy.
        chat_id = chat["id"]
        request_id = str(uuid.uuid4())

        many_deltas = [
            MockEvent("response.output_text.delta", {"delta": f"w{i} "})
            for i in range(20)
        ]
        many_deltas.append(
            MockEvent("response.output_text.done", {"text": "done"})
        )
        mock_provider.set_next_scenario(Scenario(slow=0.8, events=many_deltas))

        url = f"{API_PREFIX}/chats/{chat_id}/messages:stream"
        body = {"content": "Orphan settlement.", "request_id": request_id}

        with httpx.stream(
            "POST", url, json=body,
            headers={"Accept": "text/event-stream"},
            timeout=30,
        ) as resp:
            assert resp.status_code == 200
            # read one chunk then disconnect
            for _ in resp.iter_bytes(chunk_size=256):
                break

        # Wait for resolution
        turn = poll_turn_terminal(chat_id, request_id, timeout=30.0)
        assert turn["state"] in ("cancelled", "error"), f"Expected cancelled/error for orphan, got {turn['state']}"

        time.sleep(0.5)
        assert not has_stuck_reserves(), (
            "Stuck reserves after orphan-like turn settlement"
        )

    def test_thread_summary_trigger(self, server):
        # TODO: Feature deferred to P2. Thread summary is triggered after
        # a high number of turns (>20) in a thread. The trigger threshold
        # may be very high in production config.
        #
        # To fully test:
        # 1. Create a chat
        # 2. Send >20 messages to trigger summary
        # 3. Query DB: SELECT * FROM thread_summary_tasks WHERE chat_id = ?
        # 4. Assert a row exists
        #
        # For now: verify the chat can handle multiple messages without error.
        chat = create_chat()
        chat_id = chat["id"]

        for i in range(3):
            status, events, _ = stream_message(chat_id, f"Message {i}. Say OK.")
            assert status == 200
            expect_done(events)

        # Verify chat is still accessible
        resp = get_chat(chat_id)
        assert resp.status_code == 200
        assert resp.json()["message_count"] >= 6  # 3 user + 3 assistant

    def test_thread_summary_worker(self, server):
        # TODO: Feature deferred to P2. Depends on trigger working first.
        #
        # To fully test:
        # 1. Trigger summary (send many messages)
        # 2. Wait for worker to process
        # 3. Query DB: SELECT * FROM thread_summaries WHERE chat_id = ?
        # 4. Assert summary text is not empty
        #
        # For now: verify that the messages endpoint returns correct history.
        chat = create_chat()
        chat_id = chat["id"]

        status, events, _ = stream_message(chat_id, "Say hello.")
        assert status == 200
        expect_done(events)

        # Verify message history is accessible
        resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}/messages", timeout=10)
        assert resp.status_code == 200
        messages = resp.json()
        assert "items" in messages and isinstance(messages["items"], list)
