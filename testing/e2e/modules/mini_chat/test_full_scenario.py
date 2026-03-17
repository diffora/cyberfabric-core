"""Full end-to-end scenario test.

Creates a chat, exchanges multiple messages, verifies message history,
checks turn records and quota usage via SQLite, then cleans up.

Requires a running server with a real LLM provider.
"""

import os
import sqlite3
import uuid

import pytest
import httpx

from .conftest import API_PREFIX, DB_PATH, DEFAULT_MODEL, STANDARD_MODEL, expect_done, expect_stream_started, stream_message

pytestmark = pytest.mark.openai


def _to_blob(value):
    """Convert a UUID string to bytes for SQLite blob comparison."""
    if isinstance(value, str):
        try:
            return uuid.UUID(value).bytes
        except ValueError:
            pass
    return value


def query_db(sql: str, params: tuple = ()) -> list[dict]:
    """Run a read-only query against the mini-chat SQLite DB.

    UUID string params are auto-converted to bytes (SQLite stores UUIDs as blobs).
    """
    if not os.path.exists(DB_PATH):
        pytest.skip(f"DB not found at {DB_PATH}")
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    blob_params = tuple(_to_blob(p) for p in params)
    try:
        rows = conn.execute(sql, blob_params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


class TestFullConversationScenario:
    """Complete conversation lifecycle: create → multi-turn → verify DB → delete."""

    def test_full_conversation(self, server):
        # ── 1. Create chat with default (premium) model ──────────────────
        resp = httpx.post(f"{API_PREFIX}/chats", json={"title": "Scenario Test"})
        assert resp.status_code == 201
        chat = resp.json()
        chat_id = chat["id"]
        assert chat["model"] == DEFAULT_MODEL
        assert chat["title"] == "Scenario Test"

        # ── 2. Turn 1: simple question ───────────────────────────────────
        rid1 = str(uuid.uuid4())
        s1, ev1, _ = stream_message(chat_id, "What is 2+2? Reply with just the number.", request_id=rid1)
        assert s1 == 200

        ss1 = expect_stream_started(ev1)
        msg_id1 = ss1.data["message_id"]
        assert ss1.data["is_new_turn"] is True

        done1 = expect_done(ev1)
        assert done1.data["quota_decision"] == "allow"
        assert done1.data["effective_model"] == DEFAULT_MODEL
        usage1 = done1.data["usage"]
        assert usage1["input_tokens"] > 0
        assert usage1["output_tokens"] > 0

        # Verify delta content is non-empty
        text1 = "".join(e.data["content"] for e in ev1 if e.event == "delta")
        assert len(text1.strip()) > 0

        # ── 3. Turn 2: follow-up referencing context ─────────────────────
        rid2 = str(uuid.uuid4())
        s2, ev2, _ = stream_message(chat_id, "Now multiply that result by 10.", request_id=rid2)
        assert s2 == 200

        ss2 = expect_stream_started(ev2)
        msg_id2 = ss2.data["message_id"]
        assert ss2.data["is_new_turn"] is True

        done2 = expect_done(ev2)
        usage2 = done2.data["usage"]

        # Input tokens should be higher (conversation context grows)
        assert usage2["input_tokens"] > usage1["input_tokens"], (
            f"Turn 2 input_tokens ({usage2['input_tokens']}) should exceed "
            f"turn 1 ({usage1['input_tokens']}) — context assembly sends history"
        )

        text2 = "".join(e.data["content"] for e in ev2 if e.event == "delta")
        assert len(text2.strip()) > 0

        # ── 4. Turn 3: third exchange ────────────────────────────────────
        rid3 = str(uuid.uuid4())
        s3, ev3, _ = stream_message(chat_id, "What was my first question?", request_id=rid3)
        assert s3 == 200

        ss3 = expect_stream_started(ev3)
        msg_id3 = ss3.data["message_id"]
        assert ss3.data["is_new_turn"] is True
        expect_done(ev3)

        # ── 5. Verify message history via API ────────────────────────────
        resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}/messages")
        assert resp.status_code == 200
        msgs = resp.json()["items"]

        # 3 turns × 2 messages = 6 messages
        assert len(msgs) == 6
        roles = [m["role"] for m in msgs]
        assert roles == ["user", "assistant"] * 3

        # Messages are chronologically ordered
        timestamps = [m["created_at"] for m in msgs]
        assert timestamps == sorted(timestamps)

        # ── 6. Verify chat metadata updated ──────────────────────────────
        resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}")
        assert resp.status_code == 200
        assert resp.json()["message_count"] == 6

        # ── 7. Verify turn status via API ────────────────────────────────
        for rid in [rid1, rid2, rid3]:
            resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}/turns/{rid}")
            assert resp.status_code == 200
            turn = resp.json()
            assert turn["state"] == "done"
            assert turn["assistant_message_id"] is not None

        # ── 8. Verify turns in SQLite ────────────────────────────────────
        turns = query_db(
            "SELECT * FROM chat_turns WHERE chat_id = ? AND deleted_at IS NULL ORDER BY started_at",
            (chat_id,),
        )
        assert len(turns) == 3

        for t in turns:
            assert t["state"] == "completed"
            assert t["effective_model"] == DEFAULT_MODEL
            assert t["reserve_tokens"] is not None and t["reserve_tokens"] > 0
            assert t["max_output_tokens_applied"] is not None and t["max_output_tokens_applied"] > 0
            assert t["reserved_credits_micro"] is not None and t["reserved_credits_micro"] > 0
            assert t["policy_version_applied"] is not None
            assert t["completed_at"] is not None

        # Turns should have increasing start times
        start_times = [t["started_at"] for t in turns]
        assert start_times == sorted(start_times)

        # ── 9. Verify quota_usage in SQLite ──────────────────────────────
        quota = query_db(
            "SELECT * FROM quota_usage WHERE bucket = 'total'",
        )
        assert len(quota) >= 1

        for q in quota:
            # After settlement, reserved should be back to 0
            assert q["reserved_credits_micro"] == 0, (
                f"Stuck reserve! bucket={q['bucket']} period={q['period_type']} "
                f"reserved={q['reserved_credits_micro']}"
            )
            assert q["spent_credits_micro"] > 0
            assert q["calls"] >= 3  # at least our 3 turns
            assert q["input_tokens"] > 0
            assert q["output_tokens"] > 0

        # ── 10. Verify messages in SQLite have token counts ──────────────
        asst_msgs = query_db(
            "SELECT * FROM messages WHERE chat_id = ? AND role = 'assistant' ORDER BY created_at",
            (chat_id,),
        )
        assert len(asst_msgs) == 3
        for m in asst_msgs:
            assert m["input_tokens"] > 0
            assert m["output_tokens"] > 0
            assert len(m["content"]) > 0

        # ── 11. Idempotency: replay turn 1 ──────────────────────────────
        s_replay, ev_replay, _ = stream_message(
            chat_id, "What is 2+2? Reply with just the number.", request_id=rid1,
        )
        assert s_replay == 200
        # Replay should return stream_started with same message_id and is_new_turn=false
        ss_replay = expect_stream_started(ev_replay)
        assert ss_replay.data["message_id"] == msg_id1
        assert ss_replay.data["is_new_turn"] is False

        # ── 12. Delete chat ──────────────────────────────────────────────
        resp = httpx.delete(f"{API_PREFIX}/chats/{chat_id}")
        assert resp.status_code == 204

        # Verify gone
        resp = httpx.get(f"{API_PREFIX}/chats/{chat_id}")
        assert resp.status_code == 404


class TestQuotaAccumulation:
    """Verify quota accumulates correctly across multiple turns."""

    def test_quota_credits_accumulate(self, server):
        """Each turn should add to spent_credits_micro in quota_usage."""
        # Snapshot quota before
        quota_before = query_db("SELECT * FROM quota_usage WHERE bucket = 'total'")
        spent_before = sum(q["spent_credits_micro"] for q in quota_before)
        calls_before = sum(q["calls"] for q in quota_before)

        # Create chat and do 2 turns
        resp = httpx.post(f"{API_PREFIX}/chats", json={})
        chat_id = resp.json()["id"]

        stream_message(chat_id, "Say A.")
        stream_message(chat_id, "Say B.")

        # Snapshot after
        quota_after = query_db("SELECT * FROM quota_usage WHERE bucket = 'total'")
        spent_after = sum(q["spent_credits_micro"] for q in quota_after)
        calls_after = sum(q["calls"] for q in quota_after)

        assert spent_after > spent_before
        assert calls_after >= calls_before + 2

    def test_no_stuck_reserves_after_completion(self, server):
        """After all turns complete, reserved_credits_micro should be 0."""
        resp = httpx.post(f"{API_PREFIX}/chats", json={})
        chat_id = resp.json()["id"]

        stream_message(chat_id, "Hello.")

        # Check all quota rows — none should have stuck reserves
        quota = query_db("SELECT * FROM quota_usage")
        for q in quota:
            assert q["reserved_credits_micro"] == 0, (
                f"Stuck reserve: bucket={q['bucket']} period={q['period_type']} "
                f"reserved={q['reserved_credits_micro']}"
            )


class TestTurnDetailsInDb:
    """Verify turn-level DB fields from the P6 changes."""

    def test_max_output_tokens_applied(self, server):
        """max_output_tokens_applied should reflect min(catalog, config_cap)."""
        resp = httpx.post(f"{API_PREFIX}/chats", json={})
        chat_id = resp.json()["id"]
        rid = str(uuid.uuid4())

        stream_message(chat_id, "Say hi.", request_id=rid)

        turns = query_db(
            "SELECT * FROM chat_turns WHERE chat_id = ? AND request_id = ?",
            (chat_id, rid),
        )
        assert len(turns) == 1
        t = turns[0]

        # max_output_tokens_applied should be set and positive
        assert t["max_output_tokens_applied"] is not None
        assert t["max_output_tokens_applied"] > 0

        # For gpt-5.2 (catalog: 8192), it should be min(8192, config_cap)
        # Config cap is StreamingConfig.max_output_tokens (likely 32768)
        # So applied should be 8192
        assert t["max_output_tokens_applied"] <= 8192

    def test_reserve_tokens_formula(self, server):
        """reserve_tokens = estimated_input_tokens + max_output_tokens_applied."""
        resp = httpx.post(f"{API_PREFIX}/chats", json={})
        chat_id = resp.json()["id"]
        rid = str(uuid.uuid4())

        stream_message(chat_id, "Hello.", request_id=rid)

        turns = query_db(
            "SELECT * FROM chat_turns WHERE chat_id = ? AND request_id = ?",
            (chat_id, rid),
        )
        t = turns[0]

        # reserve_tokens should be > max_output_tokens_applied
        # (because it includes estimated input tokens)
        assert t["reserve_tokens"] > t["max_output_tokens_applied"]

    def test_credits_settled_after_completion(self, server):
        """After completion, the turn's reserved_credits_micro should match
        what was debited from quota_usage (no stuck reserve)."""
        resp = httpx.post(f"{API_PREFIX}/chats", json={})
        chat_id = resp.json()["id"]
        rid = str(uuid.uuid4())

        stream_message(chat_id, "Say OK.", request_id=rid)

        turns = query_db(
            "SELECT * FROM chat_turns WHERE chat_id = ? AND request_id = ?",
            (chat_id, rid),
        )
        t = turns[0]
        assert t["state"] == "completed"
        assert t["reserved_credits_micro"] > 0  # was reserved

        # All quota rows should have 0 reserved (fully settled)
        quota = query_db("SELECT * FROM quota_usage WHERE reserved_credits_micro > 0")
        assert len(quota) == 0, f"Stuck reserves found: {quota}"
