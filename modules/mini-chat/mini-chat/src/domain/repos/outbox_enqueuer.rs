use mini_chat_sdk::UsageEvent;
use modkit_db::secure::DBRunner;

use crate::domain::error::DomainError;

/// Domain-layer abstraction for enqueuing outbox events within a transaction.
///
/// The finalization service calls this trait to insert outbox rows atomically
/// alongside the CAS state transition and quota settlement. The infra layer
/// implements it by delegating to `modkit_db::outbox::Outbox::enqueue()`.
///
/// # Why a trait?
///
/// The `modkit_db::outbox::Outbox` API is partition-based and accepts raw
/// `Vec<u8>` payloads. Mini-Chat needs a domain-oriented interface that:
/// - Accepts a typed `UsageEvent` (from `mini-chat-sdk`; serialized by the implementation)
/// - Resolves the queue name and partition from tenant context
/// - Participates in the caller's transaction via `&impl DBRunner`
/// - Returns domain errors, not infra-level `OutboxError`
///
/// # Payload type
///
/// Uses `UsageEvent` from `mini-chat-sdk` directly — the single canonical
/// representation of the usage outbox payload. No separate domain payload type
/// exists. The SDK crate is already a dependency of the domain layer.
///
/// # Implementation note
///
/// The infra implementation (`InfraOutboxEnqueuer`) will hold an
/// `Arc<modkit_db::outbox::Outbox>` and call `outbox.enqueue(runner, ...)`
/// within the finalization transaction. The `Outbox::flush()` notification
/// is sent after the transaction commits (by the finalization service).
// TODO(P4): implement InfraOutboxEnqueuer backed by modkit_db::outbox::Outbox
// TODO(P4): Wire into FinalizationService once modkit_db::outbox is merged.
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait OutboxEnqueuer: Send + Sync {
    /// Enqueue a usage event within the caller's transaction.
    ///
    /// The implementation MUST:
    /// - Serialize `event` to `Vec<u8>` (JSON wire format)
    /// - Insert into the outbox table using the provided `runner` (transaction)
    /// - Use `queue = "mini-chat.usage_snapshot"` (or equivalent registered name)
    /// - Derive the partition from `event.tenant_id`
    ///
    /// Duplicate prevention is handled by the CAS guard in the finalization
    /// transaction — the outbox enqueue is only reached by the CAS winner.
    ///
    /// Returns `Ok(())` on success. Returns `Err` on database error.
    async fn enqueue_usage_event<C: DBRunner>(
        &self,
        runner: &C,
        event: UsageEvent,
    ) -> Result<(), DomainError>;
}
