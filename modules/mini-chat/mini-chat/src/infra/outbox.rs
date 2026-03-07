#![allow(dead_code)]

use async_trait::async_trait;
use mini_chat_sdk::UsageEvent;
use modkit_db::secure::DBRunner;
use tracing::debug;

use crate::domain::error::DomainError;
use crate::domain::repos::OutboxEnqueuer;

/// Infrastructure implementation of [`OutboxEnqueuer`].
///
/// Serializes `UsageEvent` to JSON and inserts into the outbox table
/// within the caller's transaction via `modkit_db::outbox::Outbox::enqueue()`.
///
/// TODO(P4): replace stub with real implementation once `modkit_db::outbox`
/// is merged from the `transactional-outbox` branch. The implementation should:
/// - Hold `Arc<modkit_db::outbox::Outbox>`
/// - Serialize `event` to `serde_json::to_vec(&event)?`
/// - Derive partition from `event.tenant_id` (e.g., hash % `num_partitions`)
/// - Call `outbox.enqueue(runner, queue_name, partition, payload).await`
pub struct InfraOutboxEnqueuer {
    queue_name: String,
    num_partitions: u32,
}

impl InfraOutboxEnqueuer {
    pub(crate) fn new(queue_name: String, num_partitions: u32) -> Self {
        Self {
            queue_name,
            num_partitions,
        }
    }

    fn partition_for(&self, tenant_id: uuid::Uuid) -> u32 {
        // Simple hash-based partition assignment
        let hash = tenant_id.as_u128();
        #[allow(clippy::cast_possible_truncation)] // result is bounded by num_partitions (u32)
        {
            (hash % u128::from(self.num_partitions)) as u32
        }
    }
}

#[async_trait]
impl OutboxEnqueuer for InfraOutboxEnqueuer {
    async fn enqueue_usage_event<C: DBRunner>(
        &self,
        _runner: &C,
        event: UsageEvent,
    ) -> Result<(), DomainError> {
        let _partition = self.partition_for(event.tenant_id);
        let _payload = serde_json::to_vec(&event)
            .map_err(|e| DomainError::internal(format!("failed to serialize UsageEvent: {e}")))?;

        debug!(
            turn_id = %event.turn_id,
            queue = %self.queue_name,
            partition = _partition,
            "outbox enqueue stub (modkit_db::outbox not yet available)"
        );

        // TODO(P4): replace with real outbox.enqueue() call:
        // self.outbox.enqueue(runner, &self.queue_name, partition, payload).await
        //     .map_err(|e| DomainError::internal(format!("outbox enqueue failed: {e}")))?;

        Ok(())
    }
}
