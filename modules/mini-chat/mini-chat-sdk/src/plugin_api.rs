use async_trait::async_trait;
use uuid::Uuid;

use crate::error::{MiniChatModelPolicyPluginError, PublishError};
use crate::models::{PolicySnapshot, PolicyVersionInfo, UsageEvent, UserLimits};

/// Plugin API trait for mini-chat model policy implementations.
///
/// Plugins implement this trait to provide model catalog and policy data.
/// The mini-chat module discovers plugins via GTS types-registry and
/// delegates policy queries to the selected plugin.
#[async_trait]
pub trait MiniChatModelPolicyPluginClientV1: Send + Sync {
    /// Get the current policy version for a user.
    async fn get_current_policy_version(
        &self,
        user_id: Uuid,
    ) -> Result<PolicyVersionInfo, MiniChatModelPolicyPluginError>;

    /// Get the policy snapshot for a given version.
    async fn get_policy_snapshot(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<PolicySnapshot, MiniChatModelPolicyPluginError>;

    /// Get per-user credit allocations for a specific policy version.
    async fn get_user_limits(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<UserLimits, MiniChatModelPolicyPluginError>;

    /// Publish a usage event after turn finalization.
    ///
    /// Called by the outbox processor after the finalization transaction
    /// commits. Plugins can forward the event to external billing systems.
    async fn publish_usage(&self, payload: UsageEvent) -> Result<(), PublishError>;
}
