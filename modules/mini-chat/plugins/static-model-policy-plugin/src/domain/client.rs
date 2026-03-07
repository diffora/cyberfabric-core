use async_trait::async_trait;
use mini_chat_sdk::{
    MiniChatModelPolicyPluginClientV1, MiniChatModelPolicyPluginError, PolicySnapshot,
    PolicyVersionInfo, PublishError, UsageEvent, UserLimits,
};
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

use super::service::Service;

#[async_trait]
impl MiniChatModelPolicyPluginClientV1 for Service {
    async fn get_current_policy_version(
        &self,
        user_id: Uuid,
    ) -> Result<PolicyVersionInfo, MiniChatModelPolicyPluginError> {
        Ok(PolicyVersionInfo {
            user_id,
            policy_version: 1,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    async fn get_policy_snapshot(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<PolicySnapshot, MiniChatModelPolicyPluginError> {
        if policy_version != 1 {
            return Err(MiniChatModelPolicyPluginError::NotFound);
        }
        Ok(PolicySnapshot {
            user_id,
            policy_version,
            model_catalog: self.catalog.clone(),
            kill_switches: self.kill_switches.clone(),
        })
    }

    async fn get_user_limits(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<UserLimits, MiniChatModelPolicyPluginError> {
        if policy_version != 1 {
            return Err(MiniChatModelPolicyPluginError::NotFound);
        }
        Ok(UserLimits {
            user_id,
            policy_version,
            standard: self.default_standard_limits.clone(),
            premium: self.default_premium_limits.clone(),
        })
    }

    async fn publish_usage(&self, payload: UsageEvent) -> Result<(), PublishError> {
        debug!(
            turn_id = %payload.turn_id,
            tenant_id = %payload.tenant_id,
            billing_outcome = %payload.billing_outcome,
            "static plugin: publish_usage no-op"
        );
        Ok(())
    }
}
