use std::sync::Arc;

use async_trait::async_trait;
use mini_chat_sdk::{
    MiniChatModelPolicyPluginClientV1, MiniChatModelPolicyPluginSpecV1, PolicySnapshot,
};
use modkit::client_hub::{ClientHub, ClientScope};
use modkit::plugins::{GtsPluginSelector, choose_plugin_instance};
use types_registry_sdk::{ListQuery, TypesRegistryClient};
use uuid::Uuid;

use mini_chat_sdk::UserLimits;

use crate::domain::error::DomainError;
use crate::domain::repos::model_resolver::ResolvedModel;
use crate::domain::repos::{ModelResolver, PolicySnapshotProvider, UserLimitsProvider};

/// Resolves model IDs by querying the policy plugin discovered via GTS.
pub struct ModelPolicyGateway {
    hub: Arc<ClientHub>,
    vendor: String,
    policy_selector: GtsPluginSelector,
}

impl ModelPolicyGateway {
    pub(crate) fn new(hub: Arc<ClientHub>, vendor: String) -> Self {
        Self {
            hub,
            vendor,
            policy_selector: GtsPluginSelector::new(),
        }
    }

    /// Lazily resolve the policy plugin from `ClientHub`.
    async fn get_policy_plugin(
        &self,
    ) -> Result<Arc<dyn MiniChatModelPolicyPluginClientV1>, DomainError> {
        let instance_id = self
            .policy_selector
            .get_or_init(|| self.resolve_policy_plugin())
            .await
            .map_err(|e| DomainError::internal(e.to_string()))?;

        let scope = ClientScope::gts_id(instance_id.as_ref());
        self.hub
            .try_get_scoped::<dyn MiniChatModelPolicyPluginClientV1>(&scope)
            .ok_or_else(|| {
                DomainError::internal(format!(
                    "Policy plugin client not registered: {instance_id}"
                ))
            })
    }

    /// Resolve the policy plugin instance from types-registry.
    async fn resolve_policy_plugin(&self) -> Result<String, anyhow::Error> {
        let registry = self.hub.get::<dyn TypesRegistryClient>()?;
        let plugin_type_id = MiniChatModelPolicyPluginSpecV1::gts_schema_id().clone();
        let instances = registry
            .list(
                ListQuery::new()
                    .with_pattern(format!("{plugin_type_id}*"))
                    .with_is_type(false),
            )
            .await?;

        let gts_id = choose_plugin_instance::<MiniChatModelPolicyPluginSpecV1>(
            &self.vendor,
            instances.iter().map(|e| (e.gts_id.as_str(), &e.content)),
        )?;

        Ok(gts_id)
    }
}

#[async_trait]
impl ModelResolver for ModelPolicyGateway {
    async fn resolve_model(
        &self,
        user_id: Uuid,
        model: Option<String>,
    ) -> Result<ResolvedModel, DomainError> {
        let plugin = self.get_policy_plugin().await?;
        let version_info = plugin
            .get_current_policy_version(user_id)
            .await
            .map_err(|e| DomainError::internal(e.to_string()))?;
        let snapshot = plugin
            .get_policy_snapshot(user_id, version_info.policy_version)
            .await
            .map_err(|e| DomainError::internal(e.to_string()))?;

        match model {
            None => {
                // Find default model (prefer is_default + enabled, else first enabled)
                let default = snapshot
                    .model_catalog
                    .iter()
                    .find(|m| m.is_default && m.global_enabled)
                    .or_else(|| snapshot.model_catalog.iter().find(|m| m.global_enabled));

                match default {
                    Some(entry) => Ok(ResolvedModel {
                        model_id: entry.model_id.clone(),
                        provider_id: entry.provider_id.clone(),
                    }),
                    None => Err(DomainError::invalid_model("no models available in catalog")),
                }
            }
            Some(model) if model.is_empty() => {
                Err(DomainError::invalid_model("model must not be empty"))
            }
            Some(model) => {
                // Validate provided model exists in catalog
                let entry = snapshot
                    .model_catalog
                    .iter()
                    .find(|m| m.model_id == model && m.global_enabled);

                match entry {
                    Some(e) => Ok(ResolvedModel {
                        model_id: e.model_id.clone(),
                        provider_id: e.provider_id.clone(),
                    }),
                    None => Err(DomainError::invalid_model(&model)),
                }
            }
        }
    }
}

#[async_trait]
impl PolicySnapshotProvider for ModelPolicyGateway {
    async fn get_snapshot(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<PolicySnapshot, DomainError> {
        let plugin = self.get_policy_plugin().await?;
        plugin
            .get_policy_snapshot(user_id, policy_version)
            .await
            .map_err(|e| DomainError::internal(e.to_string()))
    }

    async fn get_current_version(&self, user_id: Uuid) -> Result<u64, DomainError> {
        let plugin = self.get_policy_plugin().await?;
        let info = plugin
            .get_current_policy_version(user_id)
            .await
            .map_err(|e| DomainError::internal(e.to_string()))?;
        Ok(info.policy_version)
    }
}

#[async_trait]
impl UserLimitsProvider for ModelPolicyGateway {
    async fn get_limits(
        &self,
        user_id: Uuid,
        policy_version: u64,
    ) -> Result<UserLimits, DomainError> {
        let plugin = self.get_policy_plugin().await?;
        plugin
            .get_user_limits(user_id, policy_version)
            .await
            .map_err(|e| DomainError::internal(e.to_string()))
    }
}
