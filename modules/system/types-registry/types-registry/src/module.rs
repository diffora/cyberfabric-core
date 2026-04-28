//! Module declaration for the Types Registry module.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use modkit::api::OpenApiRegistry;
use modkit::contracts::SystemCapability;
use modkit::{Module, ModuleCtx, RestApiCapability};
use tracing::{debug, info};
use types_registry_sdk::{RegisterResult, RegisterSummary, TypesRegistryClient};

use crate::config::TypesRegistryConfig;
use crate::domain::local_client::TypesRegistryLocalClient;
use crate::domain::service::TypesRegistryService;
use crate::infra::InMemoryGtsRepository;

/// Types Registry module.
///
/// Provides GTS entity registration, storage, validation, and REST API endpoints.
///
/// ## Capabilities
///
/// - `system` — Core infrastructure module, initialized early in startup
/// - `rest` — Exposes REST API endpoints
///
/// ## Note
///
/// Core GTS types (like `BaseModkitPluginV1`) are now registered by the
/// `types` module (`modules/system/types`), not here. This maintains proper
/// separation of concerns and avoids circular dependencies.
#[modkit::module(
    name = "types-registry",
    capabilities = [system, rest]
)]
pub struct TypesRegistryModule {
    service: OnceLock<Arc<TypesRegistryService>>,
}

impl Default for TypesRegistryModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
        }
    }
}

#[async_trait]
impl Module for TypesRegistryModule {
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        let cfg: TypesRegistryConfig = ctx.config_or_default()?;
        debug!(
            "Loaded types_registry config: entity_id_fields={:?}, schema_id_fields={:?}",
            cfg.entity_id_fields, cfg.schema_id_fields
        );

        let gts_config = cfg.to_gts_config();
        let static_entities = cfg.entities.clone();
        let default_tenant_id = cfg.default_tenant_id;

        let repo = Arc::new(InMemoryGtsRepository::new(gts_config));
        let service = Arc::new(TypesRegistryService::new(repo, cfg));

        // Register static entities from config (before ready-mode validation)
        if !static_entities.is_empty() {
            let tenant_id_str = default_tenant_id.to_string();
            let entities: Vec<serde_json::Value> = static_entities
                .into_iter()
                .map(|mut v| {
                    if let Some(obj) = v.as_object_mut() {
                        obj.entry("tenant_id")
                            .or_insert_with(|| serde_json::Value::String(tenant_id_str.clone()));
                    }
                    v
                })
                .collect();

            let entity_count = entities.len();
            let results = service.register(entities);
            let summary = RegisterSummary::from_results(&results);

            if !summary.all_succeeded() {
                for result in &results {
                    if let RegisterResult::Err { gts_id, error } = result {
                        tracing::error!(
                            gts_id = gts_id.as_deref().unwrap_or("<unknown>"),
                            error = %error,
                            "Failed to register static GTS entity"
                        );
                    }
                }
                anyhow::bail!(
                    "types-registry: {}/{} static entities failed to register",
                    summary.failed,
                    summary.total()
                );
            }

            info!(
                count = entity_count,
                "Registered static GTS entities from config"
            );
        }

        self.service
            .set(service.clone())
            .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;

        let api: Arc<dyn TypesRegistryClient> = Arc::new(TypesRegistryLocalClient::new(service));
        ctx.client_hub().register::<dyn TypesRegistryClient>(api);

        Ok(())
    }
}

#[async_trait]
impl SystemCapability for TypesRegistryModule {
    /// Post-init hook: switches the registry to ready mode.
    ///
    /// This runs AFTER `init()` has completed for ALL modules.
    /// At this point, all modules have had a chance to register their types,
    /// so we can safely validate and switch to ready mode.
    async fn post_init(&self, _sys: &modkit::runtime::SystemContext) -> anyhow::Result<()> {
        info!("types_registry post_init: switching to ready mode");

        let service = self
            .service
            .get()
            .ok_or_else(|| anyhow::anyhow!("Service not initialized"))?
            .clone();

        service.switch_to_ready().map_err(|e| {
            if let Some(errors) = e.validation_errors() {
                for err in errors {
                    // Try to get the entity content for debugging
                    let entity_content = match service.get(&err.gts_id) {
                        Ok(entity) => serde_json::to_string_pretty(&entity.content)
                            .unwrap_or_else(|_| "Failed to serialize".to_owned()),
                        _ => "Entity not found or failed to retrieve".to_owned(),
                    };

                    tracing::error!(
                        gts_id = %err.gts_id,
                        message = %err.message,
                        entity_content = %entity_content,
                        "GTS validation error"
                    );
                }
            }
            anyhow::anyhow!("Failed to switch to ready mode: {e}")
        })?;

        info!("types_registry switched to ready mode successfully");
        Ok(())
    }
}

impl RestApiCapability for TypesRegistryModule {
    fn register_rest(
        &self,
        _ctx: &ModuleCtx,
        router: axum::Router,
        openapi: &dyn OpenApiRegistry,
    ) -> anyhow::Result<axum::Router> {
        info!("Registering types_registry REST routes");

        let service = self
            .service
            .get()
            .ok_or_else(|| anyhow::anyhow!("Service not initialized"))?
            .clone();

        let router = crate::api::rest::routes::register_routes(router, openapi, service);

        info!("Types registry REST routes registered successfully");
        Ok(router)
    }
}
