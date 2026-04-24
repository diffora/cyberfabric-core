//! Account Management `ModKit` module entry-point.
//!
//! Owns the module declaration (`#[modkit::module]`), the
//! `DatabaseCapability` implementation (Phase 1 migration + Phase 3
//! migration), and the `RestApiCapability` implementation (Phase 2
//! routes + Phase 3 `DELETE`). Phase 3 also adds the `stateful`
//! capability and the `serve` lifecycle entry-point that drives the
//! retention + reaper background ticks.
//!
//! Lifecycle ordering:
//!
//! 1. The runtime applies every migration via
//!    [`modkit::contracts::DatabaseCapability::migrations`].
//! 2. [`Module::init`] constructs `TenantRepoImpl`, resolves the
//!    optional `IdpTenantProvisioner` from `ClientHub` (falls back to
//!    `NoopProvisioner` in dev), builds the `TenantService`, and
//!    stores it in `OnceLock`.
//! 3. [`modkit::contracts::RestApiCapability::register_rest`] wires
//!    the five `tenants` routes onto the gateway router.
//! 4. The runtime invokes `serve` on a background task which drives the
//!    retention + reaper intervals until `cancel` is triggered.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use authz_resolver_sdk::{AuthZResolverClient, PolicyEnforcer};
use axum::extract::Extension;
use axum::routing::get;
use axum::{Json, Router};
use modkit::api::OpenApiRegistry;
use modkit::contracts::{DatabaseCapability, RestApiCapability};
use modkit::lifecycle::ReadySignal;
use modkit::{Module, ModuleCtx};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::api::tenants::register_routes;
use crate::config::AccountManagementConfig;
use crate::domain::bootstrap::service::BootstrapService;
use crate::domain::idp::provisioner::IdpTenantProvisioner;
use crate::domain::metrics::{
    AM_BOOTSTRAP_LIFECYCLE, AM_DEPENDENCY_HEALTH, MetricKind, emit_metric,
};
use crate::domain::tenant::hooks::TenantHardDeleteHook;
use crate::domain::tenant::resource_checker::{
    InertResourceOwnershipChecker, ResourceOwnershipChecker,
};
use crate::domain::tenant::service::TenantService;
use crate::domain::tenant_type::{InertTenantTypeChecker, TenantTypeChecker};
use crate::infra::idp::NoopProvisioner;
use crate::infra::rg::RgResourceOwnershipChecker;
use crate::infra::storage::migrations::Migrator;
use crate::infra::storage::repo_impl::{AmDbProvider, TenantRepoImpl};
use crate::infra::types_registry::GtsTenantTypeChecker;

type ConcreteService = TenantService<TenantRepoImpl>;

#[modkit::module(
    name = "account-management",
    deps = ["authz-resolver"],
    capabilities = [db, rest, stateful],
    lifecycle(entry = "serve", stop_timeout = "30s", await_ready)
)]
pub struct AccountManagementModule {
    service: OnceLock<Arc<ConcreteService>>,
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-state
    bootstrap_completed: Arc<AtomicBool>,
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-state
}

impl Default for AccountManagementModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            bootstrap_completed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl AccountManagementModule {
    /// Health-surface signal for platform bootstrap completion.
    #[must_use]
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-getter
    pub fn bootstrap_completed(&self) -> bool {
        self.bootstrap_completed.load(Ordering::Acquire)
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-getter

    fn set_bootstrap_completed(&self, completed: bool) {
        self.bootstrap_completed.store(completed, Ordering::Release);
    }

    /// Append a cascade hook to the hard-delete pipeline. Sibling AM
    /// features (user-groups, tenant-metadata) call this inside their
    /// own `init` to register cleanup handlers before the module's
    /// `serve` entry-point flips the state to `Running`.
    ///
    /// # Errors
    ///
    /// Returns an error if the module's `init` has not run yet (the
    /// service is stored in a `OnceLock` during `init`).
    pub fn register_hard_delete_hook(&self, hook: TenantHardDeleteHook) -> anyhow::Result<()> {
        let svc = self
            .service
            .get()
            .ok_or_else(|| anyhow::anyhow!("service not initialized"))?;
        svc.register_hard_delete_hook(hook);
        Ok(())
    }

    /// Lifecycle entry-point. Spawns the retention + reaper intervals
    /// as two independent tasks under `cancel` child tokens so a
    /// long-running retention tick cannot starve the reaper (and
    /// vice versa). The function returns once both children exit
    /// after `cancel` fires.
    ///
    /// # Errors
    ///
    /// Fails if [`Module::init`] has not run yet (the service handle
    /// is stored in a `OnceLock` during init).
    #[allow(
        clippy::redundant_pub_crate,
        reason = "module-private serve entry-point invoked by the modkit runtime"
    )]
    pub(crate) async fn serve(
        self: Arc<Self>,
        cancel: CancellationToken,
        ready: ReadySignal,
    ) -> anyhow::Result<()> {
        let Some(svc) = self.service.get().cloned() else {
            anyhow::bail!("account-management: serve invoked before init");
        };
        let retention_tick = svc.retention_tick();
        let reaper_tick = svc.reaper_tick();
        let batch_size = svc.hard_delete_batch_size();
        let provisioning_timeout = svc.provisioning_timeout();

        let retention_cancel = cancel.child_token();
        let reaper_cancel = cancel.child_token();
        let retention_svc = svc.clone();
        let reaper_svc = svc;

        let retention_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(retention_tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = retention_cancel.cancelled() => break,
                    _instant = interval.tick() => {
                        let result = retention_svc.hard_delete_batch(batch_size).await;
                        if result.processed > 0 {
                            info!(
                                target: "am.lifecycle",
                                processed = result.processed,
                                cleaned = result.cleaned,
                                deferred = result.deferred,
                                failed = result.failed,
                                "hard_delete_batch tick"
                            );
                        }
                    }
                }
            }
        });

        let reaper_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(reaper_tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = reaper_cancel.cancelled() => break,
                    _instant = interval.tick() => {
                        let result = reaper_svc.reap_stuck_provisioning(provisioning_timeout).await;
                        if result.scanned > 0 {
                            info!(
                                target: "am.lifecycle",
                                scanned = result.scanned,
                                compensated = result.compensated,
                                deferred = result.deferred,
                                "reap_stuck_provisioning tick"
                            );
                        }
                    }
                }
            }
        });

        ready.notify();
        info!(
            target: "am.lifecycle",
            retention_tick_secs = retention_tick.as_secs(),
            reaper_tick_secs = reaper_tick.as_secs(),
            "account-management background ticks started"
        );

        let (retention_res, reaper_res) = tokio::join!(retention_handle, reaper_handle);
        info!(
            target: "am.lifecycle",
            "account-management background ticks cancelled"
        );
        // Cooperative cancel-token shutdown returns `Ok(())` from the
        // task body, so any `Err(_)` from the join is a real fault
        // (panic / abort) that operators need to see — surface as an
        // `error!` log and propagate from `serve` so the runtime
        // doesn't believe the module shut down cleanly.
        check_task_join("retention", retention_res)?;
        check_task_join("reaper", reaper_res)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct AccountManagementHealth {
    status: &'static str,
    bootstrap_completed: bool,
}

async fn account_management_health(
    Extension(bootstrap_completed): Extension<Arc<AtomicBool>>,
) -> Json<AccountManagementHealth> {
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-route
    Json(AccountManagementHealth {
        status: "healthy",
        bootstrap_completed: bootstrap_completed.load(Ordering::Acquire),
    })
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-route
}

// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-nonstrict-failure-metric
fn emit_non_strict_bootstrap_failure_metric(phase: &'static str, classification: &'static str) {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", phase),
            ("classification", classification),
            ("outcome", "failure_non_strict"),
        ],
    );
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-nonstrict-failure-metric

/// Inspect the join result of a `serve`-spawned background task. A
/// `JoinError` here always indicates a panic / abort — cooperative
/// cancel-token shutdown returns `Ok(())` — so we surface it as an
/// `error!` log and propagate as an `anyhow` error.
fn check_task_join(
    name: &'static str,
    res: Result<(), tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::error!(
                target: "am.lifecycle",
                task = name,
                error = %e,
                "task ended abnormally"
            );
            Err(anyhow::anyhow!("{name} task panicked: {e}"))
        }
    }
}

#[cfg(test)]
static INERT_RG_BINDING_WARNINGS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn inert_resource_checker_for_production() -> Arc<dyn ResourceOwnershipChecker> {
    #[cfg(test)]
    INERT_RG_BINDING_WARNINGS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    warn!(
        target: "am::checkers::inert_rg",
        "InertResourceOwnershipChecker active in production; ResourceGroup checks are skipped"
    );
    emit_metric(
        AM_DEPENDENCY_HEALTH,
        MetricKind::Gauge,
        &[("target", "rg"), ("op", "bound"), ("outcome", "inert")],
    );
    Arc::new(InertResourceOwnershipChecker)
}

#[async_trait]
impl Module for AccountManagementModule {
    #[tracing::instrument(skip_all, fields(module = "account-management"))]
    async fn init(&self, ctx: &ModuleCtx) -> anyhow::Result<()> {
        let cfg: AccountManagementConfig = ctx.config_or_default()?;
        // Validate fields whose misconfiguration would panic or
        // produce undefined behavior at runtime — currently the
        // retention + reaper tick intervals (`tokio::time::interval`
        // panics on a zero `Duration`). Surfacing the bad value here
        // turns a misconfig into a clean `init` failure instead of a
        // background-task abort the host runtime sees as a panic.
        cfg.validate()
            .map_err(|err| anyhow::anyhow!("account-management config invalid: {err}"))?;
        info!(
            max_list_children_top = cfg.max_list_children_top,
            depth_strict_mode = cfg.depth_strict_mode,
            depth_threshold = cfg.depth_threshold,
            "initializing account-management module"
        );

        // Build the AM-specific DBProvider parameterized over AmError.
        let db_raw = ctx.db_required()?;
        let db: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db_raw.db()));

        let repo = Arc::new(TenantRepoImpl::new(db));

        // Try to resolve the optional IdP provisioner plugin from ClientHub.
        // If unavailable (dev / test), fall back to NoopProvisioner.
        let idp: Arc<dyn IdpTenantProvisioner + Send + Sync> =
            if let Ok(plugin) = ctx.client_hub().get::<dyn IdpTenantProvisioner>() {
                info!("idp provisioner plugin resolved from client hub");
                plugin
            } else {
                info!("no idp provisioner plugin registered; falling back to NoopProvisioner");
                Arc::new(NoopProvisioner)
            };

        // FEATURE 2.3 (tenant-type-enforcement) — try to resolve the
        // GTS Types Registry client. If unavailable, fall back to the
        // inert checker (admit every pairing) so dev / test deployments
        // without a types-registry plugin keep booting.
        let types_registry = ctx
            .client_hub()
            .get::<dyn types_registry_sdk::TypesRegistryClient>()
            .ok();
        let tenant_type_checker: Arc<dyn TenantTypeChecker + Send + Sync> = if let Some(registry) =
            types_registry.clone()
        {
            info!(
                "types-registry client resolved from client hub; enabling GTS tenant-type checker"
            );
            Arc::new(GtsTenantTypeChecker::with_config(
                registry,
                cfg.strict_barriers,
                cfg.types_registry_probe_timeout_ms,
            ))
        } else if cfg.strict_barriers {
            return Err(anyhow::anyhow!(
                "strict_barriers=true requires a types-registry client; refusing to bind InertTenantTypeChecker"
            ));
        } else {
            warn!(
                target: "am.tenant_type",
                "no types-registry client registered; falling back to InertTenantTypeChecker (every parent/child pairing admitted)"
            );
            Arc::new(InertTenantTypeChecker)
        };

        // FEATURE 2.3 follow-up — try to resolve the Resource Group
        // client for the soft-delete `tenant_has_resources` probe. If
        // unavailable, fall back to the inert checker (always 0).
        let resource_checker: Arc<dyn ResourceOwnershipChecker> = if let Ok(rg) =
            ctx.client_hub()
                .get::<dyn resource_group_sdk::ResourceGroupClient>()
        {
            info!("resource-group client resolved from client hub; enabling RG ownership checker");
            Arc::new(RgResourceOwnershipChecker::with_timeout(
                rg,
                cfg.rg_probe_timeout_ms,
            ))
        } else {
            inert_resource_checker_for_production()
        };

        // PEP boundary (DESIGN §4.2). Hard-fail when no `AuthZResolverClient`
        // is registered: DESIGN §4.3 mandates fail-closed for protected
        // operations and explicitly forbids a local authorization fallback.
        let authz = ctx
            .client_hub()
            .get::<dyn AuthZResolverClient>()
            .map_err(|e| anyhow::anyhow!("failed to get AuthZ resolver: {e}"))?;
        let enforcer = PolicyEnforcer::new(authz);
        info!("authz-resolver client resolved from client hub; PolicyEnforcer wired");

        // Phase: platform-bootstrap (FEATURE 2.1). Run BEFORE the
        // service handle is published so `serve` cannot start the
        // retention + reaper loops without a root tenant
        // (`fr-bootstrap-ordering`). When `cfg.bootstrap` is `None`
        // bootstrap is skipped (dev / multi-region deployments).
        // Reject nil identifiers / empty `root_tenant_type` /
        // inverted backoff envelope before constructing the saga —
        // `BootstrapConfig` uses `serde(default)`, so an empty
        // `[bootstrap]` TOML table deserialises to nil UUIDs (see
        // `feature-platform-bootstrap.md` lines 23-25:
        // "deployment-stable; changing it between platform restarts
        // breaks the `fr-bootstrap-idempotency` contract"). The
        // validator output is mapped to a strict-mode init failure or
        // a non-strict warning so misconfiguration surfaces during
        // `init`, never at the first DB write.
        let validated_bootstrap = match cfg.bootstrap.clone() {
            Some(boot_cfg) => match boot_cfg.validate() {
                Ok(()) => Some(boot_cfg),
                Err(err) if boot_cfg.strict => {
                    self.set_bootstrap_completed(false);
                    return Err(anyhow::anyhow!(
                        "platform-bootstrap configuration invalid (strict mode): {err}"
                    ));
                }
                Err(err) => {
                    self.set_bootstrap_completed(false);
                    emit_non_strict_bootstrap_failure_metric("validation", "configuration");
                    tracing::warn!(
                        target: "am.bootstrap",
                        error = %err,
                        "platform-bootstrap configuration invalid; skipping bootstrap (non-strict mode)"
                    );
                    None
                }
            },
            None => None,
        };

        if let Some(boot_cfg) = validated_bootstrap {
            let strict = boot_cfg.strict;
            let mut bootstrap = BootstrapService::new(repo.clone(), idp.clone(), boot_cfg);
            if let Some(registry) = types_registry.clone() {
                bootstrap = bootstrap.with_types_registry(registry);
            }
            match bootstrap.run().await {
                Ok(root) => {
                    self.set_bootstrap_completed(true);
                    info!(
                        target: "am.bootstrap",
                        root_id = %root.id,
                        "platform-bootstrap completed; module init proceeding"
                    );
                }
                Err(err) if strict => {
                    self.set_bootstrap_completed(false);
                    return Err(anyhow::anyhow!(
                        "platform-bootstrap failed (strict mode): {err}"
                    ));
                }
                Err(err) => {
                    self.set_bootstrap_completed(false);
                    emit_non_strict_bootstrap_failure_metric("run", "bootstrap");
                    tracing::warn!(
                        target: "am.bootstrap",
                        error = %err,
                        "platform-bootstrap failed in non-strict mode; module init proceeds without an active root"
                    );
                }
            }
        } else {
            self.set_bootstrap_completed(false);
            info!(
                target: "am.bootstrap",
                "no bootstrap configuration present; skipping platform-bootstrap"
            );
        }

        let service = Arc::new(TenantService::new(
            repo,
            idp,
            resource_checker,
            tenant_type_checker,
            enforcer,
            cfg,
        ));
        self.service
            .set(service)
            .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;
        Ok(())
    }
}

impl DatabaseCapability for AccountManagementModule {
    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        use sea_orm_migration::MigratorTrait;
        info!("providing account-management database migrations");
        Migrator::migrations()
    }
}

impl RestApiCapability for AccountManagementModule {
    fn register_rest(
        &self,
        _ctx: &ModuleCtx,
        router: Router,
        openapi: &dyn OpenApiRegistry,
    ) -> anyhow::Result<Router> {
        let service = self
            .service
            .get()
            .ok_or_else(|| anyhow::anyhow!("service not initialized"))?
            .clone();
        let bootstrap_completed = self.bootstrap_completed.clone();
        info!("account-management: registering REST routes");
        // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-route-registration
        Ok(register_routes::<TenantRepoImpl>(router, openapi, service)
            .route(
                "/api/account-management/v1/health",
                get(account_management_health),
            )
            .layer(Extension(bootstrap_completed)))
        // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-health-route-registration
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]
mod tests {
    //! Module-level lifecycle tests. These are deliberately narrow —
    //! the full DB wiring is exercised via integration tests; here we
    //! verify the cooperative cancellation contract only.

    use super::*;
    use crate::domain::tenant::service::TenantService;
    use crate::domain::tenant::test_support::{
        FakeIdpProvisioner, FakeOutcome, FakeTenantRepo, mock_enforcer,
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use types_registry_sdk::{GtsEntity, ListQuery, RegisterResult, TypesRegistryClient};

    struct ModuleTestRegistry;

    #[async_trait]
    impl TypesRegistryClient for ModuleTestRegistry {
        async fn register(
            &self,
            _entities: Vec<serde_json::Value>,
        ) -> Result<Vec<RegisterResult>, types_registry_sdk::TypesRegistryError> {
            unreachable!("not used by module test")
        }

        async fn list(
            &self,
            _query: ListQuery,
        ) -> Result<Vec<GtsEntity>, types_registry_sdk::TypesRegistryError> {
            unreachable!("not used by module test")
        }

        async fn get(
            &self,
            _gts_id: &str,
        ) -> Result<GtsEntity, types_registry_sdk::TypesRegistryError> {
            Ok(GtsEntity {
                id: uuid::Uuid::from_u128(0xAA),
                gts_id: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".into(),
                segments: Vec::new(),
                is_schema: true,
                content: serde_json::json!({
                    "x-gts-traits": { "allowed_parent_types": [] }
                }),
                description: None,
            })
        }
    }

    #[tokio::test]
    async fn stateful_task_shuts_down_on_cancel() {
        // Run the equivalent of `serve` (retention + reaper as two
        // independent `tokio::spawn` tasks under child tokens) and
        // prove that cancelling the root token shuts down both
        // children promptly.
        let root = uuid::Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = Arc::new(TenantService::new(
            repo,
            Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok)),
            Arc::new(InertResourceOwnershipChecker),
            crate::domain::tenant_type::inert_tenant_type_checker(),
            mock_enforcer(),
            AccountManagementConfig {
                retention_tick_secs: 1,
                reaper_tick_secs: 1,
                ..AccountManagementConfig::default()
            },
        ));

        let cancel = CancellationToken::new();
        let retention_cancel = cancel.child_token();
        let reaper_cancel = cancel.child_token();
        let retention_svc = svc.clone();
        let reaper_svc = svc;

        let retention_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = retention_cancel.cancelled() => break,
                    _tick = interval.tick() => {
                        let _ = retention_svc.hard_delete_batch(8).await;
                    }
                }
            }
        });
        let reaper_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = reaper_cancel.cancelled() => break,
                    _tick = interval.tick() => {
                        let _ = reaper_svc
                            .reap_stuck_provisioning(std::time::Duration::from_secs(1))
                            .await;
                    }
                }
            }
        });

        // Let the children run a couple of ticks.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        cancel.cancel();
        // Both child tasks must exit within the timeout window.
        let join = tokio::time::timeout(std::time::Duration::from_millis(200), async move {
            tokio::join!(retention_handle, reaper_handle)
        })
        .await;
        assert!(
            join.is_ok(),
            "retention + reaper tasks must both exit within 200ms of cancel"
        );
    }

    #[tokio::test]
    async fn inert_rg_binding_emits_warning_marker_and_dependency_gauge() {
        crate::domain::metrics::clear_captured_metric_samples();
        let before = INERT_RG_BINDING_WARNINGS.load(std::sync::atomic::Ordering::SeqCst);

        let checker = inert_resource_checker_for_production();

        assert_eq!(
            checker
                .count_ownership_links(uuid::Uuid::from_u128(0x501))
                .await
                .expect("inert checker still reports zero"),
            0
        );
        assert_eq!(
            INERT_RG_BINDING_WARNINGS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
        let samples = crate::domain::metrics::take_captured_metric_samples();
        assert!(
            samples.iter().any(|sample| {
                sample.family == AM_DEPENDENCY_HEALTH
                    && sample.kind == MetricKind::Gauge
                    && sample.labels.as_slice()
                        == &[
                            ("target", "rg".to_owned()),
                            ("op", "bound".to_owned()),
                            ("outcome", "inert".to_owned()),
                        ]
            }),
            "expected rg bound/inert gauge, got: {samples:?}"
        );
    }

    #[test]
    fn bootstrap_completed_signal_is_queryable() {
        let module = AccountManagementModule::default();
        assert!(!module.bootstrap_completed());

        module.set_bootstrap_completed(true);
        assert!(module.bootstrap_completed());

        module.set_bootstrap_completed(false);
        assert!(!module.bootstrap_completed());
    }

    #[test]
    fn non_strict_bootstrap_failure_metric_uses_expected_labels() {
        crate::domain::metrics::clear_captured_metric_samples();

        emit_non_strict_bootstrap_failure_metric("run", "bootstrap");

        let samples = crate::domain::metrics::take_captured_metric_samples();
        assert!(
            samples.iter().any(|sample| {
                sample.family == AM_BOOTSTRAP_LIFECYCLE
                    && sample.kind == MetricKind::Counter
                    && sample.labels.as_slice()
                        == &[
                            ("phase", "run".to_owned()),
                            ("classification", "bootstrap".to_owned()),
                            ("outcome", "failure_non_strict".to_owned()),
                        ]
            }),
            "expected bootstrap failure_non_strict metric, got: {samples:?}"
        );
    }

    /// FEATURE 2.1 acceptance §6 — when `bootstrap.strict = true` and
    /// the saga fails, `init` propagates the failure as an
    /// `anyhow::Error` so the runtime aborts module bring-up instead
    /// of starting `serve` with a missing root tenant. We exercise the
    /// strict-mode error-propagation path directly (rather than
    /// invoking `init` end-to-end) because constructing a real
    /// `ModuleCtx` requires a full `ModKit` runtime — out of scope for
    /// a unit test.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_strict_mode_propagates_init_failure_to_module() {
        use crate::domain::bootstrap::config::BootstrapConfig;
        use crate::domain::bootstrap::service::BootstrapService;
        use crate::domain::error::AmError;

        let root_id = uuid::Uuid::from_u128(0x900);
        let repo = Arc::new(FakeTenantRepo::new());
        let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Unsupported));
        let cfg = BootstrapConfig {
            root_id,
            root_name: "platform-root".into(),
            root_tenant_type_uuid: uuid::Uuid::from_u128(0xAA),
            root_tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".into(),
            root_tenant_metadata: None,
            idp_check_availability_attempts: 1,
            idp_check_availability_backoff_ms: 1,
            idp_wait_timeout_secs: 1,
            idp_retry_backoff_initial_secs: 1,
            idp_retry_backoff_max_secs: 1,
            strict: true,
        };

        let bootstrap = BootstrapService::new(repo, idp, cfg.clone())
            .with_types_registry(Arc::new(ModuleTestRegistry));
        // Simulate the `init` strict-mode short-circuit.
        let init_result: anyhow::Result<()> = match bootstrap.run().await {
            Err(err) if cfg.strict => Err(anyhow::anyhow!(
                "platform-bootstrap failed (strict mode): {err}"
            )),
            Ok(_) | Err(_) => Ok(()),
        };
        let outer_err = init_result.expect_err("strict mode must surface bootstrap failure");
        let msg = outer_err.to_string();
        assert!(
            msg.contains("platform-bootstrap failed (strict mode)"),
            "expected strict-mode wrapping, got: {msg}"
        );
        // And the root cause is an `idp_unsupported_operation` AmError.
        let chain = outer_err.chain().last().expect("chain not empty");
        assert!(
            chain.to_string().contains("IdP unsupported operation")
                || chain
                    .downcast_ref::<AmError>()
                    .is_some_and(|e| matches!(e, AmError::IdpUnsupportedOperation { .. })),
            "expected IdP unsupported root cause, got chain tail: {chain}"
        );
    }
}
