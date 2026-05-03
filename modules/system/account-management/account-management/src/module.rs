//! Account Management `ModKit` module entry-point.
//!
//! Owns the module declaration (`#[modkit::module]`), the
//! [`DatabaseCapability`] implementation (Phase 1 migrations), and the
//! lifecycle entry-point (`serve`) that drives the retention + reaper
//! background ticks.
//!
//! REST routes, the platform-bootstrap saga, and hierarchy-integrity
//! audit are deliberately out of scope for this module file — they
//! live in subsequent PRs together with their own subsystems
//! (`api/`, `domain/bootstrap/`, hierarchy audit).
//!
//! Lifecycle ordering:
//!
//! 1. The runtime applies every migration via
//!    [`modkit::contracts::DatabaseCapability::migrations`].
//! 2. [`Module::init`] constructs `TenantRepoImpl`, hard-resolves
//!    `AuthZResolverClient` (DESIGN §4.3 fail-closed),
//!    `TypesRegistryClient`, and `ResourceGroupClient` from `ClientHub`
//!    (all three are declared in `deps` so the runtime guarantees init
//!    ordering; missing client → `init` returns an error), resolves
//!    the `IdpTenantProvisionerClient` plugin under a config-gated
//!    policy (`idp_required = true` → fail-closed; `false` → fall back
//!    to `NoopProvisioner`), builds the `TenantService`, and stores
//!    it in `OnceLock`.
//! 3. The runtime invokes `serve` on a background task which spawns the
//!    retention + reaper interval loops and returns once `cancel` fires.

use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;

use async_trait::async_trait;
use authz_resolver_sdk::{AuthZResolverClient, PolicyEnforcer};
use modkit::contracts::DatabaseCapability;
use modkit::lifecycle::ReadySignal;
use modkit::{Module, ModuleCtx};
use tokio_util::sync::CancellationToken;
use tracing::info;

use account_management_sdk::IdpTenantProvisionerClient;

use crate::config::AccountManagementConfig;
use crate::domain::tenant::hooks::TenantHardDeleteHook;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
use crate::domain::tenant::service::TenantService;
use crate::domain::tenant_type::TenantTypeChecker;
use crate::infra::idp::NoopProvisioner;
use crate::infra::rg::RgResourceOwnershipChecker;
use crate::infra::storage::migrations::Migrator;
use crate::infra::storage::repo_impl::{AmDbProvider, TenantRepoImpl};
use crate::infra::types_registry::GtsTenantTypeChecker;

type ConcreteService = TenantService<TenantRepoImpl>;

#[modkit::module(
    name = "account-management",
    deps = ["authz-resolver", "types-registry", "resource-group"],
    capabilities = [db, stateful],
    lifecycle(entry = "serve", stop_timeout = "30s", await_ready)
)]
pub struct AccountManagementModule {
    service: OnceLock<Arc<ConcreteService>>,
    /// Hooks registered before [`Module::init`] has set up the service.
    /// Drained into the service inside `init` before the `OnceLock` is
    /// populated, so siblings can call `register_hard_delete_hook`
    /// regardless of init ordering between modules. Always locked
    /// briefly; never held across `await`.
    pending_hard_delete_hooks: Mutex<Vec<TenantHardDeleteHook>>,
}

impl Default for AccountManagementModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            pending_hard_delete_hooks: Mutex::new(Vec::new()),
        }
    }
}

impl AccountManagementModule {
    /// Append a cascade hook to the hard-delete pipeline. Sibling AM
    /// features (user-groups, tenant-metadata) call this inside their
    /// own `init` to register cleanup handlers before the module's
    /// `serve` entry-point flips the state to `Running`.
    ///
    /// # Lifecycle ordering
    ///
    /// This module's `init` may run before *or* after sibling-feature
    /// `init`s. To stay order-independent, hooks registered before
    /// `init` are buffered and replayed into the service when `init`
    /// finishes constructing it. After `init` completes, registrations
    /// forward to the service directly. Siblings still **MUST**
    /// register from their own `init` (not from a `serve` background
    /// task): once `serve` starts the retention + reaper tick loops,
    /// hooks registered later may race with an in-flight
    /// `hard_delete_one` call (the hook list is snapshotted per tick,
    /// so a late-arriving hook may be observed by some concurrent
    /// tenants but not others).
    pub fn register_hard_delete_hook(&self, hook: TenantHardDeleteHook) {
        // Lock the buffer first, *then* check the OnceLock: this
        // ordering is the atomic switch with `init`, which drains
        // the buffer under the same lock before publishing the
        // service to the OnceLock. See `init` for the matching
        // sequence. Without the lock around the OnceLock check,
        // a hook registered concurrently with `init` could land in
        // the buffer *after* the drain ran, never reaching the
        // service.
        let mut pending = self.pending_hard_delete_hooks.lock();
        if let Some(svc) = self.service.get() {
            // Drop the lock before forwarding so a hook that calls
            // back into the module cannot deadlock on us. The
            // buffer is already empty (drained in `init`) and the
            // service exists, so nothing else needs the lock.
            drop(pending);
            svc.register_hard_delete_hook(hook);
        } else {
            pending.push(hook);
        }
    }

    /// Lifecycle entry-point. Spawns the retention + reaper intervals
    /// as two independent tasks under a shared child token of `cancel`
    /// so a long-running retention tick cannot starve the reaper (and
    /// vice versa). The function returns once both children exit after
    /// either `cancel` fires (normal shutdown) or one of the children
    /// panics (early-fail).
    ///
    /// # Errors
    ///
    /// Fails if [`Module::init`] has not run yet (the service handle
    /// is stored in a `OnceLock` during init), or if either background
    /// task panics — cooperative cancel-token shutdown returns
    /// `Ok(())`, so any join error is a real fault we propagate so the
    /// runtime sees the abort instead of believing the module shut
    /// down cleanly. On panic, the surviving task is cancelled via the
    /// shared child token and joined before we return, so neither task
    /// is left orphaned beyond `serve()`.
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

        // Shared child token — cancelled by either the runtime
        // (normal shutdown via `cancel`) or by `serve()` itself when
        // one of the tick tasks dies (early-fail). Both tick tasks
        // observe the same token so a panic in one shuts down the
        // other deterministically instead of leaving it running for
        // up to one full tick beyond `serve()`'s return.
        let tasks_cancel = cancel.child_token();
        let retention_cancel = tasks_cancel.clone();
        let reaper_cancel = tasks_cancel.clone();
        let retention_svc = svc.clone();
        let reaper_svc = svc;

        let mut retention_handle = tokio::spawn(async move {
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

        let mut reaper_handle = tokio::spawn(async move {
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
                                already_absent = result.already_absent,
                                terminal = result.terminal,
                                deferred = result.deferred,
                                "reap_stuck_provisioning tick"
                            );
                        }
                    }
                }
            }
        });

        // Flip the runtime's `Starting -> Running` gate. Note: this
        // returns once both `tokio::spawn` calls above have submitted
        // their futures to the scheduler, but **before** either child
        // task has had its first poll on the `select!` inside its loop.
        // The Tokio scheduler is free to defer that first poll, so
        // there is a narrow window where a consumer observing
        // `Running` could call `cancel.cancel()` before either tick
        // loop has been polled even once. Both child tasks observe
        // `cancelled()` on the very first `select!` poll — this is the
        // accepted "Running but not yet ticked" pattern documented at
        // [`modkit::lifecycle::ReadySignal`] — so the race is bounded
        // (no missed work, no data loss; the tick loops simply exit
        // before processing any tick).
        ready.notify();
        info!(
            target: "am.lifecycle",
            retention_tick_secs = retention_tick.as_secs(),
            reaper_tick_secs = reaper_tick.as_secs(),
            "account-management background ticks started"
        );

        // `select!` on the join handles instead of `join!`: a `join!`
        // would wait for **both** tasks to complete, which means a
        // panic in one is invisible until the other finishes its
        // current tick (potentially the full retention or reaper
        // interval). With `select!` the first task to finish wins;
        // we then cancel `tasks_cancel` to stop the survivor and
        // join it before returning.
        //
        // The `&mut handle` borrow keeps both `JoinHandle`s alive
        // past the `select!` so we can `.await` the survivor in the
        // tail of the chosen arm. `JoinHandle: Unpin`, so the
        // implicit `&mut F: Future` blanket impl applies.
        let serve_result: anyhow::Result<()> = tokio::select! {
            res = &mut retention_handle => {
                tasks_cancel.cancel();
                let reaper_res = (&mut reaper_handle).await;
                check_task_join("retention", res)?;
                check_task_join("reaper", reaper_res)?;
                Ok(())
            }
            res = &mut reaper_handle => {
                tasks_cancel.cancel();
                let retention_res = (&mut retention_handle).await;
                check_task_join("reaper", res)?;
                check_task_join("retention", retention_res)?;
                Ok(())
            }
        };
        info!(
            target: "am.lifecycle",
            "account-management background ticks cancelled"
        );
        serve_result
    }
}

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

        // AM-specific DBProvider parameterized over DomainError.
        let db_raw = ctx.db_required()?;
        let db: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db_raw.db()));

        let repo = Arc::new(TenantRepoImpl::new(db));

        // Resolve the IdP provisioner plugin from ClientHub. The
        // resolution policy is config-gated by `idp_required`:
        //   * `idp_required = true`  → fail-closed at init when the
        //                              plugin is missing (production
        //                              posture for deployments that
        //                              integrate with an external IdP).
        //   * `idp_required = false` → fall back to `NoopProvisioner`
        //                              (dev / test, or AM-only
        //                              deployments without external
        //                              user store). `create_child` then
        //                              returns `UnsupportedOperation`
        //                              at runtime if the saga reaches
        //                              the IdP step.
        let idp: Arc<dyn IdpTenantProvisionerClient> =
            match ctx.client_hub().get::<dyn IdpTenantProvisionerClient>() {
                Ok(plugin) => {
                    info!("idp provisioner plugin resolved from client hub");
                    plugin
                }
                Err(e) if cfg.idp_required => {
                    return Err(anyhow::anyhow!(
                        "idp_required=true but no IdpTenantProvisionerClient is registered: {e}"
                    ));
                }
                Err(_) => {
                    info!(
                        "no idp provisioner plugin registered; falling back to NoopProvisioner \
                         (idp_required=false)"
                    );
                    Arc::new(NoopProvisioner)
                }
            };

        // FEATURE 2.3 (tenant-type-enforcement) — hard-resolve the
        // GTS Types Registry client. types-registry is declared in
        // `deps` so the runtime guarantees init ordering, and AM
        // genuinely cannot function without it: every TenantInfo
        // returned to API consumers carries a `tenant_type` field
        // sourced from the registry, and tenant-type enforcement
        // (parent/child pairing admission) is the registry's
        // dedicated job. A missing client would degrade those into
        // null `tenant_type` fields and admit-everything pairings,
        // which is contract-broken rather than degraded — so we
        // fail closed at init instead of binding an inert fallback
        // in production. (Tests construct the service directly with
        // `inert_tenant_type_checker()` and bypass this init path.)
        //
        // The resolved client is reused for two purposes:
        //   * the type-compatibility barrier
        //     ([`GtsTenantTypeChecker`])
        //   * the `tenant_type_uuid` → chained-id lookup that lowers
        //     `TenantModel` into the public [`TenantInfo`] shape on
        //     every service-layer CRUD return value.
        let types_registry: Arc<dyn types_registry_sdk::TypesRegistryClient> = ctx
            .client_hub()
            .get::<dyn types_registry_sdk::TypesRegistryClient>()
            .map_err(|e| anyhow::anyhow!("failed to get TypesRegistryClient: {e}"))?;
        info!("types-registry client resolved from client hub; enabling GTS tenant-type checker");
        let tenant_type_checker: Arc<dyn TenantTypeChecker + Send + Sync> =
            Arc::new(GtsTenantTypeChecker::new(types_registry.clone()));

        // FEATURE 2.3 follow-up — hard-resolve the Resource Group
        // client for the soft-delete `tenant_has_resources` probe.
        // resource-group is declared in `deps` so the runtime guarantees
        // init ordering, and the probe is load-bearing for soft-delete
        // safety (DESIGN §3.5): a missing client would silently admit
        // soft-delete on tenants that still own RG rows, which is
        // contract-broken rather than degraded — so we fail closed at
        // init instead of binding an inert fallback in production.
        // (Tests construct the service directly with
        // `InertResourceOwnershipChecker` and bypass this init path.)
        let rg_client = ctx
            .client_hub()
            .get::<dyn resource_group_sdk::ResourceGroupClient>()
            .map_err(|e| anyhow::anyhow!("failed to get ResourceGroupClient: {e}"))?;
        info!("resource-group client resolved from client hub; enabling RG ownership checker");
        let resource_checker: Arc<dyn ResourceOwnershipChecker> =
            Arc::new(RgResourceOwnershipChecker::new(rg_client));

        // PEP boundary (DESIGN §4.2). Hard-fail when no `AuthZResolverClient`
        // is registered: DESIGN §4.3 mandates fail-closed for protected
        // operations and explicitly forbids a local authorization fallback.
        let authz = ctx
            .client_hub()
            .get::<dyn AuthZResolverClient>()
            .map_err(|e| anyhow::anyhow!("failed to get AuthZ resolver: {e}"))?;
        let enforcer = PolicyEnforcer::new(authz);
        info!("authz-resolver client resolved from client hub; PolicyEnforcer wired");

        let mut service = TenantService::new(
            repo,
            idp,
            resource_checker,
            tenant_type_checker,
            enforcer,
            cfg,
        );
        service = service.with_types_registry(types_registry);

        // Drain the pre-init hook buffer into the service and
        // publish the service through `OnceLock` *under the same
        // lock*. This is the matching half of the atomic switch in
        // `register_hard_delete_hook`: any concurrent registration
        // either runs before we acquire the buffer lock (it lands
        // in the buffer; we drain it) or after we drop it (it sees
        // `service.get() == Some(_)` and forwards directly). A
        // naive drain-then-set would leave a window where a hook
        // arrives between drain and set, lands in the buffer, and
        // is never replayed.
        {
            let mut buf = self.pending_hard_delete_hooks.lock();
            for hook in buf.drain(..) {
                service.register_hard_delete_hook(hook);
            }
            self.service
                .set(Arc::new(service))
                .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;
        }

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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "module_tests.rs"]
mod tests;
