//! Account Management `ModKit` module entry-point.
//!
//! Owns the module declaration (`#[modkit::module]`), the
//! [`DatabaseCapability`] implementation (Phase 1 migrations), and the
//! lifecycle entry-point (`serve`) that drives the retention, reaper,
//! and periodic hierarchy-integrity-check background ticks.
//!
//! REST routes are deliberately out of scope for this module file —
//! they land in a subsequent PR once the `InTenantSubtree` predicate
//! makes the storage-level subtree clamp safe (cyberware-rust#1813).
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
//!    the `IdpPluginClient` plugin under a config-gated
//!    policy (`idp.required = true` → fail-closed; `false` → fall back
//!    to `NoopIdpProvider`), validates the bootstrap configuration
//!    (fail-fast for strict-mode invalid configs), builds the
//!    `TenantService`, and stores it in `OnceLock`. `init()` does
//!    **not** run the bootstrap saga — it only validates the config
//!    and stores the parameters for `serve()`.
//! 3. The runtime invokes `serve` on a background task. `serve()`
//!    first runs the platform-bootstrap saga (if configured) with
//!    the `CancellationToken` provided by the runtime, ensuring the
//!    saga is interruptible on SIGTERM. Under `bootstrap.strict = true`
//!    (production posture) a successful saga guarantees an `Active`
//!    root row is present before retention + reaper start, so those
//!    loops never observe a rootless platform. Under
//!    `bootstrap.strict = false` (or when the `[bootstrap]` section
//!    is absent entirely) the saga is allowed to fail or skip —
//!    `serve()` logs and continues. After bootstrap, `serve()` spawns
//!    the retention + reaper interval loops and returns once `cancel`
//!    fires.

use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;

use async_trait::async_trait;
use authz_resolver_sdk::{AuthZResolverClient, PolicyEnforcer};
use modkit::contracts::DatabaseCapability;
use modkit::lifecycle::ReadySignal;
use modkit::{Module, ModuleCtx};
use tokio_util::sync::CancellationToken;
use tracing::info;

use account_management_sdk::IdpPluginClient;

use crate::config::AccountManagementConfig;
use crate::domain::bootstrap::BootstrapService;
use crate::domain::conversion::repo::ConversionRepo;
use crate::domain::conversion::service::{ConversionScope, ConversionService};
use crate::domain::integrity_check::{IntegrityChecker, run_integrity_check_loop};
use crate::domain::tenant::TenantRepo;
use crate::domain::tenant::hooks::TenantHardDeleteHook;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
use crate::domain::tenant::service::TenantService;
use crate::domain::tenant_type::TenantTypeChecker;
use crate::domain::user::service::UserService;
use crate::infra::idp::NoopIdpProvider;
use crate::infra::rg::RgResourceOwnershipChecker;
use crate::infra::storage::migrations::Migrator;
use crate::infra::storage::repo_impl::{AmDbProvider, ConversionRepoImpl, TenantRepoImpl};
use crate::infra::types_registry::GtsTenantTypeChecker;

type ConcreteService = TenantService<TenantRepoImpl>;

/// Bootstrap dependencies captured in `init()` and consumed by
/// `serve()`. Separating validation (fast, in `init`) from execution
/// (slow, cancellable, in `serve`) keeps `init()` fail-fast and lets
/// the orchestrator mark the pod as live before the `IdP` wait begins.
struct BootstrapParams {
    config: crate::domain::bootstrap::BootstrapConfig,
    idp_required: bool,
    repo: Arc<TenantRepoImpl>,
    idp: Arc<dyn IdpPluginClient>,
    types_registry: Arc<dyn types_registry_sdk::TypesRegistryClient>,
}

// Conversion lifecycle knobs (`approval_ttl`, `resolved_retention`,
// `cleanup_interval`, batch sizes) live on `cfg.conversion` per
// `ConversionConfig`. Defaults match `cpt-cf-account-management-adr-
// conversion-approval` (ADR-0003 §1) — `init` validates each before
// the conversion service is wired and `serve` spawns the cleanup
// tick.

#[modkit::module(
    name = "account-management",
    deps = ["authz-resolver", "types-registry", "resource-group"],
    capabilities = [db, stateful],
    lifecycle(entry = "serve", stop_timeout = "30s", await_ready)
)]
pub struct AccountManagementModule {
    service: OnceLock<Arc<ConcreteService>>,
    /// Conversion-request domain service handle, published alongside
    /// [`Self::service`] so SDK consumers (and the upcoming REST
    /// surface) can drive the dual-consent
    /// `pending -> {approved, cancelled, rejected, expired}` lifecycle
    /// without re-discovering its dependencies. Wired during
    /// [`Module::init`]; remains unset until init runs.
    conversion_service: OnceLock<Arc<ConversionService>>,
    /// `IdP` user-operations domain service handle, published alongside
    /// [`Self::service`] so SDK consumers (and the upcoming REST
    /// surface for `/tenants/{id}/users`) can drive provision /
    /// deprovision / list flows without re-discovering the resolved
    /// `IdpPluginClient`. Wired during [`Module::init`];
    /// remains unset until init runs.
    user_service: OnceLock<Arc<UserService>>,
    /// Hooks registered before [`Module::init`] has set up the service.
    /// Drained into the service inside `init` before the `OnceLock` is
    /// populated, so siblings can call `register_hard_delete_hook`
    /// regardless of init ordering between modules. Always locked
    /// briefly; never held across `await`.
    pending_hard_delete_hooks: Mutex<Vec<TenantHardDeleteHook>>,
    /// Bootstrap saga parameters validated in `init()`, consumed by
    /// `serve()`. `None` when bootstrap is not configured, config is
    /// invalid (non-strict), or after `serve()` has taken the params.
    bootstrap_params: Mutex<Option<BootstrapParams>>,
}

impl Default for AccountManagementModule {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            conversion_service: OnceLock::new(),
            user_service: OnceLock::new(),
            pending_hard_delete_hooks: Mutex::new(Vec::new()),
            bootstrap_params: Mutex::new(None),
        }
    }
}

impl AccountManagementModule {
    /// Crate-private accessor for the wired [`ConversionService`].
    ///
    /// # Visibility
    ///
    /// `pub(crate)` on purpose: the conversion service intentionally
    /// reads through `AccessScope::allow_all()` and relies on the
    /// dual-consent state-machine guards inside the service itself
    /// rather than on a [`PolicyEnforcer`] dependency. Until the
    /// upcoming REST surface (cyberfabric-core#1813 follow-up) wires
    /// the PEP boundary in front of these methods, exposing the
    /// service publicly would let a sibling module bypass the
    /// intended REST-layer authorization by calling the service
    /// directly. Promoting this accessor back to `pub` lands together
    /// with the REST handler PR.
    ///
    /// # Lifecycle
    ///
    /// Returns `None` until [`Module::init`] has finished publishing
    /// the service into its [`OnceLock`].
    #[must_use]
    #[allow(
        dead_code,
        reason = "no in-tree caller until the conversion REST handler PR (cyberfabric-core#1813) wires the PEP boundary in front of this accessor"
    )]
    pub(crate) fn conversion_service(&self) -> Option<Arc<ConversionService>> {
        self.conversion_service.get().cloned()
    }

    /// Crate-private accessor for the wired [`UserService`].
    ///
    /// # Visibility
    ///
    /// `pub(crate)` on purpose: `UserService` does not currently
    /// inject a [`PolicyEnforcer`] -- `IdP` user-ops authorization
    /// is expected to land at the REST/PEP boundary in the follow-up
    /// surface for `/tenants/{id}/users` (cyberfabric-core#1813).
    /// Until that boundary exists, exposing the service publicly
    /// would let a sibling module reach `IdP` user-ops without going
    /// through any authz check. Promoting back to `pub` lands with
    /// the REST handler PR (or after `PolicyEnforcer` is injected
    /// here, whichever ships first).
    ///
    /// # Lifecycle
    ///
    /// Returns `None` until [`Module::init`] has finished publishing
    /// the service into its [`OnceLock`].
    #[must_use]
    #[allow(
        dead_code,
        reason = "no in-tree caller until the user-ops REST handler PR (cyberfabric-core#1813) wires the PEP boundary in front of this accessor"
    )]
    pub(crate) fn user_service(&self) -> Option<Arc<UserService>> {
        self.user_service.get().cloned()
    }

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
    #[allow(
        clippy::cognitive_complexity,
        reason = "four symmetric tick-task spawns (retention, reaper, integrity, conversion) + a 4-arm select! that joins the survivors per-arm; collapsing the arms would obscure the panic-cascade contract documented above each arm"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "linear orchestration: bootstrap saga + four parallel tick-task spawns (retention, reaper, integrity, conversion) each with their own logging + a single select! that joins the survivors; splitting fragments the panic-cascade contract documented above each spawn"
    )]
    pub(crate) async fn serve(
        self: Arc<Self>,
        cancel: CancellationToken,
        ready: ReadySignal,
    ) -> anyhow::Result<()> {
        let Some(svc) = self.service.get().cloned() else {
            anyhow::bail!("account-management: serve invoked before init");
        };

        // Phase 1: run bootstrap saga before tick loops. The saga
        // gets the runtime's CancellationToken so IdP-wait sleeps
        // are interruptible on SIGTERM. The guarantee "active root
        // row exists before the loops observe the platform" is
        // preserved — loops are not spawned until after this resolves.
        let bootstrap_params = self.bootstrap_params.lock().take();
        if let Some(params) = bootstrap_params {
            run_bootstrap_saga(params, cancel.child_token()).await?;
        }

        let retention_tick = svc.retention_tick();
        let reaper_tick = svc.reaper_tick();
        let batch_size = svc.hard_delete_batch_size();
        let provisioning_timeout = svc.provisioning_timeout();
        let integrity_cfg = svc.integrity_check_config();
        // Conversion service handle is published by `init` alongside
        // the tenant service — if `init` ran successfully (which is
        // the only path that reaches `serve`), it MUST be present.
        // Bail out instead of silently skipping conversion ticks so a
        // misconfigured deployment fails loudly at startup rather
        // than letting pending conversions accumulate forever.
        let conversion_svc = self.conversion_service.get().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "account-management: serve invoked before conversion service was published"
            )
        })?;

        // Shared child token — cancelled by either the runtime
        // (normal shutdown via `cancel`) or by `serve()` itself when
        // one of the tick tasks dies (early-fail). All four tick
        // tasks observe the same token so a panic in one shuts down
        // the others deterministically instead of leaving them
        // running for up to one full tick beyond `serve()`'s return.
        let tasks_cancel = cancel.child_token();
        let retention_cancel = tasks_cancel.clone();
        let reaper_cancel = tasks_cancel.clone();
        let integrity_cancel = tasks_cancel.clone();
        let conversion_cancel = tasks_cancel.clone();
        let retention_svc = svc.clone();
        let reaper_svc = svc.clone();
        let integrity_checker: Arc<dyn IntegrityChecker> = svc;

        let mut retention_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(retention_tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // `biased;` ensures cancellation is checked before
                // `interval.tick()` when both are ready. Without it,
                // tokio's random branch selection can let the tick win
                // after a cancel signal is already pending, firing one
                // extra `hard_delete_batch` after shutdown was
                // signalled (delaying the lifecycle drain by up to one
                // batch's worth of cascade-hooks + IdP round-trips).
                tokio::select! {
                    biased;
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
                // `biased;` — same rationale as the retention loop
                // above: cancellation is checked first so a stale
                // tick cannot fire one more `reap_stuck_provisioning`
                // pass (and its IdP `deprovision_tenant` calls) after
                // shutdown was signalled.
                tokio::select! {
                    biased;
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

        // Hierarchy-integrity check loop. The loop itself is the
        // entire task body — it owns its initial-delay sleep, the
        // jittered post-tick sleep, the per-tick error policy
        // (gate-conflict → skip; other err → warn-and-continue), and
        // the cancellation observation. When `cfg.enabled = false`
        // the loop short-circuits to `cancel.cancelled().await` so
        // this `JoinHandle` retains the same lifecycle shape as
        // retention / reaper (it never resolves before shutdown),
        // keeping the `select!` arms below symmetric.
        let integrity_enabled = integrity_cfg.enabled;
        let mut integrity_handle = tokio::spawn(async move {
            run_integrity_check_loop(integrity_checker, integrity_cfg, integrity_cancel).await;
        });

        // Conversion-request expire + retention loop. Two cleanups
        // share one tick because each is bounded by its own
        // `batch_size` cap and both run against the same table — the
        // alternative (two extra spawns) would only buy independent
        // backpressure for two reads / writes that are already
        // light. Pure background work, no caller scope; uses
        // `AccessScope::allow_all` like the other AM reaper paths.
        // Errors from either method are warn-logged; the loop never
        // exits short of cancellation so a transient DB blip cannot
        // permanently silence the reaper.
        let conversion_loop_svc = Arc::clone(&conversion_svc);
        let conversion_resolved_retention = conversion_svc.resolved_retention();
        let conversion_cleanup_interval = conversion_svc.cleanup_interval();
        let conversion_expire_batch = conversion_svc.expire_batch_size();
        let conversion_retention_batch = conversion_svc.retention_batch_size();
        let mut conversion_handle = tokio::spawn(async move {
            // Dedicated `cleanup_interval` cadence per ADR-0003 §1 —
            // distinct from `retention_tick` so an operator dialing
            // tenant hard-delete down does NOT slow conversion expiry
            // / retention along with it.
            let mut interval = tokio::time::interval(conversion_cleanup_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = conversion_cancel.cancelled() => break,
                    _instant = interval.tick() => {
                        // Gate `soft_delete_resolved` on
                        // `expire_pending` returning `Ok(_)`: when
                        // the expire pass returns `Err(_)` at the
                        // scan level (the `query_expired` call
                        // itself failed — DB unreachable,
                        // serialization timeout on the scan TX),
                        // running retention on the same tick
                        // doubles the load on an already-stressed
                        // backend. Defer the retention sweep to the
                        // next tick instead.
                        //
                        // Per-row failures inside `expire_pending`
                        // do NOT propagate as `Err` — they are
                        // logged on `am.domain` and the function
                        // still returns `Ok(transitioned)`, so this
                        // gate stays open under per-row degradation
                        // and retention proceeds normally. That
                        // asymmetry is deliberate: scan-level
                        // failure is total (no progress this tick),
                        // whereas per-row failure is partial and
                        // the surviving rows still benefit from a
                        // retention pass.
                        let expire_ok = match conversion_loop_svc
                            .expire_pending(
                                &ConversionScope::system_sweep(),
                                conversion_expire_batch,
                                &conversion_cancel,
                            )
                            .await
                        {
                            Ok(transitioned) => {
                                if transitioned > 0 {
                                    info!(
                                        target: "am.lifecycle",
                                        transitioned,
                                        "conversion expire_pending tick"
                                    );
                                }
                                true
                            }
                            Err(err) => {
                                tracing::warn!(
                                    target: "am.lifecycle",
                                    error = %err,
                                    "conversion expire_pending tick failed; skipping \
                                     soft_delete_resolved this tick to avoid doubling \
                                     load on an already-stressed backend"
                                );
                                false
                            }
                        };
                        if expire_ok {
                            match conversion_loop_svc
                                .soft_delete_resolved(
                                    &ConversionScope::system_sweep(),
                                    conversion_resolved_retention,
                                    conversion_retention_batch,
                                )
                                .await
                            {
                                Ok(soft_deleted) if soft_deleted > 0 => {
                                    info!(
                                        target: "am.lifecycle",
                                        soft_deleted,
                                        "conversion soft_delete_resolved tick"
                                    );
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    tracing::warn!(
                                        target: "am.lifecycle",
                                        error = %err,
                                        "conversion soft_delete_resolved tick failed"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        // Flip the runtime's `Starting -> Running` gate. Note: this
        // returns once all three `tokio::spawn` calls above have
        // submitted their futures to the scheduler, but **before** any
        // child task has had its first poll on the `select!` inside
        // its loop. The Tokio scheduler is free to defer that first
        // poll, so there is a narrow window where a consumer observing
        // `Running` could call `cancel.cancel()` before any tick loop
        // has been polled even once. Each child task observes
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
            integrity_check_enabled = integrity_enabled,
            conversion_tick_secs = conversion_cleanup_interval.as_secs(),
            "account-management background ticks started"
        );

        // `select!` on the join handles instead of `join!`: a `join!`
        // would wait for **all** tasks to complete, which means a
        // panic in one is invisible until the others finish their
        // current ticks (potentially the full retention or reaper
        // interval). With `select!` the first task to finish wins;
        // we then cancel `tasks_cancel` to stop the survivors and
        // join them before returning.
        //
        // The `&mut handle` borrow keeps every `JoinHandle` alive
        // past the `select!` so we can `.await` the survivors in the
        // tail of the chosen arm. `JoinHandle: Unpin`, so the
        // implicit `&mut F: Future` blanket impl applies.
        let serve_result: anyhow::Result<()> = tokio::select! {
            res = &mut retention_handle => {
                tasks_cancel.cancel();
                let reaper_res = (&mut reaper_handle).await;
                let integrity_res = (&mut integrity_handle).await;
                let conversion_res = (&mut conversion_handle).await;
                check_task_join("retention", res)?;
                check_task_join("reaper", reaper_res)?;
                check_task_join("integrity", integrity_res)?;
                check_task_join("conversion", conversion_res)?;
                Ok(())
            }
            res = &mut reaper_handle => {
                tasks_cancel.cancel();
                let retention_res = (&mut retention_handle).await;
                let integrity_res = (&mut integrity_handle).await;
                let conversion_res = (&mut conversion_handle).await;
                check_task_join("reaper", res)?;
                check_task_join("retention", retention_res)?;
                check_task_join("integrity", integrity_res)?;
                check_task_join("conversion", conversion_res)?;
                Ok(())
            }
            res = &mut integrity_handle => {
                tasks_cancel.cancel();
                let retention_res = (&mut retention_handle).await;
                let reaper_res = (&mut reaper_handle).await;
                let conversion_res = (&mut conversion_handle).await;
                check_task_join("integrity", res)?;
                check_task_join("retention", retention_res)?;
                check_task_join("reaper", reaper_res)?;
                check_task_join("conversion", conversion_res)?;
                Ok(())
            }
            res = &mut conversion_handle => {
                tasks_cancel.cancel();
                let retention_res = (&mut retention_handle).await;
                let reaper_res = (&mut reaper_handle).await;
                let integrity_res = (&mut integrity_handle).await;
                check_task_join("conversion", res)?;
                check_task_join("retention", retention_res)?;
                check_task_join("reaper", reaper_res)?;
                check_task_join("integrity", integrity_res)?;
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
            max_list_children_top = cfg.listing.max_top,
            depth_strict_mode = cfg.hierarchy.depth_strict_mode,
            depth_threshold = cfg.hierarchy.depth_threshold,
            "initializing account-management module"
        );

        // AM-specific DBProvider parameterized over DomainError.
        let db_raw = ctx.db_required()?;
        let db: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db_raw.db()));

        let repo = Arc::new(TenantRepoImpl::new(Arc::clone(&db)));

        // Resolve the IdP provider plugin from ClientHub. The single
        // plugin instance now carries both tenant lifecycle (provision /
        // deprovision tenant) and user lifecycle (provision / deprovision
        // / list users) per the combined `IdpPluginClient`
        // contract. The resolution policy is config-gated by
        // `idp.required`:
        //   * `idp.required = true`  → fail-closed at init when the
        //                              plugin is missing (production
        //                              posture for deployments that
        //                              integrate with an external IdP).
        //   * `idp.required = false` → fall back to `NoopIdpProvider`
        //                              (dev / test, or AM-only
        //                              deployments without external
        //                              user store). Both `create_child`
        //                              and user-ops then return
        //                              `UnsupportedOperation` at
        //                              runtime if the saga reaches the
        //                              IdP step.
        //
        // The user-ops REST surface is deferred until
        // `cyberfabric-core#1813`; gating it with a separate
        // `idp.user_operations_required` knob can land alongside the
        // REST surface if deployments need to opt in independently.
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-resolve-plugin
        let idp: Arc<dyn IdpPluginClient> = match ctx.client_hub().get::<dyn IdpPluginClient>() {
            Ok(plugin) => {
                info!("idp provider plugin resolved from client hub");
                plugin
            }
            Err(e) if cfg.idp.required => {
                return Err(anyhow::anyhow!(
                    "idp.required=true but no IdpPluginClient is registered: {e}"
                ));
            }
            Err(_) => {
                info!(
                    "no idp provider plugin registered; falling back to NoopIdpProvider \
                         (idp.required=false)"
                );
                Arc::new(NoopIdpProvider)
            }
        };
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-resolve-plugin

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

        // Validate bootstrap config (fast, fail-fast) and store
        // params for serve(). The saga itself runs in serve() where
        // the runtime's CancellationToken is available, so IdP-wait
        // sleeps are interruptible on SIGTERM and the pod's liveness
        // probe can respond while init() is not blocked.
        if let Some(boot_cfg) = cfg.bootstrap.clone() {
            if let Err(err) = boot_cfg.validate() {
                if boot_cfg.strict {
                    return Err(anyhow::anyhow!(
                        "bootstrap configuration invalid (strict mode): {err}"
                    ));
                }
                tracing::warn!(
                    error = %err,
                    "bootstrap configuration invalid (non-strict); skipping bootstrap"
                );
            } else {
                *self.bootstrap_params.lock() = Some(BootstrapParams {
                    config: boot_cfg,
                    idp_required: cfg.idp.required,
                    repo: Arc::clone(&repo),
                    idp: Arc::clone(&idp),
                    types_registry: Arc::clone(&types_registry),
                });
            }
        }

        // Capture the conversion section before `cfg` is moved into
        // `TenantService::new` below — the conversion service is
        // constructed afterwards and needs the same validated values.
        let conversion_cfg = cfg.conversion.clone();

        let mut service = TenantService::new(
            Arc::clone(&repo),
            Arc::clone(&idp),
            resource_checker,
            Arc::clone(&tenant_type_checker),
            enforcer,
            cfg,
        );
        service = service.with_types_registry(Arc::clone(&types_registry));

        // Build the conversion-request domain service alongside the
        // tenant service. The service owns the
        // `TenantTypeChecker` dependency — type compatibility is
        // evaluated at the domain layer BEFORE the repo's apply TX
        // opens, with a TX-side TOCTOU guard on
        // `tenants.tenant_type_uuid` carried in
        // `ApplyConversionApprovalInput`. The repo therefore
        // shares only the live `AmDbProvider`.
        let conversion_repo: Arc<dyn ConversionRepo> =
            Arc::new(ConversionRepoImpl::new(Arc::clone(&db)));
        let conversion_service = Arc::new(
            ConversionService::new(
                conversion_repo,
                Arc::clone(&repo) as Arc<dyn TenantRepo>,
                Arc::clone(&tenant_type_checker),
                std::time::Duration::from_secs(conversion_cfg.approval_ttl_secs),
                std::time::Duration::from_secs(conversion_cfg.resolved_retention_secs),
            )
            .with_cleanup_lifecycle(
                std::time::Duration::from_secs(conversion_cfg.cleanup_interval_secs),
                conversion_cfg.expire_batch_size,
                conversion_cfg.retention_batch_size,
            ),
        );
        // Build the user-operations domain service alongside the
        // conversion service. Shares the same `TenantRepoImpl` for
        // tenant-existence resolution; the resolved
        // `IdpPluginClient` plugin came in via `ClientHub`
        // earlier in this `init`. Per
        // `cpt-cf-account-management-constraint-no-user-storage` the
        // service holds NO storage handles -- every read and write
        // is a live pass-through to the IdP.
        let user_service = Arc::new(UserService::new(
            Arc::clone(&repo) as Arc<dyn TenantRepo>,
            Arc::clone(&idp),
            Arc::clone(&types_registry),
        ));

        // Atomic publish of all three `OnceLock` handles together,
        // ordered so a half-published state is unobservable:
        //
        // 1. Acquire the pre-init hook buffer lock and drain it into
        //    the primary `TenantService` (the `register_hard_delete_hook`
        //    contract: any concurrent registration either runs before
        //    we acquire the lock — lands in the buffer; we drain it —
        //    or after we publish `self.service` — sees `service.get()
        //    == Some(_)` and forwards directly).
        // 2. Publish primary `self.service` first so any caller that
        //    observes one of the secondary handles (conversion /
        //    user) and then probes the primary sees a published
        //    state (or the same `init` failure path on a re-entry).
        // 3. Publish the two secondary handles after the primary.
        //    Failure to set any of them (init re-entered) returns
        //    `Err` with no rollback of the already-set primary; the
        //    second `init` is supposed to fail closed anyway per the
        //    `OnceLock` contract.
        //
        // Previously the secondary handles were published BEFORE the
        // primary, leaving a window where an external caller could
        // see a wired `ConversionService` without `TenantService`
        // being ready — a half-published init state.
        {
            let mut buf = self.pending_hard_delete_hooks.lock();
            for hook in buf.drain(..) {
                service.register_hard_delete_hook(hook);
            }
            self.service
                .set(Arc::new(service))
                .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;
        }
        self.conversion_service
            .set(Arc::clone(&conversion_service))
            .map_err(|_| {
                anyhow::anyhow!(
                    "{} module already initialized (conversion service)",
                    Self::MODULE_NAME
                )
            })?;
        self.user_service
            .set(Arc::clone(&user_service))
            .map_err(|_| {
                anyhow::anyhow!(
                    "{} module already initialized (user service)",
                    Self::MODULE_NAME
                )
            })?;

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

/// Run a validated bootstrap saga with cancellation support.
/// Called from `serve()` with the runtime's `CancellationToken`.
async fn run_bootstrap_saga(
    params: BootstrapParams,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let strict = params.config.strict;
    let mut bootstrap = BootstrapService::new(params.repo, params.idp, params.config);
    bootstrap = bootstrap
        .with_types_registry(params.types_registry)
        .with_idp_required(params.idp_required)
        .with_cancel(cancel);
    match bootstrap.run().await {
        Ok(root) => {
            info!(root_id = %root.id, "platform bootstrap saga completed");
            Ok(())
        }
        Err(err) if strict => Err(anyhow::anyhow!(
            "platform bootstrap saga failed (strict mode): {err}"
        )),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "platform bootstrap saga failed (non-strict); proceeding without root"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "module_tests.rs"]
mod tests;
