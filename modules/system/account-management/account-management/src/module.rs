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
//!    policy (`idp.required = true` → fail-closed; `false` → fall back
//!    to `NoopProvisioner`), builds the `TenantService`, and stores
//!    it in `OnceLock`. `tenant-resolver` is also declared in `deps`
//!    even though AM does not consume a runtime client from it: TR
//!    owns the registration of the `TenantResolverPluginSpecV1`
//!    type-schema in types-registry, and AM registers a
//!    `BaseModkitPluginV1<TenantResolverPluginSpecV1>` *instance* of
//!    that schema when `tr_plugin.enabled = true`. The instance
//!    registration would fail with `ParentTypeSchemaNotRegistered`
//!    if TR's init had not run first, so the dep is the
//!    init-order constraint that makes the registration block
//!    deterministic.
//!
//!    **Trade-off — TR is mandatory in any AM-included binary,**
//!    even when `tr_plugin.enabled = false`. ModKit hard-deps are
//!    static (declared at compile time) and unsatisfied deps are a
//!    fatal startup error, so we cannot conditionally drop the
//!    edge based on the runtime config flag. We accept this cost
//!    because:
//!
//!    * TR is a tiny coordinator module — the binary-size impact
//!      is negligible.
//!    * Any deploy that *uses* tenant-resolver functionality
//!      (whether AM's plugin or a third-party one) needs TR
//!      anyway, so the constraint only bites a hypothetical
//!      AM-only-no-TR build that would have nothing to resolve
//!      tenants with.
//!    * Without the dep, two `system` modules sit in the same
//!      modkit init phase with no explicit ordering, and AM could
//!      run before TR — which silently breaks `tr_plugin.enabled
//!      = true` deploys with a stale `ParentTypeSchemaNotRegistered`
//!      that is hard to diagnose.
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
use crate::tr_plugin::PluginImpl as TrPluginImpl;
use modkit::client_hub::ClientScope;
use modkit::gts::BaseModkitPluginV1;
use tenant_resolver_sdk::{TenantResolverPluginClient, TenantResolverPluginSpecV1};
use types_registry_sdk::RegisterResult;

type ConcreteService = TenantService<TenantRepoImpl>;

#[modkit::module(
    name = "account-management",
    deps = ["authz-resolver", "types-registry", "resource-group", "tenant-resolver"],
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
            max_list_children_top = cfg.listing.max_top,
            depth_strict_mode = cfg.hierarchy.depth_strict_mode,
            depth_threshold = cfg.hierarchy.depth_threshold,
            "initializing account-management module"
        );

        // AM-specific DBProvider parameterized over DomainError.
        let db_raw = ctx.db_required()?;
        let db: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db_raw.db()));

        let repo = Arc::new(TenantRepoImpl::new(db));

        // Resolve the IdP provisioner plugin from ClientHub. The
        // resolution policy is config-gated by `idp.required`:
        //   * `idp.required = true`  → fail-closed at init when the
        //                              plugin is missing (production
        //                              posture for deployments that
        //                              integrate with an external IdP).
        //   * `idp.required = false` → fall back to `NoopProvisioner`
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
                Err(e) if cfg.idp.required => {
                    return Err(anyhow::anyhow!(
                        "idp.required=true but no IdpTenantProvisionerClient is registered: {e}"
                    ));
                }
                Err(_) => {
                    info!(
                        "no idp provisioner plugin registered; falling back to NoopProvisioner \
                         (idp.required=false)"
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

        // `cfg` is moved into `TenantService::new` below. Capture the
        // tr_plugin knobs here so the registration block at the bottom
        // of `init` can still read them — `enabled`/`priority` are
        // `Copy`, `vendor` is cloned out as an owned `String`.
        let tr_plugin_enabled = cfg.tr_plugin.enabled;
        let tr_plugin_vendor = cfg.tr_plugin.vendor.clone();
        let tr_plugin_priority = cfg.tr_plugin.priority;
        let mut service = TenantService::new(
            repo,
            idp,
            resource_checker,
            tenant_type_checker,
            enforcer,
            cfg,
        );
        service = service.with_types_registry(Arc::clone(&types_registry));

        // Tenant Resolver Plugin (in-process, AM-co-located).
        //
        // **Opt-in**: gated by `cfg.tr_plugin.enabled`. While the
        // plugin is still in build-out the default is `false` so a
        // deploy that incidentally pulls AM into its binary does NOT
        // register the plugin in either types-registry or
        // `ClientHub` — without that gate, an AM-only binary would
        // be the sole candidate under the configured vendor and the
        // gateway's `choose_plugin_instance` would pick AM regardless
        // of `priority`.
        //
        // Runs BEFORE `self.service.set(...)` below: TR-plugin GTS
        // registration involves a network round-trip to
        // types-registry and is fallible (serialization, registry
        // contract violation, transient unavailability). Publishing
        // AM's `service` to its `OnceLock` first would leave the
        // module half-initialized and non-retriable on TR-plugin
        // failure (the `OnceLock` would already be taken). Doing TR
        // registration first preserves the "init() either fully
        // succeeds or fully fails" contract.
        //
        // The plugin owns no state of its own; it borrows AM's `Db`
        // and the already-resolved `TypesRegistryClient`.
        // Registration order (when enabled):
        //   1. Build `PluginImpl` from the shared deps.
        //   2. Register a `BaseModkitPluginV1<TenantResolverPluginSpecV1>`
        //      instance in types-registry (with idempotent
        //      `AlreadyExists` spec verification).
        //   3. **Only after** types-registry succeeds, bind the
        //      plugin under a scoped `ClientHub` entry keyed by its
        //      GTS instance id, matching the pattern in
        //      `static-tr-plugin` and `rg-tr-plugin`.
        // Step 3 follows step 2 so a registry failure cannot leave
        // a stale `ClientHub` entry behind on a fail-closed init.
        // The discovery race that could occur in the gap (gateway
        // observes the registered instance but the bound client is
        // not yet in the hub) is not reachable at init time —
        // modkit's init phase is sequential and the TR gateway
        // resolves plugins lazily on the first user request, after
        // every dep has finished initializing.
        //
        // Co-location rationale (DESIGN §1.1): the plugin's
        // correctness depends on AM-writer invariants beyond the
        // two-table schema (transactional `(tenants, tenant_closure)`
        // maintenance, barrier materialization over
        // `(ancestor, descendant]`, provisioning lifecycle), which a
        // standalone crate could not validate at runtime.
        if tr_plugin_enabled {
            // `tr_plugin` is enabled — emit a startup audit warning to
            // make the in-process Tenant Resolver plugin visible in
            // logs and pin the deviation from DESIGN §3.5: the plugin
            // shares AM's normal connection pool rather than a
            // dedicated read-only role. Provisioning a separate role
            // is an operator concern that lands together with a
            // `connection-pool-per-role` abstraction in `modkit-db`;
            // until that exists, an `enabled = true` deploy reads
            // through the writer-grade pool. Operators should be aware
            // of this when granting AM's connection role.
            tracing::warn!(
                target: "am.tr_plugin.audit",
                priority = tr_plugin_priority,
                "AM tr_plugin enabled — registering against shared writer pool \
                 (DESIGN §3.5 read-only role not yet provisioned)"
            );
            let tr_plugin =
                Arc::new(TrPluginImpl::new(db_raw.db(), Arc::clone(&types_registry)));
            let tr_instance_id = TenantResolverPluginSpecV1::gts_make_instance_id(
                "cf.builtin.account_management_tenant_resolver.plugin.v1",
            );
            // `vendor` and `priority` are both config-driven. `vendor`
            // defaults to `"cyberfabric"` to match the default in
            // `TenantResolverConfig::default()` — deploys that
            // override `tenant-resolver.vendor` MUST also override
            // `account-management.tr_plugin.vendor` to the same
            // string, otherwise AM's instance is registered but
            // never selectable by the gateway. `priority` defaults
            // well above every in-tree alternative (`rg-tr-plugin`
            // = 50, `static-tr-plugin` = 100) so even with
            // `enabled = true` AM does NOT win selection when
            // those plugins coexist. Full rationale lives on
            // `config::TrPluginConfig`.
            let tr_instance = BaseModkitPluginV1::<TenantResolverPluginSpecV1> {
                id: tr_instance_id.clone(),
                vendor: tr_plugin_vendor,
                priority: tr_plugin_priority,
                properties: TenantResolverPluginSpecV1,
            };
            let tr_instance_json = serde_json::to_value(&tr_instance)
                .map_err(|e| anyhow::anyhow!("tr-plugin: serialize instance failed: {e}"))?;
            let tr_results = types_registry
                .register(vec![tr_instance_json.clone()])
                .await?;
            // Idempotent restart: treat `AlreadyExists` as success only
            // when the stored spec matches our current serialized
            // instance; fail otherwise so a stale registration under
            // the same ID surfaces immediately.
            for result in &tr_results {
                if let RegisterResult::Err { error, .. } = result {
                    if error.is_already_exists() {
                        let existing = types_registry
                            .get_instance(tr_instance_id.as_ref())
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("tr-plugin: verify existing instance: {e}")
                            })?;
                        if existing.object != tr_instance_json {
                            return Err(anyhow::anyhow!(
                                "tr-plugin: instance already registered with a different spec"
                            ));
                        }
                    } else {
                        return Err(anyhow::anyhow!(
                            "tr-plugin: registration failed: {error}"
                        ));
                    }
                }
            }
            // Only after types-registry has accepted the instance
            // (or confirmed an idempotent restart) do we publish the
            // scoped client to the hub. A failure above returns Err
            // before we reach this point, leaving `ClientHub`
            // untouched.
            let tr_api: Arc<dyn TenantResolverPluginClient> = tr_plugin;
            ctx.client_hub()
                .register_scoped::<dyn TenantResolverPluginClient>(
                    ClientScope::gts_id(&tr_instance_id),
                    tr_api,
                );
            info!(
                tr_plugin_instance_id = %tr_instance_id,
                "tenant-resolver plugin registered (in-process, AM-co-located)"
            );
        } else {
            info!(
                "tenant-resolver plugin (AM-co-located) is disabled by config; \
                 set `account-management.tr_plugin.enabled = true` to opt in"
            );
        }

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
