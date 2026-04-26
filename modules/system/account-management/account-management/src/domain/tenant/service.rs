//! `TenantService` — the central domain orchestrator for the four
//! in-scope tenant-hierarchy-management flows: create-child, read-tenant,
//! list-children, and update-tenant-mutable.
//!
//! The service depends only on the domain-level [`TenantRepo`] and
//! [`IdpTenantProvisioner`] traits. All tests in this file use pure
//! in-memory fakes — no DB, no network, no filesystem.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use authz_resolver_sdk::PolicyEnforcer;
use authz_resolver_sdk::pep::{AccessRequest, ResourceType};
use futures::stream::{self, StreamExt};
use modkit_macros::domain_model;
use modkit_security::{AccessScope, SecurityContext, pep_properties};
use parking_lot::Mutex as PlMutex;
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::OnceCell;
use tracing::warn;
use uuid::Uuid;

/// AM's authoritative PEP vocabulary (DESIGN §4.2 — Authorization Model).
///
/// Resource type and supported PEP properties are pinned here so the
/// enforcer call sites cannot drift from the contract. Action names
/// match DESIGN §4.2 line 1363; renaming them is a contract change.
pub(crate) mod pep {
    use super::{ResourceType, pep_properties};

    /// `Tenant` resource — `gts.x.core.am.tenant.v1~`.
    ///
    /// Per DESIGN §4.2 line 1356 the supported PEP properties are
    /// `OWNER_TENANT_ID` (the tenant scope the resource lives under —
    /// for AM tenants this is the parent tenant id, or self for the
    /// root) and `RESOURCE_ID` (the tenant id itself for read / update
    /// / delete; absent for `create` / `list_children` since those have
    /// no single target tenant).
    pub const TENANT: ResourceType = ResourceType {
        name: "gts.x.core.am.tenant.v1~",
        supported_properties: &[pep_properties::OWNER_TENANT_ID, pep_properties::RESOURCE_ID],
    };

    /// Action vocabulary mirroring DESIGN §4.2 line 1363.
    pub mod actions {
        pub const CREATE: &str = "create";
        pub const READ: &str = "read";
        pub const UPDATE: &str = "update";
        pub const DELETE: &str = "delete";
        pub const LIST_CHILDREN: &str = "list_children";
    }
}

use crate::config::AccountManagementConfig;
use crate::domain::audit::{AuditEvent, AuditEventKind, emit_audit};
use crate::domain::error::AmError;
use crate::domain::idp::provisioner::{
    DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner, ProvisionFailure,
    ProvisionRequest,
};
use crate::domain::metrics::{
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_TENANT_RETENTION, MetricKind, emit_metric,
};
use crate::domain::tenant::closure::build_activation_rows;
use crate::domain::tenant::hooks::{HookError, TenantHardDeleteHook};
use crate::domain::tenant::integrity::{
    IntegrityReport, IntegrityScope, Violation, bucket_by_category,
    classify_closure_shape_anomalies, classify_tree_shape_anomalies,
};
use crate::domain::tenant::model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, HardDeleteResult, ReaperResult, TenantRetentionRow,
};
use crate::domain::tenant_type::checker::TenantTypeChecker;
use crate::domain::util::backoff::compute_next_backoff;

const fn tenant_status_label(status: TenantStatus) -> &'static str {
    match status {
        TenantStatus::Provisioning => "provisioning",
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Deleted => "deleted",
    }
}

/// Validated arguments for [`TenantService::create_child`].
///
/// Gate validation (parent status / type registry / depth strict reject)
/// happens inside the service so that callers don't have to thread the
/// repo through the outer layer.
#[domain_model]
#[derive(Debug, Clone)]
pub struct CreateChildInput {
    pub child_id: Uuid,
    pub parent_id: Uuid,
    pub name: String,
    pub self_managed: bool,
    pub tenant_type: String,
    pub tenant_type_uuid: Uuid,
    pub provisioning_metadata: Option<serde_json::Value>,
}

/// Central AM domain service for tenant-hierarchy CRUD.
#[domain_model]
pub struct TenantService<R: TenantRepo> {
    repo: Arc<R>,
    idp: Arc<dyn IdpTenantProvisioner + Send + Sync>,
    cfg: AccountManagementConfig,
    /// Cascade hooks registered by sibling AM features (user-groups,
    /// tenant-metadata). Invoked in registration order at the start of
    /// the hard-delete pipeline — before the `IdP` call and the DB
    /// teardown.
    hooks: Arc<PlMutex<Vec<TenantHardDeleteHook>>>,
    /// Resource-ownership probe; owns the `tenant_has_resources` reject
    /// path inside `soft_delete`.
    resource_checker: Arc<dyn ResourceOwnershipChecker>,
    /// Tenant-type compatibility barrier (FEATURE 2.3
    /// `tenant-type-enforcement`). Invoked at saga step 3
    /// (`inst-algo-saga-type-check`) of `create_child` between the
    /// parent-read and the `provisioning` row insert; rejects
    /// incompatible parent / child type pairings before any tenants /
    /// closure rows are written.
    tenant_type_checker: Arc<dyn TenantTypeChecker + Send + Sync>,
    /// PEP boundary (DESIGN §4.2). Every public CRUD method calls
    /// [`Self::authorize`] before any structural precondition or
    /// repo read. The closure-based ancestry check
    /// [`Self::ensure_caller_reaches`] runs after the PEP gate as
    /// defense-in-depth — see `feature-tenant-hierarchy-management.md`
    /// for the rationale (a misbehaving PDP returning an over-broad
    /// scope is still clamped at the closure level).
    enforcer: PolicyEnforcer,
    /// Per-tenant exponential-backoff state for the provisioning reaper.
    reaper_backoff: Arc<PlMutex<HashMap<Uuid, ReaperBackoff>>>,
    /// Cached id of the platform-root tenant, resolved on first
    /// per-caller scope build. The platform-admin override inside the
    /// closure-based ancestry check is anchored on equality between the
    /// caller's `subject_tenant_id` and this id. The `OnceCell` is
    /// `tokio::sync` so concurrent first hits do not race the storage
    /// read.
    ///
    /// During platform bootstrap, `find_root` filters out
    /// `Provisioning` rows, so this cell stays empty until the
    /// bootstrap saga finishes. While empty, [`Self::ensure_caller_reaches`]
    /// rejects every cross-tenant request — fail-closed behavior during
    /// bootstrap (no platform-admin overrides until the root is fully
    /// `Active`). The cache is never invalidated: the root is immutable
    /// after bootstrap completes.
    root_tenant_id_cache: Arc<OnceCell<Uuid>>,
}

#[domain_model]
#[derive(Debug, Clone)]
struct ReaperBackoff {
    /// Next allowed attempt time (`now + current_delay` after a retryable failure).
    next_attempt_at: OffsetDateTime,
    /// Current delay in use; doubled on each retryable failure up to the cap.
    current_delay: Duration,
}

const REAPER_BACKOFF_MIN: Duration = Duration::from_secs(30);
// `from_mins` is unstable on the workspace MSRV; keep `from_secs` form.
#[allow(clippy::duration_suboptimal_units)]
const REAPER_BACKOFF_MAX: Duration = Duration::from_secs(600);

impl<R: TenantRepo> TenantService<R> {
    /// Construct a fully-wired service. Production wiring inside
    /// [`crate::module::AccountManagementModule::init`] supplies the
    /// real `TypesRegistryClient`-backed checker when one is resolved
    /// from `ClientHub` and falls back to
    /// [`crate::domain::tenant_type::inert_tenant_type_checker`] when it is
    /// not. Tests pass an explicit checker (typically the inert one or
    /// a test fake) directly.
    #[must_use]
    pub fn new(
        repo: Arc<R>,
        idp: Arc<dyn IdpTenantProvisioner + Send + Sync>,
        resource_checker: Arc<dyn ResourceOwnershipChecker>,
        tenant_type_checker: Arc<dyn TenantTypeChecker + Send + Sync>,
        enforcer: PolicyEnforcer,
        cfg: AccountManagementConfig,
    ) -> Self {
        Self {
            repo,
            idp,
            cfg,
            hooks: Arc::new(PlMutex::new(Vec::new())),
            resource_checker,
            tenant_type_checker,
            enforcer,
            reaper_backoff: Arc::new(PlMutex::new(HashMap::new())),
            root_tenant_id_cache: Arc::new(OnceCell::new()),
        }
    }

    /// Append a cascade hook. Hooks run in registration order.
    pub fn register_hard_delete_hook(&self, hook: TenantHardDeleteHook) {
        self.hooks.lock().push(hook);
    }

    /// Borrow the configured retention tick interval (used by the
    /// module `serve` lifecycle entry).
    #[must_use]
    pub fn retention_tick(&self) -> Duration {
        Duration::from_secs(self.cfg.retention_tick_secs)
    }

    /// Borrow the configured `$top` cap for `listChildren` (used by
    /// the REST handler so the operator-tunable cap is honoured at
    /// the API boundary instead of a hardcoded 200).
    #[must_use]
    pub const fn max_list_children_top(&self) -> u32 {
        self.cfg.max_list_children_top
    }

    /// Borrow the configured reaper tick interval.
    #[must_use]
    pub fn reaper_tick(&self) -> Duration {
        Duration::from_secs(self.cfg.reaper_tick_secs)
    }

    /// Borrow the configured hard-delete batch size cap.
    #[must_use]
    pub fn hard_delete_batch_size(&self) -> usize {
        self.cfg.hard_delete_batch_size
    }

    /// Borrow the configured provisioning-timeout threshold.
    #[must_use]
    pub fn provisioning_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.provisioning_timeout_secs)
    }

    // -----------------------------------------------------------------
    // PEP gate + closure-based ancestry check (defense-in-depth)
    // -----------------------------------------------------------------

    /// Resolve (and cache) the platform-root tenant id. Used by
    /// [`Self::ensure_caller_reaches`] to recognise the platform-admin
    /// override (whose home tenant id equals the root). Uses
    /// [`AccessScope::allow_all`] for the bootstrap read — this is a
    /// structural lookup that runs *after* the PEP has already gated
    /// the operation (DESIGN §4.2 unscoped-structural-read carve-out)
    /// and is itself the answer to "who is the platform admin", so
    /// there is no upstream PEP scope to apply.
    async fn root_tenant_id(&self) -> Result<Uuid, AmError> {
        self.root_tenant_id_cache
            .get_or_try_init(|| async {
                // allow_all: structural read per DESIGN §4.2 — no
                // tenant-scoped predicate is meaningful for "find the
                // platform-root tenant".
                self.repo
                    .find_root(&AccessScope::allow_all())
                    .await?
                    .map(|t| t.id)
                    .ok_or_else(|| AmError::Internal {
                        diagnostic: "no root tenant; platform-admin override unresolved".into(),
                    })
            })
            .await
            .copied()
    }

    /// PEP gate. Calls the platform-side `PolicyEnforcer`, returns the
    /// compiled [`AccessScope`] the caller is permitted to see for
    /// `(action, resource_id)` on the `Tenant` resource type.
    ///
    /// `OWNER_TENANT_ID` is supplied by the call site (parent tenant id
    /// for `create`, target tenant id for read / update / delete) so the
    /// PDP can express ABAC policies on the tenant the resource lives
    /// under. `RESOURCE_ID` is conveyed via the standard `resource_id`
    /// argument and does not need to be set on the [`AccessRequest`].
    ///
    /// Errors:
    /// - PDP `Denied` → [`AmError::CrossTenantDenied`] (HTTP 403).
    /// - PDP transport failure → [`AmError::ServiceUnavailable`] (HTTP
    ///   503). DESIGN §4.3 mandates fail-closed; AM does not provide a
    ///   local authorization fallback.
    /// - Constraint compile failure → [`AmError::Internal`] (PEP / PDP
    ///   integration bug — unsupported constraint shape).
    ///
    /// # Known limitation — advisory constraints are dropped
    ///
    /// The `Tenant` entity maps both `OWNER_TENANT_ID` and `RESOURCE_ID`
    /// PEP properties to the row's own `id`, so the PDP's flat
    /// `id IN (...)` predicate cannot express subtree-shaped clamps
    /// (e.g. "only children of X"). The PEP integration therefore
    /// uses [`AccessRequest::require_constraints`]`(false)` and any
    /// advisory constraints the PDP returns are discarded — the
    /// decision is treated as a binary allow/deny gate. The
    /// closure-based ancestry check in
    /// [`Self::ensure_caller_reaches`] is what structurally clamps
    /// disclosure to the caller's subtree; future PDP policies that
    /// attempt to narrow visibility through constraints will be
    /// silently no-op'd here. See `feature-tenant-hierarchy-management`
    /// PEP integration notes.
    async fn authorize(
        &self,
        ctx: &SecurityContext,
        action: &str,
        owner_tenant_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> Result<AccessScope, AmError> {
        // `require_constraints(false)`: AM does not plumb the compiled
        // scope into SQL — see the per-method comments for the entity
        // model rationale (hierarchical tenant resources cannot be
        // expressed by the PEP's flat `id = X` predicate). The PEP
        // call here is a *decision* gate: PDP returns yes/no, plus
        // optional advisory constraints we discard. With
        // `require_constraints = false`, an empty-constraint response
        // compiles to `AccessScope::allow_all()` rather than
        // `CompileFailed`.
        let request = AccessRequest::new()
            .resource_property(pep_properties::OWNER_TENANT_ID, owner_tenant_id)
            .require_constraints(false);
        let scope = self
            .enforcer
            .access_scope_with(ctx, &pep::TENANT, action, resource_id, &request)
            .await?;
        Ok(scope)
    }

    /// Defense-in-depth closure-based ancestry check that runs *after*
    /// the PEP gate. Platform admin (caller's home tenant equals the
    /// platform-root tenant) is exempt because they may legitimately
    /// reach any tenant. For non-admins, accept iff the target is the
    /// caller's home tenant or a descendant per `tenant_closure`.
    ///
    /// Rationale (per `feature-tenant-hierarchy-management.md §7`): if a
    /// misconfigured PDP returns an over-broad scope (e.g. `allow_all`
    /// to a non-admin), this check still clamps disclosure to the
    /// caller's subtree. Saga-internal repo calls below this gate use
    /// `AccessScope::allow_all()` per the structural-read carve-out in
    /// DESIGN §4.2.
    // @cpt-begin:cpt-cf-account-management-algo-errors-observability-security-context-gate:p1:inst-algo-sctx-domain-propagate
    async fn ensure_caller_reaches(
        &self,
        ctx: &SecurityContext,
        target: Uuid,
    ) -> Result<(), AmError> {
        let caller_tenant = ctx.subject_tenant_id();
        let root = self.root_tenant_id().await?;
        if caller_tenant == root {
            return Ok(());
        }
        if caller_tenant == target {
            return Ok(());
        }
        // allow_all: structural ancestry probe per DESIGN §4.2 — the
        // PEP has already gated the operation upstream.
        if !self
            .repo
            .is_descendant(&AccessScope::allow_all(), caller_tenant, target)
            .await?
        {
            return Err(AmError::CrossTenantDenied);
        }
        Ok(())
    }
    // @cpt-end:cpt-cf-account-management-algo-errors-observability-security-context-gate:p1:inst-algo-sctx-domain-propagate

    // -----------------------------------------------------------------
    // Create child tenant (three-step saga)
    // -----------------------------------------------------------------

    /// Implements FEATURE `Create Child Tenant` (flow §2) + `Create-Tenant
    /// Saga` (algo §3). Runs saga steps 1–3 inline.
    ///
    /// # Errors
    ///
    /// - [`AmError::CrossTenantDenied`] when the caller is not the
    ///   platform admin and the parent tenant is outside the caller's
    ///   home subtree.
    /// - [`AmError::Validation`] when the parent is missing or not
    ///   `Active` (create under a suspended / deleted / provisioning
    ///   parent is rejected).
    /// - [`AmError::IdpUnavailable`] when the provider reports a clean
    ///   compensable failure; the `provisioning` row is removed.
    /// - [`AmError::IdpUnsupportedOperation`] when the provider signals
    ///   it cannot perform the requested provisioning.
    /// - [`AmError::Internal`] when the provider outcome is ambiguous;
    ///   the `provisioning` row is left for the reaper to compensate.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-service
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-create-tenant-saga:p1:inst-algo-saga-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-create-child-tenant-saga:p1:inst-dod-create-child-saga
    #[allow(
        clippy::cognitive_complexity,
        reason = "linear saga: authorize -> ancestor check -> validations -> insert -> IdP -> activate; \
                  splitting fragments the saga and obscures compensation branches"
    )]
    pub async fn create_child(
        &self,
        ctx: &SecurityContext,
        input: CreateChildInput,
    ) -> Result<TenantModel, AmError> {
        // PEP gate (DESIGN §4.2). For `Tenant.create` the resource
        // owner is the parent tenant; the child id is not yet a
        // committed resource so `resource_id` is `None`.
        let _scope = self
            .authorize(ctx, pep::actions::CREATE, input.parent_id, None)
            .await?;
        // Defense-in-depth: closure-based ancestry check.
        self.ensure_caller_reaches(ctx, input.parent_id).await?;

        // Saga pre-step: validate parent exists + is Active.
        // allow_all: structural read per DESIGN §4.2 — the PEP has
        // already gated the operation; the parent-status check is a
        // saga precondition, not a data-disclosure read.
        let parent = self
            .repo
            .find_by_id(&AccessScope::allow_all(), input.parent_id)
            .await?
            .ok_or_else(|| AmError::Validation {
                detail: format!("parent tenant {} not found", input.parent_id),
            })?;
        if !matches!(parent.status, TenantStatus::Active) {
            return Err(AmError::Validation {
                detail: format!(
                    "parent tenant {} not active (status={:?}); child creation requires active parent",
                    parent.id, parent.status
                ),
            });
        }

        // Pre-saga gate — `inst-algo-saga-type-check`. Pre-write
        // tenant-type compatibility barrier (FEATURE 2.3
        // `tenant-type-enforcement`). Runs BEFORE the `provisioning`
        // row insert (saga step 1) so an incompatible parent / child
        // type pairing never produces a `tenants` row, and BEFORE the
        // depth check so type-incompatibility reports as
        // `type_not_allowed` rather than masking under a depth
        // rejection. Registry unavailability surfaces as
        // `service_unavailable` (HTTP 503) with no DB side effects.
        self.tenant_type_checker
            .check_parent_child(parent.tenant_type_uuid, input.tenant_type_uuid)
            .await?;

        let observed_depth = parent.depth.saturating_add(1);
        let threshold = self.cfg.depth_threshold;
        let threshold_str = threshold.to_string();

        // Per `algo-depth-threshold-evaluation` (feature-tenant-
        // hierarchy-management.md §3 lines 301-308) the contract is:
        //   IF depth ≤ threshold → proceed silently
        //   ELSE IF advisory     → emit + proceed
        //   ELSE strict          → reject with `tenant_depth_exceeded`
        // Both branches fire at `depth > threshold`. Strict-mode is
        // checked first so a strict reject pre-empts the advisory
        // emission at the same boundary.
        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-depth-threshold-evaluation:p1:inst-algo-depth-evaluate-create
        // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-depth-threshold:p1:inst-dod-depth-threshold-create
        if observed_depth > threshold {
            if self.cfg.depth_strict_mode {
                emit_metric(
                    AM_HIERARCHY_DEPTH_EXCEEDANCE,
                    MetricKind::Counter,
                    &[
                        ("mode", "strict"),
                        ("outcome", "reject"),
                        ("threshold", threshold_str.as_str()),
                    ],
                );
                return Err(AmError::TenantDepthExceeded {
                    detail: format!("child depth {observed_depth} > strict limit {threshold}"),
                });
            }

            // Advisory mode — log + metric, then proceed. The log
            // structure is fingerprinted by AC `inst-algo-depth-
            // advisory-log` (line 305).
            warn!(
                target: "am.tenant.hierarchy",
                tenant_id = %input.child_id,
                parent_id = %parent.id,
                observed_depth,
                threshold,
                "tenant hierarchy advisory depth threshold exceeded"
            );
            emit_metric(
                AM_HIERARCHY_DEPTH_EXCEEDANCE,
                MetricKind::Counter,
                &[
                    ("mode", "advisory"),
                    ("outcome", "warn"),
                    ("threshold", threshold_str.as_str()),
                ],
            );
        }
        // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-depth-threshold:p1:inst-dod-depth-threshold-create
        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-depth-threshold-evaluation:p1:inst-algo-depth-evaluate-create

        // Saga step 1 — insert `provisioning` row (no closure writes).
        let new_tenant = NewTenant {
            id: input.child_id,
            parent_id: Some(parent.id),
            name: input.name.clone(),
            self_managed: input.self_managed,
            tenant_type_uuid: input.tenant_type_uuid,
            depth: observed_depth,
        };
        let provisioning_row = self
            .repo
            .insert_provisioning(&AccessScope::allow_all(), &new_tenant)
            .await?;

        // Saga step 2 — invoke IdP provider outside any TX.
        // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-call
        let req = ProvisionRequest {
            tenant_id: provisioning_row.id,
            parent_id: Some(parent.id),
            name: input.name.clone(),
            tenant_type: input.tenant_type.clone(),
            metadata: input.provisioning_metadata.clone(),
        };
        let provision_result = match self.idp.provision_tenant(&req).await {
            Ok(result) => {
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "provision_tenant"),
                        ("outcome", "success"),
                    ],
                );
                result
            }
            Err(failure) => {
                // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provision-failure-classify
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "provision_tenant"),
                        ("outcome", failure.as_metric_label()),
                    ],
                );
                match failure {
                    ProvisionFailure::CleanFailure { detail } => {
                        // Compensating TX — delete the provisioning row. No
                        // closure cleanup needed: nothing was ever written.
                        // Log compensation failures but always return the
                        // original IdP error so the caller sees the right
                        // variant; a stray provisioning row is handled by
                        // the reaper.
                        if let Err(e) = self
                            .repo
                            .compensate_provisioning(&AccessScope::allow_all(), provisioning_row.id)
                            .await
                        {
                            warn!(
                                target: "am.tenant.saga",
                                tenant_id = %provisioning_row.id,
                                error = %e,
                                "compensate_provisioning failed after IdP CleanFailure; \
                                 provisioning row left for reaper"
                            );
                        }
                        return Err(AmError::IdpUnavailable { detail });
                    }
                    ProvisionFailure::Ambiguous { detail } => {
                        // Leave the provisioning row in place for the reaper.
                        return Err(AmError::Internal {
                            diagnostic: format!("idp provision ambiguous outcome: {detail}"),
                        });
                    }
                    ProvisionFailure::UnsupportedOperation { detail } => {
                        // Treat as clean compensable — no IdP-side state exists.
                        // Same compensation-failure policy as CleanFailure above.
                        if let Err(e) = self
                            .repo
                            .compensate_provisioning(&AccessScope::allow_all(), provisioning_row.id)
                            .await
                        {
                            warn!(
                                target: "am.tenant.saga",
                                tenant_id = %provisioning_row.id,
                                error = %e,
                                "compensate_provisioning failed after IdP UnsupportedOperation; \
                                 provisioning row left for reaper"
                            );
                        }
                        return Err(AmError::IdpUnsupportedOperation { detail });
                    }
                }
                // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provision-failure-classify
            }
        };
        // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-call

        // Saga step 3 — finalize: load the ancestor chain, build closure
        // rows, and flip the tenant to Active in one TX. The caller
        // already holds the parent row in scope, so feed `parent.id`
        // directly to skip the redundant child-row fetch the previous
        // child-keyed shape required.
        let ancestors = self
            .repo
            .load_strict_ancestors_of_parent(&AccessScope::allow_all(), parent.id)
            .await?;
        let closure_rows = build_activation_rows(
            provisioning_row.id,
            TenantStatus::Active,
            input.self_managed,
            &ancestors,
        );
        // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-metadata
        let activated = self
            .repo
            .activate_tenant(
                &AccessScope::allow_all(),
                provisioning_row.id,
                &closure_rows,
                &provision_result.metadata_entries,
            )
            .await?;
        // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-metadata

        // Audit emission per `feature-errors-observability §audit-contract`
        // — "MUST emit platform audit records for every AM-owned
        // state-changing operation". Tenant create is one of the
        // enumerated lifecycle transitions.
        emit_audit(&AuditEvent::from_context(
            AuditEventKind::TenantStateChanged,
            ctx,
            activated.id,
            json!({
                "event": "created",
                "parent_id": activated.parent_id,
                "tenant_type": input.tenant_type,
                "self_managed": input.self_managed,
                "depth": activated.depth,
            }),
        ));

        Ok(activated)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-create-child-tenant-saga:p1:inst-dod-create-child-saga
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-create-tenant-saga:p1:inst-algo-saga-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-service

    // -----------------------------------------------------------------
    // Read tenant details
    // -----------------------------------------------------------------

    /// Implements FEATURE `Read Tenant Details`. Returns `NotFound` when
    /// the row is absent OR the row is SDK-invisible (`Provisioning`).
    ///
    /// # Errors
    ///
    /// - [`AmError::CrossTenantDenied`] when the caller is not the
    ///   platform admin and the target tenant lies outside the caller's
    ///   home subtree.
    /// - [`AmError::NotFound`] when the tenant does not exist or is in
    ///   the internal `Provisioning` state.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-read-tenant:p1:inst-flow-read-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-tenant-read-scope:p1:inst-dod-read-scope-service
    pub async fn read_tenant(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<TenantModel, AmError> {
        // PEP gate (DESIGN §4.2). The compiled `AccessScope` is
        // plumbed into the SQL filter on the disclosure read so a
        // PDP-narrowed permit (e.g. `id IN (subset)`) clamps the rows
        // visible at the database — the closure-based ancestry check
        // alone would otherwise let an over-broad subtree response
        // out of a constrained PDP decision (`feature-tenant-
        // hierarchy-management.md §7`). For policies that narrow
        // strictly to the requested resource id the predicate matches
        // the row trivially; for unconstrained permits (`allow_all`)
        // there is no narrowing and behavior matches the legacy path.
        let scope = self
            .authorize(ctx, pep::actions::READ, id, Some(id))
            .await?;
        // Defense-in-depth: closure-based ancestry check. Catches a
        // misconfigured PDP that returns `allow_all` for a non-admin
        // — the closure walk still clamps disclosure to the caller's
        // subtree.
        self.ensure_caller_reaches(ctx, id).await?;
        let tenant = self
            .repo
            .find_by_id(&scope, id)
            .await?
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {id} not found"),
            })?;
        if !tenant.status.is_sdk_visible() {
            return Err(AmError::NotFound {
                detail: format!("tenant {id} not found"),
            });
        }
        Ok(tenant)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-tenant-read-scope:p1:inst-dod-read-scope-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-read-tenant:p1:inst-flow-read-service

    // -----------------------------------------------------------------
    // List children (paginated, status-filterable)
    // -----------------------------------------------------------------

    /// Implements FEATURE `List Children (Paginated, Status-Filterable)`.
    /// The parent itself must exist + be SDK-visible, otherwise the
    /// whole call is `NotFound`.
    ///
    /// # Errors
    ///
    /// - [`AmError::CrossTenantDenied`] when the caller is not the
    ///   platform admin and the parent tenant lies outside the caller's
    ///   home subtree.
    /// - [`AmError::NotFound`] when the parent does not exist or is
    ///   SDK-invisible (`Provisioning`). Repository-level errors are
    ///   propagated unchanged.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-list-children:p1:inst-flow-listch-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-children-query-paginated:p1:inst-dod-children-query-service
    pub async fn list_children(
        &self,
        ctx: &SecurityContext,
        query: ListChildrenQuery,
    ) -> Result<TenantPage, AmError> {
        // PEP gate (DESIGN §4.2). For `Tenant.list_children` the
        // resource owner is the parent tenant whose subtree is being
        // enumerated; `resource_id` is `None` because the call returns
        // a collection. The compiled `AccessScope` is plumbed into the
        // children query so a PDP-narrowed permit (e.g.
        // `id IN (specific subset)`) clamps the row set at the
        // database. An unconstrained permit compiles to `allow_all`
        // and the SQL filter degrades to just `parent_id = …` —
        // identical to the legacy path. Closure-based ancestry is the
        // structural-disclosure backstop applied separately.
        let scope = self
            .authorize(ctx, pep::actions::LIST_CHILDREN, query.parent_id, None)
            .await?;
        // Defense-in-depth: closure-based ancestry check. THIS is the
        // actual cross-tenant enforcement boundary — a non-admin caller
        // probing a sibling subtree gets `CrossTenantDenied` here
        // before the `allow_all` read below ever runs. The PEP/PDP gate
        // above is a binary allow/deny; the closure check is what
        // structurally clamps disclosure to the caller's subtree.
        self.ensure_caller_reaches(ctx, query.parent_id).await?;
        // allow_all: structural existence/status precondition per
        // DESIGN §4.2 line 1370. Safe because `ensure_caller_reaches`
        // above already proved the caller can reach `parent_id`; the
        // read itself only resolves "does the parent exist? is it
        // SDK-visible?" rather than disclosing parent contents.
        // Disclosure of the children list flows through the scoped
        // `list_children` call further down.
        let parent = self
            .repo
            .find_by_id(&AccessScope::allow_all(), query.parent_id)
            .await?
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {} not found", query.parent_id),
            })?;
        if !parent.status.is_sdk_visible() {
            return Err(AmError::NotFound {
                detail: format!("tenant {} not found", query.parent_id),
            });
        }
        self.repo.list_children(&scope, &query).await
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-children-query-paginated:p1:inst-dod-children-query-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-list-children:p1:inst-flow-listch-service

    // -----------------------------------------------------------------
    // Update tenant (mutable-fields-only)
    // -----------------------------------------------------------------

    /// Implements FEATURE `Update Tenant Mutable Fields`.
    ///
    /// Immutable-field rejection happens at the API-DTO layer (where the
    /// `OpenAPI` contract lists only `name` + `status` as acceptable);
    /// defence-in-depth here guards against an internal caller passing a
    /// patch built from a broader type.
    ///
    /// # Errors
    ///
    /// - [`AmError::CrossTenantDenied`] when the caller is not the
    ///   platform admin and the target tenant lies outside the caller's
    ///   home subtree.
    /// - [`AmError::Validation`] when the patch is empty, the new name
    ///   violates the length bounds, or the status transition is not
    ///   allowed via PATCH (cf. [`TenantUpdate::validate_status_transition`]).
    /// - [`AmError::NotFound`] when the target tenant does not exist or
    ///   is SDK-invisible.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-update-tenant:p1:inst-flow-update-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-update-mutable-only:p1:inst-dod-update-mutable-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-change-service
    pub async fn update_tenant(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        patch: TenantUpdate,
    ) -> Result<TenantModel, AmError> {
        if patch.is_empty() {
            return Err(AmError::Validation {
                detail: "update patch is empty; at least one field required".into(),
            });
        }
        if let Some(ref new_name) = patch.name {
            TenantUpdate::validate_name(new_name)?;
        }
        // PEP gate (DESIGN §4.2). The compiled scope is plumbed into
        // both the pre-update read and the mutating write: a
        // PDP-narrowed permit clamps the rows visible / writeable at
        // the database, so a constrained authorization cannot widen
        // into a broader closure-based reach. The repo's
        // `update_tenant_mutable` opens with a scope-bounded
        // `find_by_id` that maps "no row in scope" to `NotFound`, so
        // a PDP-misconfigured scope cannot silently no-op.
        let scope = self
            .authorize(ctx, pep::actions::UPDATE, id, Some(id))
            .await?;
        // Defense-in-depth: closure-based ancestry check.
        self.ensure_caller_reaches(ctx, id).await?;
        let current = self
            .repo
            .find_by_id(&scope, id)
            .await?
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {id} not found"),
            })?;
        if !current.status.is_sdk_visible() {
            return Err(AmError::NotFound {
                detail: format!("tenant {id} not found"),
            });
        }
        if let Some(new_status) = patch.status {
            TenantUpdate::validate_status_transition(current.status, new_status)?;
        }
        let updated = self.repo.update_tenant_mutable(&scope, id, &patch).await?;

        // Audit emission per `feature-errors-observability §audit-contract`
        // — "MUST emit platform audit records for every AM-owned
        // state-changing operation". Both `name` and `status` updates
        // are state-changing; the payload preserves before/after for
        // the audit consumer.
        emit_audit(&AuditEvent::from_context(
            AuditEventKind::TenantStateChanged,
            ctx,
            updated.id,
            json!({
                "event": "updated",
                "name_changed": patch.name.is_some(),
                "status_from": tenant_status_label(current.status),
                "status_to": patch.status.map(tenant_status_label),
            }),
        ));

        Ok(updated)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-change-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-update-mutable-only:p1:inst-dod-update-mutable-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-update-tenant:p1:inst-flow-update-service

    // -----------------------------------------------------------------
    // Phase 3 — soft delete + hard-delete batch + reaper + integrity
    // -----------------------------------------------------------------

    /// Implements FEATURE `Soft-Delete Tenant`.
    ///
    /// # Errors
    ///
    /// - [`AmError::CrossTenantDenied`] when the caller is not the
    ///   platform admin and the target tenant lies outside the caller's
    ///   home subtree.
    /// - [`AmError::RootTenantCannotDelete`] when `tenant_id` is the root tenant.
    /// - [`AmError::NotFound`] when the tenant does not exist or is already SDK-invisible.
    /// - [`AmError::TenantHasChildren`] when any child tenant still exists.
    /// - [`AmError::TenantHasResources`] when the RG ownership probe finds any rows.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-sdel-service
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-dod-soft-delete-preconditions
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-soft-delete
    pub async fn soft_delete(
        &self,
        ctx: &SecurityContext,
        tenant_id: Uuid,
    ) -> Result<TenantModel, AmError> {
        // PEP gate (DESIGN §4.2). The compiled scope is plumbed into
        // the disclosure read of the target row and into the mutating
        // `schedule_deletion` write so a PDP-narrowed permit clamps
        // the rows visible / writeable at the database. Structural
        // precondition checks (`count_children`,
        // `count_ownership_links`) keep `allow_all` — those are
        // saga-internal guard counts, not data disclosure of the
        // tenant being acted on.
        let scope = self
            .authorize(ctx, pep::actions::DELETE, tenant_id, Some(tenant_id))
            .await?;
        // Defense-in-depth: closure-based ancestry check.
        self.ensure_caller_reaches(ctx, tenant_id).await?;
        let tenant = self
            .repo
            .find_by_id(&scope, tenant_id)
            .await?
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
            })?;
        if tenant.parent_id.is_none() {
            return Err(AmError::RootTenantCannotDelete);
        }
        if !tenant.status.is_sdk_visible() {
            return Err(AmError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
            });
        }
        // 1. Child-rejection guard. `include_deleted = false` excludes
        // ONLY rows in `Deleted` status; `Provisioning`, `Active` and
        // `Suspended` children all count and block the soft-delete with
        // `TenantHasChildren`. This is intentional:
        // - `Provisioning` children are mid-saga and may still settle
        //   into `Active`; the parent's deletion must wait for them.
        // - `Deleted` children are already in the retention pipeline
        //   and the leaf-first ordering of the hard-delete batch
        //   guarantees they get reaped before their parent's row
        //   teardown runs. Counting them here would deadlock: parent
        //   never goes to `Deleted`, so children never get reaped.
        let child_count = self
            .repo
            .count_children(&AccessScope::allow_all(), tenant_id, false)
            .await?;
        if child_count > 0 {
            return Err(AmError::TenantHasChildren);
        }
        // 2. Resource-ownership rejection.
        let rg_links = self
            .resource_checker
            .count_ownership_links(tenant_id)
            .await?;
        if rg_links > 0 {
            return Err(AmError::TenantHasResources);
        }
        // 3. Flip row + retention columns in one TX.
        let now = OffsetDateTime::now_utc();
        let retention: Option<Duration> = if self.cfg.default_retention_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.cfg.default_retention_secs))
        };
        let updated = self
            .repo
            .schedule_deletion(&scope, tenant_id, now, retention)
            .await?;
        emit_audit(&AuditEvent::from_context(
            AuditEventKind::TenantStateChanged,
            ctx,
            tenant_id,
            json!({
                "event": "soft_delete_requested",
                "retention_secs": self.cfg.default_retention_secs,
            }),
        ));
        Ok(updated)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-soft-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-dod-soft-delete-preconditions
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-sdel-service

    /// Implements FEATURE `Hard-Delete Cleanup Sweep`.
    ///
    /// Scans retention-due rows (leaf-first), invokes registered
    /// cascade hooks, calls [`IdpTenantProvisioner::deprovision_tenant`],
    /// and performs the transactional DB teardown via
    /// [`TenantRepo::hard_delete_one`].
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hard-delete-leaf-first-scheduler:p1:inst-algo-hdel-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-hard-delete-leaf-first:p1:inst-dod-hard-delete-leaf-first
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-hard-delete
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-hard-delete
    pub async fn hard_delete_batch(&self, batch_size: usize) -> HardDeleteResult {
        let now = OffsetDateTime::now_utc();
        let default_retention = Duration::from_secs(self.cfg.default_retention_secs);
        let system_scope = AccessScope::allow_all();
        let rows = match self
            .repo
            .scan_retention_due(&system_scope, now, default_retention, batch_size)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    target: "am.retention",
                    error = %err,
                    "hard_delete_batch: scan failed; skipping tick"
                );
                return HardDeleteResult::default();
            }
        };

        // Bucket the batch by depth. Within a single depth bucket
        // sibling tenants share no FK ordering constraint and can be
        // reclaimed concurrently. Buckets are processed leaf-first
        // (deepest depth → root) so the parent FK guard always sees
        // child rows already gone by the time the parent's turn arrives.
        let mut by_depth: BTreeMap<u32, Vec<TenantRetentionRow>> = BTreeMap::new();
        for row in rows {
            by_depth.entry(row.depth).or_default().push(row);
        }

        // Snapshot hooks once per tick so the per-tenant pipeline does
        // not re-clone the registration `Vec` for every row.
        let hooks_snapshot: Vec<TenantHardDeleteHook> = {
            let guard = self.hooks.lock();
            guard.clone()
        };

        let concurrency = self.cfg.hard_delete_concurrency.max(1);
        let mut result = HardDeleteResult::default();
        // `BTreeMap` iterates keys ascending; reverse to drain the
        // deepest bucket first.
        for (_depth, bucket) in by_depth.into_iter().rev() {
            let outcomes: Vec<(Uuid, u32, HardDeleteOutcome)> = stream::iter(bucket)
                .map(|row| {
                    let hooks = hooks_snapshot.as_slice();
                    async move {
                        let id = row.id;
                        let depth = row.depth;
                        let outcome = self.process_single_hard_delete(row, hooks).await;
                        (id, depth, outcome)
                    }
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;

            for (id, depth, outcome) in outcomes {
                if matches!(outcome, HardDeleteOutcome::Cleaned) {
                    if let Some(event) = AuditEvent::system(
                        AuditEventKind::HardDeleteCleanupCompleted,
                        id,
                        json!({ "depth": depth }),
                    ) {
                        emit_audit(&event);
                    } else {
                        warn!(
                            target: "audit.am",
                            kind = AuditEventKind::HardDeleteCleanupCompleted.as_str(),
                            tenant_id = %id,
                            "failed to construct allowed system audit event"
                        );
                    }
                }
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[
                        ("job", "hard_delete"),
                        ("outcome", outcome.as_metric_label()),
                    ],
                );
                if !matches!(outcome, HardDeleteOutcome::Cleaned)
                    && let Err(err) = self
                        .repo
                        .clear_retention_claim(&AccessScope::allow_all(), id)
                        .await
                {
                    warn!(
                        target: "am.retention",
                        tenant_id = %id,
                        error = %err,
                        "failed to clear retention claim after non-cleaned outcome"
                    );
                }
                result.tally(&outcome);
            }
        }
        result
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-hard-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-hard-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-hard-delete-leaf-first:p1:inst-dod-hard-delete-leaf-first
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hard-delete-leaf-first-scheduler:p1:inst-algo-hdel-service

    #[allow(
        clippy::cognitive_complexity,
        reason = "single linear pipeline: hooks -> idp -> db teardown; splitting obscures the flow"
    )]
    async fn process_single_hard_delete(
        &self,
        row: TenantRetentionRow,
        hooks: &[TenantHardDeleteHook],
    ) -> HardDeleteOutcome {
        // 1. Cascade hooks — run all, surface the strongest non-ok outcome.
        let mut strongest: Option<HookError> = None;
        for hook in hooks {
            let fut = hook(row.id);
            // Spawn into its own task so a panicking hook cannot kill the
            // retention loop; surface panics as Retryable so the tenant is
            // retried next tick rather than permanently stuck.
            let result = tokio::spawn(fut).await.unwrap_or_else(|e| {
                Err(HookError::Retryable {
                    detail: format!("hook panicked: {e:?}"),
                })
            });
            match result {
                Ok(()) => {}
                Err(HookError::Retryable { detail }) => {
                    let combined = match strongest {
                        Some(prev @ HookError::Terminal { .. }) => prev,
                        _ => HookError::Retryable { detail },
                    };
                    strongest = Some(combined);
                }
                Err(HookError::Terminal { detail }) => {
                    strongest = Some(HookError::Terminal { detail });
                }
            }
        }
        if let Some(err) = strongest {
            match err {
                HookError::Retryable { detail } => {
                    warn!(
                        target: "am.retention",
                        tenant_id = %row.id,
                        detail,
                        "hard_delete deferred by retryable cascade hook"
                    );
                    return HardDeleteOutcome::CascadeRetryable;
                }
                HookError::Terminal { detail } => {
                    warn!(
                        target: "am.retention",
                        tenant_id = %row.id,
                        detail,
                        "hard_delete skipped by terminal cascade hook"
                    );
                    return HardDeleteOutcome::CascadeTerminal;
                }
            }
        }

        // 2. IdP deprovision — outside any TX.
        match self
            .idp
            .deprovision_tenant(&DeprovisionRequest { tenant_id: row.id })
            .await
        {
            Ok(()) => {
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "deprovision_tenant"),
                        ("outcome", "success"),
                    ],
                );
            }
            Err(failure) => {
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "deprovision_tenant"),
                        ("outcome", failure.as_metric_label()),
                    ],
                );
                match failure {
                    DeprovisionFailure::Retryable { detail } => {
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            detail,
                            "hard_delete deferred by retryable IdP failure"
                        );
                        return HardDeleteOutcome::IdpRetryable;
                    }
                    DeprovisionFailure::Terminal { detail } => {
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            detail,
                            "hard_delete skipped by terminal IdP failure"
                        );
                        return HardDeleteOutcome::IdpTerminal;
                    }
                    DeprovisionFailure::UnsupportedOperation { .. } => {
                        // Treat as "nothing to do on the IdP side" —
                        // continue with the DB teardown.
                    }
                }
            }
        }

        // 3. DB teardown.
        match self
            .repo
            .hard_delete_one(&AccessScope::allow_all(), row.id)
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                // Storage-layer fault — pool exhausted, SERIALIZABLE
                // retry budget exhausted, network blip. Routed to a
                // dedicated `StorageError` outcome so the
                // `am.tenant_retention` counter does not lump infra
                // faults under `cascade_terminal` (which is meant for
                // user-supplied hook failures).
                warn!(
                    target: "am.retention",
                    tenant_id = %row.id,
                    error = %err,
                    "hard_delete db teardown failed"
                );
                HardDeleteOutcome::StorageError
            }
        }
    }

    /// Implements FEATURE `Provisioning Reaper`.
    ///
    /// Deviation from `inst-algo-reap-delete-tx`: routes cleanup
    /// through `schedule_deletion(retention = 0)` so every row removal
    /// (user-initiated, retention-driven, stuck-`Provisioning`) flows
    /// through one pipeline (hooks + `IdP` deprovision + closure-row
    /// removal). Worst-case stuck → row-gone latency is
    /// `reaper_tick_secs + retention_tick_secs`. See FEATURE §3
    /// `algo-tenant-hierarchy-management-provisioning-reaper-compensation`.
    #[allow(
        clippy::cognitive_complexity,
        reason = "single linear pipeline: scan -> backoff gate -> per-row classification"
    )]
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-provisioning-reaper-compensation:p1:inst-algo-reap-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provisioning-failure-reaper
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-reaper
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-reaper
    pub async fn reap_stuck_provisioning(&self, threshold: Duration) -> ReaperResult {
        let now = OffsetDateTime::now_utc();
        let older_than = match time::Duration::try_from(threshold) {
            Ok(d) => now - d,
            Err(_) => return ReaperResult::default(),
        };
        let system_scope = AccessScope::allow_all();
        let rows = match self
            .repo
            .scan_stuck_provisioning(&system_scope, older_than, self.cfg.reaper_batch_size)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    target: "am.retention",
                    error = %err,
                    "reap_stuck_provisioning: scan failed; skipping tick"
                );
                return ReaperResult::default();
            }
        };

        let mut result = ReaperResult {
            scanned: u64::try_from(rows.len()).unwrap_or(u64::MAX),
            ..ReaperResult::default()
        };

        for row in rows {
            // Honour per-tenant backoff.
            let allowed = {
                let guard = self.reaper_backoff.lock();
                guard.get(&row.id).is_none_or(|b| b.next_attempt_at <= now)
            };
            if !allowed {
                result.deferred += 1;
                continue;
            }

            match self
                .idp
                .deprovision_tenant(&DeprovisionRequest { tenant_id: row.id })
                .await
            {
                Ok(()) | Err(DeprovisionFailure::UnsupportedOperation { .. }) => {
                    // Compensable — flip the provisioning row to Deleted.
                    //
                    // Retention-window semantics: `Some(0)` means "due
                    // on the next retention tick" (`is_due` fires
                    // immediately because `now - scheduled_at >= 0`).
                    // This deliberately differs from `soft_delete`'s
                    // `None`-when-config-is-0 path, which falls through
                    // to the hard-delete pipeline's per-tick
                    // `default_retention` argument. The reaper wants
                    // immediate reclamation; user-driven soft-deletes
                    // honour the global default.
                    if let Err(err) = self
                        .repo
                        .schedule_deletion(&system_scope, row.id, now, Some(Duration::from_secs(0)))
                        .await
                    {
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            error = %err,
                            "reaper: schedule_deletion failed"
                        );
                        continue;
                    }
                    self.reaper_backoff.lock().remove(&row.id);
                    result.compensated += 1;
                    if let Some(event) = AuditEvent::system(
                        AuditEventKind::ProvisioningReaperCompensated,
                        row.id,
                        json!({}),
                    ) {
                        emit_audit(&event);
                    } else {
                        warn!(
                            target: "audit.am",
                            kind = AuditEventKind::ProvisioningReaperCompensated.as_str(),
                            tenant_id = %row.id,
                            "failed to construct allowed system audit event"
                        );
                    }
                }
                Err(DeprovisionFailure::Retryable { .. }) => {
                    self.bump_reaper_backoff(row.id, now);
                    result.deferred += 1;
                    emit_metric(
                        AM_TENANT_RETENTION,
                        MetricKind::Counter,
                        &[("job", "provisioning_reaper"), ("outcome", "retryable")],
                    );
                }
                Err(DeprovisionFailure::Terminal { detail }) => {
                    warn!(
                        target: "am.retention",
                        tenant_id = %row.id,
                        detail,
                        "reaper: terminal IdP failure; deferring"
                    );
                    self.bump_reaper_backoff(row.id, now);
                    result.deferred += 1;
                    emit_metric(
                        AM_TENANT_RETENTION,
                        MetricKind::Counter,
                        &[("job", "provisioning_reaper"), ("outcome", "terminal")],
                    );
                }
            }
        }

        result
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-reaper
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-reaper
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provisioning-failure-reaper
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-provisioning-reaper-compensation:p1:inst-algo-reap-service

    fn bump_reaper_backoff(&self, tenant_id: Uuid, now: OffsetDateTime) {
        let mut guard = self.reaper_backoff.lock();
        let entry = guard.entry(tenant_id).or_insert(ReaperBackoff {
            next_attempt_at: now,
            current_delay: REAPER_BACKOFF_MIN,
        });
        let new_delay = compute_next_backoff(entry.current_delay, REAPER_BACKOFF_MAX);
        entry.current_delay = new_delay;
        match time::Duration::try_from(new_delay) {
            Ok(d) => entry.next_attempt_at = now + d,
            // new_delay is bounded by REAPER_BACKOFF_MAX (600 s) so this
            // branch is unreachable in practice. Retry immediately rather
            // than panicking if a future refactor widens the range.
            Err(_) => entry.next_attempt_at = now,
        }
    }

    /// Implements FEATURE `Hierarchy Integrity Audit`.
    ///
    /// Runs both classifiers against the loaded snapshot, buckets the
    /// violations into the fixed-category report shape, and emits one
    /// `AM_HIERARCHY_INTEGRITY_VIOLATIONS` gauge sample per category
    /// (including zero-valued ones).
    ///
    /// # Errors
    ///
    /// Propagates any [`AmError`] produced by the repository's
    /// `load_tree_and_closure_for_scope` call.
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-diagnostics-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-integrity
    pub async fn check_hierarchy_integrity(
        &self,
        scope: IntegrityScope,
    ) -> Result<IntegrityReport, AmError> {
        // Whole-tree audits load every `tenants` row + every closure
        // row into memory. At ~100k tenants × avg-depth-10 the closure
        // alone is ~1M rows; the in-memory aggregator is not designed
        // for that. Bound the `tenants` load at the repo layer with a
        // hard cap and fail-fast **before** any closure rows are
        // streamed; the operator drives the audit through a per-subtree
        // scope when the cap fires. `Subtree` audits are unbounded by
        // design — the caller already chose a finite root.
        let tenants_cap = match scope {
            IntegrityScope::Whole => Some(self.cfg.integrity_max_tenants),
            IntegrityScope::Subtree(_) => None,
        };
        let (tenants, closure) = self
            .repo
            .load_tree_and_closure_for_scope(&AccessScope::allow_all(), scope.clone(), tenants_cap)
            .await?;
        let mut flat: Vec<Violation> = classify_tree_shape_anomalies(&tenants);
        flat.extend(classify_closure_shape_anomalies(&tenants, &closure));
        let bucketed = bucket_by_category(flat);

        // Emit one gauge sample per category (always, including zero-valued)
        // so the dashboard can distinguish "no violations" from "checker
        // never ran". The foundation `emit_metric` helper only carries the
        // family + labels; gauges additionally need a numeric value, so we
        // emit the sample inline with the same `metrics.am` target.
        for (cat, viols) in &bucketed {
            let count = viols.len();
            tracing::info!(
                target: "metrics.am",
                family = AM_HIERARCHY_INTEGRITY_VIOLATIONS,
                kind = "gauge",
                category = cat.as_str(),
                value = count as u64,
                "am metric sample"
            );
            if count > 0 {
                warn!(
                    target: "am.integrity",
                    category = cat.as_str(),
                    count,
                    "hierarchy integrity violations detected"
                );
            }
        }

        Ok(IntegrityReport {
            scope,
            violations_by_category: bucketed,
        })
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-integrity
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-diagnostics-service
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-service
}

// =======================================================================
//                                 Tests
// =======================================================================

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    //! In-file unit tests with in-memory `FakeTenantRepo` and
    //! `FakeIdpProvisioner`. All tests are hermetic — no DB, no network,
    //! no filesystem.

    use super::*;
    use crate::config::AccountManagementConfig;
    use crate::domain::tenant::closure::ClosureRow;
    use crate::domain::tenant::repo::TenantRepo;
    use crate::domain::tenant::resource_checker::InertResourceOwnershipChecker;
    use crate::domain::tenant::test_support::{
        FakeDeprovisionOutcome, FakeIdpProvisioner, FakeOutcome, FakeTenantRepo, mock_enforcer,
    };
    use async_trait::async_trait;
    use modkit_security::AccessScope;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    fn ctx_for(tenant_id: Uuid) -> SecurityContext {
        SecurityContext::builder()
            .subject_id(Uuid::from_u128(0xDEAD))
            .subject_tenant_id(tenant_id)
            .build()
            .expect("ctx")
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    fn make_service(
        repo: Arc<FakeTenantRepo>,
        outcome: FakeOutcome,
    ) -> TenantService<FakeTenantRepo> {
        TenantService::new(
            repo,
            Arc::new(FakeIdpProvisioner::new(outcome)),
            Arc::new(InertResourceOwnershipChecker),
            crate::domain::tenant_type::inert_tenant_type_checker(),
            mock_enforcer(),
            AccountManagementConfig::default(),
        )
    }

    fn child_input(child_id: Uuid, parent_id: Uuid) -> CreateChildInput {
        CreateChildInput {
            child_id,
            parent_id,
            name: "child".into(),
            self_managed: false,
            tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.customer.v1~".into(),
            tenant_type_uuid: Uuid::from_u128(0xAA),
            provisioning_metadata: None,
        }
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn create_child_happy_path_writes_self_row_and_one_ancestor_row() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x200);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);

        let created = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create ok");

        assert_eq!(created.id, child);
        assert_eq!(created.status, TenantStatus::Active);
        assert_eq!(created.depth, 1);

        // Closure: root self-row + new child self-row + one strict-ancestor row.
        let closure = repo.snapshot_closure();
        assert_eq!(closure.len(), 3);
        assert!(
            closure
                .iter()
                .any(|r| r.ancestor_id == child && r.descendant_id == child && r.barrier == 0)
        );
        assert!(
            closure
                .iter()
                .any(|r| r.ancestor_id == root && r.descendant_id == child && r.barrier == 0)
        );
    }

    #[tokio::test]
    async fn create_child_clean_failure_compensates_and_writes_no_closure_rows() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x201);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let closure_before = repo.snapshot_closure().len();
        let svc = make_service(repo.clone(), FakeOutcome::CleanFailure);

        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("should fail");
        assert_eq!(err.sub_code(), "idp_unavailable");

        // Compensation removed the provisioning row.
        let tenant = repo
            .find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo");
        assert!(tenant.is_none(), "provisioning row compensated");
        // No closure rows written.
        assert_eq!(repo.snapshot_closure().len(), closure_before);
    }

    #[tokio::test]
    async fn create_child_ambiguous_failure_keeps_provisioning_row_and_writes_no_closure_rows() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x202);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let closure_before = repo.snapshot_closure().len();
        let svc = make_service(repo.clone(), FakeOutcome::Ambiguous);

        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("should fail");
        assert_eq!(err.sub_code(), "internal");

        // Provisioning row STILL PRESENT — reaper will compensate asynchronously.
        let tenant = repo
            .find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo");
        assert!(tenant.is_some(), "provisioning row retained");
        assert_eq!(tenant.unwrap().status, TenantStatus::Provisioning);
        assert_eq!(repo.snapshot_closure().len(), closure_before);
    }

    #[tokio::test]
    async fn create_child_unsupported_op_compensates_and_surfaces_idp_unsupported_operation() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x203);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Unsupported);

        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("should fail");
        assert_eq!(err.sub_code(), "idp_unsupported_operation");
        assert!(
            repo.find_by_id(&AccessScope::allow_all(), child)
                .await
                .expect("repo")
                .is_none()
        );
    }

    #[tokio::test]
    async fn create_child_advisory_depth_threshold_emits_metric_and_succeeds() {
        // Per `algo-depth-threshold-evaluation` the advisory branch
        // fires at `depth > threshold` and creation proceeds. We pin
        // a low `depth_threshold = 4`, build a chain of depth 0..=4,
        // and create a child under the deepest existing tenant — the
        // child lands at depth 5 (= threshold + 1) which exceeds the
        // threshold and triggers the advisory emission *without*
        // strict-mode rejection.
        let repo = Arc::new(FakeTenantRepo::new());
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");

        let mut prev: Option<Uuid> = None;
        let mut deepest = Uuid::nil();
        for i in 0..=4u128 {
            let id = Uuid::from_u128(0x1000 + i);
            let model = TenantModel {
                id,
                parent_id: prev,
                name: format!("t{i}"),
                status: TenantStatus::Active,
                self_managed: false,
                tenant_type_uuid: Uuid::from_u128(0xAA),
                depth: u32::try_from(i).expect("u32"),
                created_at: now,
                updated_at: now,
                deleted_at: None,
            };
            repo.insert_tenant_raw(model);
            prev = Some(id);
            deepest = id;
        }

        let cfg = AccountManagementConfig {
            depth_strict_mode: false,
            depth_threshold: 4,
            ..AccountManagementConfig::default()
        };
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            cfg,
            Arc::new(InertResourceOwnershipChecker),
        );
        let child = Uuid::from_u128(0x9999);
        let root = Uuid::from_u128(0x1000);
        let created = svc
            .create_child(&ctx_for(root), child_input(child, deepest))
            .await
            .expect("advisory branch still proceeds");
        assert_eq!(created.depth, 5);
        assert_eq!(created.status, TenantStatus::Active);
    }

    #[tokio::test]
    async fn read_tenant_happy_path_returns_model() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo, FakeOutcome::Ok);
        let t = svc
            .read_tenant(&ctx_for(root), root)
            .await
            .expect("read ok");
        assert_eq!(t.id, root);
    }

    #[tokio::test]
    async fn read_tenant_not_found_returns_not_found() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo, FakeOutcome::Ok);
        let err = svc
            .read_tenant(&ctx_for(root), Uuid::from_u128(0xDEAD))
            .await
            .expect_err("should be not found");
        assert_eq!(err.sub_code(), "not_found");
    }

    #[tokio::test]
    async fn read_tenant_provisioning_tenant_is_reported_as_not_found() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x201);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        // Insert a provisioning tenant directly.
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        repo.insert_tenant_raw(TenantModel {
            id: child,
            parent_id: Some(root),
            name: "prov".into(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });
        let svc = make_service(repo, FakeOutcome::Ok);
        let err = svc
            .read_tenant(&ctx_for(root), child)
            .await
            .expect_err("should hide");
        assert_eq!(err.sub_code(), "not_found");
    }

    #[tokio::test]
    async fn list_children_honours_top_and_skip() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        for i in 0..5u128 {
            let child = Uuid::from_u128(0x300 + i);
            svc.create_child(&ctx_for(root), child_input(child, root))
                .await
                .expect("create");
        }
        let page = svc
            .list_children(
                &ctx_for(root),
                ListChildrenQuery::new(root, None, 2, 1).expect("query"),
            )
            .await
            .expect("list ok");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.top, 2);
        assert_eq!(page.skip, 1);
        assert_eq!(page.total, Some(5));
    }

    #[tokio::test]
    async fn list_children_status_filter_applies() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        let c1 = Uuid::from_u128(0x301);
        let c2 = Uuid::from_u128(0x302);
        svc.create_child(&ctx_for(root), child_input(c1, root))
            .await
            .expect("c1");
        svc.create_child(&ctx_for(root), child_input(c2, root))
            .await
            .expect("c2");
        svc.update_tenant(
            &ctx_for(root),
            c2,
            TenantUpdate {
                status: Some(TenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .expect("patch c2");

        let active_only = svc
            .list_children(
                &ctx_for(root),
                ListChildrenQuery::new(root, Some(vec![TenantStatus::Active]), 10, 0)
                    .expect("query"),
            )
            .await
            .expect("list ok");
        assert_eq!(active_only.items.len(), 1);
        assert_eq!(active_only.items[0].id, c1);

        let suspended_only = svc
            .list_children(
                &ctx_for(root),
                ListChildrenQuery::new(root, Some(vec![TenantStatus::Suspended]), 10, 0)
                    .expect("query"),
            )
            .await
            .expect("list ok");
        assert_eq!(suspended_only.items.len(), 1);
        assert_eq!(suspended_only.items[0].id, c2);
    }

    #[tokio::test]
    async fn update_tenant_accepts_name_and_supported_status_transitions() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        let child = Uuid::from_u128(0x400);
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create");

        let renamed = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    name: Some("renamed".into()),
                    ..Default::default()
                },
            )
            .await
            .expect("rename ok");
        assert_eq!(renamed.name, "renamed");

        let suspended = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    status: Some(TenantStatus::Suspended),
                    ..Default::default()
                },
            )
            .await
            .expect("suspend ok");
        assert_eq!(suspended.status, TenantStatus::Suspended);

        let reactivated = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    status: Some(TenantStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .expect("unsuspend ok");
        assert_eq!(reactivated.status, TenantStatus::Active);

        // Verify descendant_status was rewritten in the closure (status denorm invariant).
        let closure = repo.snapshot_closure();
        assert!(
            closure
                .iter()
                .filter(|r| r.descendant_id == child)
                .all(|r| r.descendant_status == TenantStatus::Active.as_smallint())
        );
    }

    #[tokio::test]
    async fn update_tenant_rejects_empty_patch() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        let err = svc
            .update_tenant(&ctx_for(root), root, TenantUpdate::default())
            .await
            .expect_err("reject");
        assert_eq!(err.sub_code(), "validation");
    }

    #[tokio::test]
    async fn update_tenant_rejects_transition_to_deleted() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        let child = Uuid::from_u128(0x500);
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create");

        let err = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    status: Some(TenantStatus::Deleted),
                    ..Default::default()
                },
            )
            .await
            .expect_err("delete must go through DELETE flow");
        assert_eq!(err.sub_code(), "validation");
    }

    #[tokio::test]
    async fn update_tenant_rejects_transition_from_provisioning() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x600);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        repo.insert_tenant_raw(TenantModel {
            id: child,
            parent_id: Some(root),
            name: "prov".into(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });
        let svc = make_service(repo, FakeOutcome::Ok);
        let err = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    status: Some(TenantStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .expect_err("must not see provisioning tenant");
        // Provisioning is SDK-invisible, so the service surfaces not_found.
        assert_eq!(err.sub_code(), "not_found");
    }

    #[tokio::test]
    async fn update_tenant_rejects_oversized_name() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo, FakeOutcome::Ok);
        let err = svc
            .update_tenant(
                &ctx_for(root),
                root,
                TenantUpdate {
                    name: Some("x".repeat(256)),
                    ..Default::default()
                },
            )
            .await
            .expect_err("reject oversized");
        assert_eq!(err.sub_code(), "validation");
    }

    // ---- Closure invariant end-to-end ------------------------------

    #[tokio::test]
    async fn closure_invariants_are_preserved_across_self_managed_path() {
        // Layout: root(d=0,sm=false) → mid(d=1,sm=true) → leaf(d=2,sm=false)
        let root = Uuid::from_u128(0x100);
        let mid = Uuid::from_u128(0x110);
        let leaf = Uuid::from_u128(0x111);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);

        let mut mid_input = child_input(mid, root);
        mid_input.self_managed = true;
        svc.create_child(&ctx_for(root), mid_input)
            .await
            .expect("mid ok");
        svc.create_child(&ctx_for(root), child_input(leaf, mid))
            .await
            .expect("leaf ok");

        let closure = repo.snapshot_closure();
        // Self-row barrier invariant: every self-row has barrier=0.
        for row in closure.iter().filter(|r| r.is_self_row()) {
            assert_eq!(row.barrier, 0, "self-row barrier must be 0");
        }
        // Leaf participates in 3 rows: self + mid + root.
        let leaf_rows: Vec<_> = closure.iter().filter(|r| r.descendant_id == leaf).collect();
        assert_eq!(leaf_rows.len(), 3);
        let root_to_leaf = leaf_rows
            .iter()
            .find(|r| r.ancestor_id == root)
            .expect("root->leaf row");
        let mid_to_leaf = leaf_rows
            .iter()
            .find(|r| r.ancestor_id == mid)
            .expect("mid->leaf row");
        // Strict path from root to leaf is {mid, leaf}; mid is self-managed, so barrier=1.
        assert_eq!(
            root_to_leaf.barrier, 1,
            "self-managed mid sets barrier on root->leaf"
        );
        // Strict path from mid to leaf is {leaf}; leaf is not self-managed, so barrier=0.
        assert_eq!(mid_to_leaf.barrier, 0, "no self-managed below mid");
    }

    #[tokio::test]
    async fn closure_invariants_no_self_managed_gives_all_zero_barriers() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x110);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("ok");

        let closure = repo.snapshot_closure();
        // Every row barrier must be 0 when no tenant on any strict path is self-managed.
        for row in &closure {
            assert_eq!(row.barrier, 0);
        }
    }

    #[tokio::test]
    async fn create_child_rejects_inactive_parent() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        // Suspend the root via direct mutation.
        {
            let mut state = repo.state.lock().expect("lock");
            state.tenants.get_mut(&root).expect("root").status = TenantStatus::Suspended;
        }
        let svc = make_service(repo, FakeOutcome::Ok);
        let err = svc
            .create_child(&ctx_for(root), child_input(Uuid::from_u128(0x700), root))
            .await
            .expect_err("suspended parent rejects");
        assert_eq!(err.sub_code(), "validation");
    }

    // =================================================================
    // Phase 3 — soft delete / hard delete / reaper / integrity / strict
    // =================================================================

    use crate::domain::tenant::hooks::{HookError, TenantHardDeleteHook};
    use crate::domain::tenant::integrity::{IntegrityCategory, IntegrityScope};
    use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
    use futures::future::FutureExt;
    use modkit_security::SecurityContext;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration as StdDuration;

    fn ctx() -> SecurityContext {
        // Default Phase-3 test ctx — caller is the platform admin (home
        // tenant == root tenant id used by `FakeTenantRepo::with_root`).
        SecurityContext::builder()
            .subject_id(Uuid::from_u128(0xDEAD))
            .subject_tenant_id(Uuid::from_u128(0x100))
            .build()
            .expect("ctx")
    }

    fn svc_with(
        repo: Arc<FakeTenantRepo>,
        outcome: FakeOutcome,
        cfg: AccountManagementConfig,
        checker: Arc<dyn ResourceOwnershipChecker>,
    ) -> TenantService<FakeTenantRepo> {
        TenantService::new(
            repo,
            Arc::new(FakeIdpProvisioner::new(outcome)),
            checker,
            crate::domain::tenant_type::inert_tenant_type_checker(),
            mock_enforcer(),
            cfg,
        )
    }

    struct CountingChecker {
        count: u64,
    }
    #[async_trait]
    impl ResourceOwnershipChecker for CountingChecker {
        async fn count_ownership_links(&self, _id: Uuid) -> Result<u64, AmError> {
            Ok(self.count)
        }
    }

    #[tokio::test]
    async fn soft_delete_rejects_root_tenant() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo,
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );
        let err = svc
            .soft_delete(&ctx(), root)
            .await
            .expect_err("root reject");
        assert_eq!(err.sub_code(), "root_tenant_cannot_delete");
    }

    #[tokio::test]
    async fn soft_delete_rejects_tenant_with_children() {
        let root = Uuid::from_u128(0x100);
        let mid = Uuid::from_u128(0x110);
        let leaf = Uuid::from_u128(0x111);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(mid, root))
            .await
            .expect("mid");
        svc.create_child(&ctx_for(root), child_input(leaf, mid))
            .await
            .expect("leaf");

        let err = svc
            .soft_delete(&ctx(), mid)
            .await
            .expect_err("has children");
        assert_eq!(err.sub_code(), "tenant_has_children");
    }

    #[tokio::test]
    async fn soft_delete_rejects_tenant_with_rg_resources() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x200);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(CountingChecker { count: 3 }),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("child");
        let err = svc
            .soft_delete(&ctx(), child)
            .await
            .expect_err("has resources");
        assert_eq!(err.sub_code(), "tenant_has_resources");
    }

    #[tokio::test]
    async fn soft_delete_emits_tenant_scoped_audit_event() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x200);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: 42,
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("child");

        crate::domain::audit::clear_captured_audit_events();
        svc.soft_delete(&ctx(), child).await.expect("soft-delete");

        let events = crate::domain::audit::take_captured_audit_events();
        let event = events
            .iter()
            .find(|event| event.payload.get("event") == Some(&json!("soft_delete_requested")))
            .expect("soft-delete audit event");

        assert_eq!(event.kind, AuditEventKind::TenantStateChanged);
        assert_eq!(event.tenant_id, child);
        assert_eq!(event.payload.get("retention_secs"), Some(&json!(42_u64)));
        match &event.actor {
            crate::domain::audit::AuditActor::TenantScoped {
                subject_id,
                subject_tenant_id,
            } => {
                assert_eq!(*subject_id, Uuid::from_u128(0xDEAD));
                assert_eq!(*subject_tenant_id, root);
            }
            crate::domain::audit::AuditActor::System => {
                panic!("soft-delete audit must be caller attributed");
            }
        }
    }

    #[tokio::test]
    async fn scan_retention_does_not_starve_due_rows_behind_older_not_due_backlog() {
        // Pin the no-starvation contract that
        // `TenantRepoImpl::scan_retention_due` enforces by pushing the
        // due-check into SQL. The pathological shape: a backlog of
        // older not-yet-due NULL-window rows (default 90-day retention)
        // alongside a single newer due row with explicit
        // `retention_window_secs = 0`. The earlier over-fetch + Rust
        // is_due implementation could load only the older rows (LIMIT
        // 256, ordered by scheduled_at ASC) and silently drop them all
        // as not-due, leaving the newer due row indefinitely
        // unprocessed.
        //
        // Note: the FakeRepo's `scan_retention_due` already applies
        // `is_due` before the limit, so this test reproduces the
        // *expected* behaviour and pins the contract. The SQL-side
        // regression validation lives in the integration-test suite
        // (TODO once that scaffold lands for AM — see
        // `feature-tenant-hierarchy-management.md` retention §).
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));

        let now = OffsetDateTime::now_utc();
        let eighty_days_ago = now - time::Duration::days(80);
        // 90 days in seconds. `from_hours` is unstable on the
        // workspace MSRV; use the seconds form (matches the existing
        // pattern in `repo_impl.rs::REAPER_BACKOFF_MAX`).
        #[allow(clippy::duration_suboptimal_units)]
        let ninety_day_default = std::time::Duration::from_secs(90 * 86_400);

        // 300 older NULL-window rows scheduled 80d ago — not due under
        // the default 90d retention. 300 > the historical 4×64 = 256
        // over-fetch cap, which is what triggered the starvation.
        {
            let mut state = repo.state.lock().expect("lock");
            for i in 0..300u128 {
                let id = Uuid::from_u128(0xA000 + i);
                state.tenants.insert(
                    id,
                    TenantModel {
                        id,
                        parent_id: Some(root),
                        name: format!("backlog-{i}"),
                        status: TenantStatus::Deleted,
                        self_managed: false,
                        tenant_type_uuid: Uuid::from_u128(0xAA),
                        depth: 1,
                        created_at: eighty_days_ago,
                        updated_at: eighty_days_ago,
                        deleted_at: Some(eighty_days_ago),
                    },
                );
                state.closure.push(ClosureRow {
                    ancestor_id: id,
                    descendant_id: id,
                    barrier: 0,
                    descendant_status: TenantStatus::Deleted.as_smallint(),
                });
                state.closure.push(ClosureRow {
                    ancestor_id: root,
                    descendant_id: id,
                    barrier: 0,
                    descendant_status: TenantStatus::Deleted.as_smallint(),
                });
                // NULL retention_window — use service default.
                state.retention.insert(id, (eighty_days_ago, None));
            }
        }

        // The single due row: explicit retention_window_secs = 0,
        // scheduled now → due immediately.
        let due_id = Uuid::from_u128(0xDEED);
        {
            let mut state = repo.state.lock().expect("lock");
            state.tenants.insert(
                due_id,
                TenantModel {
                    id: due_id,
                    parent_id: Some(root),
                    name: "due-now".into(),
                    status: TenantStatus::Deleted,
                    self_managed: false,
                    tenant_type_uuid: Uuid::from_u128(0xAA),
                    depth: 1,
                    created_at: now,
                    updated_at: now,
                    deleted_at: Some(now),
                },
            );
            state.closure.push(ClosureRow {
                ancestor_id: due_id,
                descendant_id: due_id,
                barrier: 0,
                descendant_status: TenantStatus::Deleted.as_smallint(),
            });
            state.closure.push(ClosureRow {
                ancestor_id: root,
                descendant_id: due_id,
                barrier: 0,
                descendant_status: TenantStatus::Deleted.as_smallint(),
            });
            state
                .retention
                .insert(due_id, (now, Some(std::time::Duration::from_secs(0))));
        }

        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: ninety_day_default.as_secs(),
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );

        let res = svc.hard_delete_batch(64).await;
        assert_eq!(
            res.processed, 1,
            "exactly the due row should be processed; the 300-row not-due backlog must not starve it"
        );
        assert_eq!(res.cleaned, 1, "the due row should reach Cleaned");
        assert!(
            repo.find_by_id(&AccessScope::allow_all(), due_id)
                .await
                .expect("repo")
                .is_none(),
            "the due row must be hard-deleted"
        );
        // None of the 300 not-due rows should have been touched.
        for i in 0..300u128 {
            let id = Uuid::from_u128(0xA000 + i);
            assert!(
                repo.find_by_id(&AccessScope::allow_all(), id)
                    .await
                    .expect("repo")
                    .is_some(),
                "not-due backlog row {id} must remain"
            );
        }
    }

    #[tokio::test]
    async fn hard_delete_batch_emits_cleanup_completed_audit() {
        // End-to-end small batch: scope is one leaf with `is_due = true`.
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x200);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: 0, // expire immediately
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("child");
        svc.soft_delete(&ctx(), child).await.expect("soft-delete");

        let res = svc.hard_delete_batch(64).await;
        assert_eq!(res.processed, 1);
        assert_eq!(res.cleaned, 1, "single leaf should reach Cleaned");

        // Verify tenant is gone.
        assert!(
            repo.find_by_id(&AccessScope::allow_all(), child)
                .await
                .expect("repo")
                .is_none()
        );
    }

    #[tokio::test]
    async fn reaper_defers_on_idp_terminal_failure() {
        let root = Uuid::from_u128(0x100);
        let stuck = Uuid::from_u128(0x210);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        // Insert a provisioning tenant directly + set its created_at 1h ago.
        let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        repo.insert_tenant_raw(TenantModel {
            id: stuck,
            parent_id: Some(root),
            name: "stuck".into(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: then,
            updated_at: then,
            deleted_at: None,
        });
        let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
        idp.set_deprovision_outcome(FakeDeprovisionOutcome::Terminal);
        let svc = TenantService::new(
            repo.clone(),
            idp,
            Arc::new(InertResourceOwnershipChecker),
            crate::domain::tenant_type::inert_tenant_type_checker(),
            mock_enforcer(),
            AccountManagementConfig::default(),
        );
        let res = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
        assert_eq!(res.scanned, 1);
        assert_eq!(
            res.deferred, 1,
            "terminal failure defers rather than cleans"
        );
        // Tenant still in provisioning.
        let row = repo
            .find_by_id(&AccessScope::allow_all(), stuck)
            .await
            .expect("repo")
            .expect("row");
        assert_eq!(row.status, TenantStatus::Provisioning);
    }

    #[tokio::test]
    async fn hard_delete_batch_skips_parent_when_child_still_exists() {
        let root = Uuid::from_u128(0x100);
        let parent = Uuid::from_u128(0x220);
        let child = Uuid::from_u128(0x221);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: 0,
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(parent, root))
            .await
            .expect("p");
        svc.create_child(&ctx_for(root), child_input(child, parent))
            .await
            .expect("c");
        // Schedule the parent for deletion DIRECTLY (bypasses the
        // child-rejection guard in soft_delete), so we can reproduce
        // the in-tx child-existence guard path during hard_delete_batch.
        let now = OffsetDateTime::now_utc();
        let _ = repo
            .schedule_deletion(
                &AccessScope::allow_all(),
                parent,
                now,
                Some(StdDuration::from_secs(0)),
            )
            .await
            .expect("schedule parent");

        let res = svc.hard_delete_batch(64).await;
        assert_eq!(res.processed, 1);
        assert_eq!(
            res.deferred, 1,
            "parent deferred because child still exists"
        );
        assert!(
            repo.find_by_id(&AccessScope::allow_all(), parent)
                .await
                .expect("repo")
                .is_some(),
            "parent row still present"
        );
    }

    #[tokio::test]
    async fn hard_delete_batch_invokes_cascade_hook_before_idp() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x230);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: 0,
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("c");
        svc.soft_delete(&ctx(), child).await.expect("sd");

        let hook_calls = Arc::new(AtomicU32::new(0));
        let hook_calls_for_hook = hook_calls.clone();
        let hook: TenantHardDeleteHook = Arc::new(move |_id: Uuid| {
            let hc = hook_calls_for_hook.clone();
            async move {
                hc.fetch_add(1, Ordering::SeqCst);
                Ok::<_, HookError>(())
            }
            .boxed()
        });
        svc.register_hard_delete_hook(hook);

        let _ = svc.hard_delete_batch(64).await;
        assert_eq!(
            hook_calls.load(Ordering::SeqCst),
            1,
            "cascade hook must run exactly once per tenant"
        );
    }

    #[tokio::test]
    async fn check_hierarchy_integrity_returns_all_category_report() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo,
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );
        let report = svc
            .check_hierarchy_integrity(IntegrityScope::Whole)
            .await
            .expect("report");
        let ordered = IntegrityCategory::all();
        assert_eq!(report.violations_by_category.len(), ordered.len());
        for (i, (cat, _)) in report.violations_by_category.iter().enumerate() {
            assert_eq!(*cat, ordered[i], "category order at index {i}");
        }
        assert_eq!(
            report.total(),
            0,
            "clean hierarchy should have no violations"
        );
    }

    #[tokio::test]
    async fn check_hierarchy_integrity_whole_rejects_oversize_load() {
        // Build a small layout (root + one child = 2 tenants) and set
        // the integrity cap to 1 so the Whole-scope load trips the
        // guardrail. Subtree audits remain unaffected by the cap.
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x110);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                integrity_max_tenants: 1,
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("child");

        let err = svc
            .check_hierarchy_integrity(IntegrityScope::Whole)
            .await
            .expect_err("integrity cap must trip");
        assert_eq!(err.sub_code(), "internal");
        // Subtree path bypasses the cap. The audit may flag a synthetic
        // OrphanedChild because the parent is excluded from the
        // subtree-bounded load; that's an inherent limitation of the
        // shape classifier and orthogonal to this test's purpose, which
        // is the cap-bypass.
        svc.check_hierarchy_integrity(IntegrityScope::Subtree(child))
            .await
            .expect("subtree audit must succeed under cap");
    }

    #[tokio::test]
    async fn hard_delete_concurrency_processes_siblings_in_parallel() {
        // Five sibling leaves at the same depth. With concurrency = 4
        // and a 50ms artificial delay per pipeline (via the cascade
        // hook) the wall-clock should be < 5×50ms = 250ms; we assert
        // strictly under 200ms so a single-flight regression is caught
        // (sequential would be ≥ 250ms).
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig {
                default_retention_secs: 0,
                hard_delete_concurrency: 4,
                ..AccountManagementConfig::default()
            },
            Arc::new(InertResourceOwnershipChecker),
        );

        for i in 0..5u128 {
            let id = Uuid::from_u128(0x300 + i);
            svc.create_child(&ctx_for(root), child_input(id, root))
                .await
                .expect("child");
            svc.soft_delete(&ctx(), id).await.expect("sd");
        }

        let hits = Arc::new(AtomicU32::new(0));
        let hits_for_hook = hits.clone();
        let hook: TenantHardDeleteHook = Arc::new(move |_id: Uuid| {
            let hc = hits_for_hook.clone();
            async move {
                tokio::time::sleep(StdDuration::from_millis(50)).await;
                hc.fetch_add(1, Ordering::SeqCst);
                Ok::<_, HookError>(())
            }
            .boxed()
        });
        svc.register_hard_delete_hook(hook);

        let start = std::time::Instant::now();
        let res = svc.hard_delete_batch(64).await;
        let elapsed = start.elapsed();

        assert_eq!(res.processed, 5);
        assert_eq!(res.cleaned, 5, "all five leaves should reach Cleaned");
        assert_eq!(hits.load(Ordering::SeqCst), 5);
        assert!(
            elapsed < StdDuration::from_millis(200),
            "expected <200ms with concurrency=4, got {elapsed:?} (sequential would be >=250ms)"
        );
    }

    #[tokio::test]
    async fn strict_mode_rejects_deep_child() {
        // Per `algo-depth-threshold-evaluation` strict-mode rejects at
        // `depth > threshold`. Build a chain of depth 0..=2 and pin
        // `depth_threshold = 2` so a child created under the deepest
        // tenant lands at depth 3 (= threshold + 1) and is rejected.
        let repo = Arc::new(FakeTenantRepo::new());
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        let mut prev: Option<Uuid> = None;
        let mut deepest = Uuid::nil();
        for i in 0..=2u128 {
            let id = Uuid::from_u128(0x2000 + i);
            repo.insert_tenant_raw(TenantModel {
                id,
                parent_id: prev,
                name: format!("t{i}"),
                status: TenantStatus::Active,
                self_managed: false,
                tenant_type_uuid: Uuid::from_u128(0xAA),
                depth: u32::try_from(i).expect("u32"),
                created_at: now,
                updated_at: now,
                deleted_at: None,
            });
            prev = Some(id);
            deepest = id;
        }

        let cfg = AccountManagementConfig {
            depth_strict_mode: true,
            depth_threshold: 2,
            ..AccountManagementConfig::default()
        };
        let svc = svc_with(
            repo,
            FakeOutcome::Ok,
            cfg,
            Arc::new(InertResourceOwnershipChecker),
        );
        let child = Uuid::from_u128(0x9001);
        let root = Uuid::from_u128(0x2000);
        let err = svc
            .create_child(&ctx_for(root), child_input(child, deepest))
            .await
            .expect_err("strict reject");
        assert_eq!(err.sub_code(), "tenant_depth_exceeded");
    }

    // =================================================================
    // Cross-tenant authorization (IDOR) — service layer
    // =================================================================
    //
    // Hierarchy used below:
    //   root(0x100)        ← platform-root + caller-A's home tenant
    //     ├── child_a(0x200)  ← inside caller-A's subtree
    //     └── stranger(0x300) ← caller-B's home; not reachable from A
    // For these tests the "non-admin caller" is `stranger` whose home
    // tenant id != root id, so the platform-admin override does not
    // fire and ancestry is checked against the closure.

    type FakeService = TenantService<FakeTenantRepo>;

    async fn build_two_tenant_layout() -> (Uuid, Uuid, Uuid, Arc<FakeTenantRepo>, FakeService) {
        let root = Uuid::from_u128(0x100);
        let child_a = Uuid::from_u128(0x200);
        let stranger = Uuid::from_u128(0x300);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        // Use the platform-admin to provision both children so the
        // closure rows are properly written by the saga.
        let admin = ctx_for(root);
        svc.create_child(&admin, child_input(child_a, root))
            .await
            .expect("child_a");
        svc.create_child(&admin, child_input(stranger, root))
            .await
            .expect("stranger");
        (root, child_a, stranger, repo, svc)
    }

    #[tokio::test]
    async fn read_tenant_cross_tenant_returns_cross_tenant_denied() {
        let (_root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        // Caller-B (home = stranger) tries to read child_a.
        let err = svc
            .read_tenant(&ctx_for(stranger), child_a)
            .await
            .expect_err("cross-tenant must be denied");
        assert_eq!(err.sub_code(), "cross_tenant_denied");
    }

    #[tokio::test]
    async fn update_tenant_cross_tenant_returns_cross_tenant_denied() {
        let (_root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        let err = svc
            .update_tenant(
                &ctx_for(stranger),
                child_a,
                TenantUpdate {
                    name: Some("hijack".into()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("cross-tenant must be denied");
        assert_eq!(err.sub_code(), "cross_tenant_denied");
    }

    #[tokio::test]
    async fn soft_delete_cross_tenant_returns_cross_tenant_denied() {
        let (_root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        let err = svc
            .soft_delete(&ctx_for(stranger), child_a)
            .await
            .expect_err("cross-tenant must be denied");
        assert_eq!(err.sub_code(), "cross_tenant_denied");
    }

    #[tokio::test]
    async fn list_children_cross_tenant_returns_cross_tenant_denied() {
        let (_root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        let err = svc
            .list_children(
                &ctx_for(stranger),
                ListChildrenQuery::new(child_a, None, 10, 0).expect("query"),
            )
            .await
            .expect_err("cross-tenant must be denied");
        assert_eq!(err.sub_code(), "cross_tenant_denied");
    }

    #[tokio::test]
    async fn create_child_with_parent_outside_scope_returns_cross_tenant_denied() {
        let (_root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        // Caller-B tries to create a sub-tenant under child_a (outside B's home).
        let new_child = Uuid::from_u128(0x900);
        let err = svc
            .create_child(&ctx_for(stranger), child_input(new_child, child_a))
            .await
            .expect_err("cross-tenant create must be denied");
        assert_eq!(err.sub_code(), "cross_tenant_denied");
    }

    #[tokio::test]
    async fn read_tenant_descendant_within_scope_succeeds() {
        // Build root → mid → leaf. mid is the caller's home; leaf is in
        // their subtree — should succeed.
        let root = Uuid::from_u128(0x100);
        let mid = Uuid::from_u128(0x110);
        let leaf = Uuid::from_u128(0x111);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), FakeOutcome::Ok);
        let admin = ctx_for(root);
        svc.create_child(&admin, child_input(mid, root))
            .await
            .expect("mid");
        svc.create_child(&admin, child_input(leaf, mid))
            .await
            .expect("leaf");

        let got = svc
            .read_tenant(&ctx_for(mid), leaf)
            .await
            .expect("descendant read should succeed");
        assert_eq!(got.id, leaf);
    }

    #[tokio::test]
    async fn platform_admin_can_read_any_tenant() {
        let (root, child_a, stranger, _repo, svc) = build_two_tenant_layout().await;
        // Admin (caller home == root) can read both subtrees.
        let admin = ctx_for(root);
        assert_eq!(
            svc.read_tenant(&admin, child_a).await.expect("admin a").id,
            child_a
        );
        assert_eq!(
            svc.read_tenant(&admin, stranger).await.expect("admin b").id,
            stranger
        );
    }

    // =================================================================
    // FEATURE 2.3 — tenant-type-enforcement (saga step 3)
    // =================================================================

    /// Programmable [`TenantTypeChecker`] used by the saga step 3 tests
    /// to drive the type-compatibility barrier through its three
    /// branches: admit, type-not-allowed reject, registry unavailable.
    struct FakeTenantTypeChecker {
        outcome: Mutex<FakeTypeOutcome>,
        calls: Mutex<Vec<(Uuid, Uuid)>>,
    }

    #[derive(Clone)]
    enum FakeTypeOutcome {
        Admit,
        TypeNotAllowed { detail: &'static str },
        ServiceUnavailable { detail: &'static str },
    }

    impl FakeTenantTypeChecker {
        fn new(outcome: FakeTypeOutcome) -> Self {
            Self {
                outcome: Mutex::new(outcome),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(Uuid, Uuid)> {
            self.calls.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl TenantTypeChecker for FakeTenantTypeChecker {
        async fn check_parent_child(
            &self,
            parent_type: Uuid,
            child_type: Uuid,
        ) -> Result<(), AmError> {
            self.calls
                .lock()
                .expect("lock")
                .push((parent_type, child_type));
            match self.outcome.lock().expect("lock").clone() {
                FakeTypeOutcome::Admit => Ok(()),
                FakeTypeOutcome::TypeNotAllowed { detail } => Err(AmError::TypeNotAllowed {
                    detail: detail.into(),
                }),
                FakeTypeOutcome::ServiceUnavailable { detail } => {
                    Err(AmError::ServiceUnavailable {
                        detail: detail.into(),
                    })
                }
            }
        }
    }

    fn make_service_with_type_checker(
        repo: Arc<FakeTenantRepo>,
        outcome: FakeOutcome,
        type_checker: Arc<dyn TenantTypeChecker + Send + Sync>,
    ) -> TenantService<FakeTenantRepo> {
        TenantService::new(
            repo,
            Arc::new(FakeIdpProvisioner::new(outcome)),
            Arc::new(InertResourceOwnershipChecker),
            type_checker,
            mock_enforcer(),
            AccountManagementConfig::default(),
        )
    }

    /// AC §6 first bullet — when the parent's `tenant_type` is not in
    /// the child's `allowed_parent_types`, the barrier rejects with
    /// `type_not_allowed` and no `tenants` row is written.
    #[tokio::test]
    async fn create_child_rejects_when_parent_type_not_in_child_allowed_parents() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x500);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let closure_before = repo.snapshot_closure().len();
        let svc = make_service_with_type_checker(
            repo.clone(),
            FakeOutcome::Ok,
            Arc::new(FakeTenantTypeChecker::new(
                FakeTypeOutcome::TypeNotAllowed {
                    detail: "customer not allowed under platform",
                },
            )),
        );

        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("type-not-allowed must reject");
        assert_eq!(err.sub_code(), "type_not_allowed");
        assert_eq!(err.http_status(), 409);

        // No `tenants` row, no closure rows written.
        let row = repo
            .find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo");
        assert!(row.is_none(), "no tenant row should be written on reject");
        assert_eq!(repo.snapshot_closure().len(), closure_before);
    }

    /// Barrier admits → saga proceeds and the checker observed exactly
    /// one `(parent_type, child_type)` call with the right shape.
    #[tokio::test]
    async fn create_child_succeeds_when_parent_child_compatible() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x501);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let checker = Arc::new(FakeTenantTypeChecker::new(FakeTypeOutcome::Admit));
        let svc = make_service_with_type_checker(repo, FakeOutcome::Ok, checker.clone());

        // Root tenant_type_uuid is `0xAA` per `FakeTenantRepo::with_root`,
        // and the child `tenant_type_uuid` from `child_input` is `0xAA`.
        let created = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("compatible types admit");
        assert_eq!(created.id, child);
        assert_eq!(created.status, TenantStatus::Active);

        let calls = checker.calls();
        assert_eq!(calls.len(), 1, "barrier must be invoked exactly once");
        assert_eq!(calls[0].0, Uuid::from_u128(0xAA), "parent type");
        assert_eq!(calls[0].1, Uuid::from_u128(0xAA), "child type");
    }

    /// AC §6 fifth bullet — when GTS is unreachable, the saga propagates
    /// `service_unavailable` (HTTP 503) and writes nothing.
    #[tokio::test]
    async fn create_child_propagates_types_registry_unavailable_as_service_unavailable() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x502);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let closure_before = repo.snapshot_closure().len();
        let svc = make_service_with_type_checker(
            repo.clone(),
            FakeOutcome::Ok,
            Arc::new(FakeTenantTypeChecker::new(
                FakeTypeOutcome::ServiceUnavailable {
                    detail: "types-registry: connection refused",
                },
            )),
        );

        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("registry down must propagate");
        assert_eq!(err.sub_code(), "service_unavailable");
        assert_eq!(err.http_status(), 503);

        // No DB side effects.
        let row = repo
            .find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo");
        assert!(row.is_none(), "no tenant row on registry unavailable");
        assert_eq!(repo.snapshot_closure().len(), closure_before);
    }

    /// AC §6 third bullet, negative half — same-type nesting requested
    /// but the GTS schema does not include the type in its own
    /// `allowed_parent_types`. Drive via the checker stub returning
    /// `type_not_allowed` for the same-type pairing.
    #[tokio::test]
    async fn create_child_rejects_same_type_nesting_when_disallowed() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x503);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let closure_before = repo.snapshot_closure().len();
        let svc = make_service_with_type_checker(
            repo.clone(),
            FakeOutcome::Ok,
            Arc::new(FakeTenantTypeChecker::new(
                FakeTypeOutcome::TypeNotAllowed {
                    detail: "type cannot nest under itself",
                },
            )),
        );

        // child_input uses `tenant_type_uuid = 0xAA` which equals the
        // root's `tenant_type_uuid`; this is the same-type nesting case.
        let err = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect_err("disallowed same-type nesting must reject");
        assert_eq!(err.sub_code(), "type_not_allowed");
        assert_eq!(err.http_status(), 409);

        let row = repo
            .find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo");
        assert!(row.is_none());
        assert_eq!(repo.snapshot_closure().len(), closure_before);
    }

    /// AC §6 third bullet, positive half — same-type nesting requested
    /// and the GTS schema admits the type as its own allowed parent.
    #[tokio::test]
    async fn create_child_accepts_same_type_nesting_when_allowed() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x504);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service_with_type_checker(
            repo.clone(),
            FakeOutcome::Ok,
            Arc::new(FakeTenantTypeChecker::new(FakeTypeOutcome::Admit)),
        );

        // Same `tenant_type_uuid` for parent and child — checker admits.
        let created = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("same-type nesting admitted by checker must succeed");
        assert_eq!(created.id, child);
        assert_eq!(created.status, TenantStatus::Active);
    }

    // =================================================================
    // Contract-review test gaps (F1–F4)
    //
    // The Phase-1/2/3 contract review identified four acceptance
    // criteria whose implementing code was already in place but lacked
    // dedicated assertions. The tests below close those gaps using the
    // same in-memory `FakeTenantRepo` + `FakeIdpProvisioner` machinery
    // as the rest of the module.
    // =================================================================

    /// F1 — `Suspended → Deleted` soft-delete transition.
    ///
    /// `model::TenantUpdate::validate_status_transition` admits
    /// `Suspended` as a source status, and `service::soft_delete` does
    /// not gate on `Active` — but the existing happy-path test only
    /// covered an active leaf. This test moves the leaf through
    /// suspension first and then asserts the soft-delete still flips
    /// the row to `Deleted` with retention metadata.
    #[tokio::test]
    async fn soft_delete_succeeds_on_suspended_leaf_tenant() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0xF100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create child");

        // Move the leaf to Suspended via the public PATCH path.
        let suspended = svc
            .update_tenant(
                &ctx_for(root),
                child,
                TenantUpdate {
                    status: Some(TenantStatus::Suspended),
                    ..Default::default()
                },
            )
            .await
            .expect("suspension allowed");
        assert_eq!(suspended.status, TenantStatus::Suspended);

        // Now soft-delete the suspended leaf — should succeed.
        let deleted = svc
            .soft_delete(&ctx_for(root), child)
            .await
            .expect("soft-delete suspended leaf");
        assert_eq!(deleted.status, TenantStatus::Deleted);
        // Retention bookkeeping must be present after soft-delete.
        assert!(
            repo.state
                .lock()
                .expect("lock")
                .retention
                .contains_key(&child),
            "retention row must be written for the soft-deleted tenant"
        );
    }

    /// Pin the public-contract requirement that soft-delete stamps
    /// `tenants.deleted_at`. The `OpenAPI` `Tenant.deleted_at` field is
    /// surfaced on every tenant response, the migration declares a
    /// partial index `idx_tenants_deleted_at` keyed on this column,
    /// and the `Tenant` schema lists it as the public-contract
    /// tombstone marker. An earlier implementation of
    /// `schedule_deletion` only stamped `deletion_scheduled_at` and
    /// left this column permanently NULL — making the partial index
    /// empty and surfacing soft-deleted rows with
    /// `status=deleted, deleted_at=null` to the API.
    #[tokio::test]
    async fn soft_delete_stamps_deleted_at_on_returned_model_and_subsequent_reads() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0xF101);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );

        let created = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create child");
        assert!(
            created.deleted_at.is_none(),
            "freshly created tenant must not carry a deleted_at timestamp"
        );

        let deleted = svc
            .soft_delete(&ctx_for(root), child)
            .await
            .expect("soft-delete leaf");
        assert_eq!(deleted.status, TenantStatus::Deleted);
        let stamped = deleted
            .deleted_at
            .expect("schedule_deletion must stamp deleted_at on the returned row");
        assert_eq!(
            stamped, deleted.updated_at,
            "deleted_at and updated_at are written in the same transaction \
             and should match `now` exactly"
        );

        // Defense-in-depth: a subsequent direct repo read must surface
        // the stamp too, not just the returned-model copy. Bypass the
        // SDK-visibility filter (deleted rows are filtered out by
        // `read_tenant`) via the `_unchecked` helper.
        let after = repo
            .find_by_id_unchecked(child)
            .expect("row still present pre hard-delete");
        assert_eq!(after.deleted_at, Some(stamped));
    }

    /// F2 — `hard_delete_batch` row-level outcome on
    /// `DeprovisionFailure::Terminal`.
    ///
    /// The existing `reaper_defers_on_idp_terminal_failure` test covers
    /// the reaper path. This adds the missing assertion for the
    /// hard-delete batch path: a soft-deleted tenant whose `IdP`
    /// deprovision returns `Terminal` is tagged `IdpTerminal` (counted
    /// as a failed/deferred outcome by `HardDeleteResult::tally`) and
    /// the `tenants` row is NOT reclaimed.
    #[tokio::test]
    async fn hard_delete_batch_marks_idp_terminal_failure_as_failed() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let tenant = repo.seed_soft_deleted_child_due_for_hard_delete(root);
        let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
        idp.set_deprovision_outcome(FakeDeprovisionOutcome::Terminal);
        let svc = TenantService::new(
            repo.clone(),
            idp,
            Arc::new(InertResourceOwnershipChecker),
            crate::domain::tenant_type::inert_tenant_type_checker(),
            mock_enforcer(),
            AccountManagementConfig {
                default_retention_secs: 0,
                ..AccountManagementConfig::default()
            },
        );

        let res = svc.hard_delete_batch(64).await;
        assert_eq!(res.processed, 1, "exactly one due row was processed");
        assert!(
            res.failed >= 1,
            "IdP terminal failure must count toward `failed`, got {res:?}"
        );
        assert_eq!(
            res.cleaned, 0,
            "row must NOT be reclaimed on IdP terminal failure"
        );
        // Tenant row + closure rows still in the DB — the reaper /
        // operator owns the next move, not the hard-delete batch.
        assert!(
            repo.find_by_id_unchecked(tenant).is_some(),
            "soft-deleted row must remain after IdP terminal"
        );
    }

    /// F3 — finalization-TX failure injection (saga step 3 abort).
    ///
    /// AC#3 calls for the `create_child` saga to leave the
    /// `Provisioning` row in place when `repo.activate_tenant` fails
    /// post-IdP-provision so the reaper can compensate. The injection
    /// goes through `FakeTenantRepo::expect_next_activation_failure`,
    /// which arms the next call to return `AmError::Internal` exactly
    /// once.
    #[tokio::test]
    async fn create_child_finalization_tx_failure_leaves_provisioning_row_in_db() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0xF300);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        repo.expect_next_activation_failure("simulated SERIALIZABLE abort");
        let svc = svc_with(
            repo.clone(),
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );

        let result = svc
            .create_child(&ctx_for(root), child_input(child, root))
            .await;
        assert!(
            matches!(result, Err(AmError::Internal { .. })),
            "activate_tenant failure must surface as Internal, got {result:?}"
        );
        // Ambiguous outcome — provisioning row stays so the reaper
        // (or operator) owns compensation.
        let provisioning_rows = repo.snapshot_provisioning_rows();
        assert_eq!(
            provisioning_rows.len(),
            1,
            "provisioning row must remain on finalization-TX failure"
        );
        assert_eq!(provisioning_rows[0].id, child);
    }

    /// F4 — end-to-end integrity coverage on a deliberately corrupt
    /// fixture. AC#15 requires `check_hierarchy_integrity` to surface
    /// every [`IntegrityCategory`] variant. The fake
    /// repo grows a `seed_corrupt_hierarchy_with_one_violation_per_category`
    /// helper that injects exactly that, then the service-level
    /// classifier is asserted to land at least one violation in each
    /// category bucket.
    #[tokio::test]
    async fn check_hierarchy_integrity_detects_one_violation_per_category() {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        repo.seed_corrupt_hierarchy_with_one_violation_per_category(root);
        let svc = svc_with(
            repo,
            FakeOutcome::Ok,
            AccountManagementConfig::default(),
            Arc::new(InertResourceOwnershipChecker),
        );

        // Use the Whole scope: several seeded categories
        // (`OrphanedChild`, `RootCountAnomaly`, `ClosureCoverageGap`,
        // `StaleClosureRow`) intentionally seed rows that are NOT in
        // root's closure subtree, so a `Subtree(root)` load would miss
        // them. The test's purpose is "all classifier branches
        // fire on a corrupt fixture", which `Whole` covers.
        let report = svc
            .check_hierarchy_integrity(IntegrityScope::Whole)
            .await
            .expect("integrity report must succeed on a small fixture");

        let mut category_counts: HashMap<IntegrityCategory, usize> = HashMap::new();
        for (cat, viols) in &report.violations_by_category {
            category_counts.insert(*cat, viols.len());
        }
        for cat in [
            IntegrityCategory::OrphanedChild,
            IntegrityCategory::BrokenParentReference,
            IntegrityCategory::DepthMismatch,
            IntegrityCategory::Cycle,
            IntegrityCategory::RootCountAnomaly,
            IntegrityCategory::MissingClosureSelfRow,
            IntegrityCategory::ClosureCoverageGap,
            IntegrityCategory::StaleClosureRow,
            IntegrityCategory::BarrierColumnDivergence,
            IntegrityCategory::DescendantStatusDivergence,
        ] {
            let count = category_counts.get(&cat).copied().unwrap_or(0);
            assert!(
                count > 0,
                "category {cat:?} should have at least one violation, got {count}"
            );
        }
    }
}
