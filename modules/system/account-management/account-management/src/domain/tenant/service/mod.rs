//! `TenantService` — the central domain orchestrator for the four
//! in-scope tenant-hierarchy-management flows: create-child, read-tenant,
//! list-children, and update-tenant-mutable.
//!
//! The service depends only on the domain-level [`TenantRepo`] and
//! the SDK-level
//! [`account_management_sdk::IdpTenantProvisionerClient`] traits. All
//! tests in this file use pure in-memory fakes — no DB, no network,
//! no filesystem.

use std::sync::Arc;
use std::time::Duration;

use authz_resolver_sdk::PolicyEnforcer;
use authz_resolver_sdk::pep::{AccessRequest, ResourceType};
use modkit_macros::domain_model;
use modkit_security::{AccessScope, SecurityContext, pep_properties};
use parking_lot::Mutex as PlMutex;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

/// AM's authoritative PEP vocabulary (DESIGN §4.2 — Authorization Model).
///
/// Resource type and supported PEP properties are pinned here so the
/// enforcer call sites cannot drift from the contract. Action names
/// match DESIGN §4.2 line 1363; renaming them is a contract change.
pub(crate) mod pep {
    use super::{ResourceType, pep_properties};

    /// `Tenant` resource — `gts.cf.core.am.tenant.v1~`.
    ///
    /// Per DESIGN §4.2 line 1356 the supported PEP properties are
    /// `OWNER_TENANT_ID` and `RESOURCE_ID`. The values supplied by the
    /// AM PEP gate depend on the action:
    ///
    /// * `create`, `list_children` — `OWNER_TENANT_ID = parent_id`
    ///   (the tenant under which the action runs). The action lives
    ///   *in* the parent's scope, and barriers naturally clamp the
    ///   PDP's `parent_id ∈ subtree(Y_caller)` query against
    ///   `tenant_closure.barrier`.
    /// * `read`, `update`, `delete` — `OWNER_TENANT_ID = tenant.id`
    ///   (the row's own id). A tenant row IS its own scope: the
    ///   self-row `(id, id, barrier=0)` makes `id ∈ subtree(id)`
    ///   trivially true, while the strict-ancestor row `(M, T)`
    ///   carries `barrier=1` whenever `T` (or any tenant on the
    ///   `M → T` path excluding `M`) is `self_managed`. Sending
    ///   `parent_id` here would let `M`'s admin read a self-managed
    ///   child `T` because `(M, M, barrier=0)` is always present —
    ///   the barrier bit lives on `(M, T)`, so the PDP must query
    ///   the descendant's own id to consult it.
    ///
    /// `RESOURCE_ID` is conveyed via the standard `resource_id`
    /// argument (the tenant id itself for `read` / `update` / `delete`,
    /// absent for `create` / `list_children` which have no single
    /// target tenant).
    pub const TENANT: ResourceType = ResourceType {
        name: "gts.cf.core.am.tenant.v1~",
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

use account_management_sdk::{
    CreateChildInput, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient,
    ListChildrenQuery, ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, TenantInfo,
    TenantPage, TenantUpdate,
};
use tenant_resolver_sdk::TenantId;
use types_registry_sdk::TypesRegistryClient;

use crate::config::AccountManagementConfig;
use crate::domain::error::DomainError;
use crate::domain::idp::ProvisionFailureExt;
use crate::domain::metrics::{
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_REPAIRED,
    AM_HIERARCHY_INTEGRITY_VIOLATIONS, AM_TENANT_RETENTION, MetricKind, emit_gauge_value,
    emit_metric,
};
use crate::domain::tenant::closure::build_activation_rows;
use crate::domain::tenant::hooks::TenantHardDeleteHook;
use crate::domain::tenant::integrity::{
    IntegrityCategory, IntegrityReport, IntegrityScope, Violation,
};
use crate::domain::tenant::model::{
    ChildCountFilter, NewTenant, TenantModel, TenantStatus, validate_status_transition,
    validate_tenant_name,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
use crate::domain::tenant_type::checker::TenantTypeChecker;

/// Central AM domain service for tenant-hierarchy CRUD.
#[domain_model]
pub struct TenantService<R: TenantRepo> {
    repo: Arc<R>,
    idp: Arc<dyn IdpTenantProvisionerClient>,
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
    /// Optional GTS Types Registry client used to resolve a tenant's
    /// `tenant_type_uuid` back to its chained-id string before the
    /// service hands a [`TenantInfo`] to public callers. `None` in
    /// dev / test deployments without a registry plugin (in which case
    /// `TenantInfo.tenant_type` is left as `None`). Production reads
    /// rely on the registry client's own caching — every CRUD return
    /// fans out one `get_type_schema_by_uuid` call (or one batched
    /// `get_type_schemas_by_uuid` for `list_children`); the cache
    /// keeps real RTT off the hot path.
    types_registry: Option<Arc<dyn TypesRegistryClient>>,
    /// PEP boundary (DESIGN §4.2). Every public CRUD method calls
    /// [`Self::authorize`] before any structural precondition or
    /// repo read. Cross-tenant authorization (subtree clamp,
    /// platform-admin override) is owned by the PDP behind this
    /// enforcer — AM does not duplicate the check at the service
    /// layer. The Tenant Resolver Plugin (separate PR in this
    /// stack) feeds the PDP the tenant hierarchy via the standard
    /// `in_tenant_subtree` constraint.
    enforcer: PolicyEnforcer,
}

pub(super) mod reaper;
pub(super) mod retention;

impl<R: TenantRepo> TenantService<R> {
    /// Construct a fully-wired service. Production wiring lives in the
    /// AM module entry-point ([`crate::module::AccountManagementModule`]):
    /// `types-registry` and `resource-group` are declared as hard `deps`,
    /// so the entry-point hard-resolves `TypesRegistryClient` (passes
    /// [`crate::infra::types_registry::GtsTenantTypeChecker`]) and
    /// `ResourceGroupClient` (passes
    /// [`crate::infra::rg::RgResourceOwnershipChecker`]); a missing
    /// client fails `init`. Tests pass explicit checkers (typically the
    /// inert ones or test fakes) directly.
    #[must_use]
    pub fn new(
        repo: Arc<R>,
        idp: Arc<dyn IdpTenantProvisionerClient>,
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
            types_registry: None,
            enforcer,
        }
    }

    /// Wire a Types Registry client used to resolve `tenant_type_uuid`
    /// back to its chained GTS id when lowering [`TenantModel`] to
    /// [`TenantInfo`] on public CRUD return values. Without this the
    /// service still works — `TenantInfo.tenant_type` is just left as
    /// `None`. Production wiring (`module.rs`) calls this from
    /// `init` after the registry client resolves from `ClientHub`;
    /// tests (which usually pin an inert tenant-type checker) leave
    /// it unset.
    #[must_use]
    pub fn with_types_registry(mut self, registry: Arc<dyn TypesRegistryClient>) -> Self {
        self.types_registry = Some(registry);
        self
    }

    /// Resolve a tenant-type UUID into its chained GTS string via the
    /// configured registry client. Returns `None` when no registry is
    /// wired or when the lookup fails — the public `tenant_type` field
    /// on [`TenantInfo`] is `Option<String>` precisely so a registry
    /// blip doesn't fail an otherwise-fine read.
    async fn resolve_tenant_type(&self, type_uuid: Uuid) -> Option<String> {
        let registry = self.types_registry.as_ref()?;
        match registry.get_type_schema_by_uuid(type_uuid).await {
            Ok(schema) => Some(schema.type_id.as_ref().to_owned()),
            Err(err) => {
                tracing::warn!(
                    target: "am.tenant.service",
                    tenant_type_uuid = %type_uuid,
                    error = %err,
                    "tenant_type uuid -> chained-id resolution failed; returning None"
                );
                None
            }
        }
    }

    /// Lower an internal [`TenantModel`] to the public [`TenantInfo`]
    /// shape (consumed by REST consumers / sibling SDK callers via
    /// `tenant-resolver-sdk`).
    ///
    /// **Invariant:** the caller must filter `Provisioning` rows
    /// before invoking this helper — every public CRUD method either
    /// short-circuits with `NotFound` for SDK-invisible rows
    /// (`read_tenant`, `update_tenant`, `soft_delete`) or filters
    /// them out (`list_children`). The status conversion uses
    /// `TryFrom<TenantStatus>` so a bypass surfaces as
    /// [`DomainError::Internal`] (HTTP 500) instead of a process
    /// panic.
    async fn lower_to_tenant_info(&self, model: TenantModel) -> Result<TenantInfo, DomainError> {
        let tenant_type = self.resolve_tenant_type(model.tenant_type_uuid).await;
        let status =
            account_management_sdk::TenantStatus::try_from(model.status).map_err(|_| {
                DomainError::Internal {
                    diagnostic: format!(
                        "tenant {} reached lower_to_tenant_info with status=Provisioning; \
                     upstream is_sdk_visible filter was bypassed",
                        model.id
                    ),
                    cause: None,
                }
            })?;
        Ok(TenantInfo {
            id: TenantId(model.id),
            name: model.name,
            status,
            tenant_type,
            parent_id: model.parent_id.map(TenantId),
            self_managed: model.self_managed,
        })
    }

    /// Batched lowering for `list_children`. Issues one
    /// `get_type_schemas_by_uuid` round-trip for the page so latency
    /// scales with number of pages, not number of rows.
    async fn lower_to_tenant_page(
        &self,
        page: TenantPage<TenantModel>,
    ) -> Result<TenantPage<TenantInfo>, DomainError> {
        let TenantPage {
            items,
            top,
            skip,
            total,
        } = page;

        // Fan out one batch lookup for distinct uuids in the page; we
        // tolerate per-uuid registry failures by leaving `tenant_type`
        // as `None` for the affected row (same policy as the
        // single-row helper).
        let mut type_strings: std::collections::HashMap<Uuid, String> =
            std::collections::HashMap::new();
        if let Some(registry) = self.types_registry.as_ref() {
            let mut distinct: Vec<Uuid> = items.iter().map(|m| m.tenant_type_uuid).collect();
            distinct.sort_unstable();
            distinct.dedup();
            if !distinct.is_empty() {
                let resolved = registry.get_type_schemas_by_uuid(distinct).await;
                for (uuid, res) in resolved {
                    if let Ok(schema) = res {
                        type_strings.insert(uuid, schema.type_id.as_ref().to_owned());
                    }
                }
            }
        }

        let mut mapped: Vec<TenantInfo> = Vec::with_capacity(items.len());
        for m in items {
            let status =
                account_management_sdk::TenantStatus::try_from(m.status).map_err(|_| {
                    DomainError::Internal {
                        diagnostic: format!(
                            "tenant {} reached lower_to_tenant_page with status=Provisioning; \
                             upstream is_sdk_visible retain was bypassed",
                            m.id
                        ),
                        cause: None,
                    }
                })?;
            mapped.push(TenantInfo {
                id: TenantId(m.id),
                name: m.name,
                status,
                tenant_type: type_strings.get(&m.tenant_type_uuid).cloned(),
                parent_id: m.parent_id.map(TenantId),
                self_managed: m.self_managed,
            });
        }

        Ok(TenantPage {
            items: mapped,
            top,
            skip,
            total,
        })
    }

    /// Append a cascade hook. Hooks run in registration order.
    ///
    /// Eventual consistency: each retention tick snapshots the hook
    /// list once at the start (`service/retention.rs:hook_snapshot`)
    /// to avoid re-cloning the registration `Vec` on every row in the
    /// batch. A hook registered while a tick is in flight therefore
    /// takes effect on the **next** tick, not the current one. In
    /// practice all hooks are registered at module-init time before
    /// the first tick fires, so the window is empty in production.
    pub fn register_hard_delete_hook(&self, hook: TenantHardDeleteHook) {
        self.hooks.lock().push(hook);
    }

    /// Borrow the configured retention tick interval (used by the
    /// module `serve` lifecycle entry).
    #[must_use]
    pub fn retention_tick(&self) -> Duration {
        Duration::from_secs(self.cfg.retention.tick_secs)
    }

    /// Borrow the configured `$top` cap for `listChildren` (used by
    /// the REST handler so the operator-tunable cap is honoured at
    /// the API boundary instead of a hardcoded 200).
    #[must_use]
    pub const fn max_list_children_top(&self) -> u32 {
        self.cfg.listing.max_top
    }

    /// Borrow the configured reaper tick interval.
    #[must_use]
    pub fn reaper_tick(&self) -> Duration {
        Duration::from_secs(self.cfg.reaper.tick_secs)
    }

    /// Borrow the configured hard-delete batch size cap.
    #[must_use]
    pub fn hard_delete_batch_size(&self) -> usize {
        self.cfg.retention.hard_delete_batch_size
    }

    /// Borrow the configured provisioning-timeout threshold.
    #[must_use]
    pub fn provisioning_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.reaper.provisioning_timeout_secs)
    }

    /// Borrow the configured periodic integrity-check job
    /// configuration. Cloned (cheaply — `IntegrityCheckConfig` is a
    /// handful of `u64` / `f64` / `bool` fields) by `serve` before
    /// the loop is spawned so the loop owns its config end-to-end.
    #[must_use]
    pub fn integrity_check_config(&self) -> crate::domain::integrity_check::IntegrityCheckConfig {
        self.cfg.integrity_check.clone()
    }

    // -----------------------------------------------------------------
    // PEP gate
    // -----------------------------------------------------------------

    /// PEP gate. Calls the platform-side `PolicyEnforcer`, returns the
    /// compiled [`AccessScope`] the caller is permitted to see for
    /// `(action, resource_id)` on the `Tenant` resource type. The
    /// PDP owns the cross-tenant decision — including subtree-clamp
    /// and platform-admin override — fed by the Tenant Resolver
    /// Plugin's hierarchy projection.
    ///
    /// `OWNER_TENANT_ID` is supplied by the call site per the
    /// `pep::TENANT` contract: `parent_id` for `create` /
    /// `list_children` (the action lives in the parent's scope) and
    /// the target tenant's own `id` for `read` / `update` / `delete`
    /// (a tenant row IS its own scope; the closure's `barrier` bit
    /// sits on `(ancestor, descendant)` pairs, so the PDP must
    /// receive the row's own id to evaluate barrier-clamp on
    /// self-managed descendants). `RESOURCE_ID` is conveyed via the
    /// standard `resource_id` argument and does not need to be set
    /// on the [`AccessRequest`].
    ///
    /// Errors:
    /// - PDP `Denied` → [`DomainError::CrossTenantDenied`] (HTTP 403).
    /// - PDP transport failure → [`DomainError::ServiceUnavailable`] (HTTP
    ///   503). DESIGN §4.3 mandates fail-closed; AM does not provide a
    ///   local authorization fallback.
    /// - Constraint compile failure → [`DomainError::Internal`] (PEP / PDP
    ///   integration bug — unsupported constraint shape).
    ///
    /// `require_constraints(false)` is set today because the AM PEP-
    /// side `in_tenant_subtree` compiler is not yet implemented; once
    /// the Tenant Resolver Plugin lands, this flips to `true` and the
    /// compiled scope is plumbed into SQL filters. **Until then, AM
    /// authorization is single-layer (PDP gate only) — see
    /// `cyberfabric-core#1813` and the crate-level `lib.rs`
    /// production-readiness note.**
    async fn authorize(
        &self,
        ctx: &SecurityContext,
        action: &str,
        owner_tenant_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> Result<AccessScope, DomainError> {
        // TODO(cyberfabric-core#1813): flip `require_constraints` to
        // `true` once `InTenantSubtree` lands in the secure-builder
        // and the AM PEP can compile subtree predicates. Today the
        // PDP gate is the only enforcement layer; SQL-level subtree
        // filtering is a no-op because the `tenants` entity is
        // `no_tenant, no_resource, no_owner, no_type` (see
        // `TenantRepo` trait doc). This is a pre-production gate.
        let request = AccessRequest::new()
            .resource_property(pep_properties::OWNER_TENANT_ID, owner_tenant_id)
            .require_constraints(false);
        let scope = self
            .enforcer
            .access_scope_with(ctx, &pep::TENANT, action, resource_id, &request)
            .await?;
        Ok(scope)
    }

    // -----------------------------------------------------------------
    // Create child tenant (three-step saga)
    // -----------------------------------------------------------------

    /// Implements FEATURE `Create Child Tenant` (flow §2) + `Create-Tenant
    /// Saga` (algo §3). Runs saga steps 1–3 inline.
    ///
    /// # Errors
    ///
    /// - [`DomainError::CrossTenantDenied`] when the PDP denies the
    ///   caller access to the parent tenant.
    /// - [`DomainError::Validation`] when the parent is missing or not
    ///   `Active` (create under a suspended / deleted / provisioning
    ///   parent is rejected).
    /// - [`DomainError::ServiceUnavailable`] when the provider reports a
    ///   clean compensable failure; the `provisioning` row is removed.
    /// - [`DomainError::UnsupportedOperation`] when the provider signals
    ///   it cannot perform the requested provisioning.
    /// - [`DomainError::Internal`] when the provider outcome is ambiguous;
    ///   the `provisioning` row is left for the reaper to compensate.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-service
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-create-tenant-saga:p1:inst-algo-saga-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-create-child-tenant-saga:p1:inst-dod-create-child-saga
    #[allow(
        clippy::cognitive_complexity,
        reason = "linear saga: authorize -> ancestor check -> validations -> insert -> IdP -> activate; \
                  splitting fragments the saga and obscures compensation branches"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "saga has six steps inline (PEP -> parent fetch -> tenant_type checker -> insert -> IdP dispatch with three compensation branches -> activate -> event); \
                  the hot variant is the linear happy path, hoisting compensation branches out splits the IdP-failure classification ladder into a method body that loses access to the saga's local state and forces re-clones"
    )]
    pub async fn create_child(
        &self,
        ctx: &SecurityContext,
        input: CreateChildInput,
    ) -> Result<TenantInfo, DomainError> {
        // PEP gate (DESIGN §4.2). For `Tenant.create` the resource
        // owner is the parent tenant; the child id is not yet a
        // committed resource so `resource_id` is `None`.
        let _scope = self
            .authorize(ctx, pep::actions::CREATE, input.parent_id, None)
            .await?;

        // Validate the caller-supplied tenant name before any DB
        // writes / IdP calls. Mirrors `update_tenant`; otherwise an
        // out-of-contract name persists and reaches the IdP.
        validate_tenant_name(&input.name)?;

        // Derive the canonical UUIDv5 from the chained GTS string.
        // `gts::GtsID::new` enforces the chain shape; `to_uuid()` is
        // the same algorithm Types Registry uses internally
        // (`types-registry-sdk/src/models.rs:152`), so the derived
        // uuid is the lookup key the registry stores under. This
        // replaces the older `tenant_type_uuid` field on
        // `CreateChildInput`, removing the AM/IdP state-divergence
        // class where the two could drift.
        let tenant_type_uuid = gts::GtsID::new(input.tenant_type.as_ref())
            .map_err(|e| DomainError::InvalidTenantType {
                detail: format!("invalid tenant_type chain `{}`: {e}", input.tenant_type),
            })?
            .to_uuid();

        // Saga pre-step: validate parent exists + is Active.
        // allow_all: structural read per DESIGN §4.2 — the PEP has
        // already gated the operation; the parent-status check is a
        // saga precondition, not a data-disclosure read.
        let parent = self
            .repo
            .find_by_id(&AccessScope::allow_all(), input.parent_id)
            .await?
            .ok_or_else(|| DomainError::Validation {
                detail: format!("parent tenant {} not found", input.parent_id),
            })?;
        if !matches!(parent.status, TenantStatus::Active) {
            return Err(DomainError::Validation {
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
            .check_parent_child(parent.tenant_type_uuid, tenant_type_uuid)
            .await?;

        // `checked_add` rather than `saturating_add` so an overflow
        // surfaces as a loud `Internal` rather than silently saturating
        // and tripping the threshold check below with a misleading
        // `observed_depth = u32::MAX`. `AccountManagementConfig::validate`
        // bounds `depth_threshold ≤ MAX_DEPTH_THRESHOLD` (1_000_000),
        // and the schema-level depth column is `INT4` whose values
        // never approach `u32::MAX` in practice, so this is purely
        // defensive.
        let observed_depth = parent.depth.checked_add(1).ok_or_else(|| {
            DomainError::internal(format!(
                "parent.depth + 1 overflowed u32 (parent_id={}, parent.depth={})",
                parent.id, parent.depth,
            ))
        })?;
        let threshold = self.cfg.hierarchy.depth_threshold;
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
            if self.cfg.hierarchy.depth_strict_mode {
                emit_metric(
                    AM_HIERARCHY_DEPTH_EXCEEDANCE,
                    MetricKind::Counter,
                    &[
                        ("mode", "strict"),
                        ("outcome", "reject"),
                        ("threshold", threshold_str.as_str()),
                    ],
                );
                return Err(DomainError::TenantDepthExceeded {
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
            tenant_type_uuid,
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
                            // Saga path: pass `None` so the repo
                            // fences the DELETE on `claimed_by IS
                            // NULL`. If a peer reaper claimed the
                            // row mid-IdP-call (timeout-driven
                            // takeover), the compensation MUST
                            // refuse rather than erase the
                            // reaper's in-flight work.
                            .compensate_provisioning(
                                &AccessScope::allow_all(),
                                provisioning_row.id,
                                None,
                            )
                            .await
                        {
                            warn!(
                                target: "am.tenant.saga",
                                tenant_id = %provisioning_row.id,
                                error = %e,
                                "compensate_provisioning failed after IdP CleanFailure; \
                                 provisioning row left for reaper"
                            );
                            // Mirrors the reaper-side
                            // `compensate_failed` counter so the
                            // dashboard can show saga-vs-reaper
                            // compensation ratios. Distinct `job`
                            // label so saga-side compensation
                            // health is separable from the reaper
                            // safety-net.
                            emit_metric(
                                AM_TENANT_RETENTION,
                                MetricKind::Counter,
                                &[
                                    ("job", "saga_compensation"),
                                    ("outcome", "compensate_failed"),
                                ],
                            );
                        }
                        return Err(ProvisionFailure::CleanFailure { detail }
                            .into_domain_error(provisioning_row.id));
                    }
                    ProvisionFailure::Ambiguous { detail } => {
                        // Leave the provisioning row in place for the reaper.
                        // The `From<ProvisionFailure> for DomainError` impl
                        // redacts the raw provider detail so vendor text
                        // never reaches the public envelope.
                        return Err(ProvisionFailure::Ambiguous { detail }
                            .into_domain_error(provisioning_row.id));
                    }
                    ProvisionFailure::UnsupportedOperation { detail } => {
                        // Treat as clean compensable — no IdP-side state exists.
                        // Same compensation-failure policy as CleanFailure above.
                        if let Err(e) = self
                            .repo
                            // Saga path: pass `None` so the repo
                            // fences the DELETE on `claimed_by IS
                            // NULL`. If a peer reaper claimed the
                            // row mid-IdP-call (timeout-driven
                            // takeover), the compensation MUST
                            // refuse rather than erase the
                            // reaper's in-flight work.
                            .compensate_provisioning(
                                &AccessScope::allow_all(),
                                provisioning_row.id,
                                None,
                            )
                            .await
                        {
                            warn!(
                                target: "am.tenant.saga",
                                tenant_id = %provisioning_row.id,
                                error = %e,
                                "compensate_provisioning failed after IdP UnsupportedOperation; \
                                 provisioning row left for reaper"
                            );
                            emit_metric(
                                AM_TENANT_RETENTION,
                                MetricKind::Counter,
                                &[
                                    ("job", "saga_compensation"),
                                    ("outcome", "compensate_failed"),
                                ],
                            );
                        }
                        return Err(ProvisionFailure::UnsupportedOperation { detail }
                            .into_domain_error(provisioning_row.id));
                    }
                    other => {
                        // SDK is `#[non_exhaustive]`; future variants
                        // arrive without an AM-side recompile. We do
                        // not know whether the new variant proves
                        // "no IdP-side state retained" (compensable)
                        // or leaves residue (ambiguous), so we take
                        // the conservative path: leave the
                        // provisioning row for the reaper to
                        // compensate, and surface as the From-impl
                        // wildcard chooses (Internal). Logged loudly
                        // so the missing arm surfaces in operator
                        // logs the moment the new variant ships.
                        tracing::error!(
                            target: "am.tenant.saga",
                            tenant_id = %provisioning_row.id,
                            variant = other.as_metric_label(),
                            "unknown ProvisionFailure variant; treating as Ambiguous (provisioning row left for reaper)"
                        );
                        return Err(other.into_domain_error(provisioning_row.id));
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
        //
        // Best-effort IdP+row compensation on step-3 failure: once
        // `provision_tenant` succeeded the IdP holds vendor-side
        // state. If the closure load or `activate_tenant` step then
        // fails, we run a best-effort `deprovision_tenant` + row
        // compensation here so the failure does not leave orphaned
        // IdP state until the next reaper tick. Failures of the
        // compensation itself are logged and the original error is
        // propagated unchanged — the reaper still owns the
        // last-resort cleanup if any compensation step fails.
        // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-metadata
        let activated = match self
            .finalize_provisioning(
                &parent,
                provisioning_row.id,
                input.self_managed,
                &provision_result.metadata_entries,
            )
            .await
        {
            Ok(row) => row,
            Err(err) => {
                self.compensate_failed_activation(provisioning_row.id).await;
                return Err(err);
            }
        };
        // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provision:p1:inst-dod-idp-provision-metadata

        // TODO(events): emit AM event when platform event-bus lands.
        // Placeholder log marks the emission point so the future
        // event-bus wiring can replace this site without losing the
        // payload shape.
        tracing::info!(
            target: "am.events",
            kind = "tenantStateChanged",
            actor = "tenant_scoped",
            subject_id = %ctx.subject_id(),
            subject_tenant_id = %ctx.subject_tenant_id(),
            tenant_id = %activated.id,
            event = "created",
            parent_id = ?activated.parent_id,
            tenant_type = %input.tenant_type,
            self_managed = input.self_managed,
            depth = activated.depth,
            "am tenant state changed"
        );

        // Saga step 3 returns an `Active` row, so lowering through the
        // `is_sdk_visible` invariant is safe. We forward the
        // caller-supplied `tenant_type` string verbatim — saga step 3
        // already proved the registry chain is valid (and resolved its
        // schema) so we don't need a registry RTT here.
        let mut info = self.lower_to_tenant_info(activated).await?;
        if info.tenant_type.is_none() {
            // `TenantInfo.tenant_type` is `Option<String>` per the
            // tenant-resolver-sdk public shape; lower the typed
            // `GtsSchemaId` back to its wire form.
            info.tenant_type = Some(input.tenant_type.into_string());
        }
        Ok(info)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-create-child-tenant-saga:p1:inst-dod-create-child-saga
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-create-tenant-saga:p1:inst-algo-saga-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-service

    /// Saga step 3 inner pipeline: load ancestor chain → build
    /// closure rows → flip the tenant to `Active`. Extracted so the
    /// caller (`create_child`) can wrap it in a single error-handling
    /// `match` and drive [`Self::compensate_failed_activation`] on
    /// any failure.
    async fn finalize_provisioning(
        &self,
        parent: &TenantModel,
        provisioning_id: Uuid,
        self_managed: bool,
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, DomainError> {
        let ancestors = self
            .repo
            .load_ancestor_chain_through_parent(&AccessScope::allow_all(), parent.id)
            .await?;
        let closure_rows = build_activation_rows(
            provisioning_id,
            TenantStatus::Active,
            self_managed,
            ancestors.as_slice(),
        );
        self.repo
            .activate_tenant(
                &AccessScope::allow_all(),
                provisioning_id,
                &closure_rows,
                metadata_entries,
            )
            .await
    }

    /// Best-effort cleanup after `finalize_provisioning` fails post-
    /// `idp.provision_tenant` success. Runs:
    ///   1. `idp.deprovision_tenant` to release vendor-side state
    ///      (skipped on `Retryable` / `Terminal` outcomes — those
    ///      need vendor-side retry, not a row delete);
    ///   2. `compensate_provisioning(claimed_by = None)` to remove
    ///      the local `Provisioning` row, fenced on no peer reaper
    ///      having claimed it (fence rejection means the reaper
    ///      already owns the row and will compensate via its own
    ///      pipeline).
    ///
    /// Every failure here is logged at `am.tenant.saga` and
    /// suppressed — the caller propagates the **original** error
    /// from saga step 3. The reaper remains the last-resort cleanup.
    #[allow(
        clippy::cognitive_complexity,
        reason = "best-effort multi-step compensation: each branch logs a distinct outcome and degrades silently to the reaper; collapsing the IdP/row legs hides which step ran"
    )]
    async fn compensate_failed_activation(&self, provisioning_id: Uuid) {
        // Step 1 — vendor-side cleanup. We only run the row delete
        // when the IdP confirms there is nothing left to orphan
        // (`Ok` / `NotFound` / `UnsupportedOperation` under
        // `idp.required=false`). Retryable / Terminal failures —
        // and `UnsupportedOperation` from a real plugin under
        // `idp.required=true` — require vendor-side resolution;
        // leave the row for the reaper, which already classifies
        // these outcomes correctly.
        let idp_clean = match self
            .idp
            .deprovision_tenant(&DeprovisionRequest {
                tenant_id: provisioning_id,
            })
            .await
        {
            Ok(()) | Err(DeprovisionFailure::NotFound { .. }) => true,
            Err(DeprovisionFailure::UnsupportedOperation { .. }) => {
                // Symmetric with the retention pipeline (see
                // `process_single_hard_delete`'s `UnsupportedOperation`
                // arm) and the reaper (`classify_deprovision`):
                // `UnsupportedOperation` is only safe to treat as
                // "no IdP-side state retained" when the deployment
                // explicitly opted out of an IdP via
                // `cfg.idp.required = false` (the wired-in
                // `NoopProvisioner` path). A real plugin returning
                // this variant under `idp.required = true` signals
                // that vendor-side state may exist but the plugin
                // can't deprovision it — hard-deleting the AM row
                // would orphan that state with no local repair
                // handle. Defer to the reaper instead.
                if self.cfg.idp.required {
                    warn!(
                        target: "am.tenant.saga",
                        tenant_id = %provisioning_id,
                        outcome = "unsupported_required",
                        "saga step-3 compensation: IdP plugin returned UnsupportedOperation \
                         but idp.required=true; refusing to orphan vendor-side state, \
                         leaving provisioning row for the reaper"
                    );
                    emit_metric(
                        AM_TENANT_RETENTION,
                        MetricKind::Counter,
                        &[
                            ("job", "saga_compensation"),
                            ("outcome", "unsupported_required"),
                        ],
                    );
                    false
                } else {
                    true
                }
            }
            Err(failure) => {
                let label = failure.as_metric_label();
                warn!(
                    target: "am.tenant.saga",
                    tenant_id = %provisioning_id,
                    outcome = label,
                    "saga step-3 compensation: IdP deprovision did not confirm cleanup; \
                     leaving provisioning row for the reaper"
                );
                // Saga-side step-3 cleanup that did not confirm
                // vendor-side teardown. Distinct `outcome` label so
                // operators can tell this apart from a storage
                // fault on the row delete below; both are still
                // "saga failed → reaper covers", but the remediation
                // is different (IdP plugin health vs DB health).
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[("job", "saga_compensation"), ("outcome", "idp_unconfirmed")],
                );
                false
            }
        };
        if !idp_clean {
            return;
        }

        // Step 2 — local row delete, fenced on no peer reaper claim
        // and no terminal stamp. A `Conflict` here is the documented
        // "reaper got there first" path — log and let the reaper's
        // own `compensate_provisioning_row` finish the cleanup.
        if let Err(err) = self
            .repo
            .compensate_provisioning(&AccessScope::allow_all(), provisioning_id, None)
            .await
        {
            warn!(
                target: "am.tenant.saga",
                tenant_id = %provisioning_id,
                error = %err,
                "saga step-3 compensation: row delete failed (peer reaper may have \
                 claimed the row mid-activation); leaving for the reaper"
            );
            emit_metric(
                AM_TENANT_RETENTION,
                MetricKind::Counter,
                &[
                    ("job", "saga_compensation"),
                    ("outcome", "compensate_failed"),
                ],
            );
        }
    }

    // -----------------------------------------------------------------
    // Read tenant details
    // -----------------------------------------------------------------

    /// Implements FEATURE `Read Tenant Details`. Returns `NotFound` when
    /// the row is absent OR the row is SDK-invisible (`Provisioning`).
    ///
    /// # Errors
    ///
    /// - [`DomainError::CrossTenantDenied`] when the PDP denies the
    ///   caller access to the target tenant.
    /// - [`DomainError::NotFound`] when the tenant does not exist or is in
    ///   the internal `Provisioning` state.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-read-tenant:p1:inst-flow-read-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-tenant-read-scope:p1:inst-dod-read-scope-service
    pub async fn read_tenant(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<TenantInfo, DomainError> {
        // PEP gate (DESIGN §4.2). The compiled scope is intentionally
        // discarded for the repo read: the `tenants` entity is
        // declared `no_tenant, no_resource, no_owner, no_type` (see
        // `entity/tenants.rs` doc + `TenantRepo` trait doc), so a
        // PDP-narrowed permit would compile to `WHERE false` at the
        // secure-extension layer and turn an authorized read into
        // `NotFound`. Subtree clamp at the database lands once the
        // `InTenantSubtree` predicate ships; tracked in
        // cyberfabric-core#1813. Until then this matches
        // `list_children`'s posture: the PDP gate is the single
        // enforcement layer; the repo read uses `allow_all` to fetch
        // the row, and the gate above already authorized the caller.
        // TODO(cyberfabric-core#1813): once `InTenantSubtree` is wired,
        // forward the compiled scope so a PDP-narrowed permit (e.g.
        // `tenant_id IN subtree(...)`) clamps the row at the database.
        let _scope = self
            .authorize(ctx, pep::actions::READ, id, Some(id))
            .await?;
        let tenant = self
            .repo
            .find_by_id(&AccessScope::allow_all(), id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {id} not found"),
                resource: id.to_string(),
            })?;
        if !tenant.status.is_sdk_visible() {
            return Err(DomainError::NotFound {
                detail: format!("tenant {id} not found"),
                resource: id.to_string(),
            });
        }
        self.lower_to_tenant_info(tenant).await
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
    /// - [`DomainError::CrossTenantDenied`] when the PDP denies the
    ///   caller access to the parent tenant.
    /// - [`DomainError::NotFound`] when the parent does not exist or is
    ///   SDK-invisible (`Provisioning`). Repository-level errors are
    ///   propagated unchanged.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-list-children:p1:inst-flow-listch-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-children-query-paginated:p1:inst-dod-children-query-service
    pub async fn list_children(
        &self,
        ctx: &SecurityContext,
        query: ListChildrenQuery,
    ) -> Result<TenantPage<TenantInfo>, DomainError> {
        // PEP gate (DESIGN §4.2). For `Tenant.list_children` the
        // resource owner is the parent tenant whose subtree is being
        // enumerated; `resource_id` is `None` because the call returns
        // a collection. Authorization is enforced by this service-level
        // PDP gate: if the caller is not permitted, `authorize` returns
        // `CrossTenantDenied` before the repo is consulted. The
        // compiled `AccessScope` is then forwarded to the repo, but
        // the `tenants` entity is currently `no_*` (see `TenantRepo`
        // trait doc) so any narrowed scope would zero-row the read —
        // callers therefore pass and rely on `allow_all` semantics for
        // the actual SQL filter (`parent_id = …`). Subtree clamp at
        // the database lands once the `InTenantSubtree` predicate
        // ships; tracked in cyberfabric-core#1813.
        // TODO(cyberfabric-core#1813): once `InTenantSubtree` is wired,
        // a PDP-narrowed permit will compile into a JOIN on
        // `tenant_closure` and clamp the row set at the database.
        // Authorization runs but the compiled scope is intentionally
        // discarded until `InTenantSubtree` lands (see comment block
        // above). The repo call below uses `allow_all()` to match the
        // documented contract; forwarding a constrained scope here
        // would zero-row the result given the `tenants` entity's
        // current `no_*` declaration.
        self.authorize(ctx, pep::actions::LIST_CHILDREN, query.parent_id, None)
            .await?;
        // allow_all: structural existence/status precondition per
        // DESIGN §4.2 line 1370. The PEP gate above already authorized
        // the caller; this read only resolves "does the parent exist
        // and is it SDK-visible?" — disclosure of the children list
        // flows through the children query further down.
        let parent = self
            .repo
            .find_by_id(&AccessScope::allow_all(), query.parent_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {} not found", query.parent_id),
                resource: query.parent_id.to_string(),
            })?;
        if !parent.status.is_sdk_visible() {
            return Err(DomainError::NotFound {
                detail: format!("tenant {} not found", query.parent_id),
                resource: query.parent_id.to_string(),
            });
        }
        let mut page = self
            .repo
            .list_children(&AccessScope::allow_all(), &query)
            .await?;
        // Defense-in-depth: drop any `Provisioning` row that slips
        // through the repo filter before we lower the page to the
        // public shape (where `Provisioning` is unrepresentable).
        page.items.retain(|r| r.status.is_sdk_visible());
        self.lower_to_tenant_page(page).await
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
    /// - [`DomainError::CrossTenantDenied`] when the PDP denies the
    ///   caller access to the target tenant.
    /// - [`DomainError::Validation`] when the patch is empty, the new name
    ///   violates the length bounds, or the status transition is not
    ///   allowed via PATCH (cf. [`TenantUpdate::validate_status_transition`]).
    /// - [`DomainError::NotFound`] when the target tenant does not exist or
    ///   is SDK-invisible.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-update-tenant:p1:inst-flow-update-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-update-mutable-only:p1:inst-dod-update-mutable-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-change-service
    pub async fn update_tenant(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        patch: TenantUpdate,
    ) -> Result<TenantInfo, DomainError> {
        if patch.is_empty() {
            return Err(DomainError::Validation {
                detail: "update patch is empty; at least one field required".into(),
            });
        }
        if let Some(ref new_name) = patch.name {
            validate_tenant_name(new_name)?;
        }
        // PEP gate (DESIGN §4.2). The compiled scope is intentionally
        // discarded for both the pre-update read and the mutating
        // write: the `tenants` entity is `no_tenant, no_resource,
        // no_owner, no_type`, so a PDP-narrowed permit would compile
        // to `WHERE false` and turn an authorized update into a
        // silent `NotFound`. The PDP gate is the single enforcement
        // layer until `InTenantSubtree` lands
        // (cyberfabric-core#1813); the repo calls below use
        // `allow_all` to match `list_children` / `read_tenant`.
        // TODO(cyberfabric-core#1813): once `InTenantSubtree` is
        // wired, forward the compiled scope so a PDP-narrowed permit
        // clamps the read AND the write at the database.
        let _scope = self
            .authorize(ctx, pep::actions::UPDATE, id, Some(id))
            .await?;
        let current = self
            .repo
            .find_by_id(&AccessScope::allow_all(), id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {id} not found"),
                resource: id.to_string(),
            })?;
        if !current.status.is_sdk_visible() {
            return Err(DomainError::NotFound {
                detail: format!("tenant {id} not found"),
                resource: id.to_string(),
            });
        }
        // Lift the SDK 3-variant patch status into the AM-internal
        // 4-variant taxonomy for the transition guard. SDK status
        // cannot represent `Provisioning`, so the transition guard
        // sees only legal source/target combinations.
        let new_status_internal: Option<TenantStatus> = patch.status.map(Into::into);
        if let Some(new_status) = new_status_internal {
            validate_status_transition(current.status, new_status)?;
        }
        let updated = self
            .repo
            .update_tenant_mutable(&AccessScope::allow_all(), id, &patch)
            .await?;

        // Suppress the lifecycle event log on an idempotent no-op
        // (option A — true HTTP PATCH idempotency). The repo skips the
        // DB write
        // when neither `name` nor `status` actually changes, so
        // `updated.updated_at` stays equal to `current.updated_at`. If
        // a sibling field changes in a future patch shape, this gate
        // will need revisiting — keep the cheap `updated_at`-equality
        // signal for now.
        let was_no_op = updated.updated_at == current.updated_at;
        if !was_no_op {
            // TODO(events): emit AM event when platform event-bus lands.
            tracing::info!(
                target: "am.events",
                kind = "tenantStateChanged",
                actor = "tenant_scoped",
                subject_id = %ctx.subject_id(),
                subject_tenant_id = %ctx.subject_tenant_id(),
                tenant_id = %updated.id,
                event = "updated",
                name_from = %current.name,
                name_to = ?patch.name.as_deref(),
                status_from = current.status.as_str(),
                status_to = ?new_status_internal.map(TenantStatus::as_str),
                "am tenant state changed"
            );
        }

        self.lower_to_tenant_info(updated).await
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
    /// - [`DomainError::CrossTenantDenied`] when the PDP denies the
    ///   caller access to the target tenant.
    /// - [`DomainError::RootTenantCannotDelete`] when `tenant_id` is the root tenant.
    /// - [`DomainError::NotFound`] when the tenant does not exist or is already SDK-invisible.
    /// - [`DomainError::TenantHasChildren`] when any child tenant still exists.
    /// - [`DomainError::TenantHasResources`] when the RG ownership probe finds any rows.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-sdel-service
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-dod-soft-delete-preconditions
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-soft-delete
    pub async fn soft_delete(
        &self,
        ctx: &SecurityContext,
        tenant_id: Uuid,
    ) -> Result<TenantInfo, DomainError> {
        // PEP gate (DESIGN §4.2). The compiled scope is intentionally
        // discarded for the disclosure read AND the mutating
        // `schedule_deletion` write: the `tenants` entity is `no_*`,
        // so a PDP-narrowed permit would compile to `WHERE false` and
        // turn an authorized soft-delete into a silent `NotFound` /
        // failed-write. The PDP gate is the single enforcement layer
        // until `InTenantSubtree` lands (cyberfabric-core#1813);
        // matches `list_children` / `read_tenant` / `update_tenant`.
        // Structural precondition checks (`count_children`,
        // `count_ownership_links`) also use `allow_all` — those are
        // saga-internal guard counts, not data disclosure of the
        // tenant being acted on.
        // TODO(cyberfabric-core#1813): once `InTenantSubtree` is
        // wired, forward the compiled scope so a PDP-narrowed permit
        // clamps both the read and the soft-delete write.
        let _scope = self
            .authorize(ctx, pep::actions::DELETE, tenant_id, Some(tenant_id))
            .await?;
        let tenant = self
            .repo
            .find_by_id(&AccessScope::allow_all(), tenant_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
            })?;
        if tenant.parent_id.is_none() {
            return Err(DomainError::RootTenantCannotDelete);
        }
        if !tenant.status.is_sdk_visible() {
            return Err(DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
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
            .count_children(
                &AccessScope::allow_all(),
                tenant_id,
                ChildCountFilter::NonDeleted,
            )
            .await?;
        if child_count > 0 {
            return Err(DomainError::TenantHasChildren);
        }
        // 2. Resource-ownership rejection. Caller's `ctx` is propagated
        // so RG-side AuthZ + SecureORM resolve the parent's
        // `AccessScope`; the checker narrows further to `tenant_id` via
        // an OData filter so the answer reflects this child specifically
        // rather than the whole reachable subtree.
        let rg_links = self
            .resource_checker
            .count_ownership_links(ctx, tenant_id)
            .await?;
        if rg_links > 0 {
            return Err(DomainError::TenantHasResources);
        }
        // 3. Flip row + retention columns in one TX.
        let now = OffsetDateTime::now_utc();
        let retention: Option<Duration> = if self.cfg.retention.default_window_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.cfg.retention.default_window_secs))
        };
        let updated = self
            .repo
            .schedule_deletion(&AccessScope::allow_all(), tenant_id, now, retention)
            .await?;
        // TODO(events): emit AM event when platform event-bus lands.
        tracing::info!(
            target: "am.events",
            kind = "tenantStateChanged",
            actor = "tenant_scoped",
            subject_id = %ctx.subject_id(),
            subject_tenant_id = %ctx.subject_tenant_id(),
            tenant_id = %tenant_id,
            event = "soft_delete_requested",
            retention_secs = self.cfg.retention.default_window_secs,
            "am tenant state changed"
        );
        self.lower_to_tenant_info(updated).await
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-soft-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-dod-soft-delete-preconditions
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-sdel-service

    /// Repair derivable hierarchy-integrity violations for `scope`
    /// and emit per-category telemetry.
    ///
    /// Forwards to
    /// [`crate::domain::tenant::repo::TenantRepo::repair_derivable_closure_violations`]
    /// with `AccessScope::allow_all()` (closure rows are
    /// `no_tenant/no_resource`, see the `check_hierarchy_integrity`
    /// rationale a few methods below — same gate). Emits one
    /// [`crate::domain::metrics::AM_HIERARCHY_INTEGRITY_REPAIRED`]
    /// gauge per category in fixed order with `bucket = repaired |
    /// deferred` so dashboards always see a stable shape.
    /// `warn`-logs the deferred bucket if any non-derivable
    /// category carries a non-zero count — those are the
    /// operator-triage signals.
    ///
    /// # Errors
    ///
    /// * [`DomainError::UnsupportedOperation`] — the staged-rollout
    ///   master switch `integrity_check.repair.enabled` is `false`
    ///   (default). The detail string contains the substring
    ///   `"disabled"` so callers can disambiguate this from an
    ///   IdP-plugin-side `UnsupportedOperation` if they need to.
    /// * [`DomainError::IntegrityCheckInProgress`] — a concurrent
    ///   check or repair holds the per-scope single-flight gate.
    /// * Any other [`DomainError`] produced by the repository.
    ///
    /// # Visibility
    ///
    /// Crate-private (`pub(crate)`) on purpose: the only production
    /// caller is the periodic-job [`IntegrityChecker`] impl in
    /// `crate::domain::integrity_check::service`, which runs under
    /// the in-process scheduler with no caller `SecurityContext` and
    /// hardcodes [`AccessScope::allow_all`]. Exposing this method as
    /// `pub` would let the first admin REST handler or sibling
    /// module that reuses it bypass authorization by construction.
    /// REST exposure lands together with the `InTenantSubtree`
    /// predicate (cyberfabric-core#1813) and will go through a
    /// privileged-context wrapper at that point.
    pub(crate) async fn repair_hierarchy_integrity(
        &self,
        scope: IntegrityScope,
    ) -> Result<crate::domain::tenant::integrity::RepairReport, DomainError> {
        // `integrity_check.repair.enabled` is the staged-rollout
        // master switch: while it is `false` (default), the repair
        // path MUST NOT mutate `tenant_closure`, even from on-demand
        // admin entry points. The periodic loop already gates on
        // this flag (`auto_after_check && repair.enabled`); the same
        // gate has to live here so the SDK / admin REST surface
        // honours the rollout switch instead of bypassing it.
        if !self.cfg.integrity_check.repair.enabled {
            return Err(DomainError::UnsupportedOperation {
                detail: "integrity_check.repair is disabled by configuration".to_owned(),
            });
        }

        let report = self
            .repo
            .repair_derivable_closure_violations(&AccessScope::allow_all(), scope)
            .await?;

        // Iterate `IntegrityCategory::all()` rather than the report
        // maps so a category that was non-zero on a previous tick
        // and absent on this one still emits a fresh zero. Mirrors
        // `check_hierarchy_integrity`'s emission shape so the
        // dashboard sees a stable per-category gauge across all
        // ticks even if a future refactor produces sparse maps.
        let repaired_lookup: std::collections::HashMap<IntegrityCategory, usize> =
            report.repaired_per_category.iter().copied().collect();
        let deferred_lookup: std::collections::HashMap<IntegrityCategory, usize> =
            report.deferred_per_category.iter().copied().collect();
        for cat in IntegrityCategory::all() {
            if cat.is_derivable() {
                let count = repaired_lookup.get(&cat).copied().unwrap_or(0);
                emit_gauge_value(
                    AM_HIERARCHY_INTEGRITY_REPAIRED,
                    i64::try_from(count).unwrap_or(i64::MAX),
                    &[("category", cat.as_str()), ("bucket", "repaired")],
                );
            } else {
                let count = deferred_lookup.get(&cat).copied().unwrap_or(0);
                emit_gauge_value(
                    AM_HIERARCHY_INTEGRITY_REPAIRED,
                    i64::try_from(count).unwrap_or(i64::MAX),
                    &[("category", cat.as_str()), ("bucket", "deferred")],
                );
            }
        }

        if report.total_deferred() > 0 {
            warn!(
                target: "am.integrity",
                deferred_total = report.total_deferred(),
                repaired_total = report.total_repaired(),
                "hierarchy integrity repair deferred non-derivable violations to operator triage"
            );
        }

        Ok(report)
    }

    /// Hierarchy-integrity check. Drives the Rust-side classifier
    /// pipeline through `TenantRepo::run_integrity_check_for_scope`, buckets
    /// the flat violation pairs into the fixed-category report shape,
    /// and emits one `AM_HIERARCHY_INTEGRITY_VIOLATIONS` gauge sample
    /// per category (including zero-valued ones, so the dashboard can
    /// distinguish "no violations" from "checker never ran").
    ///
    /// `scope` selects whole-tree (`IntegrityScope::Whole`) or
    /// subtree-rooted (`IntegrityScope::Subtree(root)`) audit. The
    /// service forwards `AccessScope::allow_all()` to the repo because
    /// `tenants` and `tenant_closure` are declared
    /// `no_tenant/no_resource/no_owner/no_type`; per-caller subtree
    /// clamping lands with the `InTenantSubtree` predicate
    /// (cyberfabric-core#1813).
    ///
    /// # Errors
    ///
    /// Propagates any [`DomainError`] produced by the repository:
    /// notably [`DomainError::IntegrityCheckInProgress`] when another worker
    /// holds the per-scope single-flight gate.
    ///
    /// # Visibility
    ///
    /// Crate-private (`pub(crate)`) for the same reason as
    /// [`Self::repair_hierarchy_integrity`]: the only production
    /// caller is the periodic-job [`IntegrityChecker`] impl, which
    /// runs under the in-process scheduler with no
    /// `SecurityContext` and hardcodes [`AccessScope::allow_all`].
    /// REST exposure ships together with the `InTenantSubtree`
    /// predicate (cyberfabric-core#1813).
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-diagnostics-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-integrity
    pub(crate) async fn check_hierarchy_integrity(
        &self,
        scope: IntegrityScope,
    ) -> Result<IntegrityReport, DomainError> {
        let pairs = self
            .repo
            .run_integrity_check_for_scope(&AccessScope::allow_all(), scope.clone())
            .await?;

        let mut bucketed: std::collections::HashMap<IntegrityCategory, Vec<Violation>> =
            std::collections::HashMap::new();
        for (cat, viol) in pairs {
            bucketed.entry(cat).or_default().push(viol);
        }

        let violations_by_category: Vec<(IntegrityCategory, Vec<Violation>)> =
            IntegrityCategory::all()
                .iter()
                .map(|cat| (*cat, bucketed.remove(cat).unwrap_or_default()))
                .collect();

        for (cat, viols) in &violations_by_category {
            let count = viols.len();
            emit_gauge_value(
                AM_HIERARCHY_INTEGRITY_VIOLATIONS,
                i64::try_from(count).unwrap_or(i64::MAX),
                &[("category", cat.as_str())],
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
            violations_by_category,
        })
    }
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-diagnostics-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-integrity
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "service_tests.rs"]
mod service_tests;
