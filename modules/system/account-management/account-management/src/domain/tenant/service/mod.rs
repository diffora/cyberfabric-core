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
    CreateChildInput, IdpTenantProvisionerClient, ListChildrenQuery, ProvisionFailure,
    ProvisionRequest, TenantInfo, TenantPage, TenantUpdate,
};
use tenant_resolver_sdk::TenantId;
use types_registry_sdk::TypesRegistryClient;

use crate::config::AccountManagementConfig;
use crate::domain::error::DomainError;
use crate::domain::metrics::{
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, MetricKind, emit_metric,
};
use crate::domain::tenant::closure::build_activation_rows;
use crate::domain::tenant::hooks::TenantHardDeleteHook;
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
    /// before invoking this helper. The
    /// `From<TenantStatus> for tenant_resolver_sdk::TenantStatus` impl
    /// `unreachable!`s on `Provisioning` precisely so a bug surfaces
    /// loudly. Every public CRUD method either short-circuits with
    /// `NotFound` for SDK-invisible rows (`read_tenant`,
    /// `update_tenant`, `soft_delete`) or filters them out
    /// (`list_children`).
    async fn lower_to_tenant_info(&self, model: TenantModel) -> TenantInfo {
        let tenant_type = self.resolve_tenant_type(model.tenant_type_uuid).await;
        TenantInfo {
            id: TenantId(model.id),
            name: model.name,
            status: model.status.into(),
            tenant_type,
            parent_id: model.parent_id.map(TenantId),
            self_managed: model.self_managed,
        }
    }

    /// Batched lowering for `list_children`. Issues one
    /// `get_type_schemas_by_uuid` round-trip for the page so latency
    /// scales with number of pages, not number of rows.
    async fn lower_to_tenant_page(&self, page: TenantPage<TenantModel>) -> TenantPage<TenantInfo> {
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

        let mapped: Vec<TenantInfo> = items
            .into_iter()
            .map(|m| TenantInfo {
                id: TenantId(m.id),
                name: m.name,
                status: m.status.into(),
                tenant_type: type_strings.get(&m.tenant_type_uuid).cloned(),
                parent_id: m.parent_id.map(TenantId),
                self_managed: m.self_managed,
            })
            .collect();

        TenantPage {
            items: mapped,
            top,
            skip,
            total,
        }
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
        let tenant_type_uuid = gts::GtsID::new(&input.tenant_type)
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
                        return Err(ProvisionFailure::CleanFailure { detail }.into());
                    }
                    ProvisionFailure::Ambiguous { detail } => {
                        // Leave the provisioning row in place for the reaper.
                        // The `From<ProvisionFailure> for DomainError` impl
                        // redacts the raw provider detail so vendor text
                        // never reaches the public envelope.
                        return Err(ProvisionFailure::Ambiguous { detail }.into());
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
                        return Err(ProvisionFailure::UnsupportedOperation { detail }.into());
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
                        return Err(other.into());
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
            .load_ancestor_chain_through_parent(&AccessScope::allow_all(), parent.id)
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
        let mut info = self.lower_to_tenant_info(activated).await;
        if info.tenant_type.is_none() {
            info.tenant_type = Some(input.tenant_type);
        }
        Ok(info)
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
        // PEP gate (DESIGN §4.2). The compiled `AccessScope` is
        // plumbed into the SQL filter on the disclosure read so a
        // PDP-narrowed permit (e.g. `id IN (subset)`) clamps rows at
        // the database. For unconstrained permits (`allow_all`) there
        // is no narrowing — the PDP is the single authority on
        // cross-tenant visibility (Tenant Resolver Plugin handles the
        // hierarchy projection separately).
        let scope = self
            .authorize(ctx, pep::actions::READ, id, Some(id))
            .await?;
        let tenant =
            self.repo
                .find_by_id(&scope, id)
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
        Ok(self.lower_to_tenant_info(tenant).await)
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
        let scope = self
            .authorize(ctx, pep::actions::LIST_CHILDREN, query.parent_id, None)
            .await?;
        // allow_all: structural existence/status precondition per
        // DESIGN §4.2 line 1370. The PEP gate above already authorized
        // the caller; this read only resolves "does the parent exist
        // and is it SDK-visible?" — disclosure of the children list
        // flows through the scoped `list_children` call further down.
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
        let mut page = self.repo.list_children(&scope, &query).await?;
        // Defense-in-depth: drop any `Provisioning` row that slips
        // through the repo filter before we lower the page to the
        // public shape (where `Provisioning` is unrepresentable).
        page.items.retain(|r| r.status.is_sdk_visible());
        Ok(self.lower_to_tenant_page(page).await)
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
        // PEP gate (DESIGN §4.2). The compiled scope is plumbed into
        // both the pre-update read and the mutating write so a
        // PDP-narrowed permit clamps rows at the database. The repo's
        // `update_tenant_mutable` opens with a scope-bounded
        // `find_by_id` that maps "no row in scope" to `NotFound`, so
        // a misconfigured scope cannot silently no-op.
        let scope = self
            .authorize(ctx, pep::actions::UPDATE, id, Some(id))
            .await?;
        let current =
            self.repo
                .find_by_id(&scope, id)
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
        let updated = self.repo.update_tenant_mutable(&scope, id, &patch).await?;

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

        Ok(self.lower_to_tenant_info(updated).await)
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
        let tenant = self
            .repo
            .find_by_id(&scope, tenant_id)
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
        let retention: Option<Duration> = if self.cfg.default_retention_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.cfg.default_retention_secs))
        };
        let updated = self
            .repo
            .schedule_deletion(&scope, tenant_id, now, retention)
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
            retention_secs = self.cfg.default_retention_secs,
            "am tenant state changed"
        );
        Ok(self.lower_to_tenant_info(updated).await)
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-soft-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-dod-soft-delete-preconditions
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-sdel-service
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "service_tests.rs"]
mod service_tests;
