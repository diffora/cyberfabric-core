//! `ConversionService` — domain orchestrator for the dual-consent
//! `pending -> {cancelled, rejected, expired, approved}` lifecycle of a
//! [`ConversionRequest`].
//!
//! This phase implements five of the six service methods:
//! `request_conversion`, `cancel`, `reject`, `list_own_for_tenant`,
//! `list_inbound_for_parent`, and `soft_delete_resolved`. The
//! counterparty-side `approve` and the system-side `expire_pending`
//! reaper land in the next phase.
//!
//! The service depends only on the domain-level [`ConversionRepo`] and
//! [`TenantRepo`] traits. It never opens transactions itself — every
//! per-call short-lived TX is owned by the repo method
//! (`insert_pending`, `transition_pending_to_*`, etc.). The service's
//! sole responsibility is to compose guards, project parent-side rows
//! down to the minimal cross-barrier surface, and emit `am.events`
//! tracing for each successful transition.
//!
//! Test seam: a deterministic clock is injected via [`with_now_fn`].
//! Production wiring uses `OffsetDateTime::now_utc` by default; the
//! service-level unit tests pin a fixed instant so `expires_at`,
//! `resolved_at`, and the retention `cutoff` are reproducible.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use account_management_sdk::TenantPage;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::conversion::model::{
    ConversionPagination, ConversionRequest, ConversionSide, ConversionStatus,
    NewConversionRequest, TargetMode,
};
use crate::domain::conversion::repo::{ApplyConversionApprovalInput, ConversionRepo};
use crate::domain::conversion::state_machine::validate_transition;
use crate::domain::error::DomainError;
use crate::domain::tenant::model::TenantStatus;
use crate::domain::tenant::repo::TenantRepo;

/// Shared clock seam. Produced by [`ConversionService::new`] from
/// `OffsetDateTime::now_utc` and overridable in tests via
/// [`ConversionService::with_now_fn`].
type NowFn = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Caller scope for every conversion-request operation that crosses
/// the dual-consent surface (`request_conversion`, `approve`, `cancel`,
/// `reject`). Carries both the side the caller acts on
/// (`Child` / `Parent`) AND the tenant the caller is authorized for
/// — child-side carries the converting tenant id, parent-side carries
/// the parent tenant id. The service uses these to enforce the
/// caller's URL-bound scope at the boundary so a misrouted call cannot
/// act on a request outside the caller's authority.
///
/// REST handlers MUST construct:
///   * `Self::child(tenant_id)` from the `/tenants/{tenant_id}/conversions` URL parameter
///   * `Self::parent(parent_tenant_id)` from the `/tenants/{parent_tenant_id}/child-conversions` URL parameter
///
/// They MUST NOT trust a client-supplied side label or scope id —
/// these IDs come from the URL path, which the platform `AuthN` layer
/// has already verified the caller is authorized for.
///
/// Today no SDK consumer wires this — the conversion-service handle is
/// published for the upcoming REST PR — so the service-layer contract
/// is the only authorization gate. When `feature-tenant-resolver-plugin`
/// plumbs `InTenantSubtree` (cyberfabric-core#1813), the storage scope
/// will narrow reads to the caller's subtree and this struct's
/// `scope_id` will continue to provide the column-level fence on
/// `request.tenant_id` / `request.parent_id`.
#[domain_model]
#[derive(Debug, Clone, Copy)]
pub struct ConversionCaller {
    side: ConversionSide,
    /// Tenant id the caller is authorized for. For `Child`, this is
    /// the converting tenant; for `Parent`, this is the parent tenant
    /// (i.e. `request.parent_id`). Kept as `Uuid` (not `Option`) since
    /// both sides MUST carry a scope post-codex-R5; the constructors
    /// are the only public path and they always populate it.
    scope_id: Uuid,
}

impl ConversionCaller {
    /// Build a child-side caller scoped to `child_tenant_id`. The
    /// service verifies that the request the caller acts on has a
    /// `tenant_id` matching this value; mismatches surface as
    /// [`DomainError::Validation`]. For `request_conversion`, the
    /// service additionally verifies `input.tenant_id` matches.
    #[must_use]
    pub const fn child(child_tenant_id: Uuid) -> Self {
        Self {
            side: ConversionSide::Child,
            scope_id: child_tenant_id,
        }
    }

    /// Build a parent-side caller scoped to `parent_tenant_id`. The
    /// service verifies that the request the caller acts on has a
    /// `parent_id` matching this value; mismatches surface as
    /// [`DomainError::Validation`].
    #[must_use]
    pub const fn parent(parent_tenant_id: Uuid) -> Self {
        Self {
            side: ConversionSide::Parent,
            scope_id: parent_tenant_id,
        }
    }

    /// Lower the caller scope into the discriminator stored on the
    /// conversion-request row.
    #[must_use]
    pub const fn side(self) -> ConversionSide {
        self.side
    }

    /// Read the caller's scope id (child tenant id for `Child`,
    /// parent tenant id for `Parent`). Both variants always carry a
    /// concrete `Uuid` so this is non-`Option`.
    #[must_use]
    pub const fn scope_id(self) -> Uuid {
        self.scope_id
    }
}

/// Service-level input to [`ConversionService::request_conversion`].
///
/// Mirrors the dual-consent contract: the caller declares its scope
/// (`caller`) and may override the target mode the conversion will
/// land on. When `target_mode_override` is `None` the service
/// computes the target as the inverse of the tenant's current
/// `self_managed` flag — `Managed` becomes `SelfManaged` and vice
/// versa, which is the only legal "flip" shape per FEATURE
/// `managed-self-managed-modes` §2.
#[domain_model]
#[derive(Debug, Clone)]
pub struct RequestConversionInput {
    pub tenant_id: Uuid,
    pub caller: ConversionCaller,
    pub target_mode_override: Option<TargetMode>,
    pub requested_by: Uuid,
}

/// Pagination + optional status-filter shape consumed by the service-
/// level `list_*` methods. Mirrors the
/// `account_management_sdk::ListChildrenQuery` ergonomics so call sites
/// stay symmetric with the tenant CRUD surface, but kept AM-internal
/// here because the conversion REST shapes haven't landed yet.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListConversionsQuery {
    pub top: u32,
    pub skip: u32,
    pub status_filter: Option<ConversionStatus>,
}

impl ListConversionsQuery {
    /// Build a query that returns every visible row for the listing,
    /// no status filter.
    #[must_use]
    pub const fn all(top: u32, skip: u32) -> Self {
        Self {
            top,
            skip,
            status_filter: None,
        }
    }

    /// Build a query that narrows to a specific lifecycle status.
    #[must_use]
    pub const fn with_status(top: u32, skip: u32, status: ConversionStatus) -> Self {
        Self {
            top,
            skip,
            status_filter: Some(status),
        }
    }

    /// Lower into the repo-level pagination value.
    #[must_use]
    pub const fn pagination(self) -> ConversionPagination {
        ConversionPagination {
            top: self.top,
            skip: self.skip,
        }
    }
}

// @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-parent-side-minimal-surface:p1:inst-dod-parent-side-projection
/// Minimal cross-barrier projection of a [`ConversionRequest`] surfaced
/// to the parent side of the dual-consent pair.
///
/// Per the `Parent-Side Inbound-Discovery Minimal Surface` `DoD`, the
/// parent listing MUST NOT carry any child-subtree fields, descendant
/// counts, user records, or resource inventories. Every field below is
/// derivable from the conversion row itself or the converting tenant's
/// own row (`name`); no closure / metadata / inventory data leaks
/// across the parent-child barrier.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionRequestParentProjection {
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub child_tenant_name: String,
    pub initiator_side: ConversionSide,
    pub target_mode: TargetMode,
    pub status: ConversionStatus,
    pub requested_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub cancelled_by: Option<Uuid>,
    pub rejected_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
}
// @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-parent-side-minimal-surface:p1:inst-dod-parent-side-projection

/// Central AM domain service for `ConversionRequest` lifecycle.
///
/// Construction mirrors `TenantService::new` — every dependency is
/// passed in as an `Arc<dyn ...>` so production wiring (`module.rs`)
/// and tests (`FakeConversionRepo` / `FakeTenantRepo`) share the same
/// constructor surface. The clock seam (`now_fn`) is overridable via
/// the [`Self::with_now_fn`] builder so service-level unit tests can
/// pin a fixed instant for the `expires_at` / `cutoff` assertions.
#[domain_model]
pub struct ConversionService {
    repo: Arc<dyn ConversionRepo>,
    tenant_repo: Arc<dyn TenantRepo>,
    now_fn: NowFn,
    approval_ttl: StdDuration,
    resolved_retention: StdDuration,
    cleanup_interval: StdDuration,
    expire_batch_size: u32,
    retention_batch_size: u32,
}

/// `ConversionRepo` calls hardcode [`AccessScope::allow_all`] per the
/// entity contract: `conversion_requests` is declared `no_tenant,
/// no_resource, no_owner, no_type`, so a narrowed scope from the
/// caller would compile to `WHERE false` (silently zero-rowing reads
/// and turning mutations into no-ops or `ScopeError::Denied`). The
/// `scope` argument that flows in from REST handlers is reserved for
/// the `TenantRepo` lookups + `verify_caller_scope` PDP boundary —
/// authorization for the conversion-row mutation as a whole is
/// enforced one layer up by the dual-consent role check, not at this
/// storage seam. Mirrors the rationale documented on
/// [`crate::domain::tenant::repo::TenantRepo`].
const _AM_CONVERSION_REPO_SCOPE_CONTRACT: () = ();

impl ConversionService {
    /// Default cleanup tick used when `with_cleanup_lifecycle` is not
    /// invoked (matches ADR-0003 §1: 60s).
    #[allow(
        clippy::duration_suboptimal_units,
        reason = "from_mins is unstable on workspace MSRV; keep from_secs"
    )]
    pub const DEFAULT_CLEANUP_INTERVAL: StdDuration = StdDuration::from_secs(60);
    /// Default per-tick caps used when `with_cleanup_lifecycle` is not
    /// invoked.
    pub const DEFAULT_EXPIRE_BATCH_SIZE: u32 = 256;
    pub const DEFAULT_RETENTION_BATCH_SIZE: u32 = 256;

    /// Construct a fully-wired service with the production clock
    /// (`OffsetDateTime::now_utc`).
    ///
    /// Cleanup-loop knobs (`cleanup_interval`, `expire_batch_size`,
    /// `retention_batch_size`) default to ADR-0003 §1 values; production
    /// wiring overrides them via [`Self::with_cleanup_lifecycle`] from
    /// `cfg.conversion`.
    #[must_use]
    pub fn new(
        repo: Arc<dyn ConversionRepo>,
        tenant_repo: Arc<dyn TenantRepo>,
        approval_ttl: StdDuration,
        resolved_retention: StdDuration,
    ) -> Self {
        Self {
            repo,
            tenant_repo,
            now_fn: Arc::new(OffsetDateTime::now_utc),
            approval_ttl,
            resolved_retention,
            cleanup_interval: Self::DEFAULT_CLEANUP_INTERVAL,
            expire_batch_size: Self::DEFAULT_EXPIRE_BATCH_SIZE,
            retention_batch_size: Self::DEFAULT_RETENTION_BATCH_SIZE,
        }
    }

    /// Override the wall-clock function used to compute `expires_at`
    /// and the retention cutoff. Mirrors `TenantService::with_*`
    /// builder methods used to plug optional collaborators after
    /// construction.
    #[must_use]
    pub fn with_now_fn(mut self, now_fn: NowFn) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Override the cleanup-loop knobs `cleanup_interval`,
    /// `expire_batch_size`, and `retention_batch_size`. Production
    /// wiring (`AccountManagementModule::init`) reads these from the
    /// `[conversion]` config section. Tests that do not invoke this
    /// builder pick up ADR-0003 §1 defaults.
    #[must_use]
    pub const fn with_cleanup_lifecycle(
        mut self,
        cleanup_interval: StdDuration,
        expire_batch_size: u32,
        retention_batch_size: u32,
    ) -> Self {
        self.cleanup_interval = cleanup_interval;
        self.expire_batch_size = expire_batch_size;
        self.retention_batch_size = retention_batch_size;
        self
    }

    /// Read-only access to the configured cleanup tick cadence.
    #[must_use]
    pub const fn cleanup_interval(&self) -> StdDuration {
        self.cleanup_interval
    }

    /// Read-only access to the configured per-tick expire batch cap.
    #[must_use]
    pub const fn expire_batch_size(&self) -> u32 {
        self.expire_batch_size
    }

    /// Read-only access to the configured per-tick retention sweep cap.
    #[must_use]
    pub const fn retention_batch_size(&self) -> u32 {
        self.retention_batch_size
    }

    /// Read-only access to the configured `approval_ttl`. Useful for
    /// callers that want to surface the TTL through the response
    /// envelope without re-reading config.
    #[must_use]
    pub const fn approval_ttl(&self) -> StdDuration {
        self.approval_ttl
    }

    /// Read-only access to the configured `resolved_retention`. The
    /// retention reaper consumes this when no override is supplied.
    #[must_use]
    pub const fn resolved_retention(&self) -> StdDuration {
        self.resolved_retention
    }

    /// Helper: snapshot the current wall-clock through the configured
    /// `now_fn`. Centralised so every `expires_at` / `resolved_at` /
    /// `cutoff` derivation reads from the same seam.
    fn now(&self) -> OffsetDateTime {
        (self.now_fn)()
    }

    // ----------------------------------------------------------------
    // request_conversion
    // ----------------------------------------------------------------

    /// Initiate a new conversion. Implements
    /// `cpt-cf-account-management-flow-managed-self-managed-modes-conversion-initiation`.
    ///
    /// Guard ordering (MUST match the FEATURE `DoD` for
    /// `single-pending-enforcement` and `root-tenant-conversion-refusal`):
    ///
    /// 1. Load the tenant via `tenant_repo.find_by_id`.
    /// 2. Reject the platform root (`parent_id IS NULL`) with
    ///    [`DomainError::RootTenantCannotConvert`].
    /// 3. Reject any non-`Active` status with
    ///    [`DomainError::Validation`].
    /// 4. Compose the [`NewConversionRequest`] (including the
    ///    `expires_at = now() + approval_ttl` derivation) and hand
    ///    off to `repo.insert_pending`. The repo-level partial-
    ///    unique-index collision returns
    ///    [`DomainError::PendingExists`] unchanged.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] when `tenant_id` does not resolve
    ///   to a tenant row.
    /// * [`DomainError::RootTenantCannotConvert`] when the resolved
    ///   tenant is the platform root.
    /// * [`DomainError::Validation`] when the resolved tenant is not
    ///   in [`TenantStatus::Active`].
    /// * [`DomainError::PendingExists`] when another `Pending` row
    ///   already exists for the tenant.
    // @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-initiation:p1:inst-flow-conversion-initiation-service
    pub async fn request_conversion(
        &self,
        scope: &AccessScope,
        input: RequestConversionInput,
    ) -> Result<ConversionRequest, DomainError> {
        let tenant = self
            .tenant_repo
            .find_by_id(scope, input.tenant_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {} not found", input.tenant_id),
                resource: input.tenant_id.to_string(),
            })?;

        // @cpt-begin:cpt-cf-account-management-algo-managed-self-managed-modes-root-tenant-conversion-refusal:p1:inst-algo-root-tenant-refusal
        // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-root-tenant-non-convertibility:p1:inst-dod-root-tenant-non-convertibility
        // Root-tenant refusal MUST be the FIRST post-authorization
        // guard. The platform root has `parent_id == None` and cannot
        // legally take a counterparty (no parent on the other side of
        // the dual-consent pair), so the conversion is rejected here
        // before any DB write.
        if tenant.parent_id.is_none() {
            return Err(DomainError::RootTenantCannotConvert);
        }
        // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-root-tenant-non-convertibility:p1:inst-dod-root-tenant-non-convertibility
        // @cpt-end:cpt-cf-account-management-algo-managed-self-managed-modes-root-tenant-conversion-refusal:p1:inst-algo-root-tenant-refusal

        // Parent-side scope verification: a parent-side caller MUST be
        // acting on a tenant whose `parent_id` matches the caller's
        // declared scope. Mirrors the FEATURE doc's parent-side
        // initiation flow (`/tenants/{parent_id}/child-conversions`):
        // ConversionService validates the child is a direct child of
        // the caller's parent scope before any DB write. Today this is
        // the only authorization gate at this seam.
        verify_caller_scope(
            input.caller,
            "request_conversion",
            tenant.id,
            tenant.parent_id,
        )?;

        // Status precondition: only `Active` tenants may convert.
        // `Provisioning` is mid-saga; `Suspended` and `Deleted`
        // freeze the lifecycle. Any non-`Active` status here is a
        // validation failure rather than a not-found because the row
        // exists and the caller can disambiguate from the
        // `attempted_status` token in the detail.
        if !matches!(tenant.status, TenantStatus::Active) {
            return Err(DomainError::Validation {
                detail: format!(
                    "tenant {} is not active (status={})",
                    tenant.id,
                    tenant.status.as_str()
                ),
            });
        }

        // Compute target mode: explicit override wins, otherwise flip
        // the tenant's current `self_managed` flag. The conversion
        // semantics are "switch mode", not "set to managed" — the
        // override slot exists so a future REST surface can express
        // "convert to specifically X" if a sibling feature requires
        // it; today both branches converge on the same flip.
        let current_mode = if tenant.self_managed {
            TargetMode::SelfManaged
        } else {
            TargetMode::Managed
        };
        let target_mode = input.target_mode_override.unwrap_or(match current_mode {
            TargetMode::SelfManaged => TargetMode::Managed,
            TargetMode::Managed => TargetMode::SelfManaged,
        });
        // Reject no-op requests per FEATURE
        // `managed-self-managed-modes` §2: the target MUST be the
        // INVERSE of the tenant's current mode. A caller-supplied
        // override that resolves to the same mode is a misuse — the
        // partial-unique-pending slot would be consumed without any
        // mode change, polluting audit history. Surfaced as
        // `Validation` so the REST envelope maps it consistently with
        // the other initiation guards.
        if target_mode == current_mode {
            return Err(DomainError::Validation {
                detail: format!(
                    "target_mode={} matches current tenant mode (no-op conversion)",
                    target_mode.as_str()
                ),
            });
        }

        let now = self.now();
        let expires_at = now + self.approval_ttl;

        let new = NewConversionRequest {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            parent_id: tenant.parent_id,
            child_tenant_name: tenant.name.clone(),
            initiator_side: input.caller.side(),
            target_mode,
            requested_by: input.requested_by,
            requested_at: now,
            expires_at,
        };

        // @cpt-begin:cpt-cf-account-management-algo-managed-self-managed-modes-single-pending-enforcement:p1:inst-algo-single-pending-enforcement
        // The partial-unique-index collision on
        // `ux_conversion_requests_pending` is mapped by the repo to
        // [`DomainError::PendingExists { request_id }`]. Bubble it up
        // unchanged — the existing pending row's id is the caller's
        // hint to drive a cancel / reject before retrying.
        let inserted = self
            .repo
            .insert_pending(&AccessScope::allow_all(), &new)
            .await?;
        // @cpt-end:cpt-cf-account-management-algo-managed-self-managed-modes-single-pending-enforcement:p1:inst-algo-single-pending-enforcement

        // TODO(events): emit AM event when the platform event-bus
        // lands. Placeholder log marks the emission point with the
        // v1-stand-in cadence proven by `TenantService` for
        // `tenant_*` events.
        tracing::info!(
            target: "am.events",
            event = "conversion_requested",
            request_id = %inserted.id,
            tenant_id = %inserted.tenant_id,
            caller_side = input.caller.side().as_str(),
            actor_uuid = %input.requested_by,
            target_mode = inserted.target_mode.as_str(),
            outcome = "ok",
            "am conversion requested"
        );

        Ok(inserted)
    }
    // @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-initiation:p1:inst-flow-conversion-initiation-service

    // ----------------------------------------------------------------
    // cancel
    // ----------------------------------------------------------------

    /// Cancel a pending conversion. Initiator-side action. Implements
    /// `cpt-cf-account-management-flow-managed-self-managed-modes-conversion-cancellation`.
    ///
    /// Guard ordering (MUST match `Dual-Consent Actor Discipline`
    /// `DoD`): load row -> status precondition (`Pending`) -> actor-
    /// side check (`caller_side == initiator_side`).
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `request_id` does not resolve.
    /// * [`DomainError::AlreadyResolved`] — row is in any terminal
    ///   status (this MUST take precedence over the actor check).
    /// * [`DomainError::InvalidActorForTransition`] — caller side
    ///   does not match the initiator side.
    // @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-cancellation:p1:inst-flow-conversion-cancellation-service
    pub async fn cancel(
        &self,
        scope: &AccessScope,
        request_id: Uuid,
        caller: ConversionCaller,
        cancelled_by: Uuid,
    ) -> Result<ConversionRequest, DomainError> {
        // `scope` is part of the public API for forward compatibility
        // with the `InTenantSubtree` (#1813) authz wiring; the
        // `ConversionRepo` calls below hardcode `AccessScope::allow_all`
        // per the entity contract, so the caller scope is currently
        // unused. Authorization for the cancel-row mutation is
        // enforced one layer up via `verify_caller_scope` + the
        // dual-consent role check.
        let _ = scope;
        // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-cancel
        let row = self
            .repo
            .find_by_id(&AccessScope::allow_all(), request_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("conversion request {request_id} not found"),
                resource: request_id.to_string(),
            })?;

        // Parent-side scope verification BEFORE the state / role
        // matrix runs: a parent-side caller MUST be acting on a
        // request whose `parent_id` matches the caller's declared
        // scope. Surfaces `Validation` so a misrouted parent-side
        // call cannot leak `AlreadyResolved` / `InvalidActor` from a
        // request that isn't theirs to act on.
        verify_caller_scope(caller, "cancel", row.tenant_id, row.parent_id)?;

        // Single guard: state-then-role validation lives in
        // `state_machine::validate_transition` so service-layer and
        // any future callers share one matrix. Returns `AlreadyResolved`
        // if the row is not pending (state precedes role per the
        // Dual-Consent Actor Discipline DoD), or
        // `InvalidActorForTransition` carrying `attempted_status =
        // "cancelled"` when `caller_side != initiator_side`.
        validate_transition(
            row.status,
            ConversionStatus::Cancelled,
            Some(caller.side()),
            row.initiator_side,
        )?;
        // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-cancel

        let now = self.now();
        let updated = self
            .repo
            .transition_pending_to_cancelled(
                &AccessScope::allow_all(),
                request_id,
                cancelled_by,
                now,
            )
            .await?;

        tracing::info!(
            target: "am.events",
            event = "conversion_cancelled",
            request_id = %updated.id,
            tenant_id = %updated.tenant_id,
            caller_side = caller.side().as_str(),
            actor_uuid = %cancelled_by,
            outcome = "ok",
            "am conversion cancelled"
        );

        Ok(updated)
    }
    // @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-cancellation:p1:inst-flow-conversion-cancellation-service

    // ----------------------------------------------------------------
    // reject
    // ----------------------------------------------------------------

    /// Reject a pending conversion. Counterparty-side action.
    /// Implements
    /// `cpt-cf-account-management-flow-managed-self-managed-modes-conversion-rejection`.
    ///
    /// Guard ordering mirrors [`Self::cancel`] — status precondition
    /// precedes actor-side check — only the actor-side rule is the
    /// inverse: `caller_side != initiator_side`.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `request_id` does not resolve.
    /// * [`DomainError::AlreadyResolved`] — row is in any terminal
    ///   status.
    /// * [`DomainError::InvalidActorForTransition`] — caller side
    ///   matches the initiator side (initiator cannot reject their
    ///   own request; they cancel instead).
    // @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-rejection:p1:inst-flow-conversion-rejection-service
    pub async fn reject(
        &self,
        scope: &AccessScope,
        request_id: Uuid,
        caller: ConversionCaller,
        rejected_by: Uuid,
    ) -> Result<ConversionRequest, DomainError> {
        // TODO(authz): enforce `InTenantSubtree` scope once #1813 lands.
        let _ = scope;
        // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-reject
        let row = self
            .repo
            .find_by_id(&AccessScope::allow_all(), request_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("conversion request {request_id} not found"),
                resource: request_id.to_string(),
            })?;

        // Parent-side scope verification BEFORE the state / role
        // matrix runs (see `cancel` for the rationale).
        verify_caller_scope(caller, "reject", row.tenant_id, row.parent_id)?;

        // State-then-role validation: see `cancel` for the full
        // rationale. For reject, the role rule inverts: the caller
        // MUST be the counterparty (`caller_side != initiator_side`).
        validate_transition(
            row.status,
            ConversionStatus::Rejected,
            Some(caller.side()),
            row.initiator_side,
        )?;
        // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-reject

        let now = self.now();
        let updated = self
            .repo
            .transition_pending_to_rejected(&AccessScope::allow_all(), request_id, rejected_by, now)
            .await?;

        tracing::info!(
            target: "am.events",
            event = "conversion_rejected",
            request_id = %updated.id,
            tenant_id = %updated.tenant_id,
            caller_side = caller.side().as_str(),
            actor_uuid = %rejected_by,
            outcome = "ok",
            "am conversion rejected"
        );

        Ok(updated)
    }
    // @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-rejection:p1:inst-flow-conversion-rejection-service

    // ----------------------------------------------------------------
    // listings
    // ----------------------------------------------------------------

    /// List conversion requests owned by `tenant_id` (the converting
    /// tenant itself). Returns the full [`ConversionRequest`] rows —
    /// the converting tenant has no cross-barrier projection rules
    /// because the request lives inside its own scope.
    ///
    /// # Errors
    ///
    /// * Any error surfaced by `repo.list_own_for_tenant`.
    pub async fn list_own_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        page_query: &ListConversionsQuery,
    ) -> Result<TenantPage<ConversionRequest>, DomainError> {
        // TODO(authz): enforce `InTenantSubtree` scope once #1813 lands.
        let _ = scope;
        let items = self
            .repo
            .list_own_for_tenant(
                &AccessScope::allow_all(),
                tenant_id,
                page_query.status_filter,
                page_query.pagination(),
            )
            .await?;
        // `total` MUST reflect the count of all matching rows under the
        // same `(tenant_id, status_filter)` predicate, NOT the current
        // page size. The cheap `count_own_for_tenant` round-trip mirrors
        // the tenant-CRUD listing contract (see
        // `repo_impl::reads::list_children`) so cursor pagination
        // (`top` / `skip`) behaves correctly when `total > top`.
        //
        // TOCTOU note: `list` and `count` are TWO independent queries.
        // On Postgres each runs at READ COMMITTED so a row committed
        // between them can make `total` differ by one from the
        // snapshot the page reflects; on `SQLite` each is its own
        // autocommit. This is the SAME asymmetry that
        // `tenant-CRUD::list_children` accepts (DESIGN §3.6) and is
        // intentional — wrapping both in a SERIALIZABLE TX would cost
        // 40001-retry cycles for a read-only listing.
        let total = self
            .repo
            .count_own_for_tenant(
                &AccessScope::allow_all(),
                tenant_id,
                page_query.status_filter,
            )
            .await?;
        Ok(TenantPage {
            items,
            top: page_query.top,
            skip: page_query.skip,
            total: Some(total),
        })
    }

    /// List conversion requests inbound to `parent_id` (the parent of
    /// each converting child). Projects each row down to the minimal
    /// cross-barrier surface ([`ConversionRequestParentProjection`])
    /// per `Parent-Side Inbound-Discovery Minimal Surface` `DoD`.
    ///
    /// The repo's `list_inbound_for_parent` already restricts to
    /// `parent_id == :parent_id` (i.e. direct children only); the
    /// service layer relies on that predicate and additionally
    /// resolves the live `child_tenant_name` from the converting
    /// tenant's row so a renamed child surfaces with the current
    /// name on the parent's listing.
    ///
    /// # Errors
    ///
    /// * Any error surfaced by `repo.list_inbound_for_parent`.
    /// * `tenant_repo.find_by_id` failures are tolerated per row —
    ///   on lookup miss the projection falls back to the
    ///   `child_tenant_name` snapshot stored on the conversion row
    ///   itself, which is always populated at request time.
    // @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-parent-child-conversions-discovery:p1:inst-flow-parent-side-discovery-service
    pub async fn list_inbound_for_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        page_query: &ListConversionsQuery,
    ) -> Result<TenantPage<ConversionRequestParentProjection>, DomainError> {
        let rows = self
            .repo
            .list_inbound_for_parent(
                &AccessScope::allow_all(),
                parent_id,
                page_query.status_filter,
                page_query.pagination(),
            )
            .await?;
        // See `list_own_for_tenant` for the rationale on splitting
        // `count` from `list` and the TOCTOU contract that both this
        // and the sibling listing share with `tenant-CRUD::list_children`.
        let total = self
            .repo
            .count_inbound_for_parent(
                &AccessScope::allow_all(),
                parent_id,
                page_query.status_filter,
            )
            .await?;

        // Live-name resolution: one batch lookup over the unique
        // tenant ids referenced by the page, instead of one
        // `find_by_id` round-trip per row. Build a positional map and
        // fall back to the snapshot captured at request time when a
        // row is missing (tenant soft-deleted, scope-invisible).
        let unique_ids: Vec<Uuid> = {
            let mut ids: Vec<Uuid> = rows.iter().map(|r| r.tenant_id).collect();
            ids.sort_unstable();
            ids.dedup();
            ids
        };
        let live_names: HashMap<Uuid, String> = if unique_ids.is_empty() {
            HashMap::new()
        } else {
            // Tolerate `find_many` failures — a transient DB error on
            // the names lookup MUST NOT shadow the conversion-row
            // listing the parent is asking about. The snapshot path
            // covers every row in that case. The error is surfaced on
            // `am.domain` (NOT `am.events` — that channel is
            // success-only by convention; routing errors there breaks
            // downstream consumers grouping by `event` count) so a
            // degraded listing (stale names) is not invisible to
            // operators monitoring the structured log.
            match self.tenant_repo.find_many(scope, &unique_ids).await {
                Ok(tenants) => tenants.into_iter().map(|t| (t.id, t.name)).collect(),
                Err(err) => {
                    tracing::warn!(
                        target: "am.domain",
                        error = %err,
                        parent_id = %parent_id,
                        unique_ids = unique_ids.len(),
                        "list_inbound_for_parent: find_many failed; falling back to snapshot names"
                    );
                    HashMap::new()
                }
            }
        };

        let mut items: Vec<ConversionRequestParentProjection> = Vec::with_capacity(rows.len());
        for row in rows {
            let child_tenant_name = live_names
                .get(&row.tenant_id)
                .cloned()
                .unwrap_or_else(|| row.child_tenant_name.clone());
            items.push(project_to_parent_view(&row, child_tenant_name));
        }

        Ok(TenantPage {
            items,
            top: page_query.top,
            skip: page_query.skip,
            total: Some(total),
        })
    }
    // @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-parent-child-conversions-discovery:p1:inst-flow-parent-side-discovery-service

    // ----------------------------------------------------------------
    // retention
    // ----------------------------------------------------------------

    /// Soft-delete resolved (`Approved` / `Cancelled` / `Rejected` /
    /// `Expired`) rows older than `cutoff = now - retention_window`.
    /// Implements the retention half of
    /// `cpt-cf-account-management-dod-managed-self-managed-modes-conversion-expiry`.
    ///
    /// The repo owns the SQL predicate (`status != Pending AND
    /// resolved_at <= cutoff AND deleted_at IS NULL`) and the short-
    /// lived TX; the service simply derives the cutoff from the
    /// configured `now_fn` and forwards the count back to the caller.
    ///
    /// # Errors
    ///
    /// * Any error surfaced by `repo.soft_delete_resolved_older_than`.
    // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-conversion-expiry:p1:inst-dod-conversion-expiry-retention
    pub async fn soft_delete_resolved(
        &self,
        scope: &AccessScope,
        retention_window: StdDuration,
        batch_size: u32,
    ) -> Result<u64, DomainError> {
        // TODO(authz): enforce `InTenantSubtree` scope once #1813 lands.
        let _ = scope;
        let now = self.now();
        let cutoff = now - retention_window;
        self.repo
            .soft_delete_resolved_older_than(&AccessScope::allow_all(), cutoff, now, batch_size)
            .await
    }
    // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-conversion-expiry:p1:inst-dod-conversion-expiry-retention

    // ----------------------------------------------------------------
    // approve
    // ----------------------------------------------------------------

    /// Approve a pending conversion. Counterparty-side action.
    ///
    /// Implements `cpt-cf-account-management-flow-managed-self-managed-modes-conversion-approval`
    /// in conjunction with the repo-owned
    /// [`ConversionRepo::apply_conversion_approval`] seam. The service
    /// runs the cheap pre-checks (load row, status precondition,
    /// tenant Active precondition, actor-side rule) and delegates the
    /// load-bearing single-TX apply (type re-evaluation,
    /// `tenants.self_managed` flip, closure-barrier rewrite, request
    /// transition) to the repo.
    ///
    /// On commit the service emits `conversion_approved` on
    /// `am.events` with `actor = approver_uuid`. Audit emission
    /// failure does NOT roll back the already-committed transaction.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `request_id` does not resolve.
    /// * [`DomainError::AlreadyResolved`] — row is in any terminal
    ///   status (status precondition precedes the actor check).
    /// * [`DomainError::Validation`] — the converting tenant is not
    ///   `Active`.
    /// * [`DomainError::InvalidActorForTransition`] — caller side
    ///   matches the initiator side (initiator cannot approve their
    ///   own request; approve is counterparty-only).
    /// * [`DomainError::TypeNotAllowed`] — type re-evaluation
    ///   rejected the parent / child type pairing under TX.
    /// * Any DB error from the underlying transaction.
    // @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-approval:p1:inst-flow-conversion-approval-service
    // @cpt-begin:cpt-cf-account-management-algo-managed-self-managed-modes-dual-consent-apply:p1:inst-algo-dual-consent-apply-service
    // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-apply:p1:inst-dod-dual-consent-apply-service
    pub async fn approve(
        &self,
        scope: &AccessScope,
        request_id: Uuid,
        caller: ConversionCaller,
        approver_uuid: Uuid,
    ) -> Result<ConversionRequest, DomainError> {
        // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-approve
        let row = self
            .repo
            .find_by_id(&AccessScope::allow_all(), request_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("conversion request {request_id} not found"),
                resource: request_id.to_string(),
            })?;

        // Parent-side scope verification BEFORE state / role / tenant
        // checks. See `cancel` for the rationale on why this fence runs
        // first.
        verify_caller_scope(caller, "approve", row.tenant_id, row.parent_id)?;

        // State-then-role validation: see `cancel` for the full
        // rationale. Approve is counterparty-only — the matrix lives
        // in `state_machine::validate_transition`, called here so the
        // service does not duplicate the role rule.
        validate_transition(
            row.status,
            ConversionStatus::Approved,
            Some(caller.side()),
            row.initiator_side,
        )?;

        // Tenant precondition runs after the state + role validation
        // so a wrong-actor or already-resolved request fails fast
        // without an extra `find_by_id` round-trip on the tenant.
        // The repo re-checks Active inside the apply transaction; this
        // is a cheap fence so the common-case rejection short-circuits
        // before the SERIALIZABLE TX opens.
        let tenant = self
            .tenant_repo
            .find_by_id(scope, row.tenant_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {} not found", row.tenant_id),
                resource: row.tenant_id.to_string(),
            })?;
        if !matches!(tenant.status, TenantStatus::Active) {
            return Err(DomainError::Validation {
                detail: format!(
                    "tenant {} is not active (status={})",
                    tenant.id,
                    tenant.status.as_str()
                ),
            });
        }
        // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-approve

        let approved = self
            .repo
            .apply_conversion_approval(
                &AccessScope::allow_all(),
                ApplyConversionApprovalInput {
                    request_id,
                    target_tenant_id: row.tenant_id,
                    target_mode: row.target_mode,
                    approver_uuid,
                    resolved_at: self.now(),
                },
            )
            .await?;

        // Post-commit audit. Failure here MUST NOT roll back.
        tracing::info!(
            target: "am.events",
            event = "conversion_approved",
            request_id = %approved.id,
            tenant_id = %approved.tenant_id,
            caller_side = caller.side().as_str(),
            actor_uuid = %approver_uuid,
            target_mode = approved.target_mode.as_str(),
            outcome = "ok",
            "am conversion approved"
        );

        Ok(approved)
    }
    // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-apply:p1:inst-dod-dual-consent-apply-service
    // @cpt-end:cpt-cf-account-management-algo-managed-self-managed-modes-dual-consent-apply:p1:inst-algo-dual-consent-apply-service
    // @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-approval:p1:inst-flow-conversion-approval-service

    // ----------------------------------------------------------------
    // expire_pending — system-driven reaper tick
    // ----------------------------------------------------------------

    /// Reaper tick. Discovers `Pending` rows whose `expires_at` is in
    /// the past, transitions each to `Expired`, and emits one
    /// `conversion_expired` audit event per row with `actor = system`
    /// on `am.events`. Returns the number of rows transitioned.
    ///
    /// The reaper MUST NOT mutate `tenants.self_managed` and MUST NOT
    /// touch closure rows — expire is purely a status transition on
    /// the conversion-request row.
    ///
    /// Idempotent: re-running after every expiration has been applied
    /// returns `0` and emits no further events.
    ///
    /// # Errors
    ///
    /// * Any error surfaced by `repo.query_expired` (the scan itself
    ///   is fail-fast — without the scan there is nothing to drive).
    /// * Per-row failures from `repo.transition_pending_to_expired`
    ///   are logged on `am.domain` and SKIPPED (best-effort batch);
    ///   the next reaper tick re-scans and re-attempts the leftovers.
    // @cpt-begin:cpt-cf-account-management-algo-managed-self-managed-modes-conversion-expiry-reaper:p1:inst-algo-conversion-expiry-reaper-service
    // @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-conversion-expiry:p1:inst-dod-conversion-expiry-reaper
    #[allow(
        clippy::cognitive_complexity,
        reason = "best-effort batch reaper: three per-row outcome arms (Ok / AlreadyResolved skip / failure-skip) each emit a distinct structured log on a different channel (am.events success, am.events idempotent skip, am.domain transient failure); collapsing the arms would obscure the per-outcome logging contract"
    )]
    pub async fn expire_pending(
        &self,
        scope: &AccessScope,
        batch_size: u32,
    ) -> Result<usize, DomainError> {
        // TODO(authz): enforce `InTenantSubtree` scope once #1813 lands.
        let _ = scope;
        let now = self.now();
        let due = self
            .repo
            .query_expired(&AccessScope::allow_all(), now, batch_size)
            .await?;
        let mut transitioned: usize = 0;
        for row in due {
            // Re-stamp `now` per row so each transition carries the
            // exact instant it was processed at, not the instant the
            // batch was scanned. Mirrors the production semantics
            // where a slow per-row UPDATE could span many ms.
            let stamp = self.now();
            match self
                .repo
                .transition_pending_to_expired(&AccessScope::allow_all(), row.id, stamp)
                .await
            {
                Ok(updated) => {
                    transitioned += 1;
                    tracing::info!(
                        target: "am.events",
                        event = "conversion_expired",
                        request_id = %updated.id,
                        tenant_id = %updated.tenant_id,
                        actor_uuid = "system",
                        outcome = "ok",
                        "am conversion expired"
                    );
                }
                Err(DomainError::AlreadyResolved) => {
                    // Peer reaper / approve / cancel / reject won
                    // this row between scan and transition. Idempotent
                    // skip; do not surface as an error to the caller.
                    tracing::debug!(
                        target: "am.events",
                        event = "conversion_expired",
                        request_id = %row.id,
                        tenant_id = %row.tenant_id,
                        outcome = "skipped_already_resolved",
                        "am conversion expire skipped"
                    );
                }
                Err(other) => {
                    // Best-effort batch: a transient per-row failure
                    // (DB blip, SI conflict surfacing as Aborted, etc.)
                    // MUST NOT strand rows N+1..N. Log on `am.domain`
                    // (errors do not belong on the success-only
                    // `am.events` channel) and continue with the next
                    // row. The caller (background loop) treats `Ok(N)`
                    // as "N rows transitioned this tick"; the next
                    // tick re-scans and re-attempts the leftovers.
                    tracing::warn!(
                        target: "am.domain",
                        error = %other,
                        request_id = %row.id,
                        tenant_id = %row.tenant_id,
                        "expire_pending: per-row transition failed; skipping for next tick"
                    );
                }
            }
        }
        Ok(transitioned)
    }
    // @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-conversion-expiry:p1:inst-dod-conversion-expiry-reaper
    // @cpt-end:cpt-cf-account-management-algo-managed-self-managed-modes-conversion-expiry-reaper:p1:inst-algo-conversion-expiry-reaper-service
}

/// Project a full [`ConversionRequest`] down to the parent-side
/// minimal surface. Centralised here so the projection contract is
/// in one place and the unit tests can pin the visible field set
/// against the model row directly.
// @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-parent-side-minimal-surface:p1:inst-dod-parent-side-projection-mapping
fn project_to_parent_view(
    row: &ConversionRequest,
    child_tenant_name: String,
) -> ConversionRequestParentProjection {
    ConversionRequestParentProjection {
        request_id: row.id,
        tenant_id: row.tenant_id,
        child_tenant_name,
        initiator_side: row.initiator_side,
        target_mode: row.target_mode,
        status: row.status,
        requested_by: row.requested_by,
        approved_by: row.approved_by,
        cancelled_by: row.cancelled_by,
        rejected_by: row.rejected_by,
        created_at: row.requested_at,
        expires_at: row.expires_at,
        resolved_at: row.resolved_at,
    }
}
// @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-parent-side-minimal-surface:p1:inst-dod-parent-side-projection-mapping

/// Enforce the caller-scope contract documented on
/// [`ConversionCaller`]: every caller MUST be acting on a request
/// whose stored fields match the caller's declared scope.
///
/// * Child-side: `row.tenant_id == caller.scope_id` (the URL-bound
///   tenant from `/tenants/{tenant_id}/conversions`).
/// * Parent-side: `row.parent_id == Some(caller.scope_id)` (the
///   URL-bound parent from `/tenants/{parent_id}/child-conversions`).
///
/// Both checks fire BEFORE the state / role matrix so a misrouted
/// call cannot learn that a request exists by reading
/// `AlreadyResolved` or `NotFound` on a row outside its scope. `op`
/// is included verbatim in `detail` so the structured log on the
/// caller side disambiguates which entry point fired
/// (`request_conversion` / `cancel` / etc.). Every violation surfaces
/// as [`DomainError::Validation`] — the same envelope the rest of the
/// initiation guards use.
///
/// A parent-side row whose stored `parent_id` is `None` (i.e. the
/// row references the platform root, which the FEATURE-doc root-
/// tenant refusal blocks at initiation time) will surface as a
/// `Validation` here too with a distinct diagnostic so operators
/// reading logs can recognize the data-integrity tag rather than
/// confusing it with a regular caller-scope mismatch.
// @cpt-begin:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-caller-scope
// @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-approval:p1:inst-flow-appr-validate-caller
// @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-cancellation:p1:inst-flow-can-validate-caller
// @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-rejection:p1:inst-flow-rej-validate-caller
// @cpt-begin:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-initiation:p1:inst-flow-init-validate-caller
fn verify_caller_scope(
    caller: ConversionCaller,
    op: &'static str,
    row_tenant_id: Uuid,
    row_parent_id: Option<Uuid>,
) -> Result<(), DomainError> {
    let scope_id = caller.scope_id();
    match caller.side() {
        ConversionSide::Child => {
            if row_tenant_id == scope_id {
                Ok(())
            } else {
                Err(DomainError::Validation {
                    detail: format!(
                        "{op}: child-side caller scoped to {scope_id} cannot act on a request \
                         whose tenant_id is {row_tenant_id}"
                    ),
                })
            }
        }
        ConversionSide::Parent => match row_parent_id {
            Some(p) if p == scope_id => Ok(()),
            // Stored `parent_id == None` should be impossible by
            // construction (root-tenant refusal runs before insert),
            // but if a peer raw-SQL'ed such a row in we MUST surface
            // it as a distinct diagnostic and not as a legitimate
            // scope mismatch.
            None => Err(DomainError::Validation {
                detail: format!(
                    "{op}: parent-side caller scoped to {scope_id} cannot act on a request \
                     with NULL parent_id (data-integrity violation: root-tenant refusal \
                     should have blocked the insert)"
                ),
            }),
            Some(other) => Err(DomainError::Validation {
                detail: format!(
                    "{op}: parent-side caller scoped to {scope_id} cannot act on a request \
                     whose parent_id is {other}"
                ),
            }),
        },
    }
}
// @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-initiation:p1:inst-flow-init-validate-caller
// @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-rejection:p1:inst-flow-rej-validate-caller
// @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-cancellation:p1:inst-flow-can-validate-caller
// @cpt-end:cpt-cf-account-management-flow-managed-self-managed-modes-conversion-approval:p1:inst-flow-appr-validate-caller
// @cpt-end:cpt-cf-account-management-dod-managed-self-managed-modes-dual-consent-actor-discipline:p1:inst-dod-dual-consent-actor-discipline-caller-scope
