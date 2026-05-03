//! Tenant repository contract.
//!
//! `TenantRepo` is the sole storage-seam the domain layer touches. It
//! abstracts the SeaORM-backed implementation so `TenantService` can be
//! unit-tested against a pure in-memory fake.
//!
//! Trait-method shape notes:
//!
//! * Every write path that changes closure rows is expressed as a single
//!   repo method that performs the `tenants` + `tenant_closure` writes in
//!   one transaction. The service never opens a transaction itself.
//! * The `activate_tenant` method corresponds to saga step 3 from
//!   DESIGN §3.3 `seq-create-child`: flip the tenant from `provisioning`
//!   to `active` AND insert the closure rows passed by the service.
//! * `compensate_provisioning` is the clean-failure compensation path;
//!   closure cleanup is not required because no closure rows are ever
//!   written while the tenant is in `provisioning`.
//! * `update_tenant_mutable` only accepts the patchable fields (name +
//!   status) and rewrites `tenant_closure.descendant_status` atomically
//!   when `status` changes.

use std::time::Duration;

use async_trait::async_trait;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use account_management_sdk::{ListChildrenQuery, ProvisionMetadataEntry, TenantPage, TenantUpdate};

use crate::domain::error::DomainError;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{ChildCountFilter, NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};

/// Read / write boundary for the `tenants` + `tenant_closure` tables.
///
/// Every method owns its own short-lived transaction unless the method
/// docs state otherwise. Caller-facing methods accept an [`AccessScope`]
/// parameter that the implementation forwards to `modkit_db`'s secure
/// query builders.
///
/// # Caller contract on `scope`
///
/// Both `tenants` and `tenant_closure` entities are declared
/// `no_tenant, no_resource, no_owner, no_type`. On these declarations
/// `Scopable::IS_UNRESTRICTED` is `false` and every constraint
/// property resolves to `None`, which means:
///
/// * `scope_with(allow_all())` → no-op (no `WHERE` clause added).
/// * `scope_with(<narrowed>)` → `deny_all()` (`WHERE false`) for reads
///   / mutations, and `ScopeError::Denied` for INSERTs.
///
/// **Until `InTenantSubtree` lands** (cyberfabric-core#1813), callers
/// MUST pass [`AccessScope::allow_all`]. A narrowed scope silently
/// zero-rows every read and turns every mutation into a no-op or hard
/// deny — no useful authorization happens at this boundary today.
/// Cross-tenant authorization is enforced one layer up by the PDP
/// gate in the service layer; this is **single-layer enforcement**
/// and is a pre-production gate (see crate-level `lib.rs` note).
///
/// # Future: subtree clamp via `InTenantSubtree`
///
/// Subtree clamp on `tenants` reads will land via a dedicated
/// `InTenantSubtree` predicate type (mirror of the existing
/// `InGroupSubtree` stack) — scoped as a separate PR in this stack
/// between the AM service PR and the Tenant Resolver Plugin PR.
/// After that lands, AM declares the `tenant_hierarchy` capability
/// and the PDP returns `InTenantSubtree(root=subject.tenant_id)`
/// constraints which the secure builder compiles to a JOIN on
/// `tenant_closure`. At that point the `scope` parameter starts
/// carrying meaningful narrowing and the impl-side `scope_with`
/// calls begin to apply auto-filter; this docstring will be updated
/// to drop the "MUST pass `allow_all`" requirement.
#[async_trait]
pub trait TenantRepo: Send + Sync {
    // ---- Read operations -----------------------------------------------

    /// Load a single tenant by id, including SDK-invisible `Provisioning`
    /// rows (so the service can distinguish "not-found" from "not-visible").
    ///
    /// Returns `Ok(None)` when no row exists or the row is outside the
    /// supplied `scope`.
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, DomainError>;

    /// Direct-children list. Excludes `Provisioning` rows at the query
    /// layer. Pagination is `top` / `skip` per `listChildren`. Order is
    /// stable (by `(created_at, id)`) so cursor re-reads are deterministic.
    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage<TenantModel>, DomainError>;

    // ---- Write operations ----------------------------------------------

    /// Saga step 1: insert a new tenant row with `status = Provisioning`.
    ///
    /// Runs in its own short TX. The implementation MUST re-read the
    /// parent row in the same TX and reject the insert unless the
    /// parent is still `Active`; otherwise a concurrent soft-delete
    /// could commit a deleted parent while a new child is being
    /// provisioned. No closure rows are written — the
    /// provisioning-exclusion invariant (DESIGN §3.1) forbids any
    /// closure entry while the tenant is in `provisioning`.
    async fn insert_provisioning(
        &self,
        scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, DomainError>;

    /// Saga step 3: flip the tenant from `Provisioning` to `Active`,
    /// insert the supplied closure rows, and persist any provider-returned
    /// metadata entries in one transaction.
    ///
    /// The `closure_rows` slice MUST contain the self-row plus one row per
    /// strict ancestor along the `parent_id` chain (built by
    /// [`crate::domain::tenant::closure::build_activation_rows`]). Any
    /// other composition violates the coverage / self-row invariants.
    async fn activate_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        closure_rows: &[ClosureRow],
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, DomainError>;

    /// Saga compensation: delete a `Provisioning` row that never reached
    /// activation. Guards on `status = Provisioning` to avoid racing an
    /// unrelated row. No closure cleanup is required.
    async fn compensate_provisioning(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), DomainError>;

    /// Apply a mutable-fields-only patch.
    ///
    /// When `patch.status` is `Some(new)` the implementation MUST also
    /// rewrite `tenant_closure.descendant_status` for every row where
    /// `descendant_id = tenant_id` in the same transaction per DESIGN
    /// §3.1 `Closure status denormalization invariant`.
    ///
    /// # Status-transition guards
    ///
    /// PATCH may only flip the row between `Active` and `Suspended`.
    /// The implementation MUST reject:
    ///
    /// * **Current row in `Deleted`** — already in the deletion
    ///   pipeline; further mutation is forbidden. Returns
    ///   [`DomainError::Conflict`].
    /// * **Current row in `Provisioning`** — saga step 3 hasn't
    ///   activated the tenant; mutable patches are not part of the
    ///   activation contract. Returns [`DomainError::Conflict`].
    /// * **`patch.status = Deleted`** — would skip the
    ///   `deleted_at` / `deletion_scheduled_at` stamps that
    ///   `schedule_deletion` is responsible for, breaking the
    ///   `Tenant` schema's tombstone contract. Returns
    ///   [`DomainError::Conflict`] with a hint to use the soft-delete
    ///   flow.
    /// * **`patch.status = Provisioning`** — would flip an
    ///   SDK-visible row back to invisible while its `tenant_closure`
    ///   rows remain present, violating the provisioning-exclusion
    ///   invariant. Returns [`DomainError::Conflict`].
    ///
    /// The current-row checks run after every SERIALIZABLE retry so
    /// a soft-delete committing between the original attempt and the
    /// retry cannot resurrect the row through a mutable patch.
    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, DomainError>;

    /// Return the closure-input ancestor chain for a new child whose
    /// parent is `parent_id`: `[parent_id, grandparent, ..., root]` in
    /// nearest-first order. The chain **includes `parent_id` itself**
    /// because `build_activation_rows` requires one closure row per
    /// `(ancestor, child)` pair, and `(parent_id, child)` is one of
    /// those pairs.
    ///
    /// The function is named "through parent" rather than "of parent"
    /// to spell out that the seed is part of the returned chain — the
    /// usual graph-theory interpretation of "strict ancestors" would
    /// exclude it.
    async fn load_ancestor_chain_through_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, DomainError>;

    // ---- Phase 3: retention + reaper + hard-delete --------------------

    /// Scan retention-due rows for the hard-delete pipeline.
    async fn scan_retention_due(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, DomainError>;

    /// Clear a hard-delete scanner claim for a row that was not reclaimed.
    async fn clear_retention_claim(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        worker_id: Uuid,
    ) -> Result<(), DomainError>;

    /// Scan rows in `status = Provisioning` with `created_at <=
    /// older_than` AND atomically claim them for the calling worker.
    /// Used by the provisioning reaper; mirrors the
    /// `scan_retention_due` claim pattern so two replicas cannot
    /// invoke `IdpTenantProvisionerClient::deprovision_tenant` for the
    /// same row inside one `RETENTION_CLAIM_TTL` window.
    ///
    /// `now` is used to compute the stale-claim cutoff so a worker
    /// that crashed mid-process eventually releases its rows for
    /// peer takeover.
    ///
    /// Returned rows carry the worker UUID stamped during the claim
    /// UPDATE; callers MUST pass it back into
    /// [`Self::clear_retention_claim`] after per-row processing.
    async fn scan_stuck_provisioning(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, DomainError>;

    /// Count direct children under `parent_id`.
    ///
    /// See [`ChildCountFilter`] for the variant semantics.
    /// `Provisioning` children are *deliberately* counted in both
    /// modes.
    async fn count_children(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        filter: ChildCountFilter,
    ) -> Result<u64, DomainError>;

    /// Flip the tenant from its current SDK-visible state to
    /// `Deleted`, stamp `deletion_scheduled_at = now`, and rewrite
    /// `tenant_closure.descendant_status` in the same transaction.
    async fn schedule_deletion(
        &self,
        scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, DomainError>;

    /// Transactional hard-delete of a single tenant.
    async fn hard_delete_one(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, DomainError>;

    /// Stamp `terminal_failure_at = now` on a `Provisioning` row that
    /// the `IdP` plugin has classified as
    /// [`account_management_sdk::DeprovisionFailure::Terminal`]. The
    /// SDK contract treats this as non-recoverable and operator-
    /// action-required; the marker keeps the row out of the
    /// `scan_stuck_provisioning` retry loop until an operator
    /// intervenes (manual hard-delete or column clear).
    ///
    /// The implementation **MUST** fence the UPDATE on both the
    /// `claimed_by` worker token and `status = Provisioning` so a
    /// peer's claim or a parallel finalizer that flipped the row
    /// to `Active` cannot have its work overridden by the marker.
    /// Returns `true` iff the row was actually marked; `false`
    /// indicates the claim was lost or the row no longer matches the
    /// fence (caller treats as no-op for idempotency — the row will
    /// either be marked by whoever still holds the claim, or has
    /// already moved past Provisioning).
    async fn mark_provisioning_terminal_failure(
        &self,
        scope: &AccessScope,
        id: Uuid,
        claimed_by: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Return `true` iff a `tenant_closure` row exists with
    /// `ancestor_id = ancestor` and `descendant_id = descendant`.
    async fn is_descendant(
        &self,
        scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, DomainError>;

    // ---- Convenience helpers used by the service ----------------------

    /// Return `true` iff the tenant exists and its status is `Active`.
    async fn parent_is_active(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<bool, DomainError> {
        match self.find_by_id(scope, parent_id).await? {
            Some(t) => Ok(matches!(t.status, TenantStatus::Active)),
            None => Ok(false),
        }
    }
}
