//! Tenant repository contract.
//!
//! `TenantRepo` is the sole storage-seam the domain layer touches. It
//! abstracts the SeaORM-backed implementation (introduced in the
//! REST-wiring phase under `infra/storage/repo_impl.rs`) so `TenantService`
//! can be unit-tested against a pure in-memory fake (see the
//! `#[cfg(test)]` mod in `service.rs`).
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

use crate::domain::error::AmError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::integrity::{IntegrityCategory, IntegrityScope, Violation};
use crate::domain::tenant::model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};

/// Read / write boundary for the `tenants` + `tenant_closure` tables.
///
/// Every method owns its own short-lived transaction unless the method
/// docs state otherwise. Caller-facing methods accept an [`AccessScope`]
/// parameter that the implementation forwards to `modkit_db`'s secure
/// query builders, so cross-tenant access is enforced at the storage
/// boundary in addition to the explicit ancestry check the service
/// performs before each call.
#[async_trait]
pub trait TenantRepo: Send + Sync {
    // ---- Read operations -----------------------------------------------

    /// Load a single tenant by id, including SDK-invisible `Provisioning`
    /// rows (so the service can distinguish "not-found" from "not-visible").
    ///
    /// Returns `Ok(None)` when no row exists or the row is outside the
    /// supplied `scope`. The service is responsible for mapping
    /// SDK-invisible rows to `AmError::NotFound` per the `Read Tenant
    /// Details` flow.
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, AmError>;

    /// Direct-children list. Excludes `Provisioning` rows at the query
    /// layer (the `OpenAPI` contract never surfaces them). Pagination is
    /// `top` / `skip` per `listChildren`. Order is stable (by
    /// `(created_at, id)` in the `SeaORM` impl) so cursor re-reads are
    /// deterministic.
    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage, AmError>;

    // ---- Write operations ----------------------------------------------

    /// Saga step 1: insert a new tenant row with `status = Provisioning`.
    ///
    /// Runs in its own short TX. No closure rows are written — the
    /// provisioning-exclusion invariant (DESIGN §3.1) forbids any
    /// closure entry while the tenant is in `provisioning`.
    async fn insert_provisioning(
        &self,
        scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, AmError>;

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
    ) -> Result<TenantModel, AmError>;

    /// Saga compensation: delete a `Provisioning` row that never reached
    /// activation. Guards on `status = Provisioning` to avoid racing an
    /// unrelated row. No closure cleanup is required.
    async fn compensate_provisioning(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), AmError>;

    /// Apply a mutable-fields-only patch.
    ///
    /// When `patch.status` is `Some(new)` the implementation MUST also
    /// rewrite `tenant_closure.descendant_status` for every row where
    /// `descendant_id = tenant_id` in the same transaction per DESIGN
    /// §3.1 `Closure status denormalization invariant`.
    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, AmError>;

    /// Return the strict-ancestor chain rooted at `parent_id` — the
    /// caller's parent itself, then `parent`'s parent, all the way up to
    /// the root — in nearest-first order. Used by the service to
    /// compute the closure rows inserted at activation time, where the
    /// just-inserted child's ancestors are exactly the parent + the
    /// parent's strict ancestors.
    ///
    /// The previous shape took the child id and looked up its parent —
    /// a redundant round-trip in the saga path where the caller already
    /// holds the parent row in scope. Pass `parent_id` directly.
    ///
    /// Returns `Err(AmError::NotFound)` if any ancestor is missing.
    async fn load_strict_ancestors_of_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, AmError>;

    // ---- Phase 3: retention + reaper + hard-delete --------------------

    /// Scan retention-due rows for the hard-delete pipeline. Returns
    /// rows where `status = Deleted` AND `deletion_scheduled_at` is
    /// populated AND `scheduled_at + effective_retention_window <= now`.
    /// `default_retention` fills in the per-tenant window when the row's
    /// `retention_window_secs` column is `NULL`. Result is limited to
    /// `limit` rows, ordered leaf-first (`depth DESC, id ASC`).
    async fn scan_retention_due(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, AmError>;

    /// Clear a hard-delete scanner claim for a row that was not reclaimed.
    ///
    /// This preserves retry behavior for rows deferred by hooks, `IdP`,
    /// child presence, or transient storage failures. `worker_id` MUST be the
    /// token returned via [`TenantRetentionRow::claimed_by`] from the
    /// matching `scan_retention_due` call: implementations clear only when
    /// the row is still owned by `worker_id`. This fences against the
    /// late-resumer race where worker A's stalled tick clears worker B's
    /// live claim after the TTL takeover, allowing the same row to be
    /// double-processed.
    async fn clear_retention_claim(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        worker_id: Uuid,
    ) -> Result<(), AmError>;

    /// Scan rows in `status = Provisioning` with `created_at <=
    /// older_than`. Result is bounded by `limit` rows ordered
    /// `(created_at ASC, id ASC)` so a large stuck-provisioning
    /// backlog does not load every row into memory in one query.
    /// Used by the provisioning reaper.
    async fn scan_stuck_provisioning(
        &self,
        scope: &AccessScope,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, AmError>;

    /// Count direct children under `parent_id`.
    ///
    /// `include_deleted` toggles **only the `Deleted` bucket**:
    ///
    /// * `true`  → counts every status: `Provisioning + Active + Suspended + Deleted`.
    /// * `false` → counts `Provisioning + Active + Suspended` (excludes `Deleted` only).
    ///
    /// `Provisioning` children are *deliberately* counted in both
    /// modes. This is the soft-delete guard's saga-correctness contract
    /// (see [`crate::domain::tenant::service::TenantService::soft_delete`]):
    /// a child mid-saga may still settle into `Active`, so its parent
    /// must not be permitted to enter `Deleted` while the saga is in
    /// flight — otherwise the post-settle state is an `Active` tenant
    /// under a `Deleted` parent, the `BrokenParentReference` violation
    /// classified in [`crate::domain::tenant::integrity`].
    ///
    /// Note: this differs from "SDK-visible" semantics — `Deleted` is
    /// itself SDK-visible (callers can fetch it via `?status=deleted`),
    /// so the toggle name reflects the wire-level filter, not
    /// SDK-visibility.
    async fn count_children(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        include_deleted: bool,
    ) -> Result<u64, AmError>;

    /// Flip the tenant from its current SDK-visible state to
    /// `Deleted`, stamp `deletion_scheduled_at = now`, and rewrite
    /// `tenant_closure.descendant_status` in the same transaction.
    /// The optional `retention` override is persisted as seconds in
    /// `retention_window_secs`; `None` leaves the column NULL (use the
    /// module default).
    async fn schedule_deletion(
        &self,
        scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, AmError>;

    /// Transactional hard-delete of a single tenant. Re-checks the
    /// **structural** eligibility guard (`status = Deleted` and
    /// `deletion_scheduled_at IS NOT NULL`) plus the **child-existence**
    /// guard under `FOR UPDATE`, then deletes closure rows first and
    /// the tenant row.
    ///
    /// **Temporal eligibility (`scheduled_at + retention_window <= now`)
    /// is the caller's responsibility**, performed up-front at
    /// candidate-selection time (see [`Self::scan_retention_due`],
    /// which already does the temporal filter at the DB with
    /// `FOR UPDATE SKIP LOCKED` and a `claimed_by` claim TTL). This
    /// method does NOT recompute "due" — and does not need to: once a
    /// row is due, it remains due (`now` is monotonic, `Deleted` is a
    /// terminal status, and `retention_window_secs` is not mutable for
    /// already-`Deleted` rows because `schedule_deletion` rejects them
    /// with `Conflict`).
    ///
    /// The outcome therefore discriminates between:
    /// * `Cleaned` — closure and tenant rows gone (also returned for
    ///   "row already absent" idempotency).
    /// * `DeferredChildPresent` — at least one child still names this
    ///   tenant as parent; retry on the next tick (leaf-first ordering
    ///   means children clear first).
    /// * `NotEligible` — the structural guard failed (row exists but
    ///   `status != Deleted` or `deletion_scheduled_at IS NULL`),
    ///   indicating either a stale candidate set or a data-integrity
    ///   anomaly.
    async fn hard_delete_one(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, AmError>;

    /// Run the eight integrity classification queries inside one
    /// `REPEATABLE READ ReadOnly` transaction and return every
    /// violation grouped by category. Memory is `O(violations)`,
    /// not `O(tenants + closure)`. Single-flight per scope is
    /// enforced inside the impl; concurrent callers receive
    /// `AmError::AuditAlreadyRunning`.
    async fn audit_integrity_for_scope(
        &self,
        scope: &AccessScope,
        integrity_scope: IntegrityScope,
    ) -> Result<Vec<(IntegrityCategory, Violation)>, AmError>;

    /// Return `true` iff a `tenant_closure` row exists with
    /// `ancestor_id = ancestor` and `descendant_id = descendant`. Used
    /// by the service to verify that a target tenant is reachable from
    /// the caller's home tenant before any read / write.
    ///
    /// **Authorization contract**: this method is the security gate for
    /// every cross-tenant access decision in `TenantService`
    /// (`ensure_caller_reaches`). Implementations **MUST** consult the
    /// real `tenant_closure` table (or an in-memory mirror that mutates
    /// in lock-step with it). Implementations **MUST NOT**
    /// short-circuit, stub, or fabricate a `true` result, including in
    /// test fakes used by code paths that exercise the gate. A lying
    /// `is_descendant` silently grants cross-tenant access — the
    /// `AccessScope::allow_all()` argument is a defence-in-depth
    /// passthrough, not the authorization decision.
    async fn is_descendant(
        &self,
        scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, AmError>;

    /// Return the platform-root tenant (the unique row with
    /// `parent_id IS NULL` and a non-`Provisioning` status). Returns
    /// `Ok(None)` if the bootstrap row does not exist yet — the service
    /// treats that as "platform-admin override is undefined" and rejects
    /// cross-tenant access.
    async fn find_root(&self, scope: &AccessScope) -> Result<Option<TenantModel>, AmError>;

    // ---- Convenience helpers used by the service ----------------------

    /// Return `true` iff the tenant exists and its status is `Active`.
    /// Used by the create-tenant saga to validate the parent.
    async fn parent_is_active(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<bool, AmError> {
        match self.find_by_id(scope, parent_id).await? {
            Some(t) => Ok(matches!(t.status, TenantStatus::Active)),
            None => Ok(false),
        }
    }
}
