//! In-memory `FakeTenantRepo` covering the entire `TenantRepo` trait
//! contract. Used by service-level unit tests in
//! `service_tests.rs` and (in later PRs) the REST handler tests.
//!
//! State invariants mirror the production schema — closure rows track
//! the parent walk, retention metadata mirrors the SQL columns added
//! by migrations, and per-tenant claim tokens are subjected to the
//! same `WHERE id = ? AND claimed_by = ?` fence as `clear_retention_claim`
//! enforces in the real repo.

#![allow(
    dead_code,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::new_without_default,
    clippy::too_many_lines,
    clippy::module_name_repetitions
)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use account_management_sdk::{ListChildrenQuery, ProvisionMetadataEntry, TenantPage, TenantUpdate};

use crate::domain::error::DomainError;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::integrity::{
    IntegrityCategory, IntegrityScope, RepairReport, Violation,
};
use crate::domain::tenant::model::{ChildCountFilter, NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteEligibility, HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};

/// Test injection — what the next call to `activate_tenant` should
/// return. Mirrors the typed `Mutex<FakeOutcome>` shape used by
/// `FakeIdpProvisioner` (one-shot toggle that resets to `Ok` after
/// firing). Replaces an earlier `fail_next_activation: bool` so future
/// variants can carry typed payload (e.g., a different `DomainError`
/// code) without growing parallel boolean flags.
#[domain_model]
#[derive(Debug, Clone, Default)]
pub enum NextActivationOutcome {
    #[default]
    Ok,
    InternalErr(String),
}

/// Test injection for `run_integrity_check_for_scope`. The default `Ok`
/// arm returns an empty violation list (a clean snapshot trivially
/// passes every classifier); `Violations` lets callers script a
/// non-empty bucket to drive the service-layer rebucketing path; and
/// `Err` exercises error propagation (e.g.
/// [`DomainError::IntegrityCheckInProgress`] surfacing through the
/// `TenantService::check_hierarchy_integrity` `?` operator). Scope is
/// not introspected by the fake — the `IntegrityScope` round-trip is
/// already covered by the service-layer test.
///
/// One-shot semantics (consumed via `mem::take` and reset to default
/// after firing) — matches the [`NextActivationOutcome`] pattern and
/// avoids a `Clone` bound on [`DomainError`] (which carries
/// non-clonable [`std::error::Error`] cause chains).
#[domain_model]
#[derive(Debug, Default)]
pub enum NextAuditOutcome {
    #[default]
    Ok,
    Violations(Vec<(IntegrityCategory, Violation)>),
    Err(DomainError),
}

#[domain_model]
#[derive(Default)]
pub struct RepoState {
    pub tenants: HashMap<Uuid, TenantModel>,
    pub closure: Vec<ClosureRow>,
    pub metadata: Vec<(Uuid, ProvisionMetadataEntry)>,
    /// Phase 3 — per-tenant retention metadata mirroring the columns
    /// added in migration `0002_add_retention_columns.sql`.
    pub retention: HashMap<Uuid, (OffsetDateTime, Option<Duration>)>,
    /// Per-tenant retention-claim worker token. Mirrors the SQL
    /// `tenants.claimed_by` column maintained by
    /// `repo_impl::scan_retention_due` / `clear_retention_claim`.
    /// Empty map = no claim. Tests may seed entries directly to
    /// simulate peer-takeover scenarios.
    pub claims: HashMap<Uuid, Uuid>,
    /// Mirror of `tenants.terminal_failure_at`. Stamped by
    /// [`TenantRepo::mark_provisioning_terminal_failure`] when the
    /// reaper observes [`account_management_sdk::DeprovisionFailure::Terminal`];
    /// rows present in this map are filtered out of
    /// `scan_stuck_provisioning` to keep the operator-action-required
    /// state out of the automatic retry loop.
    pub terminal_failures: HashMap<Uuid, OffsetDateTime>,
    /// One-shot control over the next `activate_tenant` call. F3 arms
    /// this with [`NextActivationOutcome::InternalErr`] to drive saga
    /// step 3 down its error branch without touching the `IdP`.
    pub next_activation_outcome: NextActivationOutcome,
    /// One-shot control over the next `run_integrity_check_for_scope`
    /// call (consumed via `mem::take` and reset to the default `Ok`
    /// arm). Tests that drive multiple audits within one assertion
    /// re-arm before each call.
    pub next_audit_outcome: NextAuditOutcome,
    /// Independent one-shot control over the next
    /// `repair_derivable_closure_violations` call. Separate from
    /// [`Self::next_audit_outcome`] so a service-level test that
    /// exercises the production `check → auto-repair` chain can
    /// script the check tick to surface violations AND the repair
    /// tick to bucket a (possibly different) outcome — using the
    /// same slot for both would let `mem::take` drain the script
    /// during the check, leaving the repair on the default empty
    /// path and silently weakening combined-flow coverage.
    /// Defaults to the same `Ok` arm as `next_audit_outcome`.
    pub next_repair_outcome: NextAuditOutcome,
}

#[domain_model]
pub struct FakeTenantRepo {
    pub state: Mutex<RepoState>,
}

impl FakeTenantRepo {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RepoState::default()),
        }
    }

    pub fn with_root(root_id: Uuid) -> Self {
        let repo = Self::new();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        let mut state = repo.state.lock().expect("lock");
        state.tenants.insert(
            root_id,
            TenantModel {
                id: root_id,
                parent_id: None,
                name: "root".into(),
                status: TenantStatus::Active,
                self_managed: false,
                tenant_type_uuid: Uuid::from_u128(0xAA),
                depth: 0,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            },
        );
        state.closure.push(ClosureRow {
            ancestor_id: root_id,
            descendant_id: root_id,
            barrier: 0,
            descendant_status: TenantStatus::Active.as_smallint(),
        });
        drop(state);
        repo
    }

    pub fn insert_tenant_raw(&self, t: TenantModel) {
        self.state.lock().expect("lock").tenants.insert(t.id, t);
    }

    pub fn snapshot_closure(&self) -> Vec<ClosureRow> {
        self.state.lock().expect("lock").closure.clone()
    }

    /// Direct row lookup that bypasses the `AccessScope` visibility
    /// filter applied by [`TenantRepo::find_by_id`]. F2 uses this to
    /// confirm the soft-deleted row is still in the DB after a
    /// hard-delete batch tagged it as `IdpTerminal`.
    pub fn find_by_id_unchecked(&self, id: Uuid) -> Option<TenantModel> {
        self.state.lock().expect("lock").tenants.get(&id).cloned()
    }

    /// Direct lookup of the per-row retention claim. `Some(uuid)`
    /// means the row is currently claimed by the worker that scan-
    /// claimed it; `None` means no live claim. Parking / claim-
    /// release tests use this to assert end-of-tick state without
    /// poking at `state.claims` directly.
    pub fn find_claim_unchecked(&self, id: Uuid) -> Option<Uuid> {
        self.state.lock().expect("lock").claims.get(&id).copied()
    }

    /// Whether a row carries a `terminal_failure_at` stamp (set by
    /// either `mark_provisioning_terminal_failure` or
    /// `mark_retention_terminal_failure`). Used by parking tests to
    /// assert the marker landed without exposing the internal
    /// `state.terminal_failures` map directly.
    pub fn is_terminally_failed_unchecked(&self, id: Uuid) -> bool {
        self.state
            .lock()
            .expect("lock")
            .terminal_failures
            .contains_key(&id)
    }

    /// Operator-cleanup helper: simulate the manual SQL UPDATE that
    /// clears `terminal_failure_at`, allowing the row to re-enter
    /// the scanner on the next tick. The cascade-hook /
    /// IdP-terminal parking tests use this to pin the
    /// "fix the bug, clear the marker, scanner picks it up again"
    /// flow operators are expected to follow.
    ///
    /// Also clears `state.claims` for the row. Production releases
    /// the claim immediately after parking
    /// (`release_claim_now == true` on `CascadeTerminal` /
    /// `IdpTerminal`), and any leftover claim ages out via
    /// `RETENTION_CLAIM_TTL` (~10 min). The fake repo intentionally
    /// omits TTL-based takeover (live claim = scanner skips, no
    /// matter what), so without this clear the row would still be
    /// invisible to the next scan even though `terminal_failure_at`
    /// is gone — silently breaking the docstring contract above
    /// for any test that relies on it.
    ///
    /// **Side effect:** the `state.claims` removal is unconditional —
    /// it does NOT distinguish "leftover claim from the parking
    /// worker" from "live claim from a peer worker that took over".
    /// Tests that simulate a peer-claim race (e.g. seeding a peer
    /// claim via [`Self::seed_claim`] to model TTL-elapsed
    /// takeover) and then call this helper will lose the seeded peer
    /// claim as a side effect. Such tests must drop `terminal_failure_at`
    /// directly via `state.lock().terminal_failures.remove(...)`
    /// instead of going through this helper.
    pub fn clear_terminal_failure_unchecked(&self, id: Uuid) {
        let mut state = self.state.lock().expect("lock");
        state.terminal_failures.remove(&id);
        state.claims.remove(&id);
    }

    /// Snapshot all rows currently in the `Provisioning` state.
    pub fn snapshot_provisioning_rows(&self) -> Vec<TenantModel> {
        self.state
            .lock()
            .expect("lock")
            .tenants
            .values()
            .filter(|t| matches!(t.status, TenantStatus::Provisioning))
            .cloned()
            .collect()
    }

    /// Stamp the per-row claim token — simulates a concurrent worker
    /// having already claimed the row in the same
    /// `RETENTION_CLAIM_TTL` window. The next
    /// `scan_stuck_provisioning` / `scan_retention_due` will skip the
    /// row (filter `!state.claims.contains_key(&t.id)`), reproducing
    /// the SQL claim fence at the fake level. Tests use this to
    /// exercise the "two replicas, one row" invariant without
    /// blocking on real time.
    pub fn seed_claim(&self, tenant_id: Uuid, claimed_by: Uuid) {
        self.state
            .lock()
            .expect("lock")
            .claims
            .insert(tenant_id, claimed_by);
    }

    /// Whether the row currently has a live claim. Used by reaper
    /// concurrent-claim tests to assert the per-tick claim does (or
    /// does not) get cleared on the way out.
    pub fn has_claim(&self, tenant_id: Uuid) -> bool {
        self.state
            .lock()
            .expect("lock")
            .claims
            .contains_key(&tenant_id)
    }

    /// Arm the next `activate_tenant` call to return
    /// `DomainError::Internal { diagnostic: detail }` exactly once. Used
    /// by F3 to reproduce the finalization-TX failure path (saga
    /// step 3 abort).
    pub fn expect_next_activation_failure(&self, detail: impl Into<String>) {
        self.state.lock().expect("lock").next_activation_outcome =
            NextActivationOutcome::InternalErr(detail.into());
    }

    /// Script `run_integrity_check_for_scope` to return a non-empty
    /// violation list. Drives the `TenantService::check_hierarchy_integrity`
    /// rebucketing path that the trivial default cannot exercise.
    pub fn set_audit_violations(&self, pairs: Vec<(IntegrityCategory, Violation)>) {
        self.state.lock().expect("lock").next_audit_outcome = NextAuditOutcome::Violations(pairs);
    }

    /// Script `run_integrity_check_for_scope` to return a domain error.
    /// Used to verify error propagation through
    /// `TenantService::check_hierarchy_integrity`.
    pub fn set_audit_error(&self, err: DomainError) {
        self.state.lock().expect("lock").next_audit_outcome = NextAuditOutcome::Err(err);
    }

    /// Script `repair_derivable_closure_violations` to return a
    /// non-empty violation list (the fake re-buckets it through the
    /// production category-split contract). Independent slot from
    /// [`Self::set_audit_violations`] so a combined check → repair
    /// flow (e.g. service-level `auto_after_check` coverage) can
    /// arm both ticks without one tick draining the other's script
    /// via `mem::take`.
    pub fn set_repair_violations(&self, pairs: Vec<(IntegrityCategory, Violation)>) {
        self.state.lock().expect("lock").next_repair_outcome =
            NextAuditOutcome::Violations(pairs);
    }

    /// Script `repair_derivable_closure_violations` to surface a
    /// domain error. Independent of [`Self::set_audit_error`] for
    /// the same reason as [`Self::set_repair_violations`].
    pub fn set_repair_error(&self, err: DomainError) {
        self.state.lock().expect("lock").next_repair_outcome = NextAuditOutcome::Err(err);
    }

    /// Seed a soft-deleted child under `parent` with retention=0 so
    /// the next `hard_delete_batch` tick picks it up. Returns the
    /// child id.
    pub fn seed_soft_deleted_child_due_for_hard_delete(&self, parent: Uuid) -> Uuid {
        let child = Uuid::from_u128(0xF200);
        let now = OffsetDateTime::now_utc();
        let model = TenantModel {
            id: child,
            parent_id: Some(parent),
            name: "soft-deleted-child".into(),
            status: TenantStatus::Deleted,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: Some(now),
        };
        let mut state = self.state.lock().expect("lock");
        state.tenants.insert(child, model);
        state.closure.push(ClosureRow {
            ancestor_id: child,
            descendant_id: child,
            barrier: 0,
            descendant_status: TenantStatus::Deleted.as_smallint(),
        });
        state.closure.push(ClosureRow {
            ancestor_id: parent,
            descendant_id: child,
            barrier: 0,
            descendant_status: TenantStatus::Deleted.as_smallint(),
        });
        state
            .retention
            .insert(child, (now, Some(Duration::from_secs(0))));
        child
    }
}

/// Shared body for the two terminal-failure marking variants. Mirrors
/// the symmetric helper in `repo_impl::lifecycle`: the only difference
/// between provisioning- and retention-side parking is the `status`
/// fence, so centralising the body keeps the claim / idempotency /
/// status invariants identical for both pipelines without growing a
/// "match anything" generalization. Returns `true` iff the marker
/// landed; the trait method wraps in `Ok(...)` to match the
/// production-side `Result<bool, DomainError>` signature even though
/// the in-memory fake never produces a fault on this path.
fn mark_terminal_failure_with_status(
    state: &mut RepoState,
    id: Uuid,
    claimed_by: Uuid,
    now: OffsetDateTime,
    status: TenantStatus,
) -> bool {
    if state.claims.get(&id) != Some(&claimed_by) {
        return false;
    }
    let Some(tenant) = state.tenants.get(&id) else {
        return false;
    };
    if tenant.status != status {
        return false;
    }
    // Idempotency fence — mirrors the production
    // `terminal_failure_at IS NULL` predicate added to the SQL UPDATE.
    // A retry on an already-marked row returns `false` so the
    // caller does not double-bump the `terminal` counter / metric.
    if state.terminal_failures.contains_key(&id) {
        return false;
    }
    state.terminal_failures.insert(id, now);
    true
}

/// Compute the set of tenant ids visible to `scope` on the `tenants`
/// table, matching production semantics: the `SeaORM` `Scopable` derive
/// declares `tenant_col = "id"`, so the secure-extension filter
/// translates `AccessScope::for_tenant(t)` into `WHERE tenants.id = t`
/// — only the row whose own id equals the scope's tenant matches. It
/// does **not** transparently expand to descendants via
/// `tenant_closure`. Cross-tenant authorization is enforced by the
/// PDP (`AuthZ` resolver) at the service-layer PEP call; post-gate repo
/// calls pass `AccessScope::allow_all()` so this filter is a no-op in
/// practice. The strict per-row variant is preserved here only so
/// direct fake calls behave identically to production for tests that
/// exercise the secure-extension boundary.
///
/// Mapping:
/// * `allow_all` → `None` (no filter; every row visible).
/// * `for_tenant(t)` → `Some({t})` (single-row equality).
/// * multi-tenant scope built from N owner-tenant UUIDs → `Some(set)`
///   = the union of those UUIDs (`WHERE tenants.id IN (...)`). The
///   service never builds that shape today — every post-gate call
///   uses `allow_all` — so this branch exists only for completeness.
fn visible_ids_for(_state: &RepoState, scope: &AccessScope) -> Option<HashSet<Uuid>> {
    if scope.is_unconstrained() {
        return None;
    }
    let mut visible: HashSet<Uuid> = HashSet::new();
    for tid in scope.all_uuid_values_for(modkit_security::pep_properties::OWNER_TENANT_ID) {
        visible.insert(tid);
    }
    Some(visible)
}

#[async_trait]
impl TenantRepo for FakeTenantRepo {
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, DomainError> {
        let state = self.state.lock().expect("lock");
        let visible = visible_ids_for(&state, scope);
        if let Some(ref vis) = visible
            && !vis.contains(&id)
        {
            return Ok(None);
        }
        Ok(state.tenants.get(&id).cloned())
    }

    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage<TenantModel>, DomainError> {
        let state = self.state.lock().expect("lock");
        let visible = visible_ids_for(&state, scope);
        let mut items: Vec<TenantModel> = state
            .tenants
            .values()
            .filter(|t| t.parent_id == Some(query.parent_id))
            .filter(|t| t.status.is_sdk_visible())
            .filter(|t| match &visible {
                Some(vis) => vis.contains(&t.id),
                None => true,
            })
            .filter(|t| match query.status_filter() {
                // Lift SDK 3-variant status into AM-internal so the
                // membership check against `t.status` (4-var) compiles.
                Some(allowed) if !allowed.is_empty() => {
                    allowed.iter().any(|s| TenantStatus::from(*s) == t.status)
                }
                // Default: active and suspended only, matching repo_impl default.
                _ => !matches!(t.status, TenantStatus::Deleted),
            })
            .cloned()
            .collect();
        items.sort_by_key(|t| (t.created_at, t.id));
        let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let skip = usize::try_from(query.skip).unwrap_or(usize::MAX);
        let top = usize::try_from(query.top()).unwrap_or(usize::MAX);
        let paged: Vec<TenantModel> = items.into_iter().skip(skip).take(top).collect();
        Ok(TenantPage {
            items: paged,
            top: query.top(),
            skip: query.skip,
            total: Some(total),
        })
    }

    async fn insert_provisioning(
        &self,
        _scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, DomainError> {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_100).expect("epoch");
        let model = TenantModel {
            id: tenant.id,
            parent_id: tenant.parent_id,
            name: tenant.name.clone(),
            status: TenantStatus::Provisioning,
            self_managed: tenant.self_managed,
            tenant_type_uuid: tenant.tenant_type_uuid,
            depth: tenant.depth,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let mut state = self.state.lock().expect("lock");
        if state.tenants.contains_key(&tenant.id) {
            return Err(DomainError::AlreadyExists {
                detail: format!("tenant {} already exists", tenant.id),
            });
        }
        // Mirror the production `ux_tenants_single_root` partial
        // unique index: at most one row may have `parent_id IS NULL`.
        // Without this guard, bootstrap/idempotency tests can pass
        // against a second-root state the real repo can never
        // persist, and the configured-root-id-drift detection in
        // `BootstrapService::run` (the consecutive `AlreadyExists`
        // streak) would never trip in fake-backed tests.
        if tenant.parent_id.is_none() && state.tenants.values().any(|t| t.parent_id.is_none()) {
            return Err(DomainError::AlreadyExists {
                detail: "root tenant already exists".to_owned(),
            });
        }
        // Root-tenant insert (`parent_id = None`) bypasses the parent
        // existence + status check — it is the platform-bootstrap
        // saga's `insert_root_provisioning` path. Child inserts go
        // through the parent-active fence below.
        if let Some(parent_id) = tenant.parent_id {
            let parent = state
                .tenants
                .get(&parent_id)
                .ok_or_else(|| DomainError::Validation {
                    detail: format!("parent tenant {parent_id} not found"),
                })?;
            if !matches!(parent.status, TenantStatus::Active) {
                return Err(DomainError::Validation {
                    detail: format!("parent tenant {parent_id} is not active"),
                });
            }
        }
        state.tenants.insert(tenant.id, model.clone());
        Ok(model)
    }

    async fn activate_tenant(
        &self,
        _scope: &AccessScope,
        tenant_id: Uuid,
        closure_rows: &[ClosureRow],
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, DomainError> {
        let mut state = self.state.lock().expect("lock");
        // F3 — finalization-TX failure injection: consume the typed
        // outcome toggle and short-circuit before mutating any state,
        // mirroring a SERIALIZABLE TX abort that leaves the
        // provisioning row in place for the reaper.
        let outcome = std::mem::take(&mut state.next_activation_outcome);
        if let NextActivationOutcome::InternalErr(detail) = outcome {
            return Err(DomainError::Internal {
                diagnostic: format!("fake activate_tenant aborted for {tenant_id}: {detail}"),
                cause: None,
            });
        }
        // Reaper-claim / terminal-stamp fence. Mirrors the
        // production guard in
        // `repo_impl::lifecycle::activate_tenant`: the activation
        // UPDATE must reject any row whose `claimed_by` is non-NULL
        // (the provisioning reaper grabbed it) or whose
        // `terminal_failure_at` is stamped (a peer reaper classified
        // the in-flight provision as `Terminal`). Without this
        // mirror, service-level tests could pass against a fake
        // that silently activated a row the reaper had already
        // torn down on the IdP side.
        if state.claims.contains_key(&tenant_id) {
            return Err(DomainError::Conflict {
                detail: format!(
                    "tenant {tenant_id} has been claimed by the provisioning reaper; \
                     refusing to activate (saga lost the race)"
                ),
            });
        }
        if state.terminal_failures.contains_key(&tenant_id) {
            return Err(DomainError::Conflict {
                detail: format!(
                    "tenant {tenant_id} is parked with terminal_failure_at; \
                     operator action required before activation"
                ),
            });
        }
        let tenant = state
            .tenants
            .get_mut(&tenant_id)
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found for activation"),
                resource: tenant_id.to_string(),
            })?;
        if !matches!(tenant.status, TenantStatus::Provisioning) {
            return Err(DomainError::Conflict {
                detail: format!("tenant {tenant_id} not in provisioning state"),
            });
        }
        tenant.status = TenantStatus::Active;
        let activated = tenant.clone();
        state.closure.extend(closure_rows.iter().cloned());
        state.metadata.extend(
            metadata_entries
                .iter()
                .cloned()
                .map(|entry| (tenant_id, entry)),
        );
        Ok(activated)
    }

    async fn compensate_provisioning(
        &self,
        _scope: &AccessScope,
        tenant_id: Uuid,
        expected_claimed_by: Option<Uuid>,
    ) -> Result<(), DomainError> {
        let mut state = self.state.lock().expect("lock");
        let found = state.tenants.get(&tenant_id).cloned();
        match found {
            Some(t) if matches!(t.status, TenantStatus::Provisioning) => {
                // Mirror the production fence: refuse the delete
                // when a peer reaper holds (or has parked) the row.
                // Saga path passes `None` and expects no claim;
                // reaper path passes `Some(worker_id)` and expects
                // its own claim.
                let actual_claim = state.claims.get(&tenant_id).copied();
                if actual_claim != expected_claimed_by {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "refusing to compensate: tenant {tenant_id} claim mismatch \
                             (expected={expected_claimed_by:?}, actual={actual_claim:?})"
                        ),
                    });
                }
                if state.terminal_failures.contains_key(&tenant_id) {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "refusing to compensate: tenant {tenant_id} parked with \
                             terminal_failure_at"
                        ),
                    });
                }
                state.tenants.remove(&tenant_id);
                // Parity with the real DELETE: removing the row also
                // removes any claim or terminal-failure entries the
                // production schema would have dropped with it.
                state.claims.remove(&tenant_id);
                state.terminal_failures.remove(&tenant_id);
                Ok(())
            }
            Some(_) => Err(DomainError::Conflict {
                detail: format!(
                    "refusing to compensate: tenant {tenant_id} not in provisioning state"
                ),
            }),
            None => Ok(()),
        }
    }

    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, DomainError> {
        let mut state = self.state.lock().expect("lock");
        let visible = visible_ids_for(&state, scope);
        if let Some(ref vis) = visible
            && !vis.contains(&tenant_id)
        {
            return Err(DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
            });
        }
        let tenant = state
            .tenants
            .get_mut(&tenant_id)
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
            })?;

        // Mirror the production guards in `repo_impl::updates`. A
        // service-layer test that bypasses
        // `validate_status_transition` and lands here would silently
        // pass against an un-guarded fake while production would
        // reject the patch with `Conflict`. Keeping the fake faithful
        // to the SQL impl prevents that drift.
        if matches!(tenant.status, TenantStatus::Deleted) {
            return Err(DomainError::Conflict {
                detail: format!("tenant {tenant_id} is deleted and not mutable"),
            });
        }
        if matches!(tenant.status, TenantStatus::Provisioning) {
            return Err(DomainError::Conflict {
                detail: format!("tenant {tenant_id} is provisioning and not mutable through PATCH"),
            });
        }
        let maybe_new_status: Option<TenantStatus> = patch.status.map(TenantStatus::from);
        if let Some(new_status) = maybe_new_status {
            match new_status {
                TenantStatus::Active | TenantStatus::Suspended => {}
                TenantStatus::Deleted => {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id}: PATCH cannot transition to deleted; \
                             use the soft-delete flow (`schedule_deletion`)"
                        ),
                    });
                }
                TenantStatus::Provisioning => {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id}: PATCH cannot transition to provisioning"
                        ),
                    });
                }
            }
        }

        // Idempotent no-op (HTTP PATCH semantics, option A — true
        // idempotency). Mirrors the production change-detection in
        // `repo_impl::updates`: fold "patch is Some AND value differs"
        // into an `Option` so we can pattern-match the write step
        // without a redundant flag-then-`expect` dance.
        let name_to_write = patch
            .name
            .as_ref()
            .filter(|n| n.as_str() != tenant.name.as_str());
        let status_to_write = maybe_new_status.filter(|s| *s != tenant.status);
        if name_to_write.is_none() && status_to_write.is_none() {
            return Ok(tenant.clone());
        }

        if let Some(new_name) = name_to_write {
            tenant.name = new_name.clone();
        }
        if let Some(new_status) = status_to_write {
            tenant.status = new_status;
        }
        // Production stamps `updated_at = now()` inside the same
        // transaction; mirror it so tests that read back the row see
        // the same timestamp behavior.
        tenant.updated_at = OffsetDateTime::now_utc();
        let updated = tenant.clone();
        if status_to_write.is_some() {
            for row in &mut state.closure {
                if row.descendant_id == tenant_id {
                    row.descendant_status = updated.status.as_smallint();
                }
            }
        }
        Ok(updated)
    }

    async fn load_ancestor_chain_through_parent(
        &self,
        _scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, DomainError> {
        let state = self.state.lock().expect("lock");
        let mut chain = Vec::new();
        let mut cursor_id = Some(parent_id);
        while let Some(pid) = cursor_id {
            let parent = state
                .tenants
                .get(&pid)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    detail: format!("ancestor {pid} missing while walking chain"),
                    resource: pid.to_string(),
                })?;
            cursor_id = parent.parent_id;
            chain.push(parent);
        }
        Ok(chain)
    }

    async fn scan_retention_due(
        &self,
        _scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, DomainError> {
        // Synthetic per-scan worker token. Mirrors `repo_impl`, where
        // each scan generates a fresh `worker_id` and stamps every
        // selected row's `claimed_by`. The mock writes the same token
        // into `state.claims` so `clear_retention_claim` can fence on
        // it — and so peer-takeover tests can overwrite the entry to
        // simulate a TTL-elapsed claim transfer to another worker.
        let worker_id = Uuid::new_v4();
        let mut state = self.state.lock().expect("lock");
        let mut out: Vec<TenantRetentionRow> = state
            .tenants
            .values()
            .filter(|t| matches!(t.status, TenantStatus::Deleted))
            // Mirror the SQL `terminal_failure_at IS NULL`
            // predicate: rows the retention pipeline parked via
            // `mark_retention_terminal_failure` are out of the
            // retry loop until the marker is cleared. Symmetric to
            // the `scan_stuck_provisioning` fake above.
            .filter(|t| !state.terminal_failures.contains_key(&t.id))
            // Claimable: no live claim. The mock intentionally omits
            // TTL-based takeover; tests seed `state.claims` directly
            // when they need to model peer ownership.
            .filter(|t| !state.claims.contains_key(&t.id))
            .filter_map(|t| {
                state.retention.get(&t.id).map(|(sched, win)| {
                    let retention = win.unwrap_or(default_retention);
                    TenantRetentionRow {
                        id: t.id,
                        depth: t.depth,
                        deletion_scheduled_at: *sched,
                        retention_window: retention,
                        claimed_by: worker_id,
                    }
                })
            })
            .filter(|r| {
                crate::domain::tenant::retention::is_due(
                    now,
                    r.deletion_scheduled_at,
                    r.retention_window,
                )
            })
            .collect();
        // Stable leaf-first ordering, matching `repo_impl::scan_retention_due`.
        out.sort_by(|a, b| {
            b.depth
                .cmp(&a.depth)
                .then_with(|| a.deletion_scheduled_at.cmp(&b.deletion_scheduled_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        out.truncate(limit);
        for row in &out {
            state.claims.insert(row.id, worker_id);
        }
        Ok(out)
    }

    async fn clear_retention_claim(
        &self,
        _scope: &AccessScope,
        tenant_id: Uuid,
        worker_id: Uuid,
    ) -> Result<(), DomainError> {
        // Mirrors the SQL predicate in `repo_impl::clear_retention_claim`:
        // remove the claim only when this worker still owns it. If a
        // peer worker took over after the TTL elapsed, the predicate
        // fails and this call is a no-op — the peer's live claim is
        // preserved. See `repo_impl.rs:2330-2333` for the canonical
        // SQL-side rationale.
        let mut state = self.state.lock().expect("lock");
        if state.claims.get(&tenant_id) == Some(&worker_id) {
            state.claims.remove(&tenant_id);
        }
        Ok(())
    }

    async fn scan_stuck_provisioning(
        &self,
        _scope: &AccessScope,
        _now: OffsetDateTime,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, DomainError> {
        // Synthetic per-scan worker token. Symmetric to
        // `scan_retention_due` — every selected row gets stamped
        // with the same token, and `state.claims` is updated so
        // `clear_retention_claim` can fence on it. The two
        // pipelines share the same claim namespace because a row
        // can only be in one of `Provisioning` / `Deleted` states
        // at any given time.
        let worker_id = Uuid::new_v4();
        let mut state = self.state.lock().expect("lock");
        let mut out: Vec<TenantProvisioningRow> = state
            .tenants
            .values()
            .filter(|t| matches!(t.status, TenantStatus::Provisioning))
            .filter(|t| t.created_at <= older_than)
            // Mirror the SQL `terminal_failure_at IS NULL` predicate:
            // rows the reaper marked as operator-action-required are
            // out of the retry loop until the marker is cleared.
            .filter(|t| !state.terminal_failures.contains_key(&t.id))
            // Claimable: no live claim. The mock omits TTL-based
            // takeover (real impl handles it via stale_cutoff); the
            // invariant tests below seed `state.claims` directly
            // when they need to exercise that path.
            .filter(|t| !state.claims.contains_key(&t.id))
            .map(|t| TenantProvisioningRow {
                id: t.id,
                created_at: t.created_at,
                claimed_by: worker_id,
            })
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        out.truncate(limit);
        for row in &out {
            state.claims.insert(row.id, worker_id);
        }
        Ok(out)
    }

    async fn count_children(
        &self,
        _scope: &AccessScope,
        parent_id: Uuid,
        filter: ChildCountFilter,
    ) -> Result<u64, DomainError> {
        let state = self.state.lock().expect("lock");
        let include_deleted = matches!(filter, ChildCountFilter::All);
        let count = state
            .tenants
            .values()
            .filter(|t| t.parent_id == Some(parent_id))
            .filter(|t| include_deleted || !matches!(t.status, TenantStatus::Deleted))
            .count();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    async fn schedule_deletion(
        &self,
        _scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, DomainError> {
        let mut state = self.state.lock().expect("lock");
        let existing = state
            .tenants
            .get(&id)
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {id} not found"),
                resource: id.to_string(),
            })?;
        if matches!(existing.status, TenantStatus::Deleted) {
            return Err(DomainError::Conflict {
                detail: format!("tenant {id} already deleted"),
            });
        }
        if matches!(existing.status, TenantStatus::Provisioning) {
            return Err(DomainError::Conflict {
                detail: format!(
                    "tenant {id} is in provisioning state; use the provisioning reaper to \
                     compensate, not soft-delete"
                ),
            });
        }
        let has_non_deleted_children = state
            .tenants
            .values()
            .any(|t| t.parent_id == Some(id) && !matches!(t.status, TenantStatus::Deleted));
        if has_non_deleted_children {
            return Err(DomainError::TenantHasChildren);
        }
        let tenant = state.tenants.get_mut(&id).expect("checked above");
        tenant.status = TenantStatus::Deleted;
        tenant.updated_at = now;
        // Mirror the real repo: `deleted_at` is the public-contract
        // tombstone (see `repo_impl.rs::schedule_deletion`).
        tenant.deleted_at = Some(now);
        let updated = tenant.clone();
        state.retention.insert(id, (now, retention));
        for row in &mut state.closure {
            if row.descendant_id == id {
                row.descendant_status = TenantStatus::Deleted.as_smallint();
            }
        }
        Ok(updated)
    }

    async fn mark_provisioning_terminal_failure(
        &self,
        _scope: &AccessScope,
        id: Uuid,
        claimed_by: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        // Mirror the SQL fence in `repo_impl::lifecycle::mark_provisioning_terminal_failure`:
        // refuse the mark unless this worker still holds the claim
        // AND the row is still `Provisioning`. Either invariant
        // failing means the caller's view is stale; report no-op
        // (`false`) so the caller treats it idempotently.
        Ok(mark_terminal_failure_with_status(
            &mut self.state.lock().expect("lock"),
            id,
            claimed_by,
            now,
            TenantStatus::Provisioning,
        ))
    }

    async fn mark_retention_terminal_failure(
        &self,
        _scope: &AccessScope,
        id: Uuid,
        claimed_by: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        // Mirror the SQL fence in `repo_impl::lifecycle::mark_retention_terminal_failure`:
        // refuse the mark unless this worker still holds the claim
        // AND the row is still `Deleted`. Symmetric to the
        // provisioning sibling above; backed by the same
        // `state.terminal_failures` map because a tenant row can
        // only be in one of `Provisioning` / `Deleted` at any
        // given moment.
        Ok(mark_terminal_failure_with_status(
            &mut self.state.lock().expect("lock"),
            id,
            claimed_by,
            now,
            TenantStatus::Deleted,
        ))
    }

    async fn check_hard_delete_eligibility(
        &self,
        _scope: &AccessScope,
        id: Uuid,
        claimed_by: Uuid,
    ) -> Result<HardDeleteEligibility, DomainError> {
        // Mirror of the production preflight in
        // `infra::storage::repo_impl::lifecycle::check_hard_delete_eligibility`
        // — read-only structural check before the retention pipeline
        // runs cascade hooks + IdP `deprovision_tenant`. Keeping the
        // fake faithful prevents service-level idempotency tests from
        // passing against an under-specified fake.
        let state = self.state.lock().expect("lock");
        let Some(row) = state.tenants.get(&id) else {
            return Ok(HardDeleteEligibility::NotEligible);
        };
        if !matches!(row.status, TenantStatus::Deleted) || !state.retention.contains_key(&id) {
            return Ok(HardDeleteEligibility::NotEligible);
        }
        if state.claims.get(&id).copied() != Some(claimed_by) {
            return Ok(HardDeleteEligibility::NotEligible);
        }
        let has_children = state.tenants.values().any(|t| t.parent_id == Some(id));
        if has_children {
            return Ok(HardDeleteEligibility::DeferredChildPresent);
        }
        Ok(HardDeleteEligibility::Eligible)
    }

    async fn hard_delete_one(
        &self,
        _scope: &AccessScope,
        id: Uuid,
        claimed_by: Uuid,
    ) -> Result<HardDeleteOutcome, DomainError> {
        let mut state = self.state.lock().expect("lock");
        let existing = state.tenants.get(&id).cloned();
        let Some(row) = existing else {
            return Ok(HardDeleteOutcome::Cleaned);
        };
        if !matches!(row.status, TenantStatus::Deleted) || !state.retention.contains_key(&id) {
            return Ok(HardDeleteOutcome::NotEligible);
        }
        // Claim fence carried through the final delete — mirrors
        // production. Without this, a peer that re-claimed the row
        // mid-tick would still see this worker's `hard_delete_one`
        // proceed and double up the cascade.
        if state.claims.get(&id).copied() != Some(claimed_by) {
            return Ok(HardDeleteOutcome::NotEligible);
        }
        // Child-existence guard.
        let has_children = state.tenants.values().any(|t| t.parent_id == Some(id));
        if has_children {
            return Ok(HardDeleteOutcome::DeferredChildPresent);
        }
        state
            .closure
            .retain(|r| r.ancestor_id != id && r.descendant_id != id);
        state.metadata.retain(|(tid, _)| *tid != id);
        state.tenants.remove(&id);
        state.retention.remove(&id);
        state.claims.remove(&id);
        state.terminal_failures.remove(&id);
        Ok(HardDeleteOutcome::Cleaned)
    }

    async fn is_descendant(
        &self,
        _scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, DomainError> {
        let state = self.state.lock().expect("lock");
        Ok(state
            .closure
            .iter()
            .any(|r| r.ancestor_id == ancestor && r.descendant_id == descendant))
    }

    /// Integrity-audit fake.
    ///
    /// Default (`NextAuditOutcome::Ok`): the in-memory state never
    /// violates any invariant the classifier pipeline checks (closure
    /// is rebuilt from `parent_id` walks on every write, status mirrors
    /// the tenant row), so an empty violation list matches a clean
    /// snapshot.
    ///
    /// Scripted (`Violations(_)` / `Err(_)`): set via
    /// [`Self::set_audit_violations`] / [`Self::set_audit_error`] to
    /// drive the service-layer rebucketing + error-propagation paths
    /// that the trivial default cannot exercise. Tests that need to
    /// drive the production classifier directly construct an
    /// `infra::storage::integrity::Snapshot` and invoke `run_classifiers`
    /// instead of going through the trait.
    async fn run_integrity_check_for_scope(
        &self,
        _scope: &AccessScope,
        _integrity_scope: IntegrityScope,
    ) -> Result<Vec<(IntegrityCategory, Violation)>, DomainError> {
        let outcome = std::mem::take(&mut self.state.lock().expect("lock").next_audit_outcome);
        match outcome {
            NextAuditOutcome::Ok => Ok(Vec::new()),
            NextAuditOutcome::Violations(pairs) => Ok(pairs),
            NextAuditOutcome::Err(err) => Err(err),
        }
    }

    /// Test-side analogue for the production repair planner.
    /// Consumes the dedicated one-shot `next_repair_outcome` queue
    /// (independent of [`Self::run_integrity_check_for_scope`]'s
    /// `next_audit_outcome`) so service-layer tests can script a
    /// `check → auto_after_check → repair` flow without one
    /// `mem::take` draining the other's outcome.
    ///
    /// Behaviour:
    ///
    /// * `NextAuditOutcome::Ok` (default) → empty `RepairReport`
    ///   with all derivable + deferred categories at zero (matches
    ///   a clean snapshot).
    /// * `NextAuditOutcome::Violations(pairs)` → buckets each pair
    ///   by [`IntegrityCategory::is_derivable`] using the same
    ///   per-category collapsing the production planner applies:
    ///   `DescendantStatusDivergence` is one logical update per
    ///   descendant (matches `RepairPlan::status_updates`), so
    ///   multiple stale closure rows for the same descendant
    ///   collapse to one count rather than `n`. Both vectors carry
    ///   one entry per category in fixed order with zero counts for
    ///   absent categories.
    /// * `NextAuditOutcome::Err(err)` → propagated verbatim.
    async fn repair_derivable_closure_violations(
        &self,
        _scope: &AccessScope,
        integrity_scope: IntegrityScope,
    ) -> Result<RepairReport, DomainError> {
        let outcome = std::mem::take(&mut self.state.lock().expect("lock").next_repair_outcome);
        match outcome {
            NextAuditOutcome::Ok => Ok(RepairReport {
                scope: Some(integrity_scope),
                repaired_per_category: derivable_zero_buckets(),
                deferred_per_category: deferred_zero_buckets(),
            }),
            NextAuditOutcome::Violations(pairs) => {
                let mut repaired: HashMap<IntegrityCategory, usize> = HashMap::new();
                let mut deferred: HashMap<IntegrityCategory, usize> = HashMap::new();
                // Per-descendant collapse for `DescendantStatusDivergence`
                // mirroring `RepairPlan::status_updates` (one bulk
                // update per descendant, not one per closure row).
                // Without this, a script seeding two stale rows for
                // the same descendant would surface count=2 here vs.
                // count=1 in the real repo, drifting telemetry
                // assertions even when the service layer is correct.
                let mut status_div_descendants: HashSet<Uuid> = HashSet::new();
                for (cat, viol) in pairs {
                    if matches!(cat, IntegrityCategory::DescendantStatusDivergence)
                        && let Some(tid) = viol.tenant_id
                        && !status_div_descendants.insert(tid)
                    {
                        continue;
                    }
                    if cat.is_derivable() {
                        *repaired.entry(cat).or_insert(0) += 1;
                    } else {
                        *deferred.entry(cat).or_insert(0) += 1;
                    }
                }
                Ok(RepairReport {
                    scope: Some(integrity_scope),
                    repaired_per_category: IntegrityCategory::all()
                        .into_iter()
                        .filter(|c| c.is_derivable())
                        .map(|c| (c, repaired.get(&c).copied().unwrap_or(0)))
                        .collect(),
                    deferred_per_category: IntegrityCategory::all()
                        .into_iter()
                        .filter(|c| !c.is_derivable())
                        .map(|c| (c, deferred.get(&c).copied().unwrap_or(0)))
                        .collect(),
                })
            }
            NextAuditOutcome::Err(err) => Err(err),
        }
    }
}

fn derivable_zero_buckets() -> Vec<(IntegrityCategory, usize)> {
    IntegrityCategory::all()
        .into_iter()
        .filter(|c| c.is_derivable())
        .map(|c| (c, 0))
        .collect()
}

fn deferred_zero_buckets() -> Vec<(IntegrityCategory, usize)> {
    IntegrityCategory::all()
        .into_iter()
        .filter(|c| !c.is_derivable())
        .map(|c| (c, 0))
        .collect()
}

/// Tests for fake-repository contract parity with the production repo.
#[cfg(test)]
mod repo_contract_tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::tenant::repo::TenantRepo;

    fn ts(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).expect("epoch")
    }

    fn tenant(id: Uuid, parent_id: Option<Uuid>, status: TenantStatus) -> TenantModel {
        let now = ts(1_700_000_000);
        TenantModel {
            id,
            parent_id,
            name: "tenant".to_owned(),
            status,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: u32::from(parent_id.is_some()),
            created_at: now,
            updated_at: now,
            deleted_at: matches!(status, TenantStatus::Deleted).then_some(now),
        }
    }

    fn new_tenant(id: Uuid, parent_id: Uuid) -> NewTenant {
        NewTenant {
            id,
            parent_id: Some(parent_id),
            name: "new".to_owned(),
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
        }
    }

    #[tokio::test]
    async fn list_children_empty_status_filter_uses_default_visible_set() {
        let root = Uuid::from_u128(0x100);
        let active = Uuid::from_u128(0x101);
        let suspended = Uuid::from_u128(0x102);
        let deleted = Uuid::from_u128(0x103);
        let repo = FakeTenantRepo::with_root(root);
        repo.insert_tenant_raw(tenant(active, Some(root), TenantStatus::Active));
        repo.insert_tenant_raw(tenant(suspended, Some(root), TenantStatus::Suspended));
        repo.insert_tenant_raw(tenant(deleted, Some(root), TenantStatus::Deleted));

        let query = ListChildrenQuery::new(root, Some(Vec::new()), 10, 0).expect("query");
        let page = repo
            .list_children(&AccessScope::allow_all(), &query)
            .await
            .expect("list");

        assert_eq!(
            page.items.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![active, suspended],
            "empty status filter must match production default: Active + Suspended"
        );
    }

    #[tokio::test]
    async fn insert_provisioning_duplicate_returns_already_exists() {
        let root = Uuid::from_u128(0x100);
        let repo = FakeTenantRepo::with_root(root);

        let err = repo
            .insert_provisioning(&AccessScope::allow_all(), &new_tenant(root, root))
            .await
            .expect_err("duplicate id rejected");

        assert!(
            matches!(err, DomainError::AlreadyExists { .. }),
            "duplicate id must mirror production unique-violation mapping: {err:?}"
        );
    }

    #[tokio::test]
    async fn insert_provisioning_rejects_deleted_parent() {
        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x101);
        let repo = FakeTenantRepo::with_root(root);
        {
            let mut state = repo.state.lock().expect("lock");
            state.tenants.get_mut(&root).expect("root").status = TenantStatus::Deleted;
        }

        let err = repo
            .insert_provisioning(&AccessScope::allow_all(), &new_tenant(child, root))
            .await
            .expect_err("deleted parent rejected");

        assert!(
            matches!(err, DomainError::Validation { .. }),
            "provisioning insert must re-check parent active status: {err:?}"
        );
    }

    #[tokio::test]
    async fn schedule_deletion_rejects_non_deleted_children() {
        let parent = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x101);
        let repo = FakeTenantRepo::with_root(parent);
        repo.insert_tenant_raw(tenant(child, Some(parent), TenantStatus::Active));

        let err = repo
            .schedule_deletion(
                &AccessScope::allow_all(),
                parent,
                ts(1_700_000_100),
                Some(Duration::from_secs(0)),
            )
            .await
            .expect_err("parent with child rejected");

        assert!(
            matches!(err, DomainError::TenantHasChildren),
            "fake repo must mirror production in-tx child guard: {err:?}"
        );
    }

    #[tokio::test]
    async fn hard_delete_one_clears_fake_side_state() {
        let id = Uuid::from_u128(0x100);
        let worker = Uuid::from_u128(0x200);
        let now = ts(1_700_000_100);
        let repo = FakeTenantRepo::new();
        repo.insert_tenant_raw(tenant(id, None, TenantStatus::Deleted));
        {
            let mut state = repo.state.lock().expect("lock");
            state
                .retention
                .insert(id, (now, Some(Duration::from_secs(0))));
            state.claims.insert(id, worker);
            state.terminal_failures.insert(id, now);
        }

        let outcome = repo
            .hard_delete_one(&AccessScope::allow_all(), id, worker)
            .await
            .expect("hard delete");

        assert!(
            matches!(outcome, HardDeleteOutcome::Cleaned),
            "eligible row should be hard-deleted"
        );
        let state = repo.state.lock().expect("lock");
        assert!(!state.tenants.contains_key(&id), "tenant row removed");
        assert!(
            !state.retention.contains_key(&id),
            "retention state removed"
        );
        assert!(!state.claims.contains_key(&id), "claim state removed");
        assert!(
            !state.terminal_failures.contains_key(&id),
            "terminal-failure state removed"
        );
    }

    /// Race window: the `create_child` saga's `IdP` call out-runs the
    /// reaper's `provisioning_timeout_secs`, the reaper claims the
    /// stuck `Provisioning` row, then the saga returns and tries to
    /// finalize. The activation MUST be rejected with `Conflict` so
    /// AM does not publish an `Active` row whose `IdP`-side state has
    /// been (or is being) torn down by the reaper.
    #[tokio::test]
    async fn activate_tenant_rejects_when_reaper_has_claimed_the_row() {
        use crate::domain::tenant::closure::build_activation_rows;

        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x200);
        let reaper = Uuid::from_u128(0x999);
        let repo = FakeTenantRepo::with_root(root);
        repo.insert_provisioning(&AccessScope::allow_all(), &new_tenant(child, root))
            .await
            .expect("insert provisioning");

        // Reaper times out on the in-flight provision and claims the
        // row. (Production: `repo_impl::retention::scan_stuck_provisioning`
        // sets `claimed_by`.)
        repo.seed_claim(child, reaper);

        let root_model = repo
            .find_by_id(&AccessScope::allow_all(), root)
            .await
            .expect("repo")
            .expect("root row");
        let closure_rows = build_activation_rows(child, TenantStatus::Active, false, &[root_model]);

        let err = repo
            .activate_tenant(&AccessScope::allow_all(), child, &closure_rows, &[])
            .await
            .expect_err("activation must reject reaper-claimed row");
        assert!(
            matches!(err, DomainError::Conflict { .. }),
            "reaper-claim fence must surface as Conflict, got {err:?}"
        );

        // Row must remain `Provisioning` so the reaper still owns
        // compensation. Activation MUST NOT have flipped it to Active.
        let row = repo
            .find_by_id_unchecked(child)
            .expect("provisioning row still present");
        assert_eq!(row.status, TenantStatus::Provisioning);
    }

    /// Sibling race: a peer reaper has classified the in-flight
    /// provision as `DeprovisionFailure::Terminal` and stamped
    /// `terminal_failure_at`, parking the row out of the retry loop.
    /// A late saga finalization MUST observe the parked marker and
    /// refuse to activate, so operators retain their action-required
    /// signal instead of having the row silently moved to `Active`.
    #[tokio::test]
    async fn activate_tenant_rejects_when_terminal_failure_at_is_stamped() {
        use crate::domain::tenant::closure::build_activation_rows;

        let root = Uuid::from_u128(0x100);
        let child = Uuid::from_u128(0x300);
        let repo = FakeTenantRepo::with_root(root);
        repo.insert_provisioning(&AccessScope::allow_all(), &new_tenant(child, root))
            .await
            .expect("insert provisioning");

        // Stamp the parking marker directly on the row (production:
        // a peer reaper's `mark_provisioning_terminal_failure`).
        {
            let mut state = repo.state.lock().expect("lock");
            state.terminal_failures.insert(child, ts(1_700_000_500));
        }

        let root_model = repo
            .find_by_id(&AccessScope::allow_all(), root)
            .await
            .expect("repo")
            .expect("root row");
        let closure_rows = build_activation_rows(child, TenantStatus::Active, false, &[root_model]);

        let err = repo
            .activate_tenant(&AccessScope::allow_all(), child, &closure_rows, &[])
            .await
            .expect_err("activation must reject terminal-stamped row");
        assert!(
            matches!(err, DomainError::Conflict { .. }),
            "terminal_failure fence must surface as Conflict, got {err:?}"
        );

        let row = repo
            .find_by_id_unchecked(child)
            .expect("provisioning row still present");
        assert_eq!(
            row.status,
            TenantStatus::Provisioning,
            "terminal-stamped row must NOT be activated by a late saga"
        );
    }
}

/// Tests for the retention-claim ownership invariant.
///
/// `repo_impl::clear_retention_claim` filters its UPDATE on
/// `WHERE id = ? AND claimed_by = ?` so a worker whose TTL elapsed
/// cannot revert a peer's live claim (see the SQL-side comment at
/// `infra/storage/repo_impl.rs:2330-2333`). The tests below pin the
/// same fence on the in-memory mock so service-layer regressions
/// (anything that depends on the trait contract — retention pipeline,
/// reaper, single-flight gate) trip locally without requiring the
/// real-DB integration scaffold from `tests/retention_integration.rs`.
/// A SQL-level test for the same predicate is to be added in that
/// file once the testcontainers scaffold lands.
#[cfg(test)]
mod claim_invariant_tests {
    use super::*;
    use crate::domain::tenant::repo::TenantRepo;

    fn ts(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).expect("epoch")
    }

    fn deleted_tenant(id: Uuid, scheduled_at: OffsetDateTime) -> TenantModel {
        TenantModel {
            id,
            parent_id: None,
            name: "t".to_owned(),
            status: TenantStatus::Deleted,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 0,
            created_at: scheduled_at,
            updated_at: scheduled_at,
            deleted_at: Some(scheduled_at),
        }
    }

    fn seed_due_deleted(repo: &FakeTenantRepo, id: Uuid, scheduled_at: OffsetDateTime) {
        seed_due_deleted_at_depth(repo, id, scheduled_at, 0);
    }

    fn seed_due_deleted_at_depth(
        repo: &FakeTenantRepo,
        id: Uuid,
        scheduled_at: OffsetDateTime,
        depth: u32,
    ) {
        let mut tenant = deleted_tenant(id, scheduled_at);
        tenant.depth = depth;
        let mut state = repo.state.lock().expect("lock");
        state.tenants.insert(id, tenant);
        state
            .retention
            .insert(id, (scheduled_at, Some(Duration::from_mins(1))));
    }

    #[tokio::test]
    async fn scan_retention_due_records_claim_in_state() {
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let scheduled = ts(1_000_000);
        seed_due_deleted(&repo, id, scheduled);

        let now = scheduled + time::Duration::seconds(120);
        let rows = repo
            .scan_retention_due(&AccessScope::allow_all(), now, Duration::from_mins(1), 10)
            .await
            .expect("scan");
        assert_eq!(rows.len(), 1, "single due row expected");
        let claim_token = rows[0].claimed_by;

        let state = repo.state.lock().expect("lock");
        assert_eq!(
            state.claims.get(&id),
            Some(&claim_token),
            "scan_retention_due must persist the worker token in state.claims so \
             clear_retention_claim has something to fence against"
        );
    }

    #[tokio::test]
    async fn scan_retention_due_matches_production_order() {
        let repo = FakeTenantRepo::new();
        let deep = Uuid::from_u128(0x10);
        let older_low_id = Uuid::from_u128(0x20);
        let older_high_id = Uuid::from_u128(0x30);
        let newer_lower_id = Uuid::from_u128(0x05);
        let shallow = Uuid::from_u128(0x01);

        seed_due_deleted_at_depth(&repo, deep, ts(300), 3);
        seed_due_deleted_at_depth(&repo, older_high_id, ts(100), 2);
        seed_due_deleted_at_depth(&repo, older_low_id, ts(100), 2);
        seed_due_deleted_at_depth(&repo, newer_lower_id, ts(200), 2);
        seed_due_deleted_at_depth(&repo, shallow, ts(50), 1);

        let rows = repo
            .scan_retention_due(
                &AccessScope::allow_all(),
                ts(1_000),
                Duration::from_mins(1),
                10,
            )
            .await
            .expect("scan");

        assert_eq!(
            rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![deep, older_low_id, older_high_id, newer_lower_id, shallow],
            "fake repo must mirror production order: depth DESC, \
             deletion_scheduled_at ASC, id ASC"
        );
    }

    #[tokio::test]
    async fn scan_retention_due_skips_already_claimed_rows() {
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let scheduled = ts(1_000_000);
        seed_due_deleted(&repo, id, scheduled);

        let now = scheduled + time::Duration::seconds(120);
        let rows_a = repo
            .scan_retention_due(&AccessScope::allow_all(), now, Duration::from_mins(1), 10)
            .await
            .expect("scan a");
        assert_eq!(rows_a.len(), 1, "first replica should claim the row");
        let owner_a = rows_a[0].claimed_by;

        let rows_b = repo
            .scan_retention_due(&AccessScope::allow_all(), now, Duration::from_mins(1), 10)
            .await
            .expect("scan b");
        assert!(
            rows_b.is_empty(),
            "second replica must not see a row already claimed by replica A"
        );

        let state = repo.state.lock().expect("lock");
        assert_eq!(
            state.claims.get(&id),
            Some(&owner_a),
            "second scan must not overwrite replica A's live claim"
        );
    }

    #[tokio::test]
    async fn clear_retention_claim_clears_when_worker_still_owns_it() {
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let scheduled = ts(1_000_000);
        seed_due_deleted(&repo, id, scheduled);

        let now = scheduled + time::Duration::seconds(120);
        let rows = repo
            .scan_retention_due(&AccessScope::allow_all(), now, Duration::from_mins(1), 10)
            .await
            .expect("scan");
        let owner = rows[0].claimed_by;

        repo.clear_retention_claim(&AccessScope::allow_all(), id, owner)
            .await
            .expect("clear ok");

        let state = repo.state.lock().expect("lock");
        assert!(
            !state.claims.contains_key(&id),
            "owner-issued clear must remove the claim"
        );
    }

    #[tokio::test]
    async fn clear_retention_claim_is_no_op_after_peer_takeover() {
        // Pin the invariant from `retention.rs:28-33`: a worker whose
        // TTL elapsed and whose claim was reassigned to a peer MUST
        // NOT be able to revert the peer's live claim by calling
        // `clear_retention_claim` with its own (now-stale) worker_id.
        // SQL-side, the predicate `claimed_by = worker_id` makes the
        // UPDATE a no-op; this test pins the same behaviour on the
        // mock so service-layer flows that depend on it (failed
        // `hard_delete_one` outcomes that reach `clear_retention_claim`
        // after a TTL takeover) cannot regress silently.
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let scheduled = ts(1_000_000);
        seed_due_deleted(&repo, id, scheduled);

        let now = scheduled + time::Duration::seconds(120);
        let rows_a = repo
            .scan_retention_due(&AccessScope::allow_all(), now, Duration::from_mins(1), 10)
            .await
            .expect("scan a");
        let worker_a = rows_a[0].claimed_by;

        // Simulate peer takeover (TTL elapsed, second worker re-scans
        // and overwrites the claim). The real repo achieves this
        // atomically inside the claim UPDATE; the mock just rewrites
        // the entry directly because it has no separate TTL machinery.
        let worker_b = Uuid::new_v4();
        {
            let mut state = repo.state.lock().expect("lock");
            state.claims.insert(id, worker_b);
        }

        // Worker A returns from a slow code path and tries to clear
        // its (now-stale) claim. The fence MUST treat this as a no-op.
        repo.clear_retention_claim(&AccessScope::allow_all(), id, worker_a)
            .await
            .expect("stale clear ok (no-op)");

        let state = repo.state.lock().expect("lock");
        assert_eq!(
            state.claims.get(&id),
            Some(&worker_b),
            "peer's live claim must survive a stale clear from worker A"
        );
    }

    fn provisioning_tenant(id: Uuid, created_at: OffsetDateTime) -> TenantModel {
        TenantModel {
            id,
            parent_id: None,
            name: "stuck".to_owned(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 0,
            created_at,
            updated_at: created_at,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn scan_stuck_provisioning_records_claim_in_state() {
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let created = ts(1_000_000);
        repo.insert_tenant_raw(provisioning_tenant(id, created));

        let now = created + time::Duration::seconds(600);
        let older_than = now - time::Duration::seconds(60);
        let rows = repo
            .scan_stuck_provisioning(&AccessScope::allow_all(), now, older_than, 10)
            .await
            .expect("scan");
        assert_eq!(rows.len(), 1, "single stuck row expected");
        let claim_token = rows[0].claimed_by;

        let state = repo.state.lock().expect("lock");
        assert_eq!(
            state.claims.get(&id),
            Some(&claim_token),
            "scan_stuck_provisioning must persist the worker token in state.claims so \
             the reaper can release it through clear_retention_claim"
        );
    }

    #[tokio::test]
    async fn scan_stuck_provisioning_skips_already_claimed_rows() {
        // Two replicas scanning the same window: the second one MUST
        // see the row as not-claimable. The mock's claim-namespace is
        // shared with retention; the prod-side TTL takeover lives in
        // `repo_impl::scan_stuck_provisioning` and is exercised by
        // the integration scaffold, not here.
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let created = ts(1_000_000);
        repo.insert_tenant_raw(provisioning_tenant(id, created));

        let now = created + time::Duration::seconds(600);
        let older_than = now - time::Duration::seconds(60);

        let rows_a = repo
            .scan_stuck_provisioning(&AccessScope::allow_all(), now, older_than, 10)
            .await
            .expect("scan a");
        assert_eq!(rows_a.len(), 1, "first replica should claim the row");

        let rows_b = repo
            .scan_stuck_provisioning(&AccessScope::allow_all(), now, older_than, 10)
            .await
            .expect("scan b");
        assert!(
            rows_b.is_empty(),
            "second replica must not see a row already claimed by replica A"
        );
    }

    #[tokio::test]
    async fn scan_stuck_provisioning_releases_via_clear_retention_claim() {
        // Pin the cross-pipeline contract: the reaper releases its
        // claim through `clear_retention_claim` (the same primitive
        // retention pipeline uses), so a peer worker can re-claim
        // after the release without waiting for TTL.
        let repo = FakeTenantRepo::new();
        let id = Uuid::from_u128(0x1);
        let created = ts(1_000_000);
        repo.insert_tenant_raw(provisioning_tenant(id, created));

        let now = created + time::Duration::seconds(600);
        let older_than = now - time::Duration::seconds(60);

        let rows = repo
            .scan_stuck_provisioning(&AccessScope::allow_all(), now, older_than, 10)
            .await
            .expect("scan");
        let owner = rows[0].claimed_by;

        repo.clear_retention_claim(&AccessScope::allow_all(), id, owner)
            .await
            .expect("clear ok");

        let rows_b = repo
            .scan_stuck_provisioning(&AccessScope::allow_all(), now, older_than, 10)
            .await
            .expect("scan after release");
        assert_eq!(
            rows_b.len(),
            1,
            "row becomes claimable again after the owner releases its claim"
        );
    }
}
