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
use crate::domain::tenant::model::{ChildCountFilter, NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
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
        let top = usize::try_from(query.top).unwrap_or(usize::MAX);
        let paged: Vec<TenantModel> = items.into_iter().skip(skip).take(top).collect();
        Ok(TenantPage {
            items: paged,
            top: query.top,
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
        let parent_id = tenant.parent_id.ok_or_else(|| DomainError::Validation {
            detail: format!("child tenant {} provisioning requires parent_id", tenant.id),
        })?;
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
    ) -> Result<(), DomainError> {
        let mut state = self.state.lock().expect("lock");
        let found = state.tenants.get(&tenant_id).cloned();
        match found {
            Some(t) if matches!(t.status, TenantStatus::Provisioning) => {
                state.tenants.remove(&tenant_id);
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
        if let Some(new_status) = patch.status.map(TenantStatus::from) {
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
            // No-op rejection mirrors the production defense-in-depth
            // check: a PATCH that resends the current status would
            // otherwise fire the closure-status rewrite below for no
            // observable change.
            if tenant.status == new_status {
                return Err(DomainError::Conflict {
                    detail: format!(
                        "tenant {tenant_id}: PATCH status no-op \
                         (current and target are both {new_status:?})"
                    ),
                });
            }
        }

        if let Some(ref new_name) = patch.name {
            tenant.name = new_name.clone();
        }
        if let Some(new_status) = patch.status {
            tenant.status = TenantStatus::from(new_status);
        }
        // Production stamps `updated_at = now()` inside the same
        // transaction; mirror it so tests that read back the row see
        // the same timestamp behavior.
        tenant.updated_at = OffsetDateTime::now_utc();
        let updated = tenant.clone();
        if patch.status.is_some() {
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
        let mut state = self.state.lock().expect("lock");
        if state.claims.get(&id) != Some(&claimed_by) {
            return Ok(false);
        }
        let Some(tenant) = state.tenants.get(&id) else {
            return Ok(false);
        };
        if !matches!(tenant.status, TenantStatus::Provisioning) {
            return Ok(false);
        }
        state.terminal_failures.insert(id, now);
        Ok(true)
    }

    async fn hard_delete_one(
        &self,
        _scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, DomainError> {
        let mut state = self.state.lock().expect("lock");
        let existing = state.tenants.get(&id).cloned();
        let Some(row) = existing else {
            return Ok(HardDeleteOutcome::Cleaned);
        };
        if !matches!(row.status, TenantStatus::Deleted) || !state.retention.contains_key(&id) {
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
            .hard_delete_one(&AccessScope::allow_all(), id)
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
