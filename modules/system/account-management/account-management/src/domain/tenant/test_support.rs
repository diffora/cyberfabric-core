//! In-crate test support surface.
//!
//! Phase 1 hosted its `FakeTenantRepo` + `FakeIdpProvisioner` fakes
//! inside the `#[cfg(test)] mod tests` in `service.rs` — they were only
//! visible inside that file. Phase 2 adds this sibling module so the
//! REST handler tests under `api/tenants/handlers.rs` can exercise the
//! service end-to-end without any DB / network. Everything here is
//! gated on `cfg(test)` so the production binary does not ship these
//! types.
//!
//! The types re-exported here deliberately mirror the shapes used in
//! `service.rs::tests` so a single review of the closure-invariant
//! fakes applies to both test surfaces.

#![cfg(test)]
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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, PolicyEnforcer,
    models::{EvaluationRequest, EvaluationResponse, EvaluationResponseContext},
};
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::idp::provisioner::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::integrity::IntegrityScope;
use crate::domain::tenant::model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::resource_checker::InertResourceOwnershipChecker;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};
use crate::domain::tenant::service::TenantService;

/// Test injection — what the next call to `activate_tenant` should
/// return. Mirrors the typed `Mutex<FakeOutcome>` shape used by
/// `FakeIdpProvisioner` (one-shot toggle that resets to `Ok` after
/// firing). Replaces an earlier `fail_next_activation: bool` so future
/// variants can carry typed payload (e.g., a different `AmError`
/// sub-code) without growing parallel boolean flags.
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

    /// Arm the next `activate_tenant` call to return
    /// `AmError::Internal { diagnostic: detail }` exactly once. Used
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

    /// Seed one violation per [`crate::domain::tenant::integrity::IntegrityCategory`].
    /// Used by F4 to assert `check_hierarchy_integrity` surfaces all
    /// categories on a deliberately corrupt fixture. Each tenant
    /// is intentionally narrow — we choose `depth = 0` for orphan-style
    /// rows so the depth-walk classifier returns `expected = 0` and we
    /// don't accidentally double-count `DepthMismatch`.
    pub fn seed_corrupt_hierarchy_with_one_violation_per_category(&self, root: Uuid) {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_500).expect("epoch");
        let mut state = self.state.lock().expect("lock");
        seed_orphan_child(&mut state, now);
        seed_broken_parent(&mut state, root, now);
        seed_depth_mismatch(&mut state, root, now);
        seed_cycle_detected(&mut state, now);
        seed_root_count_anomaly(&mut state, now);
        seed_missing_self_row(&mut state, root, now);
        seed_closure_coverage_gap(&mut state, root, now);
        seed_stale_closure_row(&mut state);
        seed_barrier_divergence(&mut state, root, now);
        seed_descendant_status_divergence(&mut state, root, now);
    }
}

// ---- per-category corruption seeders ---------------------------------
// Each helper mutates `state` to introduce exactly one violation of the
// labelled `IntegrityCategory`. They share `now` so timestamps are
// stable across the seeded snapshot.

fn seed_orphan_child(state: &mut RepoState, now: OffsetDateTime) {
    // `OrphanedChild` — parent_id points at a tenant that does not
    // exist; depth=0 to avoid a DepthMismatch double-count.
    let orphan = Uuid::from_u128(0xC301);
    state.tenants.insert(
        orphan,
        TenantModel {
            id: orphan,
            parent_id: Some(Uuid::from_u128(0xDEAD_BEEF)),
            name: "orphan".into(),
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
        ancestor_id: orphan,
        descendant_id: orphan,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_broken_parent(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `BrokenParentReference` — Active child whose parent is Deleted.
    // Both walked-depth and stored-depth = 1, so no DepthMismatch.
    let dead_parent = Uuid::from_u128(0xC400);
    let broken = Uuid::from_u128(0xC401);
    state.tenants.insert(
        dead_parent,
        TenantModel {
            id: dead_parent,
            parent_id: Some(root),
            name: "dead-parent".into(),
            status: TenantStatus::Deleted,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: Some(now),
        },
    );
    state.tenants.insert(
        broken,
        TenantModel {
            id: broken,
            parent_id: Some(dead_parent),
            name: "broken-child".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 2,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: dead_parent,
        descendant_id: dead_parent,
        barrier: 0,
        descendant_status: TenantStatus::Deleted.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: dead_parent,
        barrier: 0,
        descendant_status: TenantStatus::Deleted.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: broken,
        descendant_id: broken,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: dead_parent,
        descendant_id: broken,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: broken,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_depth_mismatch(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `DepthMismatch` — stored depth wildly out of step with the walk
    // (parent=root, expected=1, stored=99).
    let depth_bad = Uuid::from_u128(0xC500);
    state.tenants.insert(
        depth_bad,
        TenantModel {
            id: depth_bad,
            parent_id: Some(root),
            name: "depth-bad".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 99,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: depth_bad,
        descendant_id: depth_bad,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: depth_bad,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_cycle_detected(state: &mut RepoState, now: OffsetDateTime) {
    // `Cycle` — two active tenants point at each other. Self-rows are
    // present so the cycle category itself is the intended tree-shape signal.
    let a = Uuid::from_u128(0xC550);
    let b = Uuid::from_u128(0xC551);
    state.tenants.insert(
        a,
        TenantModel {
            id: a,
            parent_id: Some(b),
            name: "cycle-a".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.tenants.insert(
        b,
        TenantModel {
            id: b,
            parent_id: Some(a),
            name: "cycle-b".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: a,
        descendant_id: a,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: b,
        descendant_id: b,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_root_count_anomaly(state: &mut RepoState, now: OffsetDateTime) {
    // `RootCountAnomaly` — second tenant with parent_id = None.
    let second_root = Uuid::from_u128(0xC600);
    state.tenants.insert(
        second_root,
        TenantModel {
            id: second_root,
            parent_id: None,
            name: "second-root".into(),
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
        ancestor_id: second_root,
        descendant_id: second_root,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_missing_self_row(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `MissingClosureSelfRow` — SDK-visible tenant with NO (id, id)
    // closure entry. Add the (root, id) ancestor row so we don't also
    // trigger ClosureCoverageGap from the missing self-row.
    let no_self_row = Uuid::from_u128(0xC700);
    state.tenants.insert(
        no_self_row,
        TenantModel {
            id: no_self_row,
            parent_id: Some(root),
            name: "no-self-row".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: no_self_row,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_closure_coverage_gap(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `ClosureCoverageGap` — tenant has its self-row but the (root, id)
    // strict-ancestor row is missing.
    let gap = Uuid::from_u128(0xC800);
    state.tenants.insert(
        gap,
        TenantModel {
            id: gap,
            parent_id: Some(root),
            name: "coverage-gap".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: gap,
        descendant_id: gap,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_stale_closure_row(state: &mut RepoState) {
    // `StaleClosureRow` — closure row whose ancestor + descendant ids
    // both refer to non-existent tenants.
    let stale_a = Uuid::from_u128(0xCA01);
    let stale_d = Uuid::from_u128(0xCA02);
    state.closure.push(ClosureRow {
        ancestor_id: stale_a,
        descendant_id: stale_d,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_barrier_divergence(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `BarrierColumnDivergence` — strict (root, id) row carries
    // barrier=1 even though no tenant on the path is self-managed.
    let barrier_bad = Uuid::from_u128(0xCB00);
    state.tenants.insert(
        barrier_bad,
        TenantModel {
            id: barrier_bad,
            parent_id: Some(root),
            name: "barrier-bad".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: barrier_bad,
        descendant_id: barrier_bad,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: barrier_bad,
        barrier: 1, // wrong — no self-managed on path
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

fn seed_descendant_status_divergence(state: &mut RepoState, root: Uuid, now: OffsetDateTime) {
    // `DescendantStatusDivergence` — closure row's descendant_status is
    // Suspended even though the live tenant is Active.
    let status_bad = Uuid::from_u128(0xCC00);
    state.tenants.insert(
        status_bad,
        TenantModel {
            id: status_bad,
            parent_id: Some(root),
            name: "status-bad".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        },
    );
    state.closure.push(ClosureRow {
        ancestor_id: status_bad,
        descendant_id: status_bad,
        barrier: 0,
        descendant_status: TenantStatus::Suspended.as_smallint(),
    });
    state.closure.push(ClosureRow {
        ancestor_id: root,
        descendant_id: status_bad,
        barrier: 0,
        descendant_status: TenantStatus::Active.as_smallint(),
    });
}

/// Compute the set of tenant ids visible to `scope` on the `tenants`
/// table, matching production semantics: the `SeaORM` `Scopable` derive
/// declares `tenant_col = "id"`, so the secure-extension filter
/// translates `AccessScope::for_tenant(t)` into `WHERE tenants.id = t`
/// — only the row whose own id equals the scope's tenant matches. It
/// does **not** transparently expand to descendants via
/// `tenant_closure`. The service layer is the authoritative gate
/// (`TenantService::ensure_caller_reaches`), and post-gate repo calls
/// pass `AccessScope::allow_all()` so this filter is a no-op in
/// practice; the strict per-row variant is preserved here only so
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
    ) -> Result<Option<TenantModel>, AmError> {
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
    ) -> Result<TenantPage, AmError> {
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
            .filter(|t| match &query.status_filter {
                Some(allowed) => allowed.contains(&t.status),
                // Default: active and suspended only, matching repo_impl default.
                None => !matches!(t.status, TenantStatus::Deleted),
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
    ) -> Result<TenantModel, AmError> {
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
            return Err(AmError::Conflict {
                detail: format!("tenant {} already exists", tenant.id),
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
    ) -> Result<TenantModel, AmError> {
        let mut state = self.state.lock().expect("lock");
        // F3 — finalization-TX failure injection: consume the typed
        // outcome toggle and short-circuit before mutating any state,
        // mirroring a SERIALIZABLE TX abort that leaves the
        // provisioning row in place for the reaper.
        let outcome = std::mem::take(&mut state.next_activation_outcome);
        if let NextActivationOutcome::InternalErr(detail) = outcome {
            return Err(AmError::Internal {
                diagnostic: format!("fake activate_tenant aborted for {tenant_id}: {detail}"),
            });
        }
        let tenant = state
            .tenants
            .get_mut(&tenant_id)
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {tenant_id} not found for activation"),
            })?;
        if !matches!(tenant.status, TenantStatus::Provisioning) {
            return Err(AmError::Conflict {
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
    ) -> Result<(), AmError> {
        let mut state = self.state.lock().expect("lock");
        let found = state.tenants.get(&tenant_id).cloned();
        match found {
            Some(t) if matches!(t.status, TenantStatus::Provisioning) => {
                state.tenants.remove(&tenant_id);
                Ok(())
            }
            Some(_) => Err(AmError::Conflict {
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
    ) -> Result<TenantModel, AmError> {
        let mut state = self.state.lock().expect("lock");
        let visible = visible_ids_for(&state, scope);
        if let Some(ref vis) = visible
            && !vis.contains(&tenant_id)
        {
            return Err(AmError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
            });
        }
        let tenant = state
            .tenants
            .get_mut(&tenant_id)
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
            })?;
        if let Some(ref new_name) = patch.name {
            tenant.name = new_name.clone();
        }
        if let Some(new_status) = patch.status {
            tenant.status = new_status;
        }
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

    async fn load_strict_ancestors_of_parent(
        &self,
        _scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, AmError> {
        let state = self.state.lock().expect("lock");
        let mut chain = Vec::new();
        let mut cursor_id = Some(parent_id);
        while let Some(pid) = cursor_id {
            let parent = state
                .tenants
                .get(&pid)
                .cloned()
                .ok_or_else(|| AmError::NotFound {
                    detail: format!("ancestor {pid} missing while walking chain"),
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
    ) -> Result<Vec<TenantRetentionRow>, AmError> {
        let state = self.state.lock().expect("lock");
        let mut out: Vec<TenantRetentionRow> = state
            .tenants
            .values()
            .filter(|t| matches!(t.status, TenantStatus::Deleted))
            .filter_map(|t| {
                state.retention.get(&t.id).map(|(sched, win)| {
                    let retention = win.unwrap_or(default_retention);
                    TenantRetentionRow {
                        id: t.id,
                        depth: t.depth,
                        deletion_scheduled_at: *sched,
                        retention_window: retention,
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
        // Stable leaf-first ordering.
        out.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.id.cmp(&b.id)));
        out.truncate(limit);
        Ok(out)
    }

    async fn clear_retention_claim(
        &self,
        _scope: &AccessScope,
        _tenant_id: Uuid,
    ) -> Result<(), AmError> {
        Ok(())
    }

    async fn scan_stuck_provisioning(
        &self,
        _scope: &AccessScope,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, AmError> {
        let state = self.state.lock().expect("lock");
        let mut out: Vec<TenantProvisioningRow> = state
            .tenants
            .values()
            .filter(|t| matches!(t.status, TenantStatus::Provisioning))
            .filter(|t| t.created_at <= older_than)
            .map(|t| TenantProvisioningRow {
                id: t.id,
                created_at: t.created_at,
            })
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        out.truncate(limit);
        Ok(out)
    }

    async fn count_children(
        &self,
        _scope: &AccessScope,
        parent_id: Uuid,
        include_deleted: bool,
    ) -> Result<u64, AmError> {
        let state = self.state.lock().expect("lock");
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
    ) -> Result<TenantModel, AmError> {
        let mut state = self.state.lock().expect("lock");
        let tenant = state
            .tenants
            .get_mut(&id)
            .ok_or_else(|| AmError::NotFound {
                detail: format!("tenant {id} not found"),
            })?;
        if matches!(tenant.status, TenantStatus::Deleted) {
            return Err(AmError::Conflict {
                detail: format!("tenant {id} already deleted"),
            });
        }
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

    async fn hard_delete_one(
        &self,
        _scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, AmError> {
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
        state.tenants.remove(&id);
        state.retention.remove(&id);
        Ok(HardDeleteOutcome::Cleaned)
    }

    async fn load_tree_and_closure_for_scope(
        &self,
        _scope: &AccessScope,
        integrity_scope: IntegrityScope,
        tenants_cap: Option<usize>,
    ) -> Result<(Vec<TenantModel>, Vec<ClosureRow>), AmError> {
        let state = self.state.lock().expect("lock");
        let (tenants, closure): (Vec<_>, Vec<_>) = match integrity_scope {
            IntegrityScope::Whole => (
                state.tenants.values().cloned().collect(),
                state.closure.clone(),
            ),
            IntegrityScope::Subtree(root) => {
                let ids: HashSet<Uuid> = state
                    .closure
                    .iter()
                    .filter(|r| r.ancestor_id == root)
                    .map(|r| r.descendant_id)
                    .collect();
                if ids.is_empty() {
                    return Ok((Vec::new(), Vec::new()));
                }
                let tenants: Vec<_> = state
                    .tenants
                    .values()
                    .filter(|t| ids.contains(&t.id))
                    .cloned()
                    .collect();
                let closure: Vec<_> = state
                    .closure
                    .iter()
                    .filter(|r| ids.contains(&r.descendant_id))
                    .cloned()
                    .collect();
                (tenants, closure)
            }
        };
        if let Some(cap) = tenants_cap
            && tenants.len() > cap
        {
            return Err(AmError::Internal {
                diagnostic: format!(
                    "integrity scope too large; use Subtree (live tenants={}, cap={cap})",
                    tenants.len()
                ),
            });
        }
        Ok((tenants, closure))
    }

    async fn is_descendant(
        &self,
        _scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, AmError> {
        let state = self.state.lock().expect("lock");
        Ok(state
            .closure
            .iter()
            .any(|r| r.ancestor_id == ancestor && r.descendant_id == descendant))
    }

    async fn find_root(&self, _scope: &AccessScope) -> Result<Option<TenantModel>, AmError> {
        let state = self.state.lock().expect("lock");
        Ok(state
            .tenants
            .values()
            .filter(|t| t.parent_id.is_none() && !matches!(t.status, TenantStatus::Provisioning))
            .min_by_key(|t| (t.created_at, t.id))
            .cloned())
    }
}

/// Four-outcome stub for the `IdP` provisioner.
#[domain_model]
#[derive(Clone)]
pub enum FakeOutcome {
    Ok,
    CleanFailure,
    Ambiguous,
    Unsupported,
}

/// Stub for `deprovision_tenant` outcomes. Defaults to `Ok`.
#[domain_model]
#[derive(Clone)]
pub enum FakeDeprovisionOutcome {
    Ok,
    Retryable,
    Terminal,
    Unsupported,
}

#[domain_model]
pub struct FakeIdpProvisioner {
    pub outcome: Mutex<FakeOutcome>,
    pub deprovision_outcome: Mutex<FakeDeprovisionOutcome>,
    pub metadata_entries: Mutex<Vec<ProvisionMetadataEntry>>,
    pub availability_failures: Mutex<u32>,
    pub availability_calls: Mutex<u32>,
    pub calls: Mutex<Vec<Uuid>>,
    pub deprovision_calls: Mutex<Vec<Uuid>>,
}

impl FakeIdpProvisioner {
    pub fn new(outcome: FakeOutcome) -> Self {
        Self {
            outcome: Mutex::new(outcome),
            deprovision_outcome: Mutex::new(FakeDeprovisionOutcome::Ok),
            metadata_entries: Mutex::new(Vec::new()),
            availability_failures: Mutex::new(0),
            availability_calls: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
            deprovision_calls: Mutex::new(Vec::new()),
        }
    }

    pub fn set_deprovision_outcome(&self, oc: FakeDeprovisionOutcome) {
        *self.deprovision_outcome.lock().expect("lock") = oc;
    }

    pub fn set_metadata_entries(&self, entries: Vec<ProvisionMetadataEntry>) {
        *self.metadata_entries.lock().expect("lock") = entries;
    }

    pub fn fail_availability_times(&self, failures: u32) {
        *self.availability_failures.lock().expect("lock") = failures;
    }
}

#[async_trait]
impl IdpTenantProvisioner for FakeIdpProvisioner {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        *self.availability_calls.lock().expect("lock") += 1;
        let mut failures = self.availability_failures.lock().expect("lock");
        if *failures > 0 {
            *failures -= 1;
            return Err(CheckAvailabilityFailure::TransientError(
                "fake availability failure".into(),
            ));
        }
        Ok(())
    }

    async fn provision_tenant(
        &self,
        req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure> {
        self.calls.lock().expect("lock").push(req.tenant_id);
        let oc = self.outcome.lock().expect("lock").clone();
        match oc {
            FakeOutcome::Ok => Ok(ProvisionResult {
                metadata_entries: self.metadata_entries.lock().expect("lock").clone(),
            }),
            FakeOutcome::CleanFailure => Err(ProvisionFailure::CleanFailure {
                detail: "fake clean".into(),
            }),
            FakeOutcome::Ambiguous => Err(ProvisionFailure::Ambiguous {
                detail: "fake ambiguous".into(),
            }),
            FakeOutcome::Unsupported => Err(ProvisionFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
        }
    }

    async fn deprovision_tenant(&self, req: &DeprovisionRequest) -> Result<(), DeprovisionFailure> {
        self.deprovision_calls
            .lock()
            .expect("lock")
            .push(req.tenant_id);
        let oc = self.deprovision_outcome.lock().expect("lock").clone();
        match oc {
            FakeDeprovisionOutcome::Ok => Ok(()),
            FakeDeprovisionOutcome::Retryable => Err(DeprovisionFailure::Retryable {
                detail: "fake retryable".into(),
            }),
            FakeDeprovisionOutcome::Terminal => Err(DeprovisionFailure::Terminal {
                detail: "fake terminal".into(),
            }),
            FakeDeprovisionOutcome::Unsupported => Err(DeprovisionFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
        }
    }
}

/// Short alias used by the handler tests.
pub type FakeService = TenantService<FakeTenantRepo>;

pub fn make_service(repo: Arc<FakeTenantRepo>, outcome: FakeOutcome) -> Arc<FakeService> {
    Arc::new(TenantService::new(
        repo,
        Arc::new(FakeIdpProvisioner::new(outcome)),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        crate::config::AccountManagementConfig::default(),
    ))
}

/// Always-permit mock PDP for service / handler tests.
///
/// Returns `decision: true` with no constraints (i.e. compiles to
/// [`AccessScope::allow_all`]). Tenant-isolation tests rely on the
/// closure-based ancestry check inside [`TenantService`] — not on PEP
/// constraints — because AM's `tenants` entity maps both
/// `OWNER_TENANT_ID` and `RESOURCE_ID` PEP properties to the `id`
/// column and so cannot express subtree predicates at SQL level.
#[domain_model]
struct MockAuthZResolver;

#[async_trait]
impl AuthZResolverClient for MockAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        // Honour `require_constraints = false` (used by tests that
        // assert no constraint compilation happens) but otherwise
        // return an unconstrained, permitting response.
        let _ = request;
        Ok(EvaluationResponse {
            decision: true,
            context: EvaluationResponseContext::default(),
        })
    }
}

/// Build a permissive [`PolicyEnforcer`] for tests. Pairs with
/// [`make_service`] and the inline `make_service` helpers used by the
/// service-level `#[tokio::test]` blocks.
#[must_use]
pub fn mock_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(MockAuthZResolver);
    PolicyEnforcer::new(authz)
}
