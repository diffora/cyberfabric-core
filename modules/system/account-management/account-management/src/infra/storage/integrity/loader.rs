//! Snapshot loader for the Rust-side integrity check.
//!
//! Two `SecureSelect` calls — `tenants` and `tenant_closure` — issued
//! against the same `DbTx<'_>` so both reads are observed against a
//! single MVCC snapshot. The transaction is opened by the caller
//! (`integrity::run_integrity_check`) with the strongest repeatable
//! isolation the underlying backend supports (`REPEATABLE READ` on
//! `Postgres`; `Serializable` on `SQLite`, which is the only level
//! `SQLite` exposes — see `modkit_db::secure::tx_config`). The
//! `integrity_check_runs` single-flight gate INSERT/DELETE happen in
//! **separate** committed transactions wrapping this snapshot tx
//! (see `integrity::lock`), so the snapshot tx itself contains no
//! writes and runs as a clean read-only window over both tables.
//!
//! Two scope-handling rules — both load-bearing:
//!
//! * `tenants` SELECT scopes via [`AccessScope::allow_all`]
//!   unconditionally. Subtree integrity checks (`compute_subtree_ids`,
//!   `orphan`, `cycle`, `strict_ancestor`) need to see ancestors that
//!   live OUTSIDE the audited subtree to detect breakage at the
//!   subtree boundary; a narrower caller scope would silently hide
//!   those ancestors and turn corruption into false negatives. The
//!   `scope` parameter is retained on the public entry point for
//!   storage-level defence-in-depth, but the integrity-check entry
//!   asserts `allow_all` semantics here.
//! * `tenant_closure` SELECT scopes via [`AccessScope::allow_all`]
//!   unconditionally — closure rows are `no_tenant`/`no_resource` (per
//!   the entity's `#[secure(...)]` declaration), so any narrower
//!   `AccessScope` collapses to `WHERE false` and hides every row.
//!
//! `tenants.status` is filtered to the SDK-visible set
//! (`{Active, Suspended, Deleted}`); `Provisioning` rows MUST NOT enter
//! the snapshot per ADR-0007 (the classifiers in
//! `integrity/classifiers/` rely on this invariant when treating
//! provisioning-state inputs as a programmer error rather than a
//! violation).

use std::collections::{HashMap, HashSet};

use modkit_db::secure::{DbTx, SecureEntityExt};
use modkit_security::AccessScope;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::tenant::integrity::IntegrityScope;
use crate::domain::tenant::model::TenantStatus;
use crate::infra::storage::entity::{tenant_closure, tenants};

use super::snapshot::{ClosureSnap, Snapshot, TenantSnap};

/// Load a `(tenants, tenant_closure)` snapshot from the supplied
/// transaction.
///
/// Both SELECTs run inside the caller's `DbTx<'_>`, so the snapshot is
/// guaranteed to be MVCC-consistent. Provisioning tenants are filtered
/// out at the SQL level.
///
/// For [`IntegrityScope::Subtree`] the closure SELECT is narrowed to
/// rows whose `descendant_id` is in the subtree (membership computed
/// from the loaded `tenants.parent_id` map — closure rows are the
/// audit target so we cannot trust them for the scope filter). The
/// `tenants` SELECT remains full-table because the classifiers need
/// cross-subtree visibility for orphan / cycle detection on subtree
/// members whose ancestors live outside the subtree.
///
/// For [`IntegrityScope::Whole`] both SELECTs return every row matching
/// the SDK-visibility filter.
///
/// # Errors
///
/// Any `DbErr` from either SELECT, mapped through the canonical
/// `From<DbError> for DomainError` ladder via `map_scope_err`.
pub async fn load_snapshot(
    tx: &DbTx<'_>,
    scope: &AccessScope,
    integrity_scope: IntegrityScope,
) -> Result<Snapshot, DomainError> {
    // Production callers pass `AccessScope::allow_all` (the integrity
    // check is run by the service layer with allow_all per the
    // Phase-2 call-site rewrite). Defensively reject narrower scopes
    // here so a future caller cannot silently downgrade the audit by
    // hiding ancestor rows that orphan / cycle / strict-ancestor
    // classifiers need to see.
    if !scope.is_unconstrained() {
        return Err(DomainError::internal(
            "integrity-check loader requires AccessScope::allow_all; \
             a narrower scope would hide cross-subtree ancestors and \
             produce false-negative orphan/cycle reports",
        ));
    }
    let allow_all = AccessScope::allow_all();

    let tenant_rows = tenants::Entity::find()
        .secure()
        .scope_with(&allow_all)
        .filter(sdk_visible_status_filter())
        .all(tx)
        .await
        .map_err(map_scope_err)?;

    let mut tenant_snaps: Vec<TenantSnap> = Vec::with_capacity(tenant_rows.len());
    for row in &tenant_rows {
        tenant_snaps.push(tenant_row_to_snap(row)?);
    }

    let closure_rows = match &integrity_scope {
        IntegrityScope::Whole => tenant_closure::Entity::find()
            .secure()
            .scope_with(&allow_all)
            .all(tx)
            .await
            .map_err(map_scope_err)?,
        IntegrityScope::Subtree(root) => {
            // `is_in(ids)` expands to one bind parameter per subtree
            // member. A single SELECT against a large subtree
            // (>~16k members on Postgres' default 65k bind cap, less
            // under tighter pool configs) would overflow the
            // parameter limit and turn an operationally-recoverable
            // subtree audit into a hard failure. Chunk the IN-list
            // at `SUBTREE_IN_CHUNK_SIZE` so the per-statement bind
            // count stays well under any realistic backend ceiling.
            // The MVCC snapshot the outer tx holds keeps every
            // chunk's read consistent.
            const SUBTREE_IN_CHUNK_SIZE: usize = 500;

            let subtree_ids = compute_subtree_ids(&tenant_snaps, *root);
            if subtree_ids.is_empty() {
                Vec::new()
            } else {
                let ids: Vec<Uuid> = subtree_ids.into_iter().collect();
                let mut rows = Vec::with_capacity(ids.len());
                for chunk in ids.chunks(SUBTREE_IN_CHUNK_SIZE) {
                    let chunk_rows = tenant_closure::Entity::find()
                        .filter(tenant_closure::Column::DescendantId.is_in(chunk.to_vec()))
                        .secure()
                        .scope_with(&allow_all)
                        .all(tx)
                        .await
                        .map_err(map_scope_err)?;
                    rows.extend(chunk_rows);
                }
                rows
            }
        }
    };

    let mut closure_snaps: Vec<ClosureSnap> = Vec::with_capacity(closure_rows.len());
    for row in &closure_rows {
        closure_snaps.push(closure_row_to_snap(row)?);
    }

    Ok(Snapshot::new(tenant_snaps, closure_snaps))
}

/// Compute the set of tenants under `root` by walking
/// `tenants.parent_id` (the source of truth, not `tenant_closure`
/// which is the audit target). The set always includes `root` itself
/// when the row is in the loaded snapshot. Bounded by the snapshot's
/// tenant count to defend against `parent_id` cycles.
fn compute_subtree_ids(tenants: &[TenantSnap], root: Uuid) -> HashSet<Uuid> {
    let mut subtree: HashSet<Uuid> = HashSet::new();
    let parent_of: HashMap<Uuid, Option<Uuid>> =
        tenants.iter().map(|t| (t.id, t.parent_id)).collect();
    if parent_of.contains_key(&root) {
        subtree.insert(root);
    }
    let cap = tenants.len();
    for t in tenants {
        if subtree.contains(&t.id) {
            continue;
        }
        // Track the walked path with both `Vec` (for batched insert
        // at the end) AND `HashSet` (for O(1) cycle detection per
        // step). `path.contains` would be O(depth) per step, which
        // becomes O(depth^2) per tenant on deep chains — sibling
        // walks (`identify_cycle_members`, `identify_orphan_affected`,
        // `is_in_scope`) all amortise via HashSet.
        let mut path: Vec<Uuid> = vec![t.id];
        let mut path_set: HashSet<Uuid> = HashSet::from([t.id]);
        let mut cursor = t.parent_id;
        let mut steps = 0usize;
        let mut included = false;
        while let Some(anc) = cursor {
            if steps > cap || path_set.contains(&anc) {
                break; // cycle / runaway
            }
            steps += 1;
            if anc == root || subtree.contains(&anc) {
                included = true;
                break;
            }
            path.push(anc);
            path_set.insert(anc);
            cursor = parent_of.get(&anc).copied().flatten();
        }
        if included {
            for n in path {
                subtree.insert(n);
            }
        }
    }
    subtree
}

/// `tenants.status IN (Active, Suspended, Deleted)` — provisioning
/// rows are filtered out per ADR-0007.
fn sdk_visible_status_filter() -> Condition {
    Condition::any()
        .add(tenants::Column::Status.eq(TenantStatus::Active.as_smallint()))
        .add(tenants::Column::Status.eq(TenantStatus::Suspended.as_smallint()))
        .add(tenants::Column::Status.eq(TenantStatus::Deleted.as_smallint()))
}

fn tenant_row_to_snap(row: &tenants::Model) -> Result<TenantSnap, DomainError> {
    let status = TenantStatus::from_smallint(row.status).ok_or_else(|| {
        DomainError::internal(format!(
            "tenants.status out-of-domain value: {}",
            row.status
        ))
    })?;
    // Defence-in-depth: the SQL filter at `sdk_visible_status_filter`
    // excludes Provisioning at SELECT time, but a future relaxation
    // of that filter MUST NOT silently leak Provisioning into the
    // snapshot per ADR-0007. The classifiers treat Provisioning
    // inputs as a programmer error, so reject the row here with a
    // clear `Internal` instead of letting it through.
    if !status.is_sdk_visible() {
        return Err(DomainError::internal(format!(
            "tenants.status must be SDK-visible in integrity snapshot per ADR-0007: {}",
            row.status
        )));
    }
    Ok(TenantSnap {
        id: row.id,
        parent_id: row.parent_id,
        status,
        depth: row.depth,
        self_managed: row.self_managed,
    })
}

fn closure_row_to_snap(row: &tenant_closure::Model) -> Result<ClosureSnap, DomainError> {
    let descendant_status =
        TenantStatus::from_smallint(row.descendant_status).ok_or_else(|| {
            DomainError::internal(format!(
                "tenant_closure.descendant_status out-of-domain value: {}",
                row.descendant_status
            ))
        })?;
    // Defence-in-depth: unlike `tenants`, `tenant_closure` has NO
    // SQL-level filter on `descendant_status` (closure rows only
    // exist for activated tenants per the activation contract, so
    // historically there was nothing to filter). A stale or corrupt
    // Provisioning value here would still be handed to the
    // classifiers as a valid input. Reject it explicitly so
    // ADR-0007 holds without relying on the activation contract
    // staying honoured forever.
    if !descendant_status.is_sdk_visible() {
        return Err(DomainError::internal(format!(
            "tenant_closure.descendant_status must be SDK-visible in integrity snapshot per ADR-0007: {}",
            row.descendant_status
        )));
    }
    Ok(ClosureSnap {
        ancestor_id: row.ancestor_id,
        descendant_id: row.descendant_id,
        barrier: row.barrier,
        descendant_status,
    })
}

/// Mirror of `repo_impl::map_scope_err` — kept private to the
/// integrity-check module so loader/lock errors funnel through the
/// same canonical `From<DbError>` ladder used by the rest of the AM
/// repo.
fn map_scope_err(err: modkit_db::secure::ScopeError) -> DomainError {
    use modkit_db::secure::ScopeError;
    match err {
        ScopeError::Db(db) => DomainError::from(modkit_db::DbError::Sea(db)),
        ScopeError::Invalid(msg) => DomainError::internal(format!("scope invalid: {msg}")),
        ScopeError::TenantNotInScope { .. } => DomainError::CrossTenantDenied { cause: None },
        ScopeError::Denied(msg) => DomainError::internal(format!(
            "unexpected access denied in AM integrity-check loader: {msg}"
        )),
    }
}
