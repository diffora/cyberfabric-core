//! `run_integrity_check_for_scope` and
//! `repair_derivable_closure_violations` dispatch.
//!
//! Both entries follow a **three-transaction lifecycle** (see
//! [`crate::infra::storage::integrity::lock`]):
//!
//! 1. *Acquire* — `lock::acquire_committed` runs a short committed
//!    transaction that sweeps stale `integrity_check_runs` rows
//!    (older than `MAX_LOCK_AGE`) and inserts the gate row keyed by
//!    `(scope_key, worker_id)`. Committing here makes the row
//!    visible to concurrent contenders, who surface
//!    `DomainError::IntegrityCheckInProgress` from their own
//!    acquire instead of queueing on an uncommitted PK.
//! 2. *Snapshot/work* — `run_integrity_check_for_scope` opens a
//!    `REPEATABLE READ` transaction (read-only at the `SecureSelect`
//!    level; no writes inside this tx, so a long-running check
//!    cannot self-evict on SI conflicts).
//!    `repair_derivable_closure_violations` opens a `SERIALIZABLE`
//!    transaction wrapped by [`with_serializable_retry`] so the
//!    closure-side writes can re-plan against a fresh snapshot on
//!    40001 aborts.
//! 3. *Release* — `lock::release_committed` runs a short committed
//!    transaction that deletes the gate row keyed by both
//!    `scope_key` and `worker_id`. A zero-rows-affected DELETE
//!    means the row was reclaimed by a stale-lock sweep — the
//!    [`crate::infra::storage::integrity::lock::release`] helper
//!    emits a warn so the eviction is observable in telemetry.
//!
//! The release call is invoked even when the snapshot/work tx
//! returned an error so a transient failure does not leave the
//! gate held until the stale-lock TTL.
//!
//! Visibility: `pub(super)` — only the trait `impl` in [`super`]
//! dispatches here.
//!
//! TODO(integrity-sqlite-busy): on `SQLite` the `RepeatableRead`
//! request maps to `Serializable` (only level the engine exposes — see
//! `modkit_db::secure::tx_config`). Two concurrent integrity checks on
//! **different** scopes (different `integrity_check_runs.scope_key`
//! PKs) can therefore collide at `BEGIN IMMEDIATE` and surface as
//! `SQLITE_BUSY`, which the current path through
//! `transaction_with_config` (no retry helper) lifts into
//! [`DomainError::Internal`] rather than the user-meaningful
//! [`DomainError::IntegrityCheckInProgress`]. Production runs on
//! Postgres so this is dev / test only; a follow-up should either wrap
//! this entry point in a bounded retry helper or document the
//! conditional `BUSY → IntegrityCheckInProgress` mapping for `SQLite`
//! operators.

use modkit_db::secure::{
    DbTx, ScopeError, SecureDeleteExt, SecureInsertExt, SecureOnConflict, SecureUpdateExt,
    TxConfig, TxIsolationLevel,
};
use modkit_security::AccessScope;
use sea_orm::DbErr;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveValue, ColumnTrait, Condition, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::tenant::integrity::{
    IntegrityCategory, IntegrityScope, RepairReport, Violation,
};
use crate::infra::storage::entity::tenant_closure;
use crate::infra::storage::integrity;

use super::TenantRepoImpl;
use super::helpers::{TxError, map_scope_to_tx, with_serializable_retry};

pub(super) async fn run_integrity_check_for_scope(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    integrity_scope: IntegrityScope,
) -> Result<Vec<(IntegrityCategory, Violation)>, DomainError> {
    // 3-transaction lifecycle (see `integrity::lock` module docs):
    //
    // 1. Acquire (committed): sweep stale locks + INSERT row → row is
    //    visible to concurrent contenders so they surface
    //    `IntegrityCheckInProgress` instead of queueing.
    // 2. Snapshot + classify (REPEATABLE READ, read-only): MVCC view
    //    held for the duration; no writes inside this tx so a
    //    long-running check cannot be aborted by SI conflicts on the
    //    `tenants` / `tenant_closure` tables.
    // 3. Release (committed): DELETE the lock row.
    //
    // The release call uses a separate match arm rather than a Drop
    // guard because async destructors cannot run DB I/O. We always
    // attempt release on both happy and error paths so a transient
    // snapshot-tx failure does not leave the gate held until the
    // stale-lock TTL expires.
    let scope_key = integrity::lock::derive_scope_key(&integrity_scope);
    let worker_id = Uuid::new_v4();

    integrity::lock::acquire_committed(&repo.db, &scope_key, worker_id).await?;

    let cfg = TxConfig {
        isolation: Some(TxIsolationLevel::RepeatableRead),
        access_mode: None,
    };
    let scope_owned = scope.clone();
    let integrity_scope_owned = integrity_scope.clone();
    let report_result = repo
        .db
        .transaction_with_config(cfg, move |tx| {
            Box::pin(async move {
                integrity::run_integrity_check(tx, &scope_owned, integrity_scope_owned).await
            })
        })
        .await;

    // Always release, regardless of snapshot outcome. The release
    // call is short and bounded; the stale-lock sweeper on the next
    // acquire eventually reclaims the row even if release fails.
    //
    // Error precedence: when work succeeded but release failed, we
    // surface the *release* error (and lose the report). The
    // tradeoff is "loud release-failure beats silent gate-leak" — a
    // stuck gate produces phantom `IntegrityCheckInProgress` against
    // the next periodic tick, and we want the operator to see that
    // shape immediately rather than discover it via a stale-lock
    // sweep an hour later. When work failed AND release failed, the
    // work error is the more useful diagnostic, so we log the
    // release failure and propagate the work error.
    if let Err(release_err) =
        integrity::lock::release_committed(&repo.db, &scope_key, worker_id).await
    {
        if report_result.is_ok() {
            return Err(release_err);
        }
        tracing::warn!(
            target: "am.integrity",
            scope_key = %scope_key,
            worker_id = %worker_id,
            error = %release_err,
            "lock release failed after integrity check error; stale-lock sweeper will reclaim",
        );
    }

    let report = report_result?;
    // Flatten `IntegrityReport` (one entry per category) into the
    // `Vec<(IntegrityCategory, Violation)>` return shape pinned by the
    // trait surface — the service layer rebuckets these into a fresh
    // `IntegrityReport` on the consumer side.
    Ok(report
        .violations_by_category
        .into_iter()
        .flat_map(|(cat, violations)| violations.into_iter().map(move |v| (cat, v)))
        .collect())
}

/// `repair_derivable_closure_violations` dispatch — runs the
/// pure-Rust [`integrity::repair::compute_repair_plan`] over a
/// snapshot loaded inside a `SERIALIZABLE` transaction with retry
/// (see [`with_serializable_retry`]) and applies the resulting
/// closure-side INSERT / UPDATE / DELETE ops in the same tx.
///
/// The single-flight gate is **shared** with
/// [`run_integrity_check_for_scope`] — both serialize on the
/// `integrity_check_runs.scope_key` PK so a concurrent check + repair
/// on the same scope is guaranteed to happen one-at-a-time.
/// Contention surfaces as
/// [`DomainError::IntegrityCheckInProgress`].
///
/// Why `SERIALIZABLE` rather than `RepeatableRead` (the check's
/// isolation level)? The repair plan is computed from a snapshot,
/// then closure rows are written inside the same tx. Under
/// `SERIALIZABLE` the SI cycle detector aborts (40001) any tx whose
/// post-snapshot writes would be invalidated by a concurrent
/// commit's read-set / write-set, so saga races (status flip,
/// hard-delete, `activate_tenant`) cannot leave the repair tx with
/// a stale plan. [`with_serializable_retry`] re-enters from the top
/// of the closure on 40001, so retry observes the new state and
/// re-plans against it.
pub(super) async fn repair_derivable_closure_violations(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    integrity_scope: IntegrityScope,
) -> Result<RepairReport, DomainError> {
    // Same 3-transaction lifecycle as `run_integrity_check_for_scope`:
    // committed acquire, SERIALIZABLE work TX (with retry on 40001),
    // committed release. SI conflicts retry only the work TX — they
    // do not re-acquire the gate, so a SERIALIZABLE retry storm cannot
    // produce spurious `IntegrityCheckInProgress` against itself.
    let scope_key = integrity::lock::derive_scope_key(&integrity_scope);
    let worker_id = Uuid::new_v4();

    integrity::lock::acquire_committed(&repo.db, &scope_key, worker_id).await?;

    let scope_owned = scope.clone();
    let integrity_scope_owned = integrity_scope.clone();
    let work_result = with_serializable_retry(&repo.db, move || {
        let scope = scope_owned.clone();
        let integrity_scope = integrity_scope_owned.clone();
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                let snapshot =
                    integrity::loader::load_snapshot(tx, &scope, integrity_scope.clone())
                        .await
                        .map_err(TxError::Domain)?;

                let scope_root = match integrity_scope.clone() {
                    IntegrityScope::Whole => None,
                    IntegrityScope::Subtree(root) => Some(root),
                };
                let plan = integrity::repair::compute_repair_plan(&snapshot, scope_root);
                apply_repair_plan(tx, &plan).await?;

                Ok(plan.into_report(integrity_scope))
            })
        })
    })
    .await;

    if let Err(release_err) =
        integrity::lock::release_committed(&repo.db, &scope_key, worker_id).await
    {
        if work_result.is_ok() {
            return Err(release_err);
        }
        tracing::warn!(
            target: "am.integrity",
            scope_key = %scope_key,
            worker_id = %worker_id,
            error = %release_err,
            "lock release failed after repair error; stale-lock sweeper will reclaim",
        );
    }

    work_result
}

/// Apply pass — issue the INSERT / DELETE / UPDATE ops the planner
/// produced. Each pass uses the `SecureORM` bulk extensions so a
/// single statement covers all rows of one shape, keeping the apply
/// window short and SI-conflict surface bounded.
///
/// Ordering: DELETE → UPDATE → INSERT. The planner does not emit
/// overlapping `(a, d)` keys across passes for one snapshot, so the
/// order is operational only — this fixed order keeps future
/// extensions (e.g. an additional UPDATE category) from racing
/// against an INSERT against the same key.
async fn apply_repair_plan(
    tx: &DbTx<'_>,
    plan: &integrity::repair::RepairPlan,
) -> Result<(), TxError> {
    // DELETE stale closure rows in chunks. The OR-of-equalities filter
    // grows linearly in the violation count; chunking caps the per-
    // statement predicate size so a large repair (hundreds of stale
    // rows after a corruption incident) does not produce a multi-KB
    // SQL string that risks falling off the index path or hitting
    // backend statement-length limits. Matches the chunking pattern
    // used by `hard_delete_batch` in the retention path.
    const DELETE_CHUNK_SIZE: usize = 500;
    // Chunk size for the INSERT pass below. Caps the per-statement
    // parameter count at 2k (4 columns × 500 rows) so a corrupted-
    // tree rebuild that emits hundreds of thousands of inserts
    // cannot bump into the Postgres 65k bind-parameter limit and
    // turn a recoverable repair into a hard failure.
    const INSERT_CHUNK_SIZE: usize = 500;

    let allow_all = AccessScope::allow_all();

    if !plan.deletes.is_empty() {
        for chunk in plan.deletes.chunks(DELETE_CHUNK_SIZE) {
            let mut cond = Condition::any();
            for (a, d) in chunk {
                cond = cond.add(
                    Condition::all()
                        .add(tenant_closure::Column::AncestorId.eq(*a))
                        .add(tenant_closure::Column::DescendantId.eq(*d)),
                );
            }
            tenant_closure::Entity::delete_many()
                .filter(cond)
                .secure()
                .scope_with(&allow_all)
                .exec(tx)
                .await
                .map_err(map_scope_to_tx)?;
        }
    }

    // UPDATE barrier per (a, d). Issued one statement per row — the
    // ANSI SQL `CASE` form is dialect-fragile via `sea_query`, and
    // barrier divergences are rare enough in practice that
    // per-row dispatch is cheaper than building a `CASE` expression.
    for upd in &plan.barrier_updates {
        tenant_closure::Entity::update_many()
            .col_expr(
                tenant_closure::Column::Barrier,
                Expr::value(upd.new_barrier),
            )
            .filter(
                Condition::all()
                    .add(tenant_closure::Column::AncestorId.eq(upd.ancestor_id))
                    .add(tenant_closure::Column::DescendantId.eq(upd.descendant_id)),
            )
            .secure()
            .scope_with(&allow_all)
            .exec(tx)
            .await
            .map_err(map_scope_to_tx)?;
    }

    // UPDATE descendant_status — one bulk statement per affected
    // tenant. Every row whose `descendant_id = upd.descendant_id`
    // takes the same target status (closure denormalises
    // `tenants.status` for the descendant), so a single
    // `WHERE descendant_id = X` covers the whole row set.
    for upd in &plan.status_updates {
        tenant_closure::Entity::update_many()
            .col_expr(
                tenant_closure::Column::DescendantStatus,
                Expr::value(upd.new_status.as_smallint()),
            )
            .filter(tenant_closure::Column::DescendantId.eq(upd.descendant_id))
            .secure()
            .scope_with(&allow_all)
            .exec(tx)
            .await
            .map_err(map_scope_to_tx)?;
    }

    // INSERT missing self-rows + strict-ancestor edges in chunks.
    // `tenant_closure` is `no_tenant, no_resource`, so insert_many
    // takes `scope_unchecked` (matches the activation-path insert in
    // `repo_impl/lifecycle.rs::activate_tenant`).
    //
    // ON CONFLICT DO NOTHING on the composite PK
    // `(ancestor_id, descendant_id)`: the repair plan was computed
    // from a snapshot taken at tx start, but a concurrent lifecycle
    // write (e.g. an `activate_tenant` finalising a sibling subtree)
    // can commit the same closure row before this apply pass runs.
    // SERIALIZABLE isolation catches read-set conflicts and triggers
    // the retry helper, but it does not prevent unique-constraint
    // violations on rows committed before this tx began. Making the
    // insert idempotent at the storage layer keeps a benign self-
    // healing race from aborting the whole repair.
    //
    // The Secure `Insert::exec` returns `DbErr::RecordNotInserted`
    // when ON CONFLICT DO NOTHING skips every row in the chunk; we
    // treat that as success because the rows we wanted are already
    // there.
    if !plan.inserts.is_empty() {
        let mut on_conflict = SecureOnConflict::<tenant_closure::Entity>::columns([
            tenant_closure::Column::AncestorId,
            tenant_closure::Column::DescendantId,
        ]);
        on_conflict.inner_mut().do_nothing();

        for chunk in plan.inserts.chunks(INSERT_CHUNK_SIZE) {
            let active_models = chunk.iter().map(|ins| tenant_closure::ActiveModel {
                ancestor_id: ActiveValue::Set(ins.ancestor_id),
                descendant_id: ActiveValue::Set(ins.descendant_id),
                barrier: ActiveValue::Set(ins.barrier),
                descendant_status: ActiveValue::Set(ins.descendant_status.as_smallint()),
            });
            let res = tenant_closure::Entity::insert_many(active_models)
                .secure()
                .scope_unchecked(&allow_all)
                .map_err(map_scope_to_tx)?
                .on_conflict(on_conflict.clone())
                .exec(tx)
                .await;
            match res {
                // `Ok(_)` is the normal apply path; `RecordNotInserted`
                // means the whole chunk no-op'd because a concurrent
                // writer already produced every row — the repair
                // invariant is satisfied either way.
                Ok(_) | Err(ScopeError::Db(DbErr::RecordNotInserted)) => {}
                Err(err) => return Err(map_scope_to_tx(err)),
            }
        }
    }

    Ok(())
}
