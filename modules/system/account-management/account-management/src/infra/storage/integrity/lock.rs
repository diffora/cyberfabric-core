//! Uniform single-flight gate for the hierarchy-integrity check.
//!
//! Both backends (`Postgres` + `SQLite`) coordinate via a primary-key
//! INSERT into `integrity_check_runs`. The PK is a synthetic singleton
//! (`id = 1`, enforced by a CHECK constraint) so the table holds at
//! most one row at a time: a second worker attempting to insert
//! receives a unique-violation, which this module maps to
//! [`DomainError::IntegrityCheckInProgress`]. The `Postgres`
//! `pg_try_advisory_xact_lock` path used by the legacy raw-SQL
//! integrity check is intentionally not reintroduced — uniform
//! behaviour across backends is the whole point of the Rust-side
//! refactor.
//!
//! ## Three-transaction lifecycle (per-call)
//!
//! The acquire INSERT and release DELETE run in their own short,
//! committed transactions, separate from the snapshot/work
//! transaction in between. This makes the lock row visible to
//! contenders for the duration of the check: a concurrent worker
//! attempting [`acquire_committed`] sees the committed row and
//! surfaces [`DomainError::IntegrityCheckInProgress`] instead of
//! queueing on the uncommitted PK and then succeeding after the
//! original transaction commits its INSERT+DELETE pair — the
//! same-tx INSERT+DELETE pattern was the way contender races used
//! to silently degrade into redundant runs.
//!
//! ## Stale-lock cleanup
//!
//! The acquire path deletes any row whose `started_at` is older than
//! [`MAX_LOCK_AGE`] before inserting its own row. This is intentional:
//! stale rows are by construction crashed workers, so reclaiming them
//! eagerly during any acquire keeps the table size bounded without
//! needing a separate sweeper. There is no separate periodic sweeper
//! because every `acquire_committed` call already runs the cleanup.
//!
//! ## Tx-level helpers
//!
//! [`acquire`] / [`release`] operate inside an existing
//! `DbTx<'_>` and remain available for tests; production code paths
//! use [`acquire_committed`] / [`release_committed`].

use std::time::Duration;

use modkit_db::secure::{DbTx, SecureDeleteExt, is_unique_violation};
use modkit_security::AccessScope;
use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::metrics::{AM_INTEGRITY_LOCK_EVENTS, MetricKind, emit_metric};
use crate::infra::storage::entity::integrity_check_runs;
use crate::infra::storage::repo_impl::AmDbProvider;

/// Stable singleton id used as the `integrity_check_runs.id` PK
/// value. Enforced by a `CHECK (id = 1)` constraint at the DB layer
/// so the table is at-most-one-row by construction.
const SINGLETON_ID: i32 = 1;

/// Stale-lock TTL: any `integrity_check_runs` row older than this is
/// removed by the next [`acquire_committed`] call before it inserts
/// its own row. Sized well above any realistic
/// integrity-check duration on extra-large hierarchies (100k tenants
/// at depth 10 produces ~1M closure rows; even with a slow Postgres
/// backend the snapshot SELECT + classifiers complete in minutes,
/// not the better part of an hour). Live workers do **not** refresh
/// `started_at`, so this TTL is the only mechanism that recycles a
/// row left behind by a crashed worker — it MUST be larger than the
/// longest expected check or repair runtime to avoid evicting a live
/// holder. [`release_committed`] additionally warns when the DELETE
/// affects zero rows so a TTL eviction is at least observable in
/// telemetry.
pub const MAX_LOCK_AGE: Duration = Duration::from_hours(1);

/// Acquire the single-flight gate by inserting the singleton row
/// into `integrity_check_runs`.
///
/// `worker_id` is allocated by the caller
/// (`integrity::run_integrity_check`) and stored verbatim so the
/// success-path [`release`] DELETE can target the exact row this
/// worker inserted.
///
/// # Errors
///
/// * [`DomainError::IntegrityCheckInProgress`] when another worker
///   holds the gate (PK conflict — surfaced through
///   `is_unique_violation` on the `DbErr`).
/// * Any other DB error funnelled through `From<DbError> for DomainError`.
pub async fn acquire(tx: &DbTx<'_>, worker_id: Uuid) -> Result<(), DomainError> {
    let am = integrity_check_runs::ActiveModel {
        id: ActiveValue::Set(SINGLETON_ID),
        worker_id: ActiveValue::Set(worker_id),
        started_at: ActiveValue::Set(OffsetDateTime::now_utc()),
    };
    match modkit_db::secure::secure_insert::<integrity_check_runs::Entity>(
        am,
        &AccessScope::allow_all(),
        tx,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(map_acquire_err(err)),
    }
}

/// Release the single-flight gate by deleting the row this worker
/// inserted.
///
/// `worker_id` is included in the DELETE filter so a row inserted by
/// a different worker (e.g. one that took over after a stale-lock
/// sweep) is not accidentally deleted by this worker.
///
/// # Errors
///
/// Any DB error funnelled through `From<DbError> for DomainError`.
pub async fn release(tx: &DbTx<'_>, worker_id: Uuid) -> Result<(), DomainError> {
    let allow_all = AccessScope::allow_all();
    let result = integrity_check_runs::Entity::delete_many()
        .filter(integrity_check_runs::Column::WorkerId.eq(worker_id))
        .secure()
        .scope_with(&allow_all)
        .exec(tx)
        .await
        .map_err(map_scope_err)?;
    if result.rows_affected == 0 {
        // Zero affected rows means the row this worker inserted is
        // gone. The only way that happens is the stale-lock sweep on
        // a contender's [`acquire_committed`] reclaiming the slot
        // before this release ran — i.e. the check or repair took
        // longer than [`MAX_LOCK_AGE`] AND a contender raced in. The
        // contender is now running concurrently against the gate;
        // surface the anomaly so operators can detect it.
        //
        // We intentionally do NOT return an error: the check/repair
        // result is already produced, and the gate is now released
        // (by the contender's sweep), so the caller's contract is
        // honoured. We also do NOT emit on
        // `AM_HIERARCHY_INTEGRITY_RUNS` — that metric documents a
        // fixed outcome set (`completed | skipped_in_progress |
        // failed | repair_*`) describing scheduler-tick state, and
        // mixing in lock-health labels breaks dashboards keyed on
        // it. Use the dedicated `AM_INTEGRITY_LOCK_EVENTS` family
        // for lock-health alerting; the structured warn-log below
        // carries the per-event worker context.
        emit_metric(
            AM_INTEGRITY_LOCK_EVENTS,
            MetricKind::Counter,
            &[("event", "evicted_by_sweep")],
        );
        tracing::warn!(
            target: "am.integrity",
            worker_id = %worker_id,
            event = "lock_evicted_by_sweep",
            "integrity-lock release: zero rows affected; row was likely evicted by a stale-lock sweep -- check/repair exceeded MAX_LOCK_AGE",
        );
    }
    Ok(())
}

/// Sweep stale rows from `integrity_check_runs` whose `started_at`
/// exceeds `MAX_LOCK_AGE`. Runs inside the caller's `tx` so a single
/// `acquire_committed` round-trip handles cleanup + INSERT atomically.
async fn sweep_stale(tx: &DbTx<'_>) -> Result<(), DomainError> {
    let allow_all = AccessScope::allow_all();
    let cutoff = OffsetDateTime::now_utc() - MAX_LOCK_AGE;
    integrity_check_runs::Entity::delete_many()
        .filter(integrity_check_runs::Column::StartedAt.lt(cutoff))
        .secure()
        .scope_with(&allow_all)
        .exec(tx)
        .await
        .map_err(map_scope_err)?;
    Ok(())
}

/// Acquire the single-flight gate in its own short, committed
/// transaction. Sweeps stale lock rows (older than [`MAX_LOCK_AGE`])
/// before inserting so a crashed previous holder cannot block
/// indefinitely.
///
/// On commit the lock row becomes visible to concurrent contenders,
/// who then receive [`DomainError::IntegrityCheckInProgress`] from
/// their own acquire attempt. This is the contract that makes the
/// gate effective under concurrency.
///
/// # Errors
///
/// * [`DomainError::IntegrityCheckInProgress`] when another worker
///   holds the gate.
/// * Any other DB error funnelled through `From<DbError> for DomainError`.
pub async fn acquire_committed(db: &AmDbProvider, worker_id: Uuid) -> Result<(), DomainError> {
    db.transaction(move |tx| {
        Box::pin(async move {
            sweep_stale(tx).await?;
            acquire(tx, worker_id).await
        })
    })
    .await
}

/// Release the single-flight gate in its own short, committed
/// transaction.
///
/// # Errors
///
/// Any DB error funnelled through `From<DbError> for DomainError`.
pub async fn release_committed(db: &AmDbProvider, worker_id: Uuid) -> Result<(), DomainError> {
    db.transaction(move |tx| Box::pin(async move { release(tx, worker_id).await }))
        .await
}

fn map_acquire_err(err: modkit_db::secure::ScopeError) -> DomainError {
    use modkit_db::secure::ScopeError;
    match err {
        ScopeError::Db(ref db) if is_unique_violation(db) => DomainError::IntegrityCheckInProgress,
        ScopeError::Db(db) => DomainError::from(modkit_db::DbError::Sea(db)),
        ScopeError::Invalid(msg) => DomainError::internal(format!("scope invalid: {msg}")),
        ScopeError::TenantNotInScope { .. } => DomainError::CrossTenantDenied { cause: None },
        ScopeError::Denied(msg) => DomainError::internal(format!(
            "unexpected access denied in AM integrity-check lock: {msg}"
        )),
    }
}

fn map_scope_err(err: modkit_db::secure::ScopeError) -> DomainError {
    use modkit_db::secure::ScopeError;
    match err {
        ScopeError::Db(db) => DomainError::from(modkit_db::DbError::Sea(db)),
        ScopeError::Invalid(msg) => DomainError::internal(format!("scope invalid: {msg}")),
        ScopeError::TenantNotInScope { .. } => DomainError::CrossTenantDenied { cause: None },
        ScopeError::Denied(msg) => DomainError::internal(format!(
            "unexpected access denied in AM integrity-check lock: {msg}"
        )),
    }
}
