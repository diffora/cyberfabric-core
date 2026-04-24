//! `SeaORM`-backed implementation of [`TenantRepo`].
//!
//! AM is the authoritative owner of the `tenants` + `tenant_closure`
//! tables (DESIGN §4.2). Every public repo method takes an explicit
//! [`AccessScope`] parameter that is forwarded verbatim to the secure
//! `modkit_db` query builders. The service layer derives the scope from
//! the caller's [`SecurityContext`] (per-caller tenant scope, with a
//! platform-admin override anchored on the platform-root tenant id) and
//! also performs an explicit ancestry check against `tenant_closure`
//! before each call — the storage-level scope is defence-in-depth
//! against a missing service-level check. Background-task entry points
//! (retention sweep, provisioning reaper, integrity audit) are the only
//! callers that pass [`AccessScope::allow_all`] — they have no
//! per-request caller context and are explicitly allowed by DESIGN §4.2
//! to operate over the whole tree.
//!
//! The `Scopable` derives on the entities additionally enforce:
//!
//! * tenant-immutability on updates (the secure `UpdateMany` wrapper
//!   rejects any attempt to update `tenants.id` since `tenant_col = "id"`),
//! * type-safe executor selection (`DBRunner` trait is sealed so the repo
//!   cannot reach through to a raw `SeaORM` connection).
//!
//! Transactional writes (`activate_tenant`, `update_tenant_mutable`,
//! `compensate_provisioning`, `schedule_deletion`, `hard_delete_one`) go
//! through [`DBProvider::transaction_with_config`] under
//! [`TxIsolationLevel::Serializable`] via the [`with_serializable_retry`]
//! helper, which closes `DoD` `concurrency-serializability` and AC#15: the
//! tenants tree + closure invariants must be preserved under concurrent
//! mutators. Serialization conflicts (Postgres SQLSTATE `40001`,
//! `MySQL`/`MariaDB` `InnoDB` deadlocks, `PostgreSQL`
//! `could not serialize access` message) are bounded-retried up to
//! 5 attempts with exponential 1-2-4-8 ms backoff before propagating to
//! the caller as the original `AmError::Internal`. All commit / rollback
//! failures continue to flow through the `impl From<DbError> for AmError`
//! in `infra/error_conv.rs`.
//!
//! Background-task scans (`scan_retention_due`, `scan_stuck_provisioning`,
//! `audit_integrity_for_scope`) are read-only and stay on the
//! engine default isolation — they do not need SERIALIZABLE.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use modkit_db::DBProvider;
use modkit_db::secure::{
    DbTx, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureUpdateExt, TxAccessMode,
    TxConfig, TxIsolationLevel, is_unique_violation,
};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, DbBackend, EntityTrait, Order, QueryFilter, Statement};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::metrics::{AM_SERIALIZABLE_RETRY, MetricKind, emit_metric};
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::integrity::{IntegrityCategory, IntegrityScope, Violation};
use crate::domain::tenant::model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};
use crate::infra::storage::entity::{tenant_closure, tenant_metadata, tenants};

/// Shared alias used by `module.rs` + tests.
pub type AmDbProvider = DBProvider<AmError>;

/// `SeaORM` repository adapter for [`TenantRepo`].
///
/// Holds a shared [`DBProvider`] parameterized over [`AmError`] so every
/// infra failure funnels through the single `From<DbError> for AmError`
/// boundary in `infra/error_conv.rs`.
pub struct TenantRepoImpl {
    db: Arc<AmDbProvider>,
}

impl TenantRepoImpl {
    #[must_use]
    pub fn new(db: Arc<AmDbProvider>) -> Self {
        Self { db }
    }
}

// ---- private helpers ------------------------------------------------------

fn map_scope_err(err: modkit_db::secure::ScopeError) -> AmError {
    use modkit_db::secure::ScopeError;
    match err {
        // Route the underlying `sea_orm::DbErr` through the canonical
        // `From<DbError> for AmError` ladder in `infra/error_conv.rs`
        // so SQLSTATE `40001` becomes `AmError::SerializationConflict`
        // and `with_serializable_retry` actually retries it. Earlier
        // this arm flattened directly to `AmError::Internal`,
        // discarding the SQLSTATE / unique-violation classification —
        // a SERIALIZABLE conflict surfacing through a SecureORM
        // statement (the common path) was silently demoted to a 500
        // and never retried. Same routing also catches Postgres
        // `23505` / SQLite `2067` / MySQL `1062` and maps them to
        // `AmError::Conflict` (HTTP 409) per AC §15 line 711.
        ScopeError::Db(db) => AmError::from(modkit_db::DbError::Sea(db)),
        ScopeError::Invalid(msg) => AmError::Internal {
            diagnostic: format!("scope invalid: {msg}"),
        },
        ScopeError::TenantNotInScope { .. } => AmError::CrossTenantDenied,
        ScopeError::Denied(msg) => AmError::Internal {
            diagnostic: format!("unexpected access denied in AM repo: {msg}"),
        },
    }
}

fn entity_to_model(row: tenants::Model) -> Result<TenantModel, AmError> {
    let status = TenantStatus::from_smallint(row.status).ok_or_else(|| AmError::Internal {
        diagnostic: format!("tenants.status out-of-domain value: {}", row.status),
    })?;
    let depth = u32::try_from(row.depth).map_err(|_| AmError::Internal {
        diagnostic: format!("tenants.depth negative: {}", row.depth),
    })?;
    Ok(TenantModel {
        id: row.id,
        parent_id: row.parent_id,
        name: row.name,
        status,
        self_managed: row.self_managed,
        tenant_type_uuid: row.tenant_type_uuid,
        depth,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted_at: row.deleted_at,
    })
}

/// Build a simple `Condition` that matches a tenant id. Used everywhere
/// to bridge the `SimpleExpr` returned by `Column::eq` with the
/// `Condition` parameter accepted by `SecureSelect::filter`.
fn id_eq(id: Uuid) -> Condition {
    Condition::all().add(tenants::Column::Id.eq(id))
}

static GTS_NAMESPACE: LazyLock<Uuid> = LazyLock::new(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts"));

fn schema_uuid_from_gts_id(gts_id: &str) -> Uuid {
    Uuid::new_v5(&GTS_NAMESPACE, gts_id.as_bytes())
}

/// Maximum number of attempts for a SERIALIZABLE transaction before the
/// retry helper gives up and returns the underlying error to the caller.
const MAX_SERIALIZABLE_ATTEMPTS: u32 = 5;

/// TTL after which a hard-delete scan claim is considered stale and may
/// be stolen by another worker. Bounds the worst-case stuck-row latency
/// when [`TenantRepo::clear_retention_claim`] fails after a non-Cleaned
/// outcome (network blip, pool exhaustion): without this, the row would
/// be permanently invisible to future scans because `claimed_by` would
/// never return to NULL. A `Deleted` row's `updated_at` is frozen by
/// `schedule_deletion` and only touched by the scan UPDATE below, so it
/// is a reliable claim-age marker for retention rows.
// `from_mins` is unstable on the workspace MSRV; keep `from_secs` form.
#[allow(clippy::duration_suboptimal_units)]
const RETENTION_CLAIM_TTL: Duration = Duration::from_secs(600);

/// Hard step cap for every SQLite TEXT-path `WITH RECURSIVE` walk in
/// `run_sqlite_classifiers`. The Postgres branch uses bounded `UUID[]`
/// accumulators (~16 bytes/element); SQLite concatenates UUIDs into a
/// comma-separated TEXT path that grows quadratically with the walk
/// length, so an adversarial deeply-nested-but-non-cyclic chain (e.g.
/// 100k orphan rows with valid `parent_id` references but a broken
/// closure) could in principle accumulate hundreds of MB of path text
/// before the `INSTR` cycle guard terminates the walk.
///
/// 10_000 is chosen to be far above any legitimate hierarchy depth
/// (the AM hierarchy-depth threshold defaults to 10) while still
/// bounding worst-case memory at the SQL layer. Above this, the walk
/// truncates and any rows beyond the cap are not considered for the
/// classifier — which is acceptable because reaching this cap is
/// already pathological data, not a normal audit input. The cap is
/// applied uniformly to all five SQLite TEXT-path walks (Categories
/// 3, 4, 7, 8b, 9) so behaviour is consistent across classifiers.
const SQLITE_AUDIT_MAX_WALK_STEPS: i32 = 10_000;

/// Run a SERIALIZABLE transaction with bounded retry on serialization
/// failure.
///
/// SERIALIZABLE isolation can produce SQLSTATE `40001` whenever the
/// engine detects a read/write dependency cycle. These errors are
/// always safe to retry. The retry trigger is the typed
/// [`AmError::SerializationConflict`] variant routed by
/// `From<DbError>` in [`crate::infra::error_conv`]; underneath it
/// uses `modkit_db::deadlock::is_serialization_failure(&DbErr)` so
/// detection stays in sync with the workspace primitive.
///
/// Retries up to [`MAX_SERIALIZABLE_ATTEMPTS`] times with exponential
/// 1-2-4-8 ms backoff. On exhaustion the final `SerializationConflict`
/// propagates to the caller; it sits in the [`AmError`] `Conflict`
/// category (HTTP 409) with `code = serialization_conflict` per
/// `domain/error.rs` — losing concurrent mutators receive a
/// deterministic `conflict` envelope per
/// `feature-tenant-hierarchy-management §6 / AC line 711`, not a 500.
///
/// The closure may be invoked multiple times — it must be idempotent.
/// All AM mutating transactions in this file are written so that
/// re-execution from a clean transaction state produces the same end
/// state (re-read row, re-check status, re-issue the same updates).
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-concurrency-serializability:p1:inst-dod-concurrency-serializable-retry
async fn with_serializable_retry<F, T>(db: &AmDbProvider, op: F) -> Result<T, AmError>
where
    F: Fn() -> Box<
            dyn for<'a> FnOnce(
                    &'a DbTx<'a>,
                )
                    -> Pin<Box<dyn Future<Output = Result<T, AmError>> + Send + 'a>>
                + Send,
        > + Send
        + Sync,
    T: Send + 'static,
{
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let closure = op();
        let res = db
            .transaction_with_config(TxConfig::serializable(), |tx| closure(tx))
            .await;
        match res {
            Ok(v) => {
                // Telemetry — only emit when at least one retry was
                // needed. `attempts` is bounded by
                // `MAX_SERIALIZABLE_ATTEMPTS` so cardinality stays
                // small.
                if attempt > 1 {
                    let attempts = attempt.to_string();
                    emit_metric(
                        AM_SERIALIZABLE_RETRY,
                        MetricKind::Counter,
                        &[("outcome", "recovered"), ("attempts", attempts.as_str())],
                    );
                }
                return Ok(v);
            }
            Err(AmError::SerializationConflict { .. }) if attempt < MAX_SERIALIZABLE_ATTEMPTS => {
                // Exponential backoff: 1ms, 2ms, 4ms, 8ms.
                let backoff_ms = 1u64 << (attempt - 1);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(e @ AmError::SerializationConflict { .. }) => {
                // attempt == MAX_SERIALIZABLE_ATTEMPTS — retry budget
                // exhausted. Emit `outcome=exhausted` so platform
                // monitoring can alert on sustained DB contention,
                // then surface the typed error to the caller (mapped
                // to `conflict` / HTTP 409 by `AmError::category`).
                let attempts = attempt.to_string();
                emit_metric(
                    AM_SERIALIZABLE_RETRY,
                    MetricKind::Counter,
                    &[("outcome", "exhausted"), ("attempts", attempts.as_str())],
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-concurrency-serializability:p1:inst-dod-concurrency-serializable-retry

/// Postgres-only SQL-side hierarchy-integrity classifier.
///
/// Implements the `audit_integrity_for_scope` Postgres branch fixed by
/// Phase 1's design doc and Phase 3's phase file:
///
/// * The 10 indexed classification queries run inside a single
///   `REPEATABLE READ ReadOnly` transaction so every category is
///   observed against the same MVCC snapshot. A concurrent mutator
///   committing between queries cannot make a single audit "see" a
///   half-applied state where (e.g.) `tenants.status` was already
///   flipped but `tenant_closure.descendant_status` had not yet been
///   rewritten — both reads are snapshot-consistent.
/// * Tenants-side queries that take the runtime `IntegrityScope::Subtree`
///   restriction join against `tenant_closure WHERE ancestor_id = $root`
///   so the planner can use the existing
///   `idx_tenant_closure_ancestor_barrier_status` index. Whole-tree
///   audits skip the join entirely (empty `{scope_filter}`).
/// * The `&AccessScope` parameter is the storage-level defence-in-depth
///   passthrough required by the trait contract; today every caller
///   passes `AccessScope::allow_all()` (the audit is invoked by the
///   service layer with `allow_all` per Phase 2's call-site rewrite).
///   When an authenticated caller is wired in by Phase 6 the closure-
///   side queries continue to use `allow_all` because `tenant_closure`
///   is `no_tenant`/`no_resource` (rationale documented next to
///   `update_tenant_mutable` in this file: a PDP-narrowed scope
///   collapses to `WHERE false` on the closure entity, hiding every
///   row).
/// * `Statement::from_sql_and_values` is used here (rather than the
///   secure `SecureSelect` builders) because four of the ten queries
///   require `WITH RECURSIVE` CTEs that have no `Select<E>`
///   representation. The escape hatch is `DbTx::query_raw_all`, which
///   does not bypass scope: closure-side queries operate on a
///   `no_tenant` table (so scope is structurally meaningless) and
///   tenants-side queries embed the `IntegrityScope` filter directly
///   in SQL. SQL injection is impossible because every dynamic value
///   is bound through the parameter list, never spliced into the
///   query string.
async fn audit_integrity_pg(
    db: &Arc<AmDbProvider>,
    _scope: &AccessScope,
    integrity_scope: IntegrityScope,
) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
    let cfg = TxConfig {
        isolation: Some(TxIsolationLevel::RepeatableRead),
        access_mode: Some(TxAccessMode::ReadOnly),
    };
    let scope_root = match integrity_scope {
        IntegrityScope::Whole => None,
        IntegrityScope::Subtree(root) => Some(root),
    };
    // Phase 5 single-flight: stable scope identity used both for the
    // advisory lock key (`pg_try_advisory_xact_lock(hashtext(...))`)
    // and for the `AmError::AuditAlreadyRunning { scope }` payload
    // surfaced to concurrent callers. `"whole"` for full-tree audits;
    // `"subtree:<uuid>"` for subtree audits — verbatim with the SQLite
    // branch and with the contention-test fixtures.
    let scope_key = integrity_scope_key(&integrity_scope);
    db.transaction_with_config(cfg, move |tx| {
        let scope_key = scope_key.clone();
        Box::pin(async move {
            // Single-flight guard MUST be the first statement in the
            // txn so the advisory lock is acquired against the same
            // backend session that runs the classifiers; the lock is
            // auto-released at txn end (commit OR rollback) because
            // `pg_try_advisory_xact_lock` is the txn-scoped variant.
            acquire_pg_audit_lock(tx, &scope_key).await?;
            run_pg_classifiers(tx, scope_root).await
        })
    })
    .await
}

/// Stable scope identity for the single-flight gate and the
/// `AuditAlreadyRunning { scope }` payload. Mirrors the wire form
/// expected by the contention tests:
/// - `"whole"` for `IntegrityScope::Whole`.
/// - `"subtree:<uuid>"` for `IntegrityScope::Subtree(root)`, where
///   `<uuid>` is the lower-case canonical UUID rendering produced by
///   `Uuid`'s default `Display` impl.
fn integrity_scope_key(scope: &IntegrityScope) -> String {
    match scope {
        IntegrityScope::Whole => "whole".to_owned(),
        IntegrityScope::Subtree(root) => format!("subtree:{root}"),
    }
}

/// Acquire the per-scope Postgres advisory lock for the audit.
///
/// `pg_try_advisory_xact_lock(bigint)` is non-blocking: returns `true`
/// on acquisition and `false` if another session already holds the
/// matching key. The bigint key is computed server-side via
/// `hashtext('am.integrity.' || $1)::bigint` so no client-side hash
/// stability is required across releases. The `_xact_` variant
/// auto-releases the lock at txn end (commit OR rollback), which is
/// the property the brief pinned for "release on every code path
/// without an explicit unlock".
async fn acquire_pg_audit_lock(tx: &DbTx<'_>, scope_key: &str) -> Result<(), AmError> {
    let rows = tx
        .query_raw_all(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_try_advisory_xact_lock(hashtext('am.integrity.' || $1)::bigint) AS got",
            vec![sea_orm::Value::from(scope_key.to_owned())],
        ))
        .await
        .map_err(AmError::from)?;
    let got: bool = rows
        .first()
        .ok_or_else(|| AmError::Internal {
            diagnostic:
                "pg_try_advisory_xact_lock returned no row (single-flight gate query failed)"
                    .to_owned(),
        })?
        .try_get::<bool>("", "got")
        .map_err(map_query_err)?;
    if got {
        Ok(())
    } else {
        Err(AmError::AuditAlreadyRunning {
            scope: scope_key.to_owned(),
        })
    }
}

/// Run all 10 classification queries against `tx` under the snapshot
/// transaction opened by [`audit_integrity_pg`]. Returns one
/// `(IntegrityCategory, Violation)` pair per anomaly observed; an empty
/// vector means a clean audit. Per-category fan-out is bounded by the
/// total number of anomalies in the snapshot, not by the size of the
/// `tenants` / `tenant_closure` rowset (`O(violations)` memory — the
/// central refactor invariant).
#[allow(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "10-step linear pipeline of fixed-shape SQL queries; splitting into per-category helpers would obscure the snapshot-transaction control flow without simplifying any individual classifier"
)]
async fn run_pg_classifiers(
    tx: &DbTx<'_>,
    scope_root: Option<Uuid>,
) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
    let mut out: Vec<(IntegrityCategory, Violation)> = Vec::new();

    // ------------------------------------------------------------------
    // Category 1 — OrphanedChild: tenant.parent_id does not resolve to
    // any tenant row. The LEFT JOIN reports the dangling parent_id even
    // though the row itself exists, which is exactly what operators
    // need to navigate to the broken edge.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id, t.parent_id \
             FROM tenants t \
             LEFT JOIN tenants p ON p.id = t.parent_id \
             WHERE t.parent_id IS NOT NULL AND p.id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "parent_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::OrphanedChild,
                Violation {
                    category: IntegrityCategory::OrphanedChild,
                    tenant_id: Some(id),
                    details: format!("parent {parent_id} missing for tenant {id}"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 2 — BrokenParentReference: an SDK-visible (non-Deleted)
    // child references a Deleted parent. We inner-join `tenants p` so
    // the orphaned-parent case from Category 1 cannot double-report
    // here.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id, t.parent_id, t.status \
             FROM tenants t \
             JOIN tenants p ON p.id = t.parent_id \
             WHERE p.status = 3 AND t.status <> 3{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "parent_id").map_err(map_query_err)?;
            let status: i16 = row.try_get("", "status").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::BrokenParentReference,
                Violation {
                    category: IntegrityCategory::BrokenParentReference,
                    tenant_id: Some(id),
                    details: format!(
                        "tenant {id} is status={status} but parent {parent_id} is Deleted"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 3 — DepthMismatch: stored `tenants.depth` disagrees with
    // the depth derived by walking `parent_id` chain via a recursive
    // CTE. The `walk` CTE roots at `parent_id IS NULL` (depth = 0) and
    // descends one hop at a time, so the post-walk join surfaces every
    // tenant whose stored depth is not the walk-derived depth.
    //
    // The cycle-detection guard (`NOT t.id = ANY(walk.path)`) makes the
    // walk total over the input — without it a parent-id cycle would
    // recurse forever. Tenants caught by Category 4 (Cycle) below are
    // intentionally absent from `walk`, so they will not produce a
    // duplicated DepthMismatch.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "WITH RECURSIVE walk(id, depth, path) AS ( \
                SELECT id, 0, ARRAY[id]::uuid[] FROM tenants WHERE parent_id IS NULL \
                UNION ALL \
                SELECT t.id, w.depth + 1, w.path || t.id \
                FROM tenants t \
                JOIN walk w ON t.parent_id = w.id \
                WHERE NOT t.id = ANY(w.path) \
             ) \
             SELECT t.id, t.depth AS stored_depth, w.depth AS walk_depth \
             FROM tenants t \
             JOIN walk w ON w.id = t.id \
             WHERE t.depth <> w.depth{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let stored: i32 = row.try_get("", "stored_depth").map_err(map_query_err)?;
            let walk: i32 = row.try_get("", "walk_depth").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::DepthMismatch,
                Violation {
                    category: IntegrityCategory::DepthMismatch,
                    tenant_id: Some(id),
                    details: format!(
                        "tenant {id} stored depth {stored} but walk yields {walk}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 4 — Cycle: a `parent_id` chain loops. The recursive CTE
    // tracks the visited path and emits a row whenever the next hop
    // would re-enter a path member. We surface the offending node
    // (`cycle_node`) and the `parent_id` that closed the loop so
    // operators can break the cycle by patching either edge. The
    // `path && ARRAY[t.parent_id]` predicate is the cycle-closure
    // detector; any tenant satisfying it is by definition part of a
    // cycle.
    //
    // Implementation note: we deliberately use the `WHERE NOT t.id = ANY(walk.path)`
    // recursion guard pattern (rather than Postgres-14+ `CYCLE`
    // syntax) so the same SQL works on the Postgres versions covered
    // by `cf-modkit-db`'s testcontainers image (currently the upstream
    // `postgres` default).
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "WITH RECURSIVE walk(id, parent_id, path) AS ( \
                SELECT id, parent_id, ARRAY[id]::uuid[] FROM tenants WHERE parent_id IS NOT NULL \
                UNION ALL \
                SELECT t.id, t.parent_id, w.path || t.id \
                FROM walk w \
                JOIN tenants t ON t.id = w.parent_id \
                WHERE NOT t.id = ANY(w.path) \
             ) \
             SELECT DISTINCT t.id AS cycle_node, t.parent_id AS cycle_parent \
             FROM walk t \
             WHERE t.parent_id = ANY(t.path){filter}",
            // The `walk` CTE produces synthesized rows; apply scope only
            // when the original tenant row would have matched. The
            // `filter` fragment is already keyed on `t.id`, so we splice
            // it in verbatim.
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "cycle_node").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "cycle_parent").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::Cycle,
                Violation {
                    category: IntegrityCategory::Cycle,
                    tenant_id: Some(id),
                    details: format!("cycle detected during tenant_depth at parent {parent_id}"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 5 — RootCountAnomaly: a healthy tree has exactly one
    // tenant with `parent_id IS NULL`. Two-or-more roots breaks the
    // single-root invariant `bootstrap::service` depends on; zero
    // roots is anomalous only when the table is non-empty.
    //
    // Whole-tree audits are the only case that can surface this — a
    // `Subtree(root)` audit by definition starts from a single in-tree
    // pivot, so the global root-count question is meaningless inside
    // the subtree.
    // ------------------------------------------------------------------
    if scope_root.is_none() {
        let sql = "SELECT \
                (SELECT COUNT(*) FROM tenants WHERE parent_id IS NULL) AS root_count, \
                (SELECT COUNT(*) FROM tenants) AS total_count";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        if let Some(row) = rows.first() {
            let root_count: i64 = row.try_get("", "root_count").map_err(map_query_err)?;
            let total_count: i64 = row.try_get("", "total_count").map_err(map_query_err)?;
            if root_count > 1 {
                out.push((
                    IntegrityCategory::RootCountAnomaly,
                    Violation {
                        category: IntegrityCategory::RootCountAnomaly,
                        tenant_id: None,
                        details: format!(
                            "found {root_count} roots (parent_id IS NULL); expected 1"
                        ),
                    },
                ));
            }
            if root_count == 0 && total_count > 0 {
                out.push((
                    IntegrityCategory::RootCountAnomaly,
                    Violation {
                        category: IntegrityCategory::RootCountAnomaly,
                        tenant_id: None,
                        details: "no root tenant present but module has tenants".to_owned(),
                    },
                ));
            }
        }
    }

    // ------------------------------------------------------------------
    // Category 6 — MissingClosureSelfRow: every SDK-visible tenant
    // (`status <> 0`, i.e. anything except Provisioning) MUST have a
    // self-row `(id, id)` in `tenant_closure`. A LEFT JOIN against the
    // closure surfaces the gap directly. We restrict on the tenants
    // side because the closure entity is `no_tenant` and would not
    // accept an `IntegrityScope` predicate by itself.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id \
             FROM tenants t \
             LEFT JOIN tenant_closure c ON c.descendant_id = t.id AND c.ancestor_id = t.id \
             WHERE t.status <> 0 AND c.descendant_id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::MissingClosureSelfRow,
                Violation {
                    category: IntegrityCategory::MissingClosureSelfRow,
                    tenant_id: Some(id),
                    details: format!("tenant {id} lacks self-row in tenant_closure"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 7 — ClosureCoverageGap: every strict ancestor on the
    // `parent_id` walk MUST appear as an `(ancestor, descendant)` row
    // in `tenant_closure`. We rebuild the walk via a recursive CTE
    // (rooted at every SDK-visible tenant), then LEFT JOIN against the
    // closure to surface the missing edges. Provisioning tenants have
    // no closure rows by invariant, so they're excluded at the seed.
    //
    // The `path` array doubles as the cycle-detection guard — without
    // it a corrupt tree would recurse into the same parent_id forever.
    // Tenants caught by Category 4 (Cycle) drop out of `walk` and
    // therefore do not produce double-reports here.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "WITH RECURSIVE walk(descendant_id, ancestor_id, path) AS ( \
                SELECT t.id, t.parent_id, ARRAY[t.id]::uuid[] \
                FROM tenants t \
                WHERE t.status <> 0 AND t.parent_id IS NOT NULL \
                UNION ALL \
                SELECT w.descendant_id, p.parent_id, w.path || p.id \
                FROM walk w \
                JOIN tenants p ON p.id = w.ancestor_id \
                WHERE w.ancestor_id IS NOT NULL AND NOT p.id = ANY(w.path) \
             ) \
             SELECT DISTINCT t.id, w.ancestor_id \
             FROM walk w \
             JOIN tenants t ON t.id = w.descendant_id \
             LEFT JOIN tenant_closure c ON c.ancestor_id = w.ancestor_id AND c.descendant_id = w.descendant_id \
             WHERE w.ancestor_id IS NOT NULL AND c.ancestor_id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::ClosureCoverageGap,
                Violation {
                    category: IntegrityCategory::ClosureCoverageGap,
                    tenant_id: Some(id),
                    details: format!(
                        "closure gap: ancestor {ancestor_id} missing for descendant {id}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 8 — StaleClosureRow: a closure row references a tenant
    // (ancestor or descendant) that no longer exists. The closure
    // table is `no_tenant` so we use `AccessScope::allow_all` for the
    // raw query; subtree scoping is structurally meaningless here
    // (a stale row by definition has at least one endpoint missing
    // from the tenants set, so a Subtree filter on the missing side
    // could not match).
    //
    // We also surface the second flavour of staleness — both endpoints
    // exist but the asserted ancestry is not present in the parent_id
    // walk — by re-running the walk and reporting closure rows whose
    // `(ancestor, descendant)` pair is not among the walk-derived
    // edges. Skipping rows already flagged as missing-endpoint above
    // keeps the violations distinct.
    // ------------------------------------------------------------------
    {
        // 8a: missing endpoint(s).
        let sql = "\
            SELECT c.descendant_id AS dangling, 'descendant' AS side \
            FROM tenant_closure c \
            LEFT JOIN tenants t ON t.id = c.descendant_id \
            WHERE t.id IS NULL \
            UNION ALL \
            SELECT c.ancestor_id AS dangling, 'ancestor' AS side \
            FROM tenant_closure c \
            LEFT JOIN tenants t ON t.id = c.ancestor_id \
            WHERE t.id IS NULL";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let dangling: Uuid = row.try_get("", "dangling").map_err(map_query_err)?;
            let side: String = row.try_get("", "side").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::StaleClosureRow,
                Violation {
                    category: IntegrityCategory::StaleClosureRow,
                    tenant_id: Some(dangling),
                    details: format!("closure row references missing {side} {dangling}"),
                },
            ));
        }

        // 8b: ancestry-not-in-walk. Both endpoints exist but the
        // closure asserts an `(ancestor, descendant)` edge the
        // parent_id walk cannot confirm. We exclude self-rows
        // (always valid by invariant) and rows whose endpoints are
        // ALSO captured by the missing-endpoint pass above.
        let sql = "\
            WITH RECURSIVE walk(descendant_id, ancestor_id, path) AS ( \
                SELECT t.id, t.parent_id, ARRAY[t.id]::uuid[] \
                FROM tenants t \
                WHERE t.parent_id IS NOT NULL \
                UNION ALL \
                SELECT w.descendant_id, p.parent_id, w.path || p.id \
                FROM walk w \
                JOIN tenants p ON p.id = w.ancestor_id \
                WHERE w.ancestor_id IS NOT NULL AND NOT p.id = ANY(w.path) \
            ), \
            edges AS ( \
                SELECT descendant_id, ancestor_id FROM walk WHERE ancestor_id IS NOT NULL \
                UNION \
                SELECT id, id FROM tenants \
            ) \
            SELECT c.ancestor_id, c.descendant_id \
            FROM tenant_closure c \
            JOIN tenants ta ON ta.id = c.ancestor_id \
            JOIN tenants td ON td.id = c.descendant_id \
            LEFT JOIN edges e ON e.ancestor_id = c.ancestor_id AND e.descendant_id = c.descendant_id \
            WHERE c.ancestor_id <> c.descendant_id AND e.ancestor_id IS NULL";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::StaleClosureRow,
                Violation {
                    category: IntegrityCategory::StaleClosureRow,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}) asserts ancestry not present in parent_id walk"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 9 — BarrierColumnDivergence: for each strict closure
    // row `(A, D)`, the expected `barrier` value is `1` iff any tenant
    // on the `(A, D]` parent-walk path is `self_managed`, else `0`.
    // We compute the expected barrier in SQL by walking from `D` up
    // to (but not including) `A` via a recursive CTE and joining
    // against `tenants.self_managed` for each path member.
    //
    // Self-rows (`A = D`) are intentionally skipped — the schema's
    // `ck_tenant_closure_self_row_barrier` CHECK already pins their
    // barrier to 0, so any divergence there would be a separate
    // schema-level corruption and not the materialization invariant
    // this category targets.
    // ------------------------------------------------------------------
    {
        let sql = "\
            WITH RECURSIVE walk(closure_ancestor, closure_descendant, cursor_id, path, has_self_managed) AS ( \
                SELECT c.ancestor_id, c.descendant_id, t.parent_id, ARRAY[t.id]::uuid[], t.self_managed \
                FROM tenant_closure c \
                JOIN tenants t ON t.id = c.descendant_id \
                WHERE c.ancestor_id <> c.descendant_id \
                UNION ALL \
                SELECT w.closure_ancestor, w.closure_descendant, p.parent_id, w.path || p.id, \
                       w.has_self_managed OR p.self_managed \
                FROM walk w \
                JOIN tenants p ON p.id = w.cursor_id \
                WHERE w.cursor_id IS NOT NULL AND w.cursor_id <> w.closure_ancestor \
                  AND NOT p.id = ANY(w.path) \
            ), \
            terminated AS ( \
                SELECT closure_ancestor, closure_descendant, has_self_managed \
                FROM walk \
                WHERE cursor_id = closure_ancestor \
            ) \
            SELECT c.ancestor_id, c.descendant_id, c.barrier AS actual_barrier, \
                   CASE WHEN tr.has_self_managed THEN 1 ELSE 0 END AS expected_barrier \
            FROM tenant_closure c \
            JOIN terminated tr ON tr.closure_ancestor = c.ancestor_id AND tr.closure_descendant = c.descendant_id \
            WHERE c.ancestor_id <> c.descendant_id \
              AND c.barrier <> CASE WHEN tr.has_self_managed THEN 1 ELSE 0 END";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            let actual: i16 = row.try_get("", "actual_barrier").map_err(map_query_err)?;
            let expected: i32 = row.try_get("", "expected_barrier").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::BarrierColumnDivergence,
                Violation {
                    category: IntegrityCategory::BarrierColumnDivergence,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}).barrier={actual} but expected {expected}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 10 — DescendantStatusDivergence: stored
    // `tenant_closure.descendant_status` MUST track `tenants.status`
    // for every SDK-visible (`status <> 0`) descendant. A cheap
    // inner-join across the two tables surfaces every divergence
    // directly. Provisioning tenants have no closure rows by invariant,
    // so the join on `tenants.status <> 0` is what filters them.
    //
    // The closure side is `no_tenant`, so this query uses
    // `AccessScope::allow_all` (rationale documented at the head of
    // this function and at `update_tenant_mutable` in the same file).
    // The `IntegrityScope::Subtree` filter, when present, is applied
    // on the tenants side.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_pg("t", scope_root, 1);
        let sql = format!(
            "SELECT c.ancestor_id, c.descendant_id, c.descendant_status, t.status \
             FROM tenant_closure c \
             JOIN tenants t ON t.id = c.descendant_id \
             WHERE t.status <> 0 AND c.descendant_status <> t.status{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            let stored: i16 = row.try_get("", "descendant_status").map_err(map_query_err)?;
            let current: i16 = row.try_get("", "status").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::DescendantStatusDivergence,
                Violation {
                    category: IntegrityCategory::DescendantStatusDivergence,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}).descendant_status={stored} but tenants.status={current}"
                    ),
                },
            ));
        }
    }

    Ok(out)
}

/// Build the `IntegrityScope::Subtree` SQL filter fragment for a
/// tenants-side query. Returns the SQL fragment (always prefixed with
/// ` AND `) and the bound values vector. `Whole` audits return an
/// empty fragment and an empty value list.
///
/// `tenants_alias` names the `tenants t` alias (or equivalent) carrying
/// the descendant id. `next_param_idx` is the 1-based starting index of
/// the bind placeholders so that callers stacking filters on top of
/// other parameters don't collide; today every caller starts at 1.
fn scope_filter_pg(
    tenants_alias: &str,
    scope_root: Option<Uuid>,
    next_param_idx: usize,
) -> (String, Vec<sea_orm::Value>) {
    match scope_root {
        None => (String::new(), Vec::new()),
        Some(root) => {
            let placeholder = format!("${next_param_idx}");
            let fragment = format!(
                " AND ({tenants_alias}.id = {placeholder} OR {tenants_alias}.id IN \
                  (SELECT descendant_id FROM tenant_closure WHERE ancestor_id = {placeholder}))",
            );
            (fragment, vec![sea_orm::Value::from(root)])
        }
    }
}

/// `SQLite` mirror of [`scope_filter_pg`]. Identical fragment shape — the
/// `IntegrityScope::Subtree` predicate joins against `tenant_closure`
/// the same way on both backends. Lives as a separate function so the
/// dialect-aware bits stay co-located with their caller; the body is
/// intentionally a thin alias over `scope_filter_pg` because `SQLite`
/// `SeaORM` also accepts `$N` placeholders (sqlx normalizes to native
/// `?N`), so the bind syntax is portable.
fn scope_filter_sqlite(
    tenants_alias: &str,
    scope_root: Option<Uuid>,
    next_param_idx: usize,
) -> (String, Vec<sea_orm::Value>) {
    scope_filter_pg(tenants_alias, scope_root, next_param_idx)
}

/// SQLite-only SQL-side hierarchy-integrity classifier.
///
/// Mirrors [`audit_integrity_pg`] semantically — produces the same
/// `(IntegrityCategory, Violation)` set for any given DB state — but
/// substitutes SQLite-portable SQL forms wherever the Postgres branch
/// uses dialect-specific constructs:
///
/// * `ARRAY[id]::uuid[] || t.id` → TEXT path concat
///   (`',' || cast(id as text) || ','`) with `INSTR(path, ',' ||
///   cast(<candidate> as text) || ',') = 0` as the cycle-recursion
///   guard. The wrapping commas make the substring check exact (no
///   accidental match between `id=12` and `id=123`). This is the
///   pinned `sqlite_cycle_detection` decision from Phase 1.
/// * `t.parent_id = ANY(t.path)` → `INSTR(t.path, ',' ||
///   cast(t.parent_id as text) || ',') > 0` — same path-membership
///   semantics, portable shape.
/// * No `make_interval` substitution is needed; none of the 10
///   classification queries use date arithmetic.
///
/// Wraps the queries in a `RepeatableRead ReadOnly` transaction.
/// `SeaORM`'s `SQLite` driver emits a `warn!` for the isolation/access
/// hints (`SQLite`'s transaction model is fixed at compile time), but
/// the WAL-mode default already provides the snapshot semantics this
/// audit needs — every classifier observes the same MVCC view.
async fn audit_integrity_sqlite(
    db: &Arc<AmDbProvider>,
    _scope: &AccessScope,
    integrity_scope: IntegrityScope,
) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
    let cfg = TxConfig {
        isolation: Some(TxIsolationLevel::RepeatableRead),
        access_mode: Some(TxAccessMode::ReadOnly),
    };
    let scope_root = match integrity_scope {
        IntegrityScope::Whole => None,
        IntegrityScope::Subtree(root) => Some(root),
    };
    // Phase 5 single-flight: stable scope identity used both for the
    // `running_audits.scope_key` PK gate and for the
    // `AmError::AuditAlreadyRunning { scope }` payload surfaced to
    // concurrent callers. `"whole"` for full-tree audits;
    // `"subtree:<uuid>"` for subtree audits — verbatim with the
    // Postgres branch and with the contention-test fixtures.
    let scope_key = integrity_scope_key(&integrity_scope);
    db.transaction_with_config(cfg, move |tx| {
        let scope_key = scope_key.clone();
        Box::pin(async move {
            // Single-flight guard MUST be the first statement in the
            // txn so the PK contention is observed against the same
            // backend session that runs the classifiers. On ROLLBACK
            // the uncommitted INSERT row dies with the txn — no
            // explicit unlock path is needed for the failure case.
            // On COMMIT the explicit DELETE on the success branch
            // releases the slot atomically with the audit result.
            let worker_id = acquire_sqlite_audit_lock(tx, &scope_key).await?;
            let result = run_sqlite_classifiers(tx, scope_root).await?;
            release_sqlite_audit_lock(tx, &worker_id).await?;
            Ok(result)
        })
    })
    .await
}

/// Acquire the per-scope `SQLite` single-flight lock by inserting a row
/// into `running_audits` with `scope_key` as the PK. The
/// `ON CONFLICT DO NOTHING RETURNING scope_key` form lets us detect a
/// PK collision via the absence of a returned row: `SQLite` (>= 3.35,
/// covered by sqlx-sqlite) emits zero rows on conflict and one row on
/// success. Returns the freshly-allocated `worker_id` so the
/// success-path DELETE can target the row this worker inserted.
///
/// On ROLLBACK the row dies with the uncommitted txn — no separate
/// unlock path is required for the failure case.
async fn acquire_sqlite_audit_lock(
    tx: &DbTx<'_>,
    scope_key: &str,
) -> Result<String, AmError> {
    let worker_id = Uuid::new_v4().to_string();
    let started_at = OffsetDateTime::now_utc();
    let rows = tx
        .query_raw_all(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO running_audits (scope_key, worker_id, started_at) \
             VALUES (?, ?, ?) ON CONFLICT (scope_key) DO NOTHING \
             RETURNING scope_key",
            vec![
                sea_orm::Value::from(scope_key.to_owned()),
                sea_orm::Value::from(worker_id.clone()),
                sea_orm::Value::from(started_at),
            ],
        ))
        .await
        .map_err(AmError::from)?;
    if rows.is_empty() {
        Err(AmError::AuditAlreadyRunning {
            scope: scope_key.to_owned(),
        })
    } else {
        Ok(worker_id)
    }
}

/// Release the per-scope `SQLite` single-flight lock on the success
/// path by deleting the row this worker inserted. Runs INSIDE the
/// audit txn so the DELETE commits atomically with the audit result.
/// On ROLLBACK the row never committed in the first place, so no
/// explicit unlock is required.
async fn release_sqlite_audit_lock(tx: &DbTx<'_>, worker_id: &str) -> Result<(), AmError> {
    tx.query_raw_all(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "DELETE FROM running_audits WHERE worker_id = ?",
        vec![sea_orm::Value::from(worker_id.to_owned())],
    ))
    .await
    .map_err(AmError::from)?;
    Ok(())
}

/// Run all 10 classification queries against `tx` under the snapshot
/// transaction opened by [`audit_integrity_sqlite`]. Returns one
/// `(IntegrityCategory, Violation)` pair per anomaly observed; an empty
/// vector means a clean audit.
#[allow(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "10-step linear pipeline of fixed-shape SQL queries; splitting into per-category helpers would obscure the snapshot-transaction control flow without simplifying any individual classifier"
)]
async fn run_sqlite_classifiers(
    tx: &DbTx<'_>,
    scope_root: Option<Uuid>,
) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
    let mut out: Vec<(IntegrityCategory, Violation)> = Vec::new();

    // ------------------------------------------------------------------
    // Category 1 — OrphanedChild. Identical SQL to the Postgres branch:
    // a LEFT JOIN against `tenants p` is portable, and the
    // `IntegrityScope::Subtree` filter fragment substitutes an `IN
    // (SELECT descendant_id FROM tenant_closure WHERE ancestor_id = $1)`
    // sub-select that SQLite supports natively.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id, t.parent_id \
             FROM tenants t \
             LEFT JOIN tenants p ON p.id = t.parent_id \
             WHERE t.parent_id IS NOT NULL AND p.id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "parent_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::OrphanedChild,
                Violation {
                    category: IntegrityCategory::OrphanedChild,
                    tenant_id: Some(id),
                    details: format!("parent {parent_id} missing for tenant {id}"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 2 — BrokenParentReference. Direct port; `<>` and integer
    // literals are dialect-portable.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id, t.parent_id, t.status \
             FROM tenants t \
             JOIN tenants p ON p.id = t.parent_id \
             WHERE p.status = 3 AND t.status <> 3{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "parent_id").map_err(map_query_err)?;
            let status: i16 = row.try_get("", "status").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::BrokenParentReference,
                Violation {
                    category: IntegrityCategory::BrokenParentReference,
                    tenant_id: Some(id),
                    details: format!(
                        "tenant {id} is status={status} but parent {parent_id} is Deleted"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 3 — DepthMismatch. Recursive CTE walks the tree from
    // every root. The Postgres `ARRAY[id]::uuid[] || t.id` accumulator
    // is replaced by a comma-bounded TEXT `path` and the
    // `NOT t.id = ANY(walk.path)` recursion guard becomes
    // `INSTR(walk.path, ',' || cast(t.id as text) || ',') = 0`. Same
    // semantics: descend one hop only when the candidate id is not
    // already on the path. The `step` column + cap is the
    // memory-bound for adversarial deeply-nested-but-non-cyclic input
    // (see `SQLITE_AUDIT_MAX_WALK_STEPS`).
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let step_cap = SQLITE_AUDIT_MAX_WALK_STEPS;
        let sql = format!(
            "WITH RECURSIVE walk(id, depth, path, step) AS ( \
                SELECT id, 0, ',' || cast(id as text) || ',', 0 \
                FROM tenants WHERE parent_id IS NULL \
                UNION ALL \
                SELECT t.id, w.depth + 1, w.path || cast(t.id as text) || ',', w.step + 1 \
                FROM tenants t \
                JOIN walk w ON t.parent_id = w.id \
                WHERE INSTR(w.path, ',' || cast(t.id as text) || ',') = 0 \
                  AND w.step < {step_cap} \
             ) \
             SELECT t.id, t.depth AS stored_depth, w.depth AS walk_depth \
             FROM tenants t \
             JOIN walk w ON w.id = t.id \
             WHERE t.depth <> w.depth{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let stored: i32 = row.try_get("", "stored_depth").map_err(map_query_err)?;
            let walk: i32 = row.try_get("", "walk_depth").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::DepthMismatch,
                Violation {
                    category: IntegrityCategory::DepthMismatch,
                    tenant_id: Some(id),
                    details: format!(
                        "tenant {id} stored depth {stored} but walk yields {walk}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 4 — Cycle. The TEXT-path variant of the Postgres
    // recursive CTE cycle detector. We seed the walk at every node with
    // a non-null `parent_id`, walk upward, and emit the offending node
    // whenever its `parent_id` is already on the recorded path —
    // i.e. `INSTR(path, ',' || cast(parent_id as text) || ',') > 0`.
    // The INSTR guard terminates a cycle in finite time; the explicit
    // `step` cap (see `SQLITE_AUDIT_MAX_WALK_STEPS`) is the additional
    // memory-bound for adversarial deeply-nested-but-non-cyclic
    // ancestry chains where the path TEXT would otherwise grow
    // quadratically.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let step_cap = SQLITE_AUDIT_MAX_WALK_STEPS;
        let sql = format!(
            "WITH RECURSIVE walk(id, parent_id, path, step) AS ( \
                SELECT id, parent_id, ',' || cast(id as text) || ',', 0 \
                FROM tenants WHERE parent_id IS NOT NULL \
                UNION ALL \
                SELECT t.id, t.parent_id, w.path || cast(t.id as text) || ',', w.step + 1 \
                FROM walk w \
                JOIN tenants t ON t.id = w.parent_id \
                WHERE INSTR(w.path, ',' || cast(t.id as text) || ',') = 0 \
                  AND w.step < {step_cap} \
             ) \
             SELECT DISTINCT t.id AS cycle_node, t.parent_id AS cycle_parent \
             FROM walk t \
             WHERE INSTR(t.path, ',' || cast(t.parent_id as text) || ',') > 0{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "cycle_node").map_err(map_query_err)?;
            let parent_id: Uuid = row.try_get("", "cycle_parent").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::Cycle,
                Violation {
                    category: IntegrityCategory::Cycle,
                    tenant_id: Some(id),
                    details: format!("cycle detected during tenant_depth at parent {parent_id}"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 5 — RootCountAnomaly. Whole-audits only. The two
    // sub-selects + COUNT(*) form is dialect-portable; SQLite returns
    // `i64` for COUNT(*) just like Postgres.
    // ------------------------------------------------------------------
    if scope_root.is_none() {
        let sql = "SELECT \
                (SELECT COUNT(*) FROM tenants WHERE parent_id IS NULL) AS root_count, \
                (SELECT COUNT(*) FROM tenants) AS total_count";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        if let Some(row) = rows.first() {
            let root_count: i64 = row.try_get("", "root_count").map_err(map_query_err)?;
            let total_count: i64 = row.try_get("", "total_count").map_err(map_query_err)?;
            if root_count > 1 {
                out.push((
                    IntegrityCategory::RootCountAnomaly,
                    Violation {
                        category: IntegrityCategory::RootCountAnomaly,
                        tenant_id: None,
                        details: format!(
                            "found {root_count} roots (parent_id IS NULL); expected 1"
                        ),
                    },
                ));
            }
            if root_count == 0 && total_count > 0 {
                out.push((
                    IntegrityCategory::RootCountAnomaly,
                    Violation {
                        category: IntegrityCategory::RootCountAnomaly,
                        tenant_id: None,
                        details: "no root tenant present but module has tenants".to_owned(),
                    },
                ));
            }
        }
    }

    // ------------------------------------------------------------------
    // Category 6 — MissingClosureSelfRow. Direct port; LEFT JOIN ON
    // multi-key + IS NULL is portable.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let sql = format!(
            "SELECT t.id \
             FROM tenants t \
             LEFT JOIN tenant_closure c ON c.descendant_id = t.id AND c.ancestor_id = t.id \
             WHERE t.status <> 0 AND c.descendant_id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::MissingClosureSelfRow,
                Violation {
                    category: IntegrityCategory::MissingClosureSelfRow,
                    tenant_id: Some(id),
                    details: format!("tenant {id} lacks self-row in tenant_closure"),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 7 — ClosureCoverageGap. The Postgres recursive CTE that
    // walks every SDK-visible descendant up its parent chain becomes
    // a TEXT-path walk on SQLite. The same INSTR cycle guard prevents
    // a corrupt parent-id loop from running away, mirroring the
    // `NOT p.id = ANY(w.path)` semantics on Postgres. The explicit
    // `step` cap (see `SQLITE_AUDIT_MAX_WALK_STEPS`) bounds quadratic
    // path-text growth on pathological non-cyclic chains.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let step_cap = SQLITE_AUDIT_MAX_WALK_STEPS;
        let sql = format!(
            "WITH RECURSIVE walk(descendant_id, ancestor_id, path, step) AS ( \
                SELECT t.id, t.parent_id, ',' || cast(t.id as text) || ',', 0 \
                FROM tenants t \
                WHERE t.status <> 0 AND t.parent_id IS NOT NULL \
                UNION ALL \
                SELECT w.descendant_id, p.parent_id, w.path || cast(p.id as text) || ',', w.step + 1 \
                FROM walk w \
                JOIN tenants p ON p.id = w.ancestor_id \
                WHERE w.ancestor_id IS NOT NULL \
                  AND INSTR(w.path, ',' || cast(p.id as text) || ',') = 0 \
                  AND w.step < {step_cap} \
             ) \
             SELECT DISTINCT t.id, w.ancestor_id \
             FROM walk w \
             JOIN tenants t ON t.id = w.descendant_id \
             LEFT JOIN tenant_closure c ON c.ancestor_id = w.ancestor_id AND c.descendant_id = w.descendant_id \
             WHERE w.ancestor_id IS NOT NULL AND c.ancestor_id IS NULL{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let id: Uuid = row.try_get("", "id").map_err(map_query_err)?;
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::ClosureCoverageGap,
                Violation {
                    category: IntegrityCategory::ClosureCoverageGap,
                    tenant_id: Some(id),
                    details: format!(
                        "closure gap: ancestor {ancestor_id} missing for descendant {id}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 8 — StaleClosureRow. Two passes, results unioned at the
    // application layer (matches the Postgres branch shape).
    //
    // 8a — missing endpoint: closure row whose ancestor_id or
    // descendant_id has no matching tenants row. UNION ALL with a
    // literal-string discriminator column ('descendant' / 'ancestor')
    // is portable. SQLite returns the discriminator as TEXT; we read
    // it as `String`.
    //
    // 8b — ancestry-not-in-walk: closure asserts an `(A, D)` edge that
    // is neither a self-row nor reachable along the parent_id walk.
    // The walk is the same TEXT-path recursive CTE from Cat 7 with the
    // INSTR cycle guard on the candidate id.
    // ------------------------------------------------------------------
    {
        // 8a: missing endpoint.
        let sql = "\
            SELECT c.descendant_id AS dangling, 'descendant' AS side \
            FROM tenant_closure c \
            LEFT JOIN tenants t ON t.id = c.descendant_id \
            WHERE t.id IS NULL \
            UNION ALL \
            SELECT c.ancestor_id AS dangling, 'ancestor' AS side \
            FROM tenant_closure c \
            LEFT JOIN tenants t ON t.id = c.ancestor_id \
            WHERE t.id IS NULL";
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let dangling: Uuid = row.try_get("", "dangling").map_err(map_query_err)?;
            let side: String = row.try_get("", "side").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::StaleClosureRow,
                Violation {
                    category: IntegrityCategory::StaleClosureRow,
                    tenant_id: Some(dangling),
                    details: format!("closure row references missing {side} {dangling}"),
                },
            ));
        }

        // 8b: ancestry not present in parent_id walk. The explicit
        // `step` cap (see `SQLITE_AUDIT_MAX_WALK_STEPS`) bounds
        // path-text growth on pathological non-cyclic chains; this
        // walk reuses the Cat 7 shape so the same cap applies.
        let step_cap = SQLITE_AUDIT_MAX_WALK_STEPS;
        let sql = format!(
            "WITH RECURSIVE walk(descendant_id, ancestor_id, path, step) AS ( \
                SELECT t.id, t.parent_id, ',' || cast(t.id as text) || ',', 0 \
                FROM tenants t \
                WHERE t.parent_id IS NOT NULL \
                UNION ALL \
                SELECT w.descendant_id, p.parent_id, w.path || cast(p.id as text) || ',', w.step + 1 \
                FROM walk w \
                JOIN tenants p ON p.id = w.ancestor_id \
                WHERE w.ancestor_id IS NOT NULL \
                  AND INSTR(w.path, ',' || cast(p.id as text) || ',') = 0 \
                  AND w.step < {step_cap} \
            ), \
            edges AS ( \
                SELECT descendant_id, ancestor_id FROM walk WHERE ancestor_id IS NOT NULL \
                UNION \
                SELECT id, id FROM tenants \
            ) \
            SELECT c.ancestor_id, c.descendant_id \
            FROM tenant_closure c \
            JOIN tenants ta ON ta.id = c.ancestor_id \
            JOIN tenants td ON td.id = c.descendant_id \
            LEFT JOIN edges e ON e.ancestor_id = c.ancestor_id AND e.descendant_id = c.descendant_id \
            WHERE c.ancestor_id <> c.descendant_id AND e.ancestor_id IS NULL"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::StaleClosureRow,
                Violation {
                    category: IntegrityCategory::StaleClosureRow,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}) asserts ancestry not present in parent_id walk"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 9 — BarrierColumnDivergence. The Postgres recursive CTE
    // walks every strict closure row's `(D, A]` parent chain with an
    // accumulating `has_self_managed OR p.self_managed` flag. SQLite
    // stores `self_managed` as INTEGER (0/1) per the migration in
    // `m0001_create_tenants.rs`; the OR is replaced by `MAX(...)` over
    // 0/1 integers because SQLite does not implicitly coerce
    // INTEGER ↔ BOOLEAN like Postgres. The terminating `cursor_id =
    // closure_ancestor` predicate and the comparison
    // `c.barrier <> CASE WHEN tr.has_self_managed THEN 1 ELSE 0 END`
    // are dialect-portable. The explicit `step` cap (see
    // `SQLITE_AUDIT_MAX_WALK_STEPS`) bounds path-text growth on
    // pathological non-cyclic chains.
    // ------------------------------------------------------------------
    {
        let step_cap = SQLITE_AUDIT_MAX_WALK_STEPS;
        let sql = format!(
            "WITH RECURSIVE walk(closure_ancestor, closure_descendant, cursor_id, path, has_self_managed, step) AS ( \
                SELECT c.ancestor_id, c.descendant_id, t.parent_id, \
                       ',' || cast(t.id as text) || ',', t.self_managed, 0 \
                FROM tenant_closure c \
                JOIN tenants t ON t.id = c.descendant_id \
                WHERE c.ancestor_id <> c.descendant_id \
                UNION ALL \
                SELECT w.closure_ancestor, w.closure_descendant, p.parent_id, \
                       w.path || cast(p.id as text) || ',', \
                       MAX(w.has_self_managed, p.self_managed), \
                       w.step + 1 \
                FROM walk w \
                JOIN tenants p ON p.id = w.cursor_id \
                WHERE w.cursor_id IS NOT NULL AND w.cursor_id <> w.closure_ancestor \
                  AND INSTR(w.path, ',' || cast(p.id as text) || ',') = 0 \
                  AND w.step < {step_cap} \
            ), \
            terminated AS ( \
                SELECT closure_ancestor, closure_descendant, has_self_managed \
                FROM walk \
                WHERE cursor_id = closure_ancestor \
            ) \
            SELECT c.ancestor_id, c.descendant_id, c.barrier AS actual_barrier, \
                   CASE WHEN tr.has_self_managed THEN 1 ELSE 0 END AS expected_barrier \
            FROM tenant_closure c \
            JOIN terminated tr ON tr.closure_ancestor = c.ancestor_id AND tr.closure_descendant = c.descendant_id \
            WHERE c.ancestor_id <> c.descendant_id \
              AND c.barrier <> CASE WHEN tr.has_self_managed THEN 1 ELSE 0 END"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![],
            ))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            let actual: i16 = row.try_get("", "actual_barrier").map_err(map_query_err)?;
            let expected: i32 = row.try_get("", "expected_barrier").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::BarrierColumnDivergence,
                Violation {
                    category: IntegrityCategory::BarrierColumnDivergence,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}).barrier={actual} but expected {expected}"
                    ),
                },
            ));
        }
    }

    // ------------------------------------------------------------------
    // Category 10 — DescendantStatusDivergence. Direct port — INNER
    // JOIN + `<>` on SMALLINT columns is portable.
    // ------------------------------------------------------------------
    {
        let (filter, values) = scope_filter_sqlite("t", scope_root, 1);
        let sql = format!(
            "SELECT c.ancestor_id, c.descendant_id, c.descendant_status, t.status \
             FROM tenant_closure c \
             JOIN tenants t ON t.id = c.descendant_id \
             WHERE t.status <> 0 AND c.descendant_status <> t.status{filter}"
        );
        let rows = tx
            .query_raw_all(Statement::from_sql_and_values(DbBackend::Sqlite, sql, values))
            .await
            .map_err(AmError::from)?;
        for row in rows {
            let ancestor_id: Uuid = row.try_get("", "ancestor_id").map_err(map_query_err)?;
            let descendant_id: Uuid = row.try_get("", "descendant_id").map_err(map_query_err)?;
            let stored: i16 = row.try_get("", "descendant_status").map_err(map_query_err)?;
            let current: i16 = row.try_get("", "status").map_err(map_query_err)?;
            out.push((
                IntegrityCategory::DescendantStatusDivergence,
                Violation {
                    category: IntegrityCategory::DescendantStatusDivergence,
                    tenant_id: Some(descendant_id),
                    details: format!(
                        "closure({ancestor_id} -> {descendant_id}).descendant_status={stored} but tenants.status={current}"
                    ),
                },
            ));
        }
    }

    Ok(out)
}

/// Map a `SeaORM` `DbErr` (raised by `QueryResult::try_get` when a
/// column is missing or a value can't be coerced) into the canonical
/// AM internal error. We do not route this through the standard
/// `From<DbError> for AmError` ladder because column-extraction
/// failures are always programmer errors (drift between query SQL and
/// the column names this code expects), not transient infra failures
/// — surfacing them as `Internal` is the correct mapping.
#[allow(
    clippy::needless_pass_by_value,
    reason = "used as a map_err callback; the DbErr is consumed into the formatted diagnostic"
)]
fn map_query_err(err: sea_orm::DbErr) -> AmError {
    AmError::Internal {
        diagnostic: format!("audit query column extraction failed: {err}"),
    }
}

#[async_trait]
impl TenantRepo for TenantRepoImpl {
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, AmError> {
        let conn = self.db.conn()?;
        let row = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(id_eq(id))
            .one(&conn)
            .await
            .map_err(map_scope_err)?;
        match row {
            Some(r) => Ok(Some(entity_to_model(r)?)),
            None => Ok(None),
        }
    }

    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage, AmError> {
        let conn = self.db.conn()?;

        // Base filter: parent_id = query.parent_id AND status filter.
        let status_filter_cond = if let Some(statuses) = query.status_filter() {
            let mut any_of = Condition::any();
            for s in statuses {
                any_of = any_of.add(tenants::Column::Status.eq(s.as_smallint()));
            }
            any_of
        } else {
            // Default: active and suspended only. Callers must explicitly
            // request status=deleted to see soft-deleted tenants.
            Condition::any()
                .add(tenants::Column::Status.eq(TenantStatus::Active.as_smallint()))
                .add(tenants::Column::Status.eq(TenantStatus::Suspended.as_smallint()))
        };

        let base = Condition::all()
            .add(tenants::Column::ParentId.eq(query.parent_id))
            .add(status_filter_cond);

        // Stable ordering: (created_at ASC, id ASC) per DESIGN §3.3.
        let items_rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(base.clone())
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .limit(u64::from(query.top))
            .offset(u64::from(query.skip))
            .all(&conn)
            .await
            .map_err(map_scope_err)?;

        let total: u64 = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(base)
            .count(&conn)
            .await
            .map_err(map_scope_err)?;

        let mut items = Vec::with_capacity(items_rows.len());
        for r in items_rows {
            items.push(entity_to_model(r)?);
        }

        Ok(TenantPage {
            items,
            top: query.top,
            skip: query.skip,
            total: Some(total),
        })
    }

    async fn insert_provisioning(
        &self,
        scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, AmError> {
        use sea_orm::ActiveValue;
        let conn = self.db.conn()?;
        let now = OffsetDateTime::now_utc();
        let am = tenants::ActiveModel {
            id: ActiveValue::Set(tenant.id),
            parent_id: ActiveValue::Set(tenant.parent_id),
            name: ActiveValue::Set(tenant.name.clone()),
            status: ActiveValue::Set(TenantStatus::Provisioning.as_smallint()),
            self_managed: ActiveValue::Set(tenant.self_managed),
            tenant_type_uuid: ActiveValue::Set(tenant.tenant_type_uuid),
            depth: ActiveValue::Set(i32::try_from(tenant.depth).map_err(|_| {
                AmError::Internal {
                    diagnostic: format!("depth overflow: {}", tenant.depth),
                }
            })?),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
            deleted_at: ActiveValue::Set(None),
            deletion_scheduled_at: ActiveValue::Set(None),
            retention_window_secs: ActiveValue::Set(None),
            claimed_by: ActiveValue::Set(None),
            claimed_at: ActiveValue::Set(None),
        };
        // scope_unchecked: `tenants.tenant_col = "id"` so `scope_with` would
        // require an existing row with that id — there is none yet on INSERT.
        // The caller always passes `allow_all` (PEP gate is the real guard).
        let model: tenants::Model = tenants::Entity::insert(am)
            .secure()
            .scope_unchecked(scope)
            .map_err(map_scope_err)?
            .exec_with_returning(&conn)
            .await
            .map_err(|e| match e {
                modkit_db::secure::ScopeError::Db(ref db) if is_unique_violation(db) => {
                    AmError::Conflict {
                        detail: format!("tenant {} already exists", tenant.id),
                    }
                }
                other => map_scope_err(other),
            })?;
        entity_to_model(model)
    }

    async fn activate_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        closure_rows: &[ClosureRow],
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, AmError> {
        let rows = closure_rows.to_vec();
        let metadata_entries = metadata_entries.to_vec();
        let scope = scope.clone();
        let result = with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            let rows = rows.clone();
            let metadata_entries = metadata_entries.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    use sea_orm::ActiveValue;

                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {tenant_id} not found for activation"),
                        })?;

                    if existing.status != TenantStatus::Provisioning.as_smallint() {
                        return Err(AmError::Conflict {
                            detail: format!("tenant {tenant_id} not in provisioning state"),
                        });
                    }

                    // Flip status -> Active + bump updated_at via SecureUpdateMany.
                    let now = OffsetDateTime::now_utc();
                    let rows_affected = tenants::Entity::update_many()
                        .col_expr(
                            tenants::Column::Status,
                            Expr::value(TenantStatus::Active.as_smallint()),
                        )
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                        .filter(id_eq(tenant_id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?
                        .rows_affected;
                    if rows_affected == 0 {
                        return Err(AmError::NotFound {
                            detail: format!("tenant {tenant_id} missing during activation"),
                        });
                    }

                    // Insert closure rows in a single multi-row INSERT.
                    // SeaORM `Entity::insert_many` returns the same
                    // `Insert<A>` builder the secure wrapper extends,
                    // so we keep the secure-execution path while
                    // collapsing depth-N RT into one. The closure
                    // entity is declared with `no_tenant, no_resource,
                    // no_owner, no_type` — closure rows are
                    // cross-tenant by definition — so `scope_unchecked`
                    // is the appropriate scope mode (matches the
                    // single-row insert path immediately above the
                    // refactor).
                    if !rows.is_empty() {
                        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                        let active_models = rows.iter().map(|row| tenant_closure::ActiveModel {
                            ancestor_id: ActiveValue::Set(row.ancestor_id),
                            descendant_id: ActiveValue::Set(row.descendant_id),
                            barrier: ActiveValue::Set(row.barrier),
                            descendant_status: ActiveValue::Set(row.descendant_status),
                        });
                        tenant_closure::Entity::insert_many(active_models)
                            .secure()
                            .scope_unchecked(&scope)
                            .map_err(map_scope_err)?
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;
                        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                    }

                    if !metadata_entries.is_empty() {
                        let metadata_rows =
                            metadata_entries.iter().map(|entry| tenant_metadata::ActiveModel {
                                tenant_id: ActiveValue::Set(tenant_id),
                                schema_uuid: ActiveValue::Set(schema_uuid_from_gts_id(
                                    &entry.schema_id,
                                )),
                                value: ActiveValue::Set(entry.value.clone()),
                                created_at: ActiveValue::Set(now),
                                updated_at: ActiveValue::Set(now),
                            });
                        tenant_metadata::Entity::insert_many(metadata_rows)
                            .secure()
                            .scope_unchecked(&scope)
                            .map_err(map_scope_err)?
                            .exec(tx)
                            .await
                            .map_err(|e| match e {
                                modkit_db::secure::ScopeError::Db(ref db)
                                    if is_unique_violation(db) =>
                                {
                                    AmError::Conflict {
                                        detail: format!(
                                            "tenant {tenant_id} metadata contains duplicate schema entries"
                                        ),
                                    }
                                }
                                other => map_scope_err(other),
                            })?;
                    }

                    // Re-read so the caller gets a fresh model with the new status.
                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {tenant_id} disappeared after activation"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await?;
        Ok(result)
    }

    async fn compensate_provisioning(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), AmError> {
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?;
                    match existing {
                        Some(row)
                            if row.status == TenantStatus::Provisioning.as_smallint() =>
                        {
                            tenants::Entity::delete_many()
                                .filter(
                                    Condition::all()
                                        .add(tenants::Column::Id.eq(tenant_id))
                                        .add(
                                            tenants::Column::Status
                                                .eq(TenantStatus::Provisioning.as_smallint()),
                                        ),
                                )
                                .secure()
                                .scope_with(&scope)
                                .exec(tx)
                                .await
                                .map_err(map_scope_err)?;
                            Ok(())
                        }
                        Some(_) => Err(AmError::Conflict {
                            detail: format!(
                                "refusing to compensate: tenant {tenant_id} not in provisioning state"
                            ),
                        }),
                        None => Ok(()),
                    }
                })
            })
        })
        .await
    }

    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, AmError> {
        let patch_owned = patch.clone();
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let patch_owned = patch_owned.clone();
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    // SERIALIZABLE anti-dependency anchor: the SELECT
                    // forces this transaction to see the row in its
                    // pre-update state, so a concurrent PATCH on the
                    // same row triggers a `40001` serialization
                    // failure instead of a lost update. The row value
                    // itself is unused — discarded with `let _row`
                    // rather than removed entirely so the read isn't
                    // optimised away. Also gates the path on row
                    // existence, mapping a missing tenant to
                    // `NotFound` before any write SQL is sent.
                    let _row = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {tenant_id} not found"),
                        })?;

                    let now = OffsetDateTime::now_utc();
                    let mut upd = tenants::Entity::update_many()
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now));
                    if let Some(ref new_name) = patch_owned.name {
                        upd = upd.col_expr(tenants::Column::Name, Expr::value(new_name.clone()));
                    }
                    if let Some(new_status) = patch_owned.status {
                        upd = upd.col_expr(
                            tenants::Column::Status,
                            Expr::value(new_status.as_smallint()),
                        );
                    }
                    upd.filter(id_eq(tenant_id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Rewrite tenant_closure.descendant_status atomically on status change.
                    // The closure entity is `no_tenant, no_resource, no_owner,
                    // no_type` — closure rows are cross-tenant by definition,
                    // matching the rationale at the activation insert above.
                    // A PDP-narrowed `scope` would resolve every property to
                    // `None` on this entity and `build_scope_condition`
                    // collapses that to `WHERE false` (all constraints fail
                    // to compile → `deny_all()`), making the UPDATE silently
                    // affect zero rows. Use `allow_all` so the in-tx
                    // descendant-status rewrite reaches its target rows;
                    // authorization for the underlying tenant is already
                    // enforced one statement up by the scoped `tenants`
                    // UPDATE.
                    if let Some(new_status) = patch_owned.status {
                        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-status-update
                        tenant_closure::Entity::update_many()
                            .col_expr(
                                tenant_closure::Column::DescendantStatus,
                                Expr::value(new_status.as_smallint()),
                            )
                            .filter(
                                Condition::all()
                                    .add(tenant_closure::Column::DescendantId.eq(tenant_id)),
                            )
                            .secure()
                            .scope_with(&AccessScope::allow_all())
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;
                        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-status-update
                    }

                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {tenant_id} disappeared after update"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await
    }

    async fn load_strict_ancestors_of_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, AmError> {
        let conn = self.db.conn()?;

        // Resolve the strict ancestors via `parent`'s closure rows:
        // every `descendant_id = parent_id` row in `tenant_closure`
        // names a tenant on the chain `[parent, parent's parent, …,
        // root]`. One RT into closure → one RT into `tenants` for the
        // strict-ancestor set, regardless of depth.
        //
        // `tenant_closure` carries no per-row tenant ownership column
        // (`no_tenant`, `no_resource`) — closure rows are cross-tenant
        // by definition — so the scoped read is the subsequent
        // `tenants` query.
        let closure_rows = tenant_closure::Entity::find()
            .secure()
            .scope_with(&AccessScope::allow_all())
            .filter(Condition::all().add(tenant_closure::Column::DescendantId.eq(parent_id)))
            .all(&conn)
            .await
            .map_err(map_scope_err)?;

        if closure_rows.is_empty() {
            // Defensive fallback: parent has no closure rows yet (e.g.
            // diagnostic call against an in-flight provisioning parent).
            // Walk via `parent_id` like the legacy implementation; this
            // path is rare and bounded by the depth invariant.
            //
            // The walk is hard-capped at `MAX_ANCESTOR_WALK_HOPS` so a
            // corrupt `parent_id` cycle (or a depth value that disagrees
            // with the actual chain length) can't loop indefinitely
            // issuing one DB round-trip per hop. The cap is well above
            // any realistic depth_threshold; overrun returns
            // `AmError::Internal` so ops sees the corruption.
            const MAX_ANCESTOR_WALK_HOPS: usize = 64;
            // Emit a WARN whenever we land here so a closure-table gap
            // developing in production (the only non-bootstrap reason
            // this branch fires) is surfaced rather than silently
            // absorbing the per-hop round-trips.
            tracing::warn!(
                target: "am.tenant_repo",
                parent_id = %parent_id,
                "load_strict_ancestors_of_parent: closure rows empty; falling back to parent_id walk (one query per hop)"
            );
            let mut chain = Vec::new();
            let mut cursor_id = Some(parent_id);
            let mut hops = 0usize;
            while let Some(pid) = cursor_id {
                if hops >= MAX_ANCESTOR_WALK_HOPS {
                    return Err(AmError::Internal {
                        diagnostic: format!(
                            "ancestor walk exceeded {MAX_ANCESTOR_WALK_HOPS} hops from parent {parent_id}; possible parent_id cycle"
                        ),
                    });
                }
                let parent = tenants::Entity::find()
                    .secure()
                    .scope_with(scope)
                    .filter(id_eq(pid))
                    .one(&conn)
                    .await
                    .map_err(map_scope_err)?
                    .ok_or_else(|| AmError::NotFound {
                        detail: format!("ancestor {pid} missing while walking chain"),
                    })?;
                cursor_id = parent.parent_id;
                chain.push(entity_to_model(parent)?);
                hops += 1;
            }
            return Ok(chain);
        }

        let ancestor_ids: Vec<Uuid> = closure_rows.iter().map(|r| r.ancestor_id).collect();
        let rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(Condition::all().add(tenants::Column::Id.is_in(ancestor_ids.clone())))
            .order_by(tenants::Column::Depth, Order::Desc)
            .all(&conn)
            .await
            .map_err(map_scope_err)?;
        if rows.len() != ancestor_ids.len() {
            let found: HashSet<Uuid> = rows.iter().map(|r| r.id).collect();
            let mut missing_ids: Vec<Uuid> = ancestor_ids
                .iter()
                .copied()
                .filter(|id| !found.contains(id))
                .collect();
            missing_ids.sort_unstable();
            return Err(AmError::NotFound {
                detail: format!("ancestor ids missing: {missing_ids:?}"),
            });
        }

        let mut chain = Vec::with_capacity(rows.len());
        for r in rows {
            chain.push(entity_to_model(r)?);
        }
        Ok(chain)
    }

    // -----------------------------------------------------------------
    // Phase 3 — retention scan, reaper scan, hard-delete, integrity load
    // -----------------------------------------------------------------

    async fn scan_retention_due(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, AmError> {
        // Push the per-row due-check into SQL so the `LIMIT` applies to
        // *due* rows only. The earlier implementation over-fetched
        // `4 × batch` rows ordered by `scheduled_at ASC` and applied
        // `is_due` in Rust afterwards — but a backlog of older
        // not-yet-due rows (typical case: NULL `retention_window_secs`
        // → default 90 days) could fill the over-fetch window and
        // starve newer due rows (e.g. soft-deleted with explicit
        // `retention_window_secs = 0`). The reviewer flagged this as
        // an indefinite-delay class of bug; by filtering at the DB the
        // due-set is exact and starvation is impossible.
        //
        // The effective due predicate is
        //   `scheduled_at + COALESCE(retention_window_secs, default) seconds <= now`.
        // Both supported backends express this as a single comparison
        // against `now`; no engine-specific INTERVAL arithmetic is
        // exposed to Rust. The MySQL backend is unsupported by AM
        // migrations (see `m0001_create_tenants`) so it errors here
        // for symmetry with the migration-set rejection.
        let engine = self.db.db().db_engine();
        let default_secs = i64::try_from(default_retention.as_secs()).unwrap_or(i64::MAX);
        let due_check = match engine {
            "postgres" => Expr::cust_with_values(
                "deletion_scheduled_at + make_interval(secs => COALESCE(retention_window_secs, $1)) <= $2",
                vec![
                    sea_orm::Value::from(default_secs),
                    sea_orm::Value::from(now),
                ],
            ),
            "sqlite" => Expr::cust_with_values(
                // SQLite stores TIMESTAMP as TEXT (ISO-8601);
                // `julianday()` returns a numeric so the comparison
                // is monotonic regardless of the textual format
                // SeaORM uses for the bound `now`.
                "julianday(deletion_scheduled_at) + COALESCE(retention_window_secs, $1) / 86400.0 <= julianday($2)",
                vec![
                    sea_orm::Value::from(default_secs),
                    sea_orm::Value::from(now),
                ],
            ),
            other => {
                return Err(AmError::Internal {
                    diagnostic: format!(
                        "scan_retention_due: backend '{other}' is not a supported AM backend"
                    ),
                });
            }
        };

        let cap = u64::try_from(limit).unwrap_or(u64::MAX);
        let worker_id = Uuid::new_v4();
        // Stale-claim cutoff: a row claimed before this instant whose
        // `clear_retention_claim` evidently never landed (else
        // `claimed_by` would be NULL) is up for re-claim by another
        // worker. Computed in Rust so the SQL stays portable across
        // the two supported engines.
        let stale_cutoff = match time::Duration::try_from(RETENTION_CLAIM_TTL) {
            Ok(d) => now - d,
            Err(_) => now,
        };
        let scope = scope.clone();
        let rows = self
            .db
            .transaction_with_config(
                TxConfig {
                    isolation: Some(TxIsolationLevel::ReadCommitted),
                    access_mode: Some(TxAccessMode::ReadWrite),
                },
                move |tx| {
                    Box::pin(async move {
                        // Claimable iff unclaimed OR the previous claim
                        // is older than `RETENTION_CLAIM_TTL`. The
                        // dedicated `claimed_at` column is the
                        // claim-age marker (see comment on
                        // `RETENTION_CLAIM_TTL`); decoupled from
                        // `updated_at` so any future patch path that
                        // bumps `updated_at` on a `Deleted`-status row
                        // does not inadvertently keep stale claims
                        // alive.
                        let claimable = Condition::any()
                            .add(tenants::Column::ClaimedBy.is_null())
                            .add(tenants::Column::ClaimedAt.lte(stale_cutoff));
                        let scan_filter = Condition::all()
                            .add(tenants::Column::Status.eq(TenantStatus::Deleted.as_smallint()))
                            .add(tenants::Column::DeletionScheduledAt.is_not_null())
                            .add(claimable.clone())
                            .add(due_check);

                        // No `FOR UPDATE SKIP LOCKED` here: the
                        // claim-and-go correctness relies on the
                        // atomic UPDATE below — only one worker can
                        // satisfy the `claimable` predicate for any
                        // given row, the others' UPDATE simply
                        // affects 0 rows. Skipping the lock keeps the
                        // scan portable across the two supported
                        // backends; under high concurrency two workers
                        // may scan overlapping candidate sets and
                        // waste a round-trip on the losing UPDATE,
                        // but no row is double-claimed.
                        let candidates = tenants::Entity::find()
                            .secure()
                            .scope_with(&scope)
                            .filter(scan_filter)
                            .order_by(tenants::Column::DeletionScheduledAt, Order::Asc)
                            .order_by(tenants::Column::Depth, Order::Desc)
                            .order_by(tenants::Column::Id, Order::Asc)
                            .limit(cap)
                            .all(tx)
                            .await
                            .map_err(map_scope_err)?;
                        let candidate_ids: Vec<Uuid> =
                            candidates.iter().map(|row| row.id).collect();
                        if candidate_ids.is_empty() {
                            return Ok(Vec::new());
                        }

                        // Stamp `claimed_at` with `now` so the new
                        // claim's age can be aged out by the same TTL
                        // predicate above if `clear_retention_claim`
                        // later fails. `updated_at` is intentionally
                        // not touched: claim acquisition is a
                        // worker-side bookkeeping event, not a tenant
                        // mutation, and conflating the two columns
                        // would couple worker-liveness detection to
                        // any future patch path.
                        //
                        // Two-statement portable pattern (UPDATE then
                        // SELECT-by-claim-marker) instead of
                        // `UPDATE … RETURNING`: the latter is Postgres-
                        // and SQLite-only, but `modkit-db` is meant to
                        // stay backend-agnostic so MySQL deployments
                        // remain viable. We're inside the
                        // `with_serializable_retry` boundary, so the
                        // SELECT observes a snapshot consistent with
                        // the UPDATE we just issued — exactly the rows
                        // whose `claimed_by` is now `worker_id`
                        // restricted to the candidate window.
                        let candidate_ids_for_select = candidate_ids.clone();
                        tenants::Entity::update_many()
                            .col_expr(tenants::Column::ClaimedBy, Expr::value(worker_id))
                            .col_expr(tenants::Column::ClaimedAt, Expr::value(now))
                            .filter(
                                Condition::all()
                                    .add(tenants::Column::Id.is_in(candidate_ids))
                                    .add(claimable),
                            )
                            .secure()
                            .scope_with(&scope)
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;

                        tenants::Entity::find()
                            .filter(
                                Condition::all()
                                    .add(tenants::Column::Id.is_in(candidate_ids_for_select))
                                    .add(tenants::Column::ClaimedBy.eq(worker_id)),
                            )
                            .secure()
                            .scope_with(&scope)
                            .all(tx)
                            .await
                            .map_err(map_scope_err)
                    })
                },
            )
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Some(scheduled_at) = r.deletion_scheduled_at else {
                continue;
            };
            let retention = match r.retention_window_secs {
                Some(secs) if secs >= 0 => Duration::from_secs(u64::try_from(secs).unwrap_or(0)),
                _ => default_retention,
            };
            // Defense-in-depth: the SQL filter is the source of truth;
            // we re-verify in Rust to catch any semantic drift between
            // backend date math and the domain `is_due` contract
            // (e.g. timezone normalisation differences). A mismatch is
            // logged but does not surface a hard error — the row is
            // simply skipped this tick and re-evaluated next one.
            if !crate::domain::tenant::retention::is_due(now, scheduled_at, retention) {
                tracing::warn!(
                    target: "am.tenant_retention",
                    tenant_id = %r.id,
                    "row matched SQL due-check but failed Rust is_due; skipping for this tick"
                );
                continue;
            }
            out.push(TenantRetentionRow {
                id: r.id,
                depth: u32::try_from(r.depth).map_err(|_| AmError::Internal {
                    diagnostic: format!(
                        "tenants.depth negative for retention row {}: {}",
                        r.id, r.depth
                    ),
                })?,
                deletion_scheduled_at: scheduled_at,
                retention_window: retention,
                claimed_by: worker_id,
            });
        }
        // The SQL ordering is by `scheduled_at ASC` for index locality;
        // re-sort to the leaf-first order the batch processor expects
        // (`depth DESC, id ASC`).
        out.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn clear_retention_claim(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        worker_id: Uuid,
    ) -> Result<(), AmError> {
        let conn = self.db.conn()?;
        // `claimed_by = worker_id` predicate fences this UPDATE to the
        // worker that originally claimed the row. If the TTL elapsed
        // and a peer worker took over, the predicate fails and this
        // call is a no-op — the peer's live claim is preserved.
        // `claimed_at` is cleared together with `claimed_by` so the
        // claim-age column never lingers on an unclaimed row.
        tenants::Entity::update_many()
            .col_expr(
                tenants::Column::ClaimedBy,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                tenants::Column::ClaimedAt,
                Expr::value(Option::<OffsetDateTime>::None),
            )
            .filter(
                Condition::all()
                    .add(tenants::Column::Id.eq(tenant_id))
                    .add(tenants::Column::ClaimedBy.eq(worker_id)),
            )
            .secure()
            .scope_with(scope)
            .exec(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(())
    }

    async fn scan_stuck_provisioning(
        &self,
        scope: &AccessScope,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, AmError> {
        let conn = self.db.conn()?;
        // Bound the query at the SQL layer so a large stuck-provisioning
        // backlog cannot load every row into memory in one round-trip.
        // Mirrors `scan_retention_due`'s capped fetch pattern.
        //
        // Unlike `scan_retention_due` this method does NOT take a row
        // lock or atomic claim. Two reaper instances scanning the same
        // window may both pick up the same `Provisioning` row and both
        // call `IdpTenantProvisioner::deprovision_tenant` for it. That
        // is acceptable because:
        // 1. `deprovision_tenant` is idempotent per the
        //    `idp-tenant-deprovision` DoD — a second invocation on an
        //    already-removed tenant returns Ok or `UnsupportedOperation`,
        //    not a hard error.
        // 2. The follow-up DB teardown flows through
        //    `schedule_deletion(retention = 0)` which itself errors with
        //    `Conflict` if the row is already `Deleted`, so the second
        //    worker's branch lands on `NotEligible` at hard-delete time.
        // The cost is a wasted IdP call window equal to one
        // `reaper_tick_secs`, traded against the schema cost of adding a
        // claim column purely for liveness.
        let cap = u64::try_from(limit).unwrap_or(u64::MAX);
        let rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(
                Condition::all()
                    .add(tenants::Column::Status.eq(TenantStatus::Provisioning.as_smallint()))
                    .add(tenants::Column::CreatedAt.lte(older_than)),
            )
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .limit(cap)
            .all(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(rows
            .into_iter()
            .map(|r| TenantProvisioningRow {
                id: r.id,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn count_children(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        include_deleted: bool,
    ) -> Result<u64, AmError> {
        let connection = self.db.conn()?;
        let mut filter = Condition::all().add(tenants::Column::ParentId.eq(parent_id));
        if !include_deleted {
            filter = filter.add(tenants::Column::Status.ne(TenantStatus::Deleted.as_smallint()));
        }
        tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(filter)
            .count(&connection)
            .await
            .map_err(map_scope_err)
    }

    async fn schedule_deletion(
        &self,
        scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, AmError> {
        // Fail-fast on overflow. Silently clamping a misconfigured
        // duration of e.g. `Duration::MAX` to ~292 billion years would
        // mask the misconfig and produce rows that never become
        // retention-due. Returning `Internal` surfaces the bug to ops
        // immediately.
        let retention_secs: Option<i64> = match retention {
            None => None,
            Some(d) => Some(i64::try_from(d.as_secs()).map_err(|_| AmError::Internal {
                diagnostic: format!(
                    "retention duration {} secs overflows i64; misconfiguration",
                    d.as_secs()
                ),
            })?),
        };
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {id} not found"),
                        })?;
                    if existing.status == TenantStatus::Deleted.as_smallint() {
                        return Err(AmError::Conflict {
                            detail: format!("tenant {id} already deleted"),
                        });
                    }

                    let mut upd = tenants::Entity::update_many()
                        .col_expr(
                            tenants::Column::Status,
                            Expr::value(TenantStatus::Deleted.as_smallint()),
                        )
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                        // `deleted_at` is the public-contract tombstone
                        // exposed through the `Tenant` schema
                        // (`account-management-v1.yaml:591`) and the
                        // partial index `idx_tenants_deleted_at`
                        // declared by `m0001_create_tenants`. The
                        // earlier implementation only stamped
                        // `deletion_scheduled_at` and left this column
                        // permanently NULL — which both made the
                        // dedicated partial index empty and surfaced
                        // soft-deleted rows to the API with
                        // `status=deleted, deleted_at=null`, violating
                        // the OpenAPI contract.
                        .col_expr(tenants::Column::DeletedAt, Expr::value(now))
                        .col_expr(tenants::Column::DeletionScheduledAt, Expr::value(now));
                    if let Some(secs) = retention_secs {
                        upd = upd.col_expr(tenants::Column::RetentionWindowSecs, Expr::value(secs));
                    }
                    upd.filter(id_eq(id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Rewrite descendant_status on every closure row that
                    // points at this tenant (same invariant as update).
                    // `allow_all` for the same reason as `update_tenant_mutable`:
                    // closure is `no_tenant/no_resource/no_owner/no_type`, so a
                    // PDP-narrowed scope collapses to `WHERE false` here. The
                    // scoped `tenants` UPDATE above already enforces caller
                    // authorization for the target tenant.
                    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-soft-delete-status
                    tenant_closure::Entity::update_many()
                        .col_expr(
                            tenant_closure::Column::DescendantStatus,
                            Expr::value(TenantStatus::Deleted.as_smallint()),
                        )
                        .filter(Condition::all().add(tenant_closure::Column::DescendantId.eq(id)))
                        .secure()
                        .scope_with(&AccessScope::allow_all())
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-soft-delete-status

                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {id} disappeared after schedule_deletion"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await
    }

    async fn hard_delete_one(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, AmError> {
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?;
                    let Some(row) = existing else {
                        // Row already gone — treat as cleaned for idempotency.
                        return Ok(HardDeleteOutcome::Cleaned);
                    };
                    if row.status != TenantStatus::Deleted.as_smallint()
                        || row.deletion_scheduled_at.is_none()
                    {
                        return Ok(HardDeleteOutcome::NotEligible);
                    }

                    // In-tx child-existence guard. If any row (including
                    // Deleted children that haven't been reclaimed yet)
                    // still names this tenant as parent, defer.
                    let children = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(Condition::all().add(tenants::Column::ParentId.eq(id)))
                        .count(tx)
                        .await
                        .map_err(map_scope_err)?;
                    if children > 0 {
                        return Ok(HardDeleteOutcome::DeferredChildPresent);
                    }

                    // Closure rows first (FK cascades would do this on
                    // Postgres, but we clear explicitly to remain
                    // dialect-portable). `allow_all` because the closure
                    // entity is `no_tenant/no_resource/no_owner/no_type` —
                    // see `update_tenant_mutable` for the full rationale.
                    // The retention pipeline calls `hard_delete_one` with
                    // `allow_all` today, so this also future-proofs the
                    // method against any caller that might pass a
                    // narrowed scope.
                    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete
                    tenant_closure::Entity::delete_many()
                        .filter(
                            Condition::any()
                                .add(tenant_closure::Column::AncestorId.eq(id))
                                .add(tenant_closure::Column::DescendantId.eq(id)),
                        )
                        .secure()
                        .scope_with(&AccessScope::allow_all())
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete

                    // Metadata rows next. Same dialect-portability rule as
                    // closure: SQLite does not enforce FK cascades because
                    // `modkit-db` does not enable `PRAGMA foreign_keys`,
                    // so the `ON DELETE CASCADE` declared in
                    // `m0004_create_tenant_metadata` would silently leak
                    // orphaned rows on SQLite-backed deployments. The
                    // entity carries `tenant_col = "tenant_id"` so the
                    // caller's scope is meaningful here; pass it through
                    // unchanged.
                    tenant_metadata::Entity::delete_many()
                        .filter(Condition::all().add(tenant_metadata::Column::TenantId.eq(id)))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Tenant row.
                    tenants::Entity::delete_many()
                        .filter(id_eq(id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    Ok(HardDeleteOutcome::Cleaned)
                })
            })
        })
        .await
    }

    async fn audit_integrity_for_scope(
        &self,
        scope: &AccessScope,
        integrity_scope: IntegrityScope,
    ) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
        // Engine-dispatch shape pinned by phase-03-classifier-postgres.md.
        // The Postgres branch runs all 10 classification queries inside
        // one `REPEATABLE READ ReadOnly` transaction so every category is
        // observed against the same MVCC snapshot — a cross-category
        // anomaly (e.g. an OrphanedChild that simultaneously trips a
        // DepthMismatch) is guaranteed to surface coherently in the
        // returned vector. The SQLite branch is filled in by Phase 4;
        // Phase 5 layers the single-flight guard on top of this same
        // dispatch table, surfacing `AmError::AuditAlreadyRunning` to
        // concurrent callers without re-entering the queries below.
        match self.db.db().db_engine() {
            "postgres" => audit_integrity_pg(&self.db, scope, integrity_scope).await,
            "sqlite" => audit_integrity_sqlite(&self.db, scope, integrity_scope).await,
            other => Err(AmError::Internal {
                diagnostic: format!("unsupported db_engine: {other}"),
            }),
        }
    }

    async fn is_descendant(
        &self,
        scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, AmError> {
        // `is_descendant` answers a structural question — "does the
        // closure carry an `(ancestor, descendant)` row?" — that is
        // scope-independent by construction. `tenant_closure` is
        // `no_tenant/no_resource/no_owner/no_type`, so passing a
        // PDP-narrowed scope through `scope_with` would collapse to
        // `WHERE false` and silently return `false` for valid
        // ancestry edges, breaking `ensure_caller_reaches`. The PEP
        // gate at the service layer is what enforces caller scope;
        // this read is the structural truth that gate consults.
        let _ = scope;
        let conn = self.db.conn()?;
        let count = tenant_closure::Entity::find()
            .secure()
            .scope_with(&AccessScope::allow_all())
            .filter(
                Condition::all()
                    .add(tenant_closure::Column::AncestorId.eq(ancestor))
                    .add(tenant_closure::Column::DescendantId.eq(descendant)),
            )
            .count(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(count > 0)
    }

    async fn find_root(&self, scope: &AccessScope) -> Result<Option<TenantModel>, AmError> {
        let conn = self.db.conn()?;
        let row = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(
                Condition::all()
                    .add(tenants::Column::ParentId.is_null())
                    .add(tenants::Column::Status.ne(TenantStatus::Provisioning.as_smallint())),
            )
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .one(&conn)
            .await
            .map_err(map_scope_err)?;
        match row {
            Some(r) => Ok(Some(entity_to_model(r)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    // Most of the repo_impl logic is exercised through integration tests
    // against a real DB (Phase 3 owns cross-backend coverage). These unit
    // tests cover the pure helpers only.
    use super::*;

    #[test]
    fn entity_to_model_rejects_unknown_status() {
        let row = tenants::Model {
            id: Uuid::nil(),
            parent_id: None,
            name: "x".into(),
            status: 42,
            self_managed: false,
            tenant_type_uuid: Uuid::nil(),
            depth: 0,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted_at: None,
            deletion_scheduled_at: None,
            retention_window_secs: None,
            claimed_by: None,
            claimed_at: None,
        };
        let err = entity_to_model(row).expect_err("unknown status");
        assert_eq!(err.code(), "internal");
    }

    #[test]
    fn entity_to_model_rejects_negative_depth() {
        let row = tenants::Model {
            id: Uuid::nil(),
            parent_id: None,
            name: "x".into(),
            status: 1,
            self_managed: false,
            tenant_type_uuid: Uuid::nil(),
            depth: -1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted_at: None,
            deletion_scheduled_at: None,
            retention_window_secs: None,
            claimed_by: None,
            claimed_at: None,
        };
        let err = entity_to_model(row).expect_err("negative depth");
        assert_eq!(err.code(), "internal");
    }

    /// Pin the SQLSTATE 40001 → `SerializationConflict` routing through
    /// `map_scope_err`. The previous implementation flattened
    /// `ScopeError::Db` directly into `AmError::Internal`, which made
    /// the `with_serializable_retry` loop unable to recognise the
    /// retry trigger — a SERIALIZABLE conflict surfaced through a
    /// `SecureORM` statement was silently demoted to HTTP 500 and never
    /// retried.
    #[test]
    fn map_scope_err_routes_sqlstate_40001_to_serialization_conflict() {
        use modkit_db::secure::ScopeError;
        use sea_orm::{DbErr, RuntimeErr};
        let scope_err = ScopeError::Db(DbErr::Exec(RuntimeErr::Internal(
            "error returned from database: 40001: could not serialize access".to_owned(),
        )));
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.code(), "serialization_conflict");
        assert!(matches!(am_err, AmError::SerializationConflict { .. }));
    }

    /// Same routing also catches unique-violation SQLSTATE values
    /// (`Postgres` `23505`, `SQLite` `2067`, `MySQL` `1062`) and maps them
    /// to `AmError::Conflict` (HTTP 409) per
    /// `feature-tenant-hierarchy-management §6` AC line 711. Without
    /// this, racing inserts that hit `ScopeError::Db` would surface
    /// as 500.
    #[test]
    fn map_scope_err_routes_unique_violation_to_conflict() {
        use modkit_db::secure::ScopeError;
        use sea_orm::{DbErr, RuntimeErr};
        let scope_err = ScopeError::Db(DbErr::Exec(RuntimeErr::Internal(
            "duplicate key value violates unique constraint".to_owned(),
        )));
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.code(), "conflict");
        assert_eq!(am_err.http_status(), 409);
    }

    /// `ScopeError::TenantNotInScope` MUST always map to
    /// `cross_tenant_denied` regardless of the routing change.
    #[test]
    fn map_scope_err_preserves_tenant_not_in_scope_routing() {
        use modkit_db::secure::ScopeError;
        let scope_err = ScopeError::TenantNotInScope {
            tenant_id: Uuid::nil(),
        };
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.code(), "cross_tenant_denied");
    }
}
