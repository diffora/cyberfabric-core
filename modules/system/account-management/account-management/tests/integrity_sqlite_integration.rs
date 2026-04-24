//! Integration tests for the SQL-side integrity classifier — `SQLite`
//! branch (Phase 4 of `integrity-sql-refactor`).
//!
//! Each test brings up a fresh `:memory:` `SQLite` database, runs the AM
//! migrations, seeds a hierarchy that violates exactly one
//! [`IntegrityCategory`] (or, in the snapshot-consistency test, two at
//! once), and asserts that
//! [`TenantRepo::audit_integrity_for_scope`](account_management::TenantRepo)
//! surfaces the expected violations under
//! [`IntegrityScope::Whole`].
//!
//! Mirrors `tests/integrity_pg_integration.rs` 1:1 in scenario coverage
//! so backend parity is verifiable: the same seed must produce the
//! same `(category, violation)` set on both backends. The harness is
//! lighter — `:memory:` `SQLite` needs no testcontainer, so each test is
//! self-contained, fast, and runs without Docker.
//!
//! ## Why `SQLite` has slightly different "drop FK / drop check" plumbing
//!
//! `SQLite` does not support `ALTER TABLE ... DROP CONSTRAINT`, so the
//! tests that need to seed a structurally invalid state (Cat 1
//! `OrphanedChild`, Cat 4 `Cycle`, Cat 8 `StaleClosureRow`) cannot
//! drop the constraint after the fact. Instead, each such test issues
//! `PRAGMA foreign_keys = OFF;` on the connection and re-creates the
//! `tenants` / `tenant_closure` tables without the constraints that would
//! otherwise reject the anomalous shape. That keeps the test
//! semantically equivalent to the Postgres harness while honoring the
//! dialect's schema-management constraints.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::items_after_statements)]

use std::sync::Arc;

use account_management::{
    AmDbProvider, AmError, IntegrityCategory, IntegrityScope, TenantRepo, TenantRepoImpl,
    TestMigrator, Violation,
};
use anyhow::Result;
use modkit_db::migration_runner::run_migrations_for_testing;
use modkit_db::{ConnectOpts, connect_db};
use modkit_security::AccessScope;
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

/// Lightweight harness that owns the `:memory:` `SQLite` database +
/// repo. Drop = database released. There's no container to manage.
struct SqliteHarness {
    repo: TenantRepoImpl,
    provider: Arc<AmDbProvider>,
}

/// Bring up a fresh `:memory:` `SQLite` database, run the AM migrations
/// against it, and return a connected [`TenantRepoImpl`].
///
/// `:memory:` databases are private to the connection — `SeaORM`'s pool
/// must be sized to 1 so every query lands on the same instance.
/// `connect_db("sqlite::memory:", ConnectOpts::default())` already
/// configures this internally.
async fn bring_up_sqlite() -> Result<SqliteHarness> {
    let db = connect_db("sqlite::memory:", ConnectOpts::default()).await?;
    let provider: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db.clone()));

    // SQLite `:memory:` databases are private to a single connection,
    // so the Postgres-style "open a second connection for migrations"
    // pattern doesn't apply. The public `migration_runner::
    // run_migrations_for_testing` helper threads the migrations
    // through the existing `Db` handle (same connection, same in-
    // memory database) — that's the workspace pattern documented in
    // `libs/modkit-db/tests/sqlite/*.rs`. We pass `TestMigrator::
    // migrations()` (the vec of `Box<dyn MigrationTrait>` returned by
    // the AM migrator) so the runner can apply them in order.
    run_migrations_for_testing(&db, TestMigrator::migrations())
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(SqliteHarness {
        repo: TenantRepoImpl::new(Arc::clone(&provider)),
        provider,
    })
}

/// Insert a tenant row directly via raw SQL — bypassing the saga so
/// each test can construct anomalous shapes the production happy-path
/// would otherwise reject.
async fn insert_tenant(
    harness: &SqliteHarness,
    id: Uuid,
    parent_id: Option<Uuid>,
    name: &str,
    status: i16,
    self_managed: bool,
    depth: i32,
) -> Result<()> {
    use sea_orm::{Statement, Value};
    let conn = harness.provider.conn()?;
    let backend = sea_orm::DbBackend::Sqlite;
    let stmt = Statement::from_sql_and_values(
        backend,
        "INSERT INTO tenants (id, parent_id, name, status, self_managed, tenant_type_uuid, depth) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        vec![
            Value::from(id),
            Value::from(parent_id),
            Value::from(name.to_owned()),
            Value::from(status),
            Value::from(self_managed),
            Value::from(Uuid::nil()),
            Value::from(depth),
        ],
    );
    conn.query_raw_all(stmt).await?;
    Ok(())
}

/// Insert a closure row directly via raw SQL — used to seed both the
/// happy-path closure entries (self-rows) and the anomalous shapes
/// (gaps, stale rows, divergent barrier / status).
async fn insert_closure(
    harness: &SqliteHarness,
    ancestor_id: Uuid,
    descendant_id: Uuid,
    barrier: i16,
    descendant_status: i16,
) -> Result<()> {
    use sea_orm::{Statement, Value};
    let conn = harness.provider.conn()?;
    let backend = sea_orm::DbBackend::Sqlite;
    let stmt = Statement::from_sql_and_values(
        backend,
        "INSERT INTO tenant_closure (ancestor_id, descendant_id, barrier, descendant_status) \
         VALUES ($1, $2, $3, $4)",
        vec![
            Value::from(ancestor_id),
            Value::from(descendant_id),
            Value::from(barrier),
            Value::from(descendant_status),
        ],
    );
    conn.query_raw_all(stmt).await?;
    Ok(())
}

/// Disable foreign-key enforcement on the `SQLite` connection so tests
/// that need a structurally invalid shape (orphaned child, cycle,
/// stale closure row) can seed it without `ALTER TABLE DROP
/// CONSTRAINT` (which `SQLite` does not support).
async fn disable_fks(harness: &SqliteHarness) -> Result<()> {
    let conn = harness.provider.conn()?;
    conn.query_raw_all(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Sqlite,
        "PRAGMA foreign_keys = OFF;",
    ))
    .await?;
    Ok(())
}

/// Drop the single-root unique index so a test can seed two
/// `parent_id IS NULL` rows for the Cat 5 `RootCountAnomaly` scenario.
async fn drop_single_root_index(harness: &SqliteHarness) -> Result<()> {
    let conn = harness.provider.conn()?;
    conn.query_raw_all(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Sqlite,
        "DROP INDEX IF EXISTS ux_tenants_single_root;",
    ))
    .await?;
    Ok(())
}

/// Drop the `ck_tenants_root_depth` CHECK constraint so the cycle
/// test can seed `(parent IS NOT NULL, depth = 1)` for both nodes
/// of a 2-cycle. `SQLite` cannot DROP CHECK; we drop+recreate the
/// table without the check.
///
/// We assume the table is empty at this point (the cycle test calls
/// this before any inserts).
async fn drop_root_depth_check(harness: &SqliteHarness) -> Result<()> {
    let conn = harness.provider.conn()?;
    for stmt in [
        "DROP TABLE IF EXISTS tenant_closure;",
        "DROP TABLE IF EXISTS tenants;",
        // Recreate `tenants` without `ck_tenants_root_depth` and
        // without the FK on `parent_id` (so cycle pairs can be
        // inserted). Other invariants we still want to honor for
        // the integrity classifier are preserved.
        "CREATE TABLE tenants ( \
            id TEXT PRIMARY KEY NOT NULL, \
            parent_id TEXT NULL, \
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255), \
            status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)), \
            self_managed INTEGER NOT NULL DEFAULT 0, \
            tenant_type_uuid TEXT NOT NULL, \
            depth INTEGER NOT NULL CHECK (depth >= 0), \
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, \
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, \
            deleted_at TEXT NULL \
        );",
        // Skipping ux_tenants_single_root because the cycle nodes
        // both have non-null parent_id (so it'd never trip).
        "CREATE TABLE tenant_closure ( \
            ancestor_id TEXT NOT NULL, \
            descendant_id TEXT NOT NULL, \
            barrier SMALLINT NOT NULL DEFAULT 0, \
            descendant_status SMALLINT NOT NULL CHECK (descendant_status IN (1, 2, 3)), \
            PRIMARY KEY (ancestor_id, descendant_id), \
            CONSTRAINT ck_tenant_closure_self_row_barrier \
                CHECK (ancestor_id <> descendant_id OR barrier = 0), \
            CONSTRAINT ck_tenant_closure_barrier_nonnegative \
                CHECK (barrier >= 0) \
        );",
    ] {
        conn.query_raw_all(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            stmt,
        ))
        .await?;
    }
    Ok(())
}

/// Seed a clean two-node tree (root + active child with all closure
/// rows). Used as a negative-control baseline.
async fn seed_clean_two_node_tree(harness: &SqliteHarness) -> Result<(Uuid, Uuid)> {
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(harness, root, None, "root", 1, false, 0).await?;
    insert_tenant(harness, child, Some(root), "child", 1, false, 1).await?;
    insert_closure(harness, root, root, 0, 1).await?;
    insert_closure(harness, child, child, 0, 1).await?;
    insert_closure(harness, root, child, 0, 1).await?;
    Ok((root, child))
}

/// Run the audit and return the violations grouped by category.
async fn audit(harness: &SqliteHarness) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
    harness
        .repo
        .audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Whole)
        .await
}

fn count_for(
    violations: &[(IntegrityCategory, Violation)],
    category: IntegrityCategory,
) -> usize {
    violations
        .iter()
        .filter(|(c, _)| *c == category)
        .count()
}

fn count_total(violations: &[(IntegrityCategory, Violation)]) -> usize {
    violations.len()
}

// ---------------------------------------------------------------------------
// Negative control — clean tree must produce zero violations.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_tree_yields_no_violations() {
    let harness = bring_up_sqlite().await.expect("sqlite :memory:");
    seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");
    let viols = audit(&harness).await.expect("audit succeeds");
    assert_eq!(
        count_total(&viols),
        0,
        "clean tree must surface zero violations: {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 1 — OrphanedChild.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_orphaned_child() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    disable_fks(&harness).await.expect("disable fks");

    let phantom_parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, phantom_parent, None, "phantom-root", 1, false, 0)
        .await
        .expect("seed phantom parent");
    insert_tenant(&harness, child, Some(phantom_parent), "child", 1, false, 1)
        .await
        .expect("seed child");
    insert_closure(&harness, phantom_parent, phantom_parent, 0, 1).await.unwrap();
    insert_closure(&harness, child, child, 0, 1).await.unwrap();
    insert_closure(&harness, phantom_parent, child, 0, 1).await.unwrap();

    // Now delete the parent row + its closure entries, leaving
    // `child.parent_id` dangling.
    let conn = harness.provider.conn().expect("conn");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "DELETE FROM tenant_closure WHERE descendant_id = $1 OR ancestor_id = $1;",
        vec![sea_orm::Value::from(phantom_parent)],
    ))
    .await
    .expect("clear closure for parent");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "DELETE FROM tenants WHERE id = $1;",
        vec![sea_orm::Value::from(phantom_parent)],
    ))
    .await
    .expect("delete phantom parent");

    let viols = audit(&harness).await.expect("audit succeeds");
    assert!(
        count_for(&viols, IntegrityCategory::OrphanedChild) >= 1,
        "expected OrphanedChild violation, got {viols:?}"
    );
    let surfaced = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::OrphanedChild)
        .expect("OrphanedChild row");
    assert_eq!(surfaced.1.tenant_id, Some(child));
}

// ---------------------------------------------------------------------------
// Category 2 — BrokenParentReference.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_broken_parent_reference() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 3, false, 0).await.unwrap(); // Deleted
    insert_tenant(&harness, child, Some(root), "child", 1, false, 1).await.unwrap(); // Active
    insert_closure(&harness, root, root, 0, 3).await.unwrap();
    insert_closure(&harness, child, child, 0, 1).await.unwrap();
    insert_closure(&harness, root, child, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::BrokenParentReference) >= 1,
        "expected BrokenParentReference, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 3 — DepthMismatch.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_depth_mismatch() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    // Stored depth=3 but walk yields 1 — that's the divergence.
    insert_tenant(&harness, child, Some(root), "child", 1, false, 3).await.unwrap();
    insert_closure(&harness, root, root, 0, 1).await.unwrap();
    insert_closure(&harness, child, child, 0, 1).await.unwrap();
    insert_closure(&harness, root, child, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::DepthMismatch) >= 1,
        "expected DepthMismatch, got {viols:?}"
    );
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::DepthMismatch)
        .unwrap();
    assert_eq!(v.1.tenant_id, Some(child));
}

// ---------------------------------------------------------------------------
// Category 4 — Cycle. Drop the FK + root-depth check so we can insert
// `(a.parent = b, b.parent = a)` with both depth=1.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_cycle() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    disable_fks(&harness).await.expect("disable fks");
    drop_root_depth_check(&harness)
        .await
        .expect("recreate tables without check");

    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    insert_tenant(&harness, a, Some(b), "a", 1, false, 1).await.unwrap();
    insert_tenant(&harness, b, Some(a), "b", 1, false, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::Cycle) >= 1,
        "expected Cycle, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 5 — RootCountAnomaly: two parent_id IS NULL rows.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_root_count_anomaly_two_roots() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    drop_single_root_index(&harness)
        .await
        .expect("drop unique index");
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    insert_tenant(&harness, a, None, "a", 1, false, 0).await.unwrap();
    insert_tenant(&harness, b, None, "b", 1, false, 0).await.unwrap();
    insert_closure(&harness, a, a, 0, 1).await.unwrap();
    insert_closure(&harness, b, b, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::RootCountAnomaly) >= 1,
        "expected RootCountAnomaly, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 6 — MissingClosureSelfRow.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_missing_closure_self_row() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    // Deliberately do NOT insert the (root, root) self-row.
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::MissingClosureSelfRow) >= 1,
        "expected MissingClosureSelfRow, got {viols:?}"
    );
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::MissingClosureSelfRow)
        .unwrap();
    assert_eq!(v.1.tenant_id, Some(root));
}

// ---------------------------------------------------------------------------
// Category 7 — ClosureCoverageGap.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_closure_coverage_gap() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    insert_tenant(&harness, child, Some(root), "child", 1, false, 1).await.unwrap();
    // Self-rows present, but the strict (root, child) is missing.
    insert_closure(&harness, root, root, 0, 1).await.unwrap();
    insert_closure(&harness, child, child, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::ClosureCoverageGap) >= 1,
        "expected ClosureCoverageGap, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 8 — StaleClosureRow: closure references missing tenant.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_stale_closure_row_missing_descendant() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    disable_fks(&harness).await.expect("disable fks");
    let root = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    insert_closure(&harness, root, root, 0, 1).await.unwrap();
    // Row references a tenant that does not exist.
    let dangling = Uuid::new_v4();
    insert_closure(&harness, root, dangling, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::StaleClosureRow) >= 1,
        "expected StaleClosureRow, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 9 — BarrierColumnDivergence.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_barrier_column_divergence() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    // Child is self_managed → expected barrier on (root, child) is 1,
    // but we seed barrier=0 to trigger the divergence.
    insert_tenant(&harness, child, Some(root), "child", 1, true, 1).await.unwrap();
    insert_closure(&harness, root, root, 0, 1).await.unwrap();
    insert_closure(&harness, child, child, 0, 1).await.unwrap();
    insert_closure(&harness, root, child, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::BarrierColumnDivergence) >= 1,
        "expected BarrierColumnDivergence, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 10 — DescendantStatusDivergence.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_descendant_status_divergence() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    // Tenant says Active (1), closure says Suspended (2).
    insert_closure(&harness, root, root, 0, 2).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::DescendantStatusDivergence) >= 1,
        "expected DescendantStatusDivergence, got {viols:?}"
    );
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::DescendantStatusDivergence)
        .unwrap();
    assert_eq!(v.1.tenant_id, Some(root));
}

// ---------------------------------------------------------------------------
// Snapshot consistency — two simultaneous violations surface in the
// same audit. Mirrors the Postgres harness scenario.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_surfaces_two_categories_simultaneously() {
    let harness = bring_up_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&harness, root, None, "root", 1, false, 0).await.unwrap();
    insert_tenant(&harness, child, Some(root), "child", 1, false, 1).await.unwrap();
    // Root has its self-row but with the wrong descendant_status
    // (closure says Suspended=2, tenants says Active=1) →
    // DescendantStatusDivergence.
    insert_closure(&harness, root, root, 0, 2).await.unwrap();
    // Child has the strict (root, child) row but is missing its own
    // (child, child) self-row → MissingClosureSelfRow.
    insert_closure(&harness, root, child, 0, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::DescendantStatusDivergence) >= 1,
        "expected DescendantStatusDivergence in multi-cat audit: {viols:?}"
    );
    assert!(
        count_for(&viols, IntegrityCategory::MissingClosureSelfRow) >= 1,
        "expected MissingClosureSelfRow in multi-cat audit: {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase 5 — Single-flight contention.
//
// SQLite serializes writers (single-writer model), so two concurrent
// audit txns that both wanted to INSERT into `running_audits` would
// naturally serialize: by the time the second writer obtains the
// SQLite write lock, the first has already committed AND deleted its
// gate row. The single-flight gate would never engage under the
// natural SQLite scheduling. To prove the gate semantics we therefore
// pre-populate `running_audits` with a synthetic "in-flight audit" row
// (mimicking another worker that has acquired the slot but not yet
// released it) and assert that `audit_integrity_for_scope` refuses
// with `AmError::AuditAlreadyRunning { scope }`. We then DELETE the
// synthetic row and assert the very next audit succeeds — that is the
// release-path assertion (the gate row was released).
//
// `:memory:` SQLite databases are private to a single connection, but
// for THIS test we only need one connection (we run the synthetic
// INSERT through `provider.conn()` and then run the audit on the same
// pool). No shared-cache DSN is required.
//
// We do additionally run a `tokio::spawn`-based concurrency test that
// asserts: under a barrier-released N-way concurrent burst, the
// outcomes are EXACTLY one of two valid SQLite scenarios — every
// audit succeeds (writers serialized through the SQLite write lock,
// gate row never collided), or some subset returns AuditAlreadyRunning
// (gate row contended). NEITHER case may surface a non-gate error.
// This test is the smoke-level guard against accidental regressions
// (e.g. deadlocks, missing release-path DELETE, wrong scope payload).
// ---------------------------------------------------------------------------

/// Insert a synthetic `running_audits` row directly via raw SQL so
/// `audit_integrity_for_scope` observes the gate as already held.
/// Returns the synthetic `worker_id` so the caller can DELETE the row
/// after the assertion.
async fn pre_populate_gate(harness: &SqliteHarness, scope_key: &str) -> Result<String> {
    let worker_id = Uuid::new_v4().to_string();
    let conn = harness.provider.conn()?;
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "INSERT INTO running_audits (scope_key, worker_id, started_at) \
         VALUES (?, ?, datetime('now'))",
        vec![
            sea_orm::Value::from(scope_key.to_owned()),
            sea_orm::Value::from(worker_id.clone()),
        ],
    ))
    .await?;
    Ok(worker_id)
}

/// DELETE the synthetic gate row inserted by `pre_populate_gate`,
/// simulating "another worker finished its audit and released the slot".
async fn release_gate(harness: &SqliteHarness, worker_id: &str) -> Result<()> {
    let conn = harness.provider.conn()?;
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "DELETE FROM running_audits WHERE worker_id = ?",
        vec![sea_orm::Value::from(worker_id.to_owned())],
    ))
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_flight_pre_held_gate_refuses_whole_scope_audit() {
    let harness = bring_up_sqlite().await.expect("sqlite :memory:");
    seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");

    // Synthetic in-flight audit row — `audit_integrity_for_scope` MUST
    // observe the PK collision and refuse with `AuditAlreadyRunning`.
    let held_worker = pre_populate_gate(&harness, "whole")
        .await
        .expect("pre-populate gate");

    let result = harness
        .repo
        .audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Whole)
        .await;
    match result {
        Err(AmError::AuditAlreadyRunning { ref scope }) => {
            assert_eq!(
                scope, "whole",
                "AuditAlreadyRunning under Whole scope must carry scope=\"whole\""
            );
        }
        other => panic!(
            "expected AuditAlreadyRunning when gate is held; got {other:?}"
        ),
    }

    // Release-path assertion: once the synthetic row is removed the
    // very next audit MUST succeed, proving the gate is not "sticky"
    // and the implementation reads the live state on every call.
    release_gate(&harness, &held_worker)
        .await
        .expect("release synthetic gate");

    let post = harness
        .repo
        .audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Whole)
        .await
        .expect("post-release audit must succeed");
    assert!(
        post.is_empty(),
        "post-release audit on a clean tree must surface zero violations: {post:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_flight_pre_held_gate_carries_subtree_uuid_in_payload() {
    let harness = bring_up_sqlite().await.expect("sqlite :memory:");
    let (root, _child) = seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");

    let scope_key = format!("subtree:{root}");
    let held_worker = pre_populate_gate(&harness, &scope_key)
        .await
        .expect("pre-populate gate");

    let result = harness
        .repo
        .audit_integrity_for_scope(
            &AccessScope::allow_all(),
            IntegrityScope::Subtree(root),
        )
        .await;
    match result {
        Err(AmError::AuditAlreadyRunning { scope }) => {
            assert_eq!(
                scope, scope_key,
                "AuditAlreadyRunning under Subtree(root) must carry scope=\"subtree:<root>\""
            );
        }
        other => panic!(
            "expected AuditAlreadyRunning when subtree gate is held; got {other:?}"
        ),
    }

    release_gate(&harness, &held_worker)
        .await
        .expect("release synthetic gate");
    let post = harness
        .repo
        .audit_integrity_for_scope(
            &AccessScope::allow_all(),
            IntegrityScope::Subtree(root),
        )
        .await
        .expect("post-release subtree audit must succeed");
    assert!(
        post.is_empty(),
        "post-release subtree audit on a clean tree must surface zero violations: {post:?}"
    );
}

/// Concurrency smoke: spawn N audits behind a barrier and assert that
/// (a) no task surfaces a non-gate error and (b) every reported
/// `AuditAlreadyRunning` carries the canonical scope payload. We
/// deliberately do NOT assert that contention is observed — `SQLite`'s
/// single-writer model often serializes the whole burst, in which case
/// every task wins the gate sequentially. The deterministic
/// gate-refused assertion lives in
/// [`single_flight_pre_held_gate_refuses_whole_scope_audit`]; this
/// test guards against deadlocks and against the success path forgetting
/// to release the gate row (which would surface here as "first task
/// succeeds, all subsequent tasks fail with `AuditAlreadyRunning` forever
/// because the gate row is sticky").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_concurrent_burst_observes_only_gate_or_success() {
    let harness = bring_up_sqlite().await.expect("sqlite :memory:");
    seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");

    const TASK_COUNT: usize = 6;
    let barrier = Arc::new(tokio::sync::Barrier::new(TASK_COUNT));
    let repo = Arc::new(harness.repo);
    let mut handles = Vec::with_capacity(TASK_COUNT);
    for _ in 0..TASK_COUNT {
        let repo = Arc::clone(&repo);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Whole)
                .await
        }));
    }
    let mut ok_count = 0usize;
    let mut gate_count = 0usize;
    let mut other = Vec::new();
    for handle in handles {
        match handle.await.expect("task panicked") {
            Ok(_) => ok_count += 1,
            Err(AmError::AuditAlreadyRunning { ref scope }) if scope == "whole" => {
                gate_count += 1;
            }
            Err(e) => other.push(e),
        }
    }
    assert!(
        other.is_empty(),
        "no concurrent audit may fail with anything other than AuditAlreadyRunning: {other:?}"
    );
    assert_eq!(
        ok_count + gate_count,
        TASK_COUNT,
        "every task must resolve to Ok or AuditAlreadyRunning"
    );
    assert!(
        ok_count >= 1,
        "at least one concurrent audit must succeed (got {ok_count} Ok of {TASK_COUNT})"
    );
}

// ---------------------------------------------------------------------------
// Subtree-scope filtering coverage.
//
// `IntegrityScope::Subtree(root)` is the narrowed audit target: every
// classifier's final SELECT carries a `WHERE t.id IN (SELECT
// descendant_id FROM tenant_closure WHERE ancestor_id = $1)` filter so
// only tenants under `root` (inclusive) are reported. The 10
// `classifies_*` tests above run under `IntegrityScope::Whole`; this
// test exercises the same machinery under `Subtree` and pins the scope
// isolation invariant: a violation seeded under one subtree MUST NOT
// surface when the audit is narrowed to a sibling subtree.
//
// We seed two violations in two sibling subtrees and run three audits:
//
// * `Subtree(subtree_a)` → only the orphan-child violation surfaces.
// * `Subtree(subtree_b)` → only the depth-mismatch violation surfaces.
// * `Whole`              → both violations surface together.
//
// This is one representative test rather than a full Whole×Subtree
// matrix across all 10 categories because the scope-filter SQL fragment
// is shared across every classifier — once we prove it isolates one
// representative pair, the rest follow.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subtree_scope_isolates_violations_to_subtree_root() {
    let harness = bring_up_sqlite().await.expect("sqlite :memory:");
    disable_fks(&harness).await.expect("disable fks");

    // Tree shape:
    //   root
    //   ├── subtree_a (orphan-child violation lives below this)
    //   └── subtree_b (depth-mismatch violation lives below this)
    let root = Uuid::new_v4();
    let subtree_a = Uuid::new_v4();
    let subtree_b = Uuid::new_v4();
    let phantom_parent = Uuid::new_v4();
    let orphan_child = Uuid::new_v4();
    let depth_anomaly = Uuid::new_v4();

    insert_tenant(&harness, root, None, "root", 1, false, 0)
        .await
        .expect("seed root");
    insert_tenant(&harness, subtree_a, Some(root), "subtree-a", 1, false, 1)
        .await
        .expect("seed subtree A");
    insert_tenant(&harness, subtree_b, Some(root), "subtree-b", 1, false, 1)
        .await
        .expect("seed subtree B");
    insert_closure(&harness, root, root, 0, 1).await.unwrap();
    insert_closure(&harness, subtree_a, subtree_a, 0, 1).await.unwrap();
    insert_closure(&harness, subtree_b, subtree_b, 0, 1).await.unwrap();
    insert_closure(&harness, root, subtree_a, 0, 1).await.unwrap();
    insert_closure(&harness, root, subtree_b, 0, 1).await.unwrap();

    // === Subtree A — seed an OrphanedChild violation. ===
    // Insert phantom_parent + orphan_child under subtree_a, with full
    // closure rows, then DELETE phantom_parent (and its closure rows)
    // so orphan_child has a dangling parent_id and its closure
    // ancestry still places it under subtree_a / root.
    insert_tenant(
        &harness,
        phantom_parent,
        Some(subtree_a),
        "phantom",
        1,
        false,
        2,
    )
    .await
    .unwrap();
    insert_tenant(
        &harness,
        orphan_child,
        Some(phantom_parent),
        "orphan",
        1,
        false,
        3,
    )
    .await
    .unwrap();
    insert_closure(&harness, phantom_parent, phantom_parent, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, orphan_child, orphan_child, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, phantom_parent, orphan_child, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, subtree_a, phantom_parent, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, subtree_a, orphan_child, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, root, phantom_parent, 0, 1).await.unwrap();
    insert_closure(&harness, root, orphan_child, 0, 1).await.unwrap();

    let conn = harness.provider.conn().expect("conn");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "DELETE FROM tenant_closure WHERE descendant_id = $1 OR ancestor_id = $1;",
        vec![sea_orm::Value::from(phantom_parent)],
    ))
    .await
    .expect("clear phantom closure");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Sqlite,
        "DELETE FROM tenants WHERE id = $1;",
        vec![sea_orm::Value::from(phantom_parent)],
    ))
    .await
    .expect("delete phantom");

    // === Subtree B — seed a DepthMismatch violation. ===
    // depth_anomaly is a real child of subtree_b but with stored
    // depth=99 instead of the walked depth=2 (root → subtree_b → x).
    insert_tenant(
        &harness,
        depth_anomaly,
        Some(subtree_b),
        "depth-bad",
        1,
        false,
        99,
    )
    .await
    .unwrap();
    insert_closure(&harness, depth_anomaly, depth_anomaly, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, subtree_b, depth_anomaly, 0, 1)
        .await
        .unwrap();
    insert_closure(&harness, root, depth_anomaly, 0, 1).await.unwrap();

    // === Audit narrowed to subtree A — only OrphanedChild surfaces. ===
    let viols_a = harness
        .repo
        .audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Subtree(subtree_a))
        .await
        .expect("subtree A audit");
    assert!(
        count_for(&viols_a, IntegrityCategory::OrphanedChild) >= 1,
        "subtree A audit must surface OrphanedChild: {viols_a:?}"
    );
    assert_eq!(
        count_for(&viols_a, IntegrityCategory::DepthMismatch),
        0,
        "subtree A audit MUST NOT leak the DepthMismatch from sibling subtree B: {viols_a:?}"
    );

    // === Audit narrowed to subtree B — only DepthMismatch surfaces. ===
    let viols_b = harness
        .repo
        .audit_integrity_for_scope(&AccessScope::allow_all(), IntegrityScope::Subtree(subtree_b))
        .await
        .expect("subtree B audit");
    assert!(
        count_for(&viols_b, IntegrityCategory::DepthMismatch) >= 1,
        "subtree B audit must surface DepthMismatch: {viols_b:?}"
    );
    assert_eq!(
        count_for(&viols_b, IntegrityCategory::OrphanedChild),
        0,
        "subtree B audit MUST NOT leak the OrphanedChild from sibling subtree A: {viols_b:?}"
    );

    // === Whole audit — both violations surface together. ===
    let viols_whole = audit(&harness).await.expect("whole audit");
    assert!(
        count_for(&viols_whole, IntegrityCategory::OrphanedChild) >= 1,
        "whole audit must surface OrphanedChild: {viols_whole:?}"
    );
    assert!(
        count_for(&viols_whole, IntegrityCategory::DepthMismatch) >= 1,
        "whole audit must surface DepthMismatch: {viols_whole:?}"
    );
}
