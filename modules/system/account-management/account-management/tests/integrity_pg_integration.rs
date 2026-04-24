//! Integration tests for the SQL-side integrity classifier
//! (Phase 3 / 7 of `integrity-sql-refactor`).
//!
//! Each test brings up a fresh Postgres testcontainer, runs the AM
//! migrations, seeds a hierarchy that violates exactly one
//! [`IntegrityCategory`] (or, in the snapshot-consistency test, two at
//! once), and asserts that
//! [`TenantRepo::audit_integrity_for_scope`](account_management::TenantRepo)
//! surfaces the expected violations under
//! `IntegrityScope::Whole`.
//!
//! The harness mirrors the workspace pattern documented in
//! `libs/modkit-db/tests/common.rs`: container lifetime is bound to
//! the test scope, and every test seeds its tree from raw SQL so the
//! AM service / saga layer is bypassed (we are exercising the storage-
//! level audit, not the create-tenant flow).
//!
//! The tests are tagged `#[cfg(feature = "...")]`-free; they require a
//! running Docker daemon and will fail noisily if one is not
//! available. That matches the contract in `phase-03-classifier-postgres.md`:
//! the testcontainers tests are the acceptance criteria, not optional
//! coverage.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::items_after_statements)]

use std::sync::Arc;
use std::time::Duration;

use account_management::{
    AmDbProvider, AmError, IntegrityCategory, IntegrityScope, TenantRepo, TenantRepoImpl,
    TestMigrator, Violation,
};
use anyhow::Result;
use modkit_db::{ConnectOpts, connect_db};
use modkit_security::AccessScope;
use sea_orm_migration::MigratorTrait;
use testcontainers::{ContainerRequest, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

/// Wait up to `timeout` for `host:port` to accept a TCP connection.
/// Mirrors `libs/modkit-db/tests/common.rs::wait_for_tcp` so the
/// container is observably ready before the migrator runs.
async fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> Result<()> {
    use tokio::{
        net::TcpStream,
        time::{Instant, sleep},
    };
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect((host, port)).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for {host}:{port}");
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// Container handle returned by [`bring_up_postgres`]. The
/// `_container` field exists solely to keep the testcontainers handle
/// alive for the duration of the test (drop = container removed); the
/// caller-facing surface is `repo` + `provider`.
struct PgHarness {
    repo: TenantRepoImpl,
    provider: Arc<AmDbProvider>,
    /// Connection DSN — exposed so the single-flight contention test
    /// can open a second backend session (separate from the pool that
    /// runs the audit) to hold the advisory lock externally.
    dsn: String,
    _container:
        testcontainers::ContainerAsync<Postgres>,
}

/// Bring up a fresh Postgres testcontainer, run the AM migrations
/// against it, and return a connected [`TenantRepoImpl`].
///
/// The container lifetime is bound to the returned [`PgHarness`]; it
/// drops (and is removed) at the end of each test, so tests are
/// fully isolated even when run in parallel.
async fn bring_up_postgres() -> Result<PgHarness> {
    let postgres_image = Postgres::default();
    let request = ContainerRequest::from(postgres_image)
        .with_env_var("POSTGRES_PASSWORD", "pass")
        .with_env_var("POSTGRES_USER", "user")
        .with_env_var("POSTGRES_DB", "app");
    let container = request.start().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    wait_for_tcp("127.0.0.1", port, Duration::from_secs(30)).await?;

    let dsn = format!("postgres://user:pass@127.0.0.1:{port}/app");
    let db = connect_db(&dsn, ConnectOpts::default()).await?;
    let provider: Arc<AmDbProvider> = Arc::new(AmDbProvider::new(db.clone()));

    // Run the AM migrations against the fresh database. We use the
    // crate-internal `Db::sea_internal_ref()` path indirectly via the
    // public `Db::conn()` boundary; the migrator wants an owned
    // `DatabaseConnection`, so we need to obtain one via SeaORM's
    // public `Database::connect` API instead. That keeps the
    // migrations boundary identical to production wiring (modkit's
    // `DatabaseCapability::run_migrations`).
    let conn = sea_orm::Database::connect(&dsn).await?;
    TestMigrator::up(&conn, None).await?;
    drop(conn);

    Ok(PgHarness {
        repo: TenantRepoImpl::new(Arc::clone(&provider)),
        provider,
        dsn,
        _container: container,
    })
}

/// Insert a tenant row directly via raw SQL — bypassing the saga so
/// each test can construct anomalous shapes the production happy-path
/// would otherwise reject.
async fn insert_tenant(
    harness: &PgHarness,
    id: Uuid,
    parent_id: Option<Uuid>,
    name: &str,
    status: i16,
    self_managed: bool,
    depth: i32,
) -> Result<()> {
    use sea_orm::{Statement, Value};
    let conn = harness.provider.conn()?;
    let backend = sea_orm::DbBackend::Postgres;
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
    harness: &PgHarness,
    ancestor_id: Uuid,
    descendant_id: Uuid,
    barrier: i16,
    descendant_status: i16,
) -> Result<()> {
    use sea_orm::{Statement, Value};
    let conn = harness.provider.conn()?;
    let backend = sea_orm::DbBackend::Postgres;
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

/// Set up a clean two-node tree: root + active child, both with their
/// self-rows and the strict (root, child) closure row populated. Used
/// as the negative-control baseline that subsequent tests perturb to
/// produce a single category violation.
async fn seed_clean_two_node_tree(harness: &PgHarness) -> Result<(Uuid, Uuid)> {
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
async fn audit(harness: &PgHarness) -> Result<Vec<(IntegrityCategory, Violation)>, AmError> {
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
    let harness = bring_up_postgres()
        .await
        .expect("postgres testcontainer must be available (Docker daemon required)");
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
// Category 1 — OrphanedChild: child references a parent_id that does
// not exist in `tenants`. We deliberately disable the FK by deleting
// the parent row AFTER the child + closure rows are in place; that's
// the same pathological state a partial restore from backup or a
// bypassed-FK manual repair could produce.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_orphaned_child() {
    let harness = bring_up_postgres()
        .await
        .expect("postgres testcontainer must be available");
    // Insert a parent that we will then forcibly delete to simulate
    // the orphan state. The closure FK uses ON DELETE CASCADE so we
    // delete closure rows first via raw SQL to avoid cascading the
    // child away too. Disable the FK temporarily.
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
    // Drop the parent row directly with FK-disabled session — the
    // FK on `tenants.parent_id` would otherwise reject the DELETE.
    let conn = harness.provider.conn().expect("conn");
    conn.query_raw_all(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Postgres,
        "ALTER TABLE tenants DROP CONSTRAINT fk_tenants_parent;",
    ))
    .await
    .expect("drop parent fk");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Postgres,
        "DELETE FROM tenant_closure WHERE descendant_id = $1 OR ancestor_id = $1;",
        vec![sea_orm::Value::from(phantom_parent)],
    ))
    .await
    .expect("clear closure for parent");
    conn.query_raw_all(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Postgres,
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
// Category 2 — BrokenParentReference: a non-Deleted child has a
// Deleted parent. The closure rows stay in place (deletion is soft).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_broken_parent_reference() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// Category 3 — DepthMismatch: child has stored depth that disagrees
// with its parent_id walk depth.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_depth_mismatch() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// Category 4 — Cycle: parent_id chain loops. We need to drop the FK
// constraint to insert two rows that point at each other, mirroring
// the OrphanedChild test pattern.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_cycle() {
    let harness = bring_up_postgres().await.expect("postgres");
    let conn = harness.provider.conn().expect("conn");
    // Drop both the FK and the root-depth check to permit the
    // cyclic shape (`a.parent = b`, `b.parent = a`, both depth=1).
    // Postgres rejects multiple commands in a single prepared
    // statement (SQLSTATE 42601), so issue each ALTER separately.
    for stmt in [
        "ALTER TABLE tenants DROP CONSTRAINT fk_tenants_parent;",
        "ALTER TABLE tenants DROP CONSTRAINT ck_tenants_root_depth;",
        "DROP INDEX IF EXISTS ux_tenants_single_root;",
    ] {
        conn.query_raw_all(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            stmt,
        ))
        .await
        .expect("drop fk + check");
    }
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    // Insert a referencing b first. Because there is no row with id=b
    // yet, we sidestep the FK by inserting both then patching.
    insert_tenant(&harness, a, Some(b), "a", 1, false, 1).await.unwrap();
    insert_tenant(&harness, b, Some(a), "b", 1, false, 1).await.unwrap();
    let viols = audit(&harness).await.expect("audit");
    assert!(
        count_for(&viols, IntegrityCategory::Cycle) >= 1,
        "expected Cycle, got {viols:?}"
    );
}

// ---------------------------------------------------------------------------
// Category 5 — RootCountAnomaly: two parent_id IS NULL rows. We must
// drop `ux_tenants_single_root` to seed the second root.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_root_count_anomaly_two_roots() {
    let harness = bring_up_postgres().await.expect("postgres");
    let conn = harness.provider.conn().expect("conn");
    conn.query_raw_all(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Postgres,
        "DROP INDEX IF EXISTS ux_tenants_single_root;",
    ))
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
// Category 6 — MissingClosureSelfRow: SDK-visible tenant lacks `(id, id)`.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_missing_closure_self_row() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// Category 7 — ClosureCoverageGap: strict ancestor missing in closure.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_closure_coverage_gap() {
    let harness = bring_up_postgres().await.expect("postgres");
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
    let harness = bring_up_postgres().await.expect("postgres");
    // Drop the closure FKs to permit a row referencing a non-existent
    // descendant id. Postgres rejects multiple commands in a single
    // prepared statement, so issue each ALTER separately.
    let conn = harness.provider.conn().expect("conn");
    for stmt in [
        "ALTER TABLE tenant_closure DROP CONSTRAINT fk_tenant_closure_ancestor;",
        "ALTER TABLE tenant_closure DROP CONSTRAINT fk_tenant_closure_descendant;",
    ] {
        conn.query_raw_all(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            stmt,
        ))
        .await
        .expect("drop closure fks");
    }
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
// Category 9 — BarrierColumnDivergence: strict closure row's barrier
// disagrees with the self_managed flag on the path.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_barrier_column_divergence() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// Category 10 — DescendantStatusDivergence: closure descendant_status
// diverges from tenants.status.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_descendant_status_divergence() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// same audit. We seed a tree that trips MissingClosureSelfRow AND
// DescendantStatusDivergence simultaneously, then assert both
// categories are present in the same returned vector. The
// `RepeatableRead`+`ReadOnly` snapshot makes this assertion
// deterministic regardless of any concurrent writer.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_surfaces_two_categories_simultaneously() {
    let harness = bring_up_postgres().await.expect("postgres");
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
// Phase 5 — Single-flight contention (Postgres advisory-lock branch).
//
// The Postgres single-flight gate is `pg_try_advisory_xact_lock(
// hashtext('am.integrity.' || $scope_key)::bigint)`. Because the lock
// is *backend-session-scoped* and acquired non-blocking, we can prove
// the gate semantics deterministically by holding the lock on a
// separate session (via `pg_advisory_lock(bigint)` — session-scoped,
// blocking acquire) while invoking `audit_integrity_for_scope` on the
// pool used by `TenantRepoImpl`. The audit's `pg_try_…` call will
// observe the conflict and refuse with `AmError::AuditAlreadyRunning`.
//
// Releasing the holder via `pg_advisory_unlock(bigint)` then proves
// the gate is not "sticky": the next audit from the pool succeeds.
//
// We additionally run a barrier-released N-way concurrent audit burst
// without an external holder to guard against deadlocks and to assert
// every reported `AuditAlreadyRunning` carries the canonical scope
// payload — but we do NOT assert that contention is observed in the
// burst (the queries are fast enough on an empty tree that the
// scheduler may serialize the entire burst sequentially).
// ---------------------------------------------------------------------------

/// Compute the bigint advisory-lock key the AM `audit_integrity_for_scope`
/// uses for a given `scope_key`. Mirrors the SQL the implementation runs
/// in `acquire_pg_audit_lock` (`hashtext('am.integrity.' || $1)::bigint`)
/// so the test holder grabs the *same* lock the audit will try to
/// acquire.
async fn pg_audit_lock_key(conn: &sea_orm::DatabaseConnection, scope_key: &str) -> i64 {
    use sea_orm::{ConnectionTrait, Statement, Value};
    let row = conn
        .query_one(Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT hashtext('am.integrity.' || $1)::bigint AS k",
            vec![Value::from(scope_key.to_owned())],
        ))
        .await
        .expect("compute advisory key")
        .expect("hashtext returned no row");
    row.try_get::<i64>("", "k")
        .expect("advisory key column must be bigint")
}

/// Open a second backend session (separate from the audit pool) and
/// hold the advisory lock for `scope_key` indefinitely. Returns the
/// holder connection so the caller can drop it (which releases the
/// lock) once the contention assertion is complete.
///
/// We deliberately use `pg_advisory_lock` (session-scoped, blocking)
/// rather than the `_xact_` variant the audit itself uses, because the
/// holder is OUTSIDE any transaction and we want the lock to live
/// across multiple queries on the holder session.
async fn hold_pg_audit_lock(
    dsn: &str,
    scope_key: &str,
) -> sea_orm::DatabaseConnection {
    use sea_orm::{ConnectionTrait, Statement, Value};
    let holder = sea_orm::Database::connect(dsn)
        .await
        .expect("holder connect");
    let key = pg_audit_lock_key(&holder, scope_key).await;
    holder
        .execute(Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT pg_advisory_lock($1)",
            vec![Value::from(key)],
        ))
        .await
        .expect("hold advisory lock");
    holder
}

/// Release the externally-held advisory lock on `holder` for
/// `scope_key`. The session is dropped after release, which would
/// also release the lock — explicit unlock is symmetric with the
/// explicit acquire and asserts the wire form works in both directions.
async fn release_pg_audit_lock(holder: &sea_orm::DatabaseConnection, scope_key: &str) {
    use sea_orm::{ConnectionTrait, Statement, Value};
    let key = pg_audit_lock_key(holder, scope_key).await;
    holder
        .execute(Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT pg_advisory_unlock($1)",
            vec![Value::from(key)],
        ))
        .await
        .expect("release advisory lock");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_pre_held_advisory_lock_refuses_whole_scope_audit() {
    let harness = bring_up_postgres()
        .await
        .expect("postgres testcontainer must be available (Docker daemon required)");
    seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");

    let holder = hold_pg_audit_lock(&harness.dsn, "whole").await;

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
            "expected AuditAlreadyRunning when advisory lock is held externally; got {other:?}"
        ),
    }

    // Release-path assertion: once the holder unlocks, the very next
    // audit must succeed — the gate is not sticky and observes live state.
    release_pg_audit_lock(&holder, "whole").await;
    drop(holder);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_pre_held_advisory_lock_carries_subtree_uuid_in_payload() {
    let harness = bring_up_postgres()
        .await
        .expect("postgres testcontainer must be available");
    let (root, _child) = seed_clean_two_node_tree(&harness)
        .await
        .expect("seed clean tree");

    let scope_key = format!("subtree:{root}");
    let holder = hold_pg_audit_lock(&harness.dsn, &scope_key).await;

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
            "expected AuditAlreadyRunning when subtree advisory lock is held; got {other:?}"
        ),
    }

    release_pg_audit_lock(&holder, &scope_key).await;
    drop(holder);
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
/// (a) no task surfaces a non-gate error, (b) every reported
/// `AuditAlreadyRunning` carries the canonical scope payload, and
/// (c) at least one task succeeds. We do NOT require contention to be
/// observed in the burst itself — Postgres's `pg_try_advisory_xact_lock`
/// is fast enough on an empty tree that the scheduler may serialize
/// the burst sequentially. The deterministic gate-refused assertion
/// lives in [`single_flight_pre_held_advisory_lock_refuses_whole_scope_audit`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_concurrent_burst_observes_only_gate_or_success() {
    let harness = bring_up_postgres()
        .await
        .expect("postgres testcontainer must be available");
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
