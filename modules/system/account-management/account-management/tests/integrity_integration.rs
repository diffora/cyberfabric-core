//! Real-DB integration tests for `run_integrity_check_for_scope`
//! against in-memory `SQLite`.
//!
//! Mirrors the donor's
//! `refactor/am-integrity-audit-rust-side`:`tests/integrity_integration.rs`
//! sqlite test set, retargeted at the current crate's naming
//! (`run_integrity_check_for_scope` /
//! `DomainError::IntegrityCheckInProgress` /
//! `integrity_check_runs`). Each test seeds a deliberately broken
//! `(tenants, tenant_closure)` shape via `SecureORM` inserts and
//! asserts the classifier pipeline surfaces the expected category
//! through the production `TenantRepoImpl`.
//!
//! Pure-Rust per-classifier coverage already lives in
//! `infra/storage/integrity/classifiers/*_tests.rs` over hand-built
//! `Snapshot` fixtures; these tests are the runtime counterpart and
//! exercise the `SecureORM` snapshot loader + single-flight gate +
//! repo-trait dispatch end-to-end.

#![cfg_attr(coverage_nightly, coverage(off))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use account_management::domain::error::DomainError;
use account_management::domain::tenant::TenantRepo;
use account_management::domain::tenant::integrity::{IntegrityCategory, IntegrityScope};
use uuid::Uuid;

use common::*;

/// Convenience: invoke the integrity check via the production repo
/// path with `allow_all` and unwrap to a flat `Vec<(category,
/// violation)>`.
async fn run_check(
    repo: &Arc<account_management::infra::storage::repo_impl::TenantRepoImpl>,
    scope: IntegrityScope,
) -> Result<
    Vec<(
        IntegrityCategory,
        account_management::domain::tenant::integrity::Violation,
    )>,
    DomainError,
> {
    repo.run_integrity_check_for_scope(&allow_all(), scope)
        .await
}

// ---------------------------------------------------------------------
// Negative control.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_tree_yields_no_violations() {
    let h = setup_sqlite().await.expect("sqlite :memory:");
    let _ = seed_clean_two_node_tree(&h.provider)
        .await
        .expect("seed clean tree");

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        viols.is_empty(),
        "clean tree must surface zero violations: {viols:?}"
    );
}

// ---------------------------------------------------------------------
// Per-classifier coverage — one test per category.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orphan_classifier_detects_seeded_orphan() {
    let h = setup_sqlite().await.expect("sqlite");
    let phantom = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(
        &h.provider,
        child,
        Some(phantom),
        "orphan",
        ACTIVE,
        false,
        1,
    )
    .await
    .expect("seed orphan child");
    insert_closure(&h.provider, child, child, 0, ACTIVE)
        .await
        .expect("self-row");

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::OrphanedChild) >= 1,
        "expected OrphanedChild, got {viols:?}"
    );
    let surfaced = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::OrphanedChild)
        .expect("OrphanedChild row");
    assert_eq!(surfaced.1.tenant_id, Some(child));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broken_parent_reference_classifier_detects_deleted_parent() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    // Parent in `Deleted` status but still a row → broken parent ref
    // (child is Active under a Deleted parent).
    insert_tenant(&h.provider, root, None, "root", DELETED, false, 0)
        .await
        .unwrap();
    insert_tenant(&h.provider, child, Some(root), "child", ACTIVE, false, 1)
        .await
        .unwrap();
    insert_closure(&h.provider, root, root, 0, DELETED)
        .await
        .unwrap();
    insert_closure(&h.provider, child, child, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, root, child, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::BrokenParentReference) >= 1,
        "expected BrokenParentReference, got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn depth_classifier_detects_mismatch() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    // Stored depth = 3, walk yields depth = 1 → DepthMismatch.
    insert_tenant(&h.provider, child, Some(root), "child", ACTIVE, false, 3)
        .await
        .unwrap();
    insert_closure(&h.provider, root, root, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, child, child, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, root, child, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::DepthMismatch)
        .expect("DepthMismatch row");
    assert_eq!(v.1.tenant_id, Some(child));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cycle_classifier_detects_self_loop() {
    let h = setup_sqlite().await.expect("sqlite");
    let a = Uuid::new_v4();
    // SQLite migration omits FK enforcement, so the self-referential
    // `parent_id` is accepted directly. Postgres would reject this
    // via FK; the classifier is what catches it on dialects without.
    insert_tenant(&h.provider, a, Some(a), "self-loop", ACTIVE, false, 1)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::Cycle) >= 1,
        "expected Cycle (self-loop), got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cycle_classifier_detects_two_cycle() {
    let h = setup_sqlite().await.expect("sqlite");
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    insert_tenant(&h.provider, a, Some(b), "a", ACTIVE, false, 1)
        .await
        .unwrap();
    insert_tenant(&h.provider, b, Some(a), "b", ACTIVE, false, 1)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::Cycle) >= 1,
        "expected Cycle (2-cycle), got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_classifier_detects_zero_root_anomaly() {
    let h = setup_sqlite().await.expect("sqlite");
    // Use the *zero-roots* variant to avoid colliding with
    // `ux_tenants_single_root`'s partial-unique index. A single
    // tenant with a non-resolving `parent_id` produces zero
    // NULL-parent rows in the snapshot, which the root classifier
    // flags as `RootCountAnomaly` (alongside `OrphanedChild`).
    let phantom = Uuid::new_v4();
    let lone = Uuid::new_v4();
    insert_tenant(&h.provider, lone, Some(phantom), "lone", ACTIVE, false, 1)
        .await
        .unwrap();
    insert_closure(&h.provider, lone, lone, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::RootCountAnomaly) >= 1,
        "expected RootCountAnomaly, got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_row_classifier_detects_missing() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    // Deliberately omit the (root, root) self-row.

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::MissingClosureSelfRow)
        .expect("MissingClosureSelfRow row");
    assert_eq!(v.1.tenant_id, Some(root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_ancestor_classifier_detects_gap() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    insert_tenant(&h.provider, child, Some(root), "child", ACTIVE, false, 1)
        .await
        .unwrap();
    // Self-rows present, strict (root, child) deliberately absent.
    insert_closure(&h.provider, root, root, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, child, child, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::ClosureCoverageGap) >= 1,
        "expected ClosureCoverageGap, got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extra_edge_classifier_detects_dangling() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    insert_closure(&h.provider, root, root, 0, ACTIVE)
        .await
        .unwrap();
    // Closure references a tenant that does not exist in `tenants`
    // (no FK in the SQLite migration to reject this).
    let dangling = Uuid::new_v4();
    insert_closure(&h.provider, root, dangling, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::StaleClosureRow) >= 1,
        "expected StaleClosureRow, got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn barrier_classifier_detects_divergence() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    // Child is `self_managed = true` → expected barrier=1 on (root,
    // child); we deliberately store barrier=0 to trigger the
    // classifier.
    insert_tenant(&h.provider, child, Some(root), "child", ACTIVE, true, 1)
        .await
        .unwrap();
    insert_closure(&h.provider, root, root, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, child, child, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&h.provider, root, child, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::BarrierColumnDivergence) >= 1,
        "expected BarrierColumnDivergence, got {viols:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn descendant_status_classifier_detects_divergence() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    // tenants.status = ACTIVE, closure says SUSPENDED → divergence.
    insert_closure(&h.provider, root, root, 0, SUSPENDED)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    let v = viols
        .iter()
        .find(|(c, _)| *c == IntegrityCategory::DescendantStatusDivergence)
        .expect("DescendantStatusDivergence row");
    assert_eq!(v.1.tenant_id, Some(root));
}

// ---------------------------------------------------------------------
// Snapshot consistency — multiple categories surfaced from a single
// snapshot (mirrors donor's `snapshot_surfaces_two_categories_simultaneously`).
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_surfaces_multiple_categories_simultaneously() {
    let h = setup_sqlite().await.expect("sqlite");
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&h.provider, root, None, "root", ACTIVE, false, 0)
        .await
        .unwrap();
    insert_tenant(&h.provider, child, Some(root), "child", ACTIVE, false, 1)
        .await
        .unwrap();
    // Two anomalies seeded in a single snapshot:
    //   1) root self-row says SUSPENDED while tenants says ACTIVE
    //      → DescendantStatusDivergence.
    //   2) child self-row deliberately omitted
    //      → MissingClosureSelfRow.
    insert_closure(&h.provider, root, root, 0, SUSPENDED)
        .await
        .unwrap();
    insert_closure(&h.provider, root, child, 0, ACTIVE)
        .await
        .unwrap();

    let viols = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("check");
    assert!(
        count_for(&viols, IntegrityCategory::DescendantStatusDivergence) >= 1,
        "expected DescendantStatusDivergence in multi-cat check: {viols:?}"
    );
    assert!(
        count_for(&viols, IntegrityCategory::MissingClosureSelfRow) >= 1,
        "expected MissingClosureSelfRow in multi-cat check: {viols:?}"
    );
}

// ---------------------------------------------------------------------
// Single-flight gate — pre-populate `integrity_check_runs` so the
// next acquire surfaces `IntegrityCheckInProgress`. Mirrors the
// donor's `single_flight_pre_held_gate_*` tests.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_refuses_when_whole_scope_gate_is_held() {
    let h = setup_sqlite().await.expect("sqlite :memory:");
    let _ = seed_clean_two_node_tree(&h.provider).await.expect("seed");

    let held = pre_populate_gate(&h.provider, "whole")
        .await
        .expect("pre-populate gate");

    let result = run_check(&h.repo, IntegrityScope::Whole).await;
    match result {
        Err(DomainError::IntegrityCheckInProgress { ref scope }) => {
            assert_eq!(
                scope, "whole",
                "IntegrityCheckInProgress under Whole scope must carry scope=\"whole\""
            );
        }
        other => panic!("expected IntegrityCheckInProgress when gate is held; got {other:?}"),
    }

    release_gate(&h.provider, "whole", held)
        .await
        .expect("release gate");

    let post = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("post-release check must succeed");
    assert!(
        post.is_empty(),
        "post-release check on a clean tree must surface zero violations: {post:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_refuses_when_subtree_gate_is_held_and_carries_uuid_in_payload() {
    let h = setup_sqlite().await.expect("sqlite :memory:");
    let (root, _child) = seed_clean_two_node_tree(&h.provider).await.expect("seed");

    let scope_key = format!("subtree:{root}");
    let held = pre_populate_gate(&h.provider, &scope_key)
        .await
        .expect("pre-populate gate");

    let result = run_check(&h.repo, IntegrityScope::Subtree(root)).await;
    match result {
        Err(DomainError::IntegrityCheckInProgress { scope }) => {
            assert_eq!(
                scope, scope_key,
                "IntegrityCheckInProgress under Subtree(root) must carry scope=\"subtree:<root>\""
            );
        }
        other => {
            panic!("expected IntegrityCheckInProgress when subtree gate is held; got {other:?}")
        }
    }

    release_gate(&h.provider, &scope_key, held)
        .await
        .expect("release");

    let post = run_check(&h.repo, IntegrityScope::Subtree(root))
        .await
        .expect("post-release subtree check must succeed");
    assert!(
        post.is_empty(),
        "post-release subtree check on a clean tree must surface zero violations: {post:?}"
    );
}

// ---------------------------------------------------------------------
// Cross-scope independence — different scope keys MUST NOT serialize
// against each other. Pin this so a future regression that collapses
// the per-scope PK gate into a global lock cannot land silently. The
// SQLite path also doubles as a smoke check for the
// `SQLITE_BUSY → IntegrityCheckInProgress` mapping TODO in
// `repo_impl/integrity.rs` — the test would surface a regression
// there as a spurious `Internal` rather than the expected `Ok(_)`.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_scope_gates_do_not_serialize_each_other() {
    let h = setup_sqlite().await.expect("sqlite :memory:");
    let (root, _child) = seed_clean_two_node_tree(&h.provider).await.expect("seed");

    // Pre-hold the Whole gate. A subtree run on a different scope key
    // must still proceed — the contract is per-scope mutual exclusion,
    // not a global lock.
    let held = pre_populate_gate(&h.provider, "whole")
        .await
        .expect("pre-populate whole gate");

    let subtree = run_check(&h.repo, IntegrityScope::Subtree(root))
        .await
        .expect("subtree check must proceed while the Whole gate is held by a peer");
    assert!(
        subtree.is_empty(),
        "clean two-node subtree must surface zero violations even with the Whole gate held: {subtree:?}"
    );

    release_gate(&h.provider, "whole", held)
        .await
        .expect("release");

    // Symmetric direction: pre-hold the subtree gate, Whole must
    // proceed.
    let scope_key = format!("subtree:{root}");
    let held = pre_populate_gate(&h.provider, &scope_key)
        .await
        .expect("pre-populate subtree gate");

    let whole = run_check(&h.repo, IntegrityScope::Whole)
        .await
        .expect("whole check must proceed while the subtree gate is held by a peer");
    assert!(
        whole.is_empty(),
        "clean tree must surface zero violations even with the subtree gate held: {whole:?}"
    );

    release_gate(&h.provider, &scope_key, held)
        .await
        .expect("release");
}
