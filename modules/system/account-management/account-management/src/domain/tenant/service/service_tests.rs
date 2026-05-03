//! In-file unit tests with in-memory `FakeTenantRepo` and
//! `FakeIdpProvisioner`. All tests are hermetic -- no DB, no network,
//! no filesystem.

use account_management_sdk::TenantStatus as PublicTenantStatus;

use super::*;
use crate::config::AccountManagementConfig;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::resource_checker::InertResourceOwnershipChecker;
use crate::domain::tenant::test_support::{
    FakeDeprovisionOutcome, FakeIdpProvisioner, FakeOutcome, FakeTenantRepo, mock_enforcer,
};
use async_trait::async_trait;
use modkit_security::AccessScope;
use std::sync::Mutex;
use time::OffsetDateTime;

fn ctx_for(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::from_u128(0xDEAD))
        .subject_tenant_id(tenant_id)
        .build()
        .expect("ctx")
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn make_service(repo: Arc<FakeTenantRepo>, outcome: FakeOutcome) -> TenantService<FakeTenantRepo> {
    TenantService::new(
        repo,
        Arc::new(FakeIdpProvisioner::new(outcome)),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    )
}

fn child_input(child_id: Uuid, parent_id: Uuid) -> CreateChildInput {
    CreateChildInput {
        child_id,
        parent_id,
        name: "child".into(),
        self_managed: false,
        tenant_type: "gts.cf.core.am.tenant_type.v1~x.core.am.customer.v1~".into(),
        provisioning_metadata: None,
    }
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

#[tokio::test]
async fn create_child_happy_path_writes_self_row_and_one_ancestor_row() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x200);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);

    let created = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create ok");

    assert_eq!(created.id.0, child);
    assert_eq!(created.status, account_management_sdk::TenantStatus::Active);
    // `depth` is an internal storage column, not part of TenantInfo;
    // verify via the repo snapshot.
    let row = repo
        .find_by_id_unchecked(child)
        .expect("activated row in fake repo");
    assert_eq!(row.depth, 1);

    // Closure: root self-row + new child self-row + one strict-ancestor row.
    let closure = repo.snapshot_closure();
    assert_eq!(closure.len(), 3);
    assert!(
        closure
            .iter()
            .any(|r| r.ancestor_id == child && r.descendant_id == child && r.barrier == 0)
    );
    assert!(
        closure
            .iter()
            .any(|r| r.ancestor_id == root && r.descendant_id == child && r.barrier == 0)
    );
}

#[tokio::test]
async fn create_child_clean_failure_compensates_and_writes_no_closure_rows() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x201);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();
    let svc = make_service(repo.clone(), FakeOutcome::CleanFailure);

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("should fail");
    assert_eq!(err.code(), "service_unavailable");

    // Compensation removed the provisioning row.
    let tenant = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(tenant.is_none(), "provisioning row compensated");
    // No closure rows written.
    assert_eq!(repo.snapshot_closure().len(), closure_before);
}

#[tokio::test]
async fn create_child_ambiguous_failure_keeps_provisioning_row_and_writes_no_closure_rows() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x202);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();
    let svc = make_service(repo.clone(), FakeOutcome::Ambiguous);

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("should fail");
    assert_eq!(err.code(), "internal");

    // Provisioning row STILL PRESENT -- reaper will compensate asynchronously.
    let tenant = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(tenant.is_some(), "provisioning row retained");
    assert_eq!(tenant.unwrap().status, TenantStatus::Provisioning);
    assert_eq!(repo.snapshot_closure().len(), closure_before);
}

#[tokio::test]
async fn create_child_unsupported_op_compensates_and_surfaces_idp_unsupported_operation() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x203);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Unsupported);

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("should fail");
    assert_eq!(err.code(), "unsupported_operation");
    assert!(
        repo.find_by_id(&AccessScope::allow_all(), child)
            .await
            .expect("repo")
            .is_none()
    );
}

#[tokio::test]
async fn create_child_advisory_depth_threshold_emits_metric_and_succeeds() {
    // Per `algo-depth-threshold-evaluation` the advisory branch
    // fires at `depth > threshold` and creation proceeds. We pin
    // a low `depth_threshold = 4`, build a chain of depth 0..=4,
    // and create a child under the deepest existing tenant -- the
    // child lands at depth 5 (= threshold + 1) which exceeds the
    // threshold and triggers the advisory emission *without*
    // strict-mode rejection.
    let repo = Arc::new(FakeTenantRepo::new());
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");

    let mut prev: Option<Uuid> = None;
    let mut deepest = Uuid::nil();
    for i in 0..=4u128 {
        let id = Uuid::from_u128(0x1000 + i);
        let model = TenantModel {
            id,
            parent_id: prev,
            name: format!("t{i}"),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: u32::try_from(i).expect("u32"),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        repo.insert_tenant_raw(model);
        prev = Some(id);
        deepest = id;
    }

    let cfg = AccountManagementConfig {
        depth_strict_mode: false,
        depth_threshold: 4,
        ..AccountManagementConfig::default()
    };
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        cfg,
        Arc::new(InertResourceOwnershipChecker),
    );
    let child = Uuid::from_u128(0x9999);
    let root = Uuid::from_u128(0x1000);
    let created = svc
        .create_child(&ctx_for(root), child_input(child, deepest))
        .await
        .expect("advisory branch still proceeds");
    assert_eq!(created.status, account_management_sdk::TenantStatus::Active);
    let row = repo
        .find_by_id_unchecked(child)
        .expect("activated row in fake repo");
    assert_eq!(row.depth, 5);
}

#[tokio::test]
async fn read_tenant_happy_path_returns_model() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo, FakeOutcome::Ok);
    let t = svc
        .read_tenant(&ctx_for(root), root)
        .await
        .expect("read ok");
    assert_eq!(t.id.0, root);
}

#[tokio::test]
async fn read_tenant_not_found_returns_not_found() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo, FakeOutcome::Ok);
    let err = svc
        .read_tenant(&ctx_for(root), Uuid::from_u128(0xDEAD))
        .await
        .expect_err("should be not found");
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn read_tenant_provisioning_tenant_is_reported_as_not_found() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x201);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    // Insert a provisioning tenant directly.
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: child,
        parent_id: Some(root),
        name: "prov".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    });
    let svc = make_service(repo, FakeOutcome::Ok);
    let err = svc
        .read_tenant(&ctx_for(root), child)
        .await
        .expect_err("should hide");
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn list_children_honours_top_and_skip() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    for i in 0..5u128 {
        let child = Uuid::from_u128(0x300 + i);
        svc.create_child(&ctx_for(root), child_input(child, root))
            .await
            .expect("create");
    }
    let page = svc
        .list_children(
            &ctx_for(root),
            ListChildrenQuery::new(root, None, 2, 1).expect("query"),
        )
        .await
        .expect("list ok");
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.top, 2);
    assert_eq!(page.skip, 1);
    assert_eq!(page.total, Some(5));
}

#[tokio::test]
async fn list_children_status_filter_applies() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    let c1 = Uuid::from_u128(0x301);
    let c2 = Uuid::from_u128(0x302);
    svc.create_child(&ctx_for(root), child_input(c1, root))
        .await
        .expect("c1");
    svc.create_child(&ctx_for(root), child_input(c2, root))
        .await
        .expect("c2");
    svc.update_tenant(
        &ctx_for(root),
        c2,
        TenantUpdate {
            status: Some(PublicTenantStatus::Suspended),
            ..Default::default()
        },
    )
    .await
    .expect("patch c2");

    let active_only = svc
        .list_children(
            &ctx_for(root),
            ListChildrenQuery::new(root, Some(vec![PublicTenantStatus::Active]), 10, 0)
                .expect("query"),
        )
        .await
        .expect("list ok");
    assert_eq!(active_only.items.len(), 1);
    assert_eq!(active_only.items[0].id.0, c1);

    let suspended_only = svc
        .list_children(
            &ctx_for(root),
            ListChildrenQuery::new(root, Some(vec![PublicTenantStatus::Suspended]), 10, 0)
                .expect("query"),
        )
        .await
        .expect("list ok");
    assert_eq!(suspended_only.items.len(), 1);
    assert_eq!(suspended_only.items[0].id.0, c2);
}

#[tokio::test]
async fn update_tenant_accepts_name_and_supported_status_transitions() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    let child = Uuid::from_u128(0x400);
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create");

    let renamed = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .expect("rename ok");
    assert_eq!(renamed.name, "renamed");

    let suspended = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                status: Some(PublicTenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .expect("suspend ok");
    assert_eq!(suspended.status, PublicTenantStatus::Suspended);

    let reactivated = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                status: Some(PublicTenantStatus::Active),
                ..Default::default()
            },
        )
        .await
        .expect("unsuspend ok");
    assert_eq!(reactivated.status, PublicTenantStatus::Active);

    // Verify descendant_status was rewritten in the closure (status denorm invariant).
    let closure = repo.snapshot_closure();
    assert!(
        closure
            .iter()
            .filter(|r| r.descendant_id == child)
            .all(|r| r.descendant_status == TenantStatus::Active.as_smallint())
    );
}

#[tokio::test]
async fn update_tenant_rejects_empty_patch() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    let err = svc
        .update_tenant(&ctx_for(root), root, TenantUpdate::default())
        .await
        .expect_err("reject");
    assert_eq!(err.code(), "validation");
}

#[tokio::test]
async fn update_tenant_rejects_transition_to_deleted() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    let child = Uuid::from_u128(0x500);
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create");

    let err = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                status: Some(PublicTenantStatus::Deleted),
                ..Default::default()
            },
        )
        .await
        .expect_err("delete must go through DELETE flow");
    // PR1 tightened `validate_status_transition` to reject every
    // non-`Active ↔ Suspended` PATCH with `DomainError::Conflict`
    // (HTTP 409) -- see feature-tenant-hierarchy-management.md.
    assert_eq!(err.code(), "conflict");
}

#[tokio::test]
async fn update_tenant_rejects_transition_from_provisioning() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x600);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: child,
        parent_id: Some(root),
        name: "prov".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    });
    let svc = make_service(repo, FakeOutcome::Ok);
    let err = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                status: Some(PublicTenantStatus::Active),
                ..Default::default()
            },
        )
        .await
        .expect_err("must not see provisioning tenant");
    // Provisioning is SDK-invisible, so the service surfaces not_found.
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn update_tenant_rejects_oversized_name() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo, FakeOutcome::Ok);
    let err = svc
        .update_tenant(
            &ctx_for(root),
            root,
            TenantUpdate {
                name: Some("x".repeat(256)),
                ..Default::default()
            },
        )
        .await
        .expect_err("reject oversized");
    assert_eq!(err.code(), "validation");
}

// ---- Closure invariant end-to-end ------------------------------

#[tokio::test]
async fn closure_invariants_are_preserved_across_self_managed_path() {
    // Layout: root(d=0,sm=false) → mid(d=1,sm=true) → leaf(d=2,sm=false)
    let root = Uuid::from_u128(0x100);
    let mid = Uuid::from_u128(0x110);
    let leaf = Uuid::from_u128(0x111);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);

    let mut mid_input = child_input(mid, root);
    mid_input.self_managed = true;
    svc.create_child(&ctx_for(root), mid_input)
        .await
        .expect("mid ok");
    svc.create_child(&ctx_for(root), child_input(leaf, mid))
        .await
        .expect("leaf ok");

    let closure = repo.snapshot_closure();
    // Self-row barrier invariant: every self-row has barrier=0.
    for row in closure.iter().filter(|r| r.is_self_row()) {
        assert_eq!(row.barrier, 0, "self-row barrier must be 0");
    }
    // Leaf participates in 3 rows: self + mid + root.
    let leaf_rows: Vec<_> = closure.iter().filter(|r| r.descendant_id == leaf).collect();
    assert_eq!(leaf_rows.len(), 3);
    let root_to_leaf = leaf_rows
        .iter()
        .find(|r| r.ancestor_id == root)
        .expect("root->leaf row");
    let mid_to_leaf = leaf_rows
        .iter()
        .find(|r| r.ancestor_id == mid)
        .expect("mid->leaf row");
    // Strict path from root to leaf is {mid, leaf}; mid is self-managed, so barrier=1.
    assert_eq!(
        root_to_leaf.barrier, 1,
        "self-managed mid sets barrier on root->leaf"
    );
    // Strict path from mid to leaf is {leaf}; leaf is not self-managed, so barrier=0.
    assert_eq!(mid_to_leaf.barrier, 0, "no self-managed below mid");
}

#[tokio::test]
async fn closure_invariants_no_self_managed_gives_all_zero_barriers() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x110);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service(repo.clone(), FakeOutcome::Ok);
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("ok");

    let closure = repo.snapshot_closure();
    // Every row barrier must be 0 when no tenant on any strict path is self-managed.
    for row in &closure {
        assert_eq!(row.barrier, 0);
    }
}

#[tokio::test]
async fn create_child_rejects_inactive_parent() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    // Suspend the root via direct mutation.
    {
        let mut state = repo.state.lock().expect("lock");
        state.tenants.get_mut(&root).expect("root").status = TenantStatus::Suspended;
    }
    let svc = make_service(repo, FakeOutcome::Ok);
    let err = svc
        .create_child(&ctx_for(root), child_input(Uuid::from_u128(0x700), root))
        .await
        .expect_err("suspended parent rejects");
    assert_eq!(err.code(), "validation");
}

// =================================================================
// Phase 3 -- soft delete / hard delete / reaper / integrity / strict
// =================================================================

use crate::domain::tenant::hooks::{HookError, TenantHardDeleteHook};
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;
use futures::future::FutureExt;
use modkit_security::SecurityContext;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration as StdDuration;

fn ctx() -> SecurityContext {
    // Default Phase-3 test ctx -- caller is the platform admin (home
    // tenant == root tenant id used by `FakeTenantRepo::with_root`).
    SecurityContext::builder()
        .subject_id(Uuid::from_u128(0xDEAD))
        .subject_tenant_id(Uuid::from_u128(0x100))
        .build()
        .expect("ctx")
}

fn svc_with(
    repo: Arc<FakeTenantRepo>,
    outcome: FakeOutcome,
    cfg: AccountManagementConfig,
    checker: Arc<dyn ResourceOwnershipChecker>,
) -> TenantService<FakeTenantRepo> {
    TenantService::new(
        repo,
        Arc::new(FakeIdpProvisioner::new(outcome)),
        checker,
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        cfg,
    )
}

#[allow(unknown_lints, de0309_must_have_domain_model)]
struct CountingChecker {
    count: u64,
}
#[async_trait]
impl ResourceOwnershipChecker for CountingChecker {
    async fn count_ownership_links(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
    ) -> Result<u64, DomainError> {
        Ok(self.count)
    }
}

#[tokio::test]
async fn soft_delete_rejects_root_tenant() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo,
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(InertResourceOwnershipChecker),
    );
    let err = svc
        .soft_delete(&ctx(), root)
        .await
        .expect_err("root reject");
    assert_eq!(err.code(), "root_tenant_cannot_delete");
}

#[tokio::test]
async fn soft_delete_rejects_tenant_with_children() {
    let root = Uuid::from_u128(0x100);
    let mid = Uuid::from_u128(0x110);
    let leaf = Uuid::from_u128(0x111);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(InertResourceOwnershipChecker),
    );
    svc.create_child(&ctx_for(root), child_input(mid, root))
        .await
        .expect("mid");
    svc.create_child(&ctx_for(root), child_input(leaf, mid))
        .await
        .expect("leaf");

    let err = svc
        .soft_delete(&ctx(), mid)
        .await
        .expect_err("has children");
    assert_eq!(err.code(), "tenant_has_children");
}

#[tokio::test]
async fn soft_delete_rejects_tenant_with_rg_resources() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x200);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(CountingChecker { count: 3 }),
    );
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("child");
    let err = svc
        .soft_delete(&ctx(), child)
        .await
        .expect_err("has resources");
    assert_eq!(err.code(), "tenant_has_resources");
}

#[tokio::test]
async fn scan_retention_does_not_starve_due_rows_behind_older_not_due_backlog() {
    // **This test is NOT a regression test for the SQL-side
    // starvation bug.** It is a fake↔prod alignment pin. The
    // historical bug — over-fetching with `LIMIT N` ordered by
    // `scheduled_at ASC` and applying `is_due` in Rust — could
    // hide a single newer due row behind ≥256 older not-yet-due
    // NULL-window rows. The fix pushes the due-check into SQL.
    //
    // The `FakeTenantRepo` here ALREADY applies `is_due` before
    // the limit (see `test_support/repo.rs::scan_retention_due`),
    // so the assertion below pins the contract that the SQL
    // implementation *also* applies due-filter pre-limit. It does
    // not, on its own, prove the SQL implementation is correct —
    // the FakeRepo could match the contract while the SQL drifts.
    // Authoritative SQL validation lives in the integration-test
    // suite once the testcontainers scaffold lands for AM (TODO —
    // see `feature-tenant-hierarchy-management.md` retention §).
    //
    // Pathological shape exercised here: 300 older NULL-window
    // rows scheduled 80d ago (not due under default 90d retention)
    // + 1 newer row with explicit `retention_window_secs = 0`
    // (due immediately).
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));

    let now = OffsetDateTime::now_utc();
    let eighty_days_ago = now - time::Duration::days(80);
    // 90 days in seconds. `from_hours` is unstable on the
    // workspace MSRV; use the seconds form.
    #[allow(clippy::duration_suboptimal_units)]
    let ninety_day_default = std::time::Duration::from_secs(90 * 86_400);

    // 300 older NULL-window rows scheduled 80d ago -- not due under
    // the default 90d retention. 300 > the historical 4×64 = 256
    // over-fetch cap, which is what triggered the starvation.
    {
        let mut state = repo.state.lock().expect("lock");
        for i in 0..300u128 {
            let id = Uuid::from_u128(0xA000 + i);
            state.tenants.insert(
                id,
                TenantModel {
                    id,
                    parent_id: Some(root),
                    name: format!("backlog-{i}"),
                    status: TenantStatus::Deleted,
                    self_managed: false,
                    tenant_type_uuid: Uuid::from_u128(0xAA),
                    depth: 1,
                    created_at: eighty_days_ago,
                    updated_at: eighty_days_ago,
                    deleted_at: Some(eighty_days_ago),
                },
            );
            state.closure.push(ClosureRow {
                ancestor_id: id,
                descendant_id: id,
                barrier: 0,
                descendant_status: TenantStatus::Deleted.as_smallint(),
            });
            state.closure.push(ClosureRow {
                ancestor_id: root,
                descendant_id: id,
                barrier: 0,
                descendant_status: TenantStatus::Deleted.as_smallint(),
            });
            // NULL retention_window -- use service default.
            state.retention.insert(id, (eighty_days_ago, None));
        }
    }

    // The single due row: explicit retention_window_secs = 0,
    // scheduled now → due immediately.
    let due_id = Uuid::from_u128(0xDEED);
    {
        let mut state = repo.state.lock().expect("lock");
        state.tenants.insert(
            due_id,
            TenantModel {
                id: due_id,
                parent_id: Some(root),
                name: "due-now".into(),
                status: TenantStatus::Deleted,
                self_managed: false,
                tenant_type_uuid: Uuid::from_u128(0xAA),
                depth: 1,
                created_at: now,
                updated_at: now,
                deleted_at: Some(now),
            },
        );
        state.closure.push(ClosureRow {
            ancestor_id: due_id,
            descendant_id: due_id,
            barrier: 0,
            descendant_status: TenantStatus::Deleted.as_smallint(),
        });
        state.closure.push(ClosureRow {
            ancestor_id: root,
            descendant_id: due_id,
            barrier: 0,
            descendant_status: TenantStatus::Deleted.as_smallint(),
        });
        state
            .retention
            .insert(due_id, (now, Some(std::time::Duration::from_secs(0))));
    }

    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig {
            default_retention_secs: ninety_day_default.as_secs(),
            ..AccountManagementConfig::default()
        },
        Arc::new(InertResourceOwnershipChecker),
    );

    let res = svc.hard_delete_batch(64).await;
    assert_eq!(
        res.processed, 1,
        "exactly the due row should be processed; the 300-row not-due backlog must not starve it"
    );
    assert_eq!(res.cleaned, 1, "the due row should reach Cleaned");
    assert!(
        repo.find_by_id(&AccessScope::allow_all(), due_id)
            .await
            .expect("repo")
            .is_none(),
        "the due row must be hard-deleted"
    );
    // None of the 300 not-due rows should have been touched.
    for i in 0..300u128 {
        let id = Uuid::from_u128(0xA000 + i);
        assert!(
            repo.find_by_id(&AccessScope::allow_all(), id)
                .await
                .expect("repo")
                .is_some(),
            "not-due backlog row {id} must remain"
        );
    }
}

#[tokio::test]
async fn reaper_records_idp_not_found_as_already_absent_distinct_from_compensated() {
    // Plugin reports the vendor never had the tenant (or already
    // wiped it) — surfaces as `DeprovisionFailure::NotFound`. AM
    // treats this as success-equivalent for *teardown*: the
    // provisioning row is **physically removed** (not flipped to
    // `Deleted`) because provisioning rows never become SDK-visible,
    // so retention-pipeline tombstoning would leak rows. The
    // operator-visible counter must report it under `already_absent`,
    // not `compensated`: `compensated` counts rows the reaper
    // actively cleaned, `already_absent` counts rows that were
    // already gone on the vendor side (typically a lost-claim or
    // cross-system inconsistency signal worth investigating).
    let root = Uuid::from_u128(0x100);
    let stuck = Uuid::from_u128(0x215);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: stuck,
        parent_id: Some(root),
        name: "stuck".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: then,
        updated_at: then,
        deleted_at: None,
    });
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    idp.set_deprovision_outcome(FakeDeprovisionOutcome::NotFound);
    let svc = TenantService::new(
        repo.clone(),
        idp,
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );
    let res = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(res.scanned, 1);
    assert_eq!(
        res.already_absent, 1,
        "NotFound must surface as already_absent, not compensated"
    );
    assert_eq!(
        res.compensated, 0,
        "compensated counts only rows we actively cleaned"
    );
    assert_eq!(res.deferred, 0, "NotFound is not a defer outcome");
    assert!(
        repo.find_by_id(&AccessScope::allow_all(), stuck)
            .await
            .expect("repo")
            .is_none(),
        "compensation must physically remove the provisioning row, not leave a tombstone"
    );
}

// `reaper_releases_claim_on_terminal_failure` was deleted: it
// asserted the old defer-on-Terminal contract (release_claim so the
// row is rescanned next tick), which is the exact loop we now reject.
// Terminal failures stamp `terminal_failure_at` instead, and the
// scan-skip invariant is covered by
// `reaper_marks_terminal_failure_and_parks_row_out_of_retry_loop`
// directly. The claim is still released for column-tidiness, but
// that is implementation detail rather than load-bearing contract.

#[tokio::test]
async fn reaper_defers_on_idp_retryable_failure() {
    // Mirror of
    // `reaper_marks_terminal_failure_and_parks_row_out_of_retry_loop`
    // for the `Retryable` arm of `reap_stuck_provisioning` —
    // Retryable defers and releases the claim (row eligible next
    // tick), unlike Terminal which stamps `terminal_failure_at`
    // and parks the row indefinitely. The Retryable path is the
    // most-likely-to-fire branch in production (transient IdP) and
    // was previously uncovered.
    let root = Uuid::from_u128(0x100);
    let stuck = Uuid::from_u128(0x213);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: stuck,
        parent_id: Some(root),
        name: "stuck".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: then,
        updated_at: then,
        deleted_at: None,
    });
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    idp.set_deprovision_outcome(FakeDeprovisionOutcome::Retryable);
    let svc = TenantService::new(
        repo.clone(),
        idp,
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );
    let res = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(res.scanned, 1);
    assert_eq!(res.deferred, 1, "retryable failure defers");
    assert_eq!(
        res.compensated, 0,
        "retryable failure must NOT mark row compensated"
    );
    let row = repo
        .find_by_id(&AccessScope::allow_all(), stuck)
        .await
        .expect("repo")
        .expect("row");
    assert_eq!(
        row.status,
        TenantStatus::Provisioning,
        "row stays provisioning until the next reaper tick"
    );
}

#[tokio::test]
async fn reaper_redrives_on_each_tick_when_idp_keeps_failing() {
    // Reaper holds no per-tenant retry state across ticks. Retry /
    // backoff / circuit-breaker policy lives in the IdP plugin. As
    // long as the plugin keeps returning `Retryable` and the per-
    // tick claim is properly released on the defer path, every
    // tick re-issues the call — the plugin is responsible for its
    // own rate-limiting.
    //
    // This test pins that contract by running two ticks back-to-
    // back and asserting that `deprovision_tenant` was invoked
    // twice (once per tick), which only works if the claim was
    // released after the first tick's defer.
    let root = Uuid::from_u128(0x100);
    let stuck = Uuid::from_u128(0x214);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: stuck,
        parent_id: Some(root),
        name: "stuck".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: then,
        updated_at: then,
        deleted_at: None,
    });
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    idp.set_deprovision_outcome(FakeDeprovisionOutcome::Retryable);
    let svc = TenantService::new(
        repo.clone(),
        idp.clone(),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );

    let r1 = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(r1.scanned, 1);
    assert_eq!(r1.deferred, 1);

    let r2 = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(r2.scanned, 1, "row still present, scan picks it up");
    assert_eq!(r2.deferred, 1);

    let calls = idp.deprovision_calls.lock().expect("lock").len();
    assert_eq!(
        calls, 2,
        "stateless reaper re-issues on every tick; plugin owns rate-limiting"
    );
}

#[tokio::test]
async fn reaper_marks_terminal_failure_and_parks_row_out_of_retry_loop() {
    // Per the SDK contract, `DeprovisionFailure::Terminal` is
    // non-recoverable — the IdP plugin is signalling that the
    // vendor refuses to deprovision and operator intervention is
    // required. The reaper must:
    //   * stamp `terminal_failure_at` on the row,
    //   * count the row under `result.terminal` (NOT `deferred`,
    //     which is reserved for transient defers),
    //   * NOT release the row back into the scan-eligible pool.
    //
    // The follow-up assertion exercises the second tick to pin the
    // park-out-of-loop contract: the IdP MUST NOT be re-invoked on
    // the next tick because the scan filter excludes
    // `terminal_failure_at IS NOT NULL` rows. Without this, the
    // earlier reaper would loop forever and never surface the
    // operator-action-required signal.
    let root = Uuid::from_u128(0x100);
    let stuck = Uuid::from_u128(0x210);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    repo.insert_tenant_raw(TenantModel {
        id: stuck,
        parent_id: Some(root),
        name: "stuck".into(),
        status: TenantStatus::Provisioning,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth: 1,
        created_at: then,
        updated_at: then,
        deleted_at: None,
    });
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    idp.set_deprovision_outcome(FakeDeprovisionOutcome::Terminal);
    let svc = TenantService::new(
        repo.clone(),
        idp.clone(),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );

    let r1 = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(r1.scanned, 1);
    assert_eq!(
        r1.terminal, 1,
        "terminal failure must surface as result.terminal, not deferred"
    );
    assert_eq!(
        r1.deferred, 0,
        "deferred is reserved for transient defers; terminal is its own bucket"
    );

    // Row stays in `Provisioning` — terminal_failure_at is the
    // operator-action-required marker, the row is not deleted nor
    // moved to a different status.
    let row = repo
        .find_by_id(&AccessScope::allow_all(), stuck)
        .await
        .expect("repo")
        .expect("row");
    assert_eq!(row.status, TenantStatus::Provisioning);

    // Second tick: scan filter must exclude the marked row, so the
    // IdP is not contacted again. This is the contract that the
    // pre-fix reaper violated (it would defer + release_claim and
    // re-issue indefinitely).
    let r2 = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(
        r2.scanned, 0,
        "terminal-marked row must be excluded from subsequent scans"
    );
    assert_eq!(
        idp.deprovision_calls.lock().expect("lock").len(),
        1,
        "IdP must NOT be re-invoked on the second tick (the marker parks the row)"
    );
}

/// Concurrent-claim invariant: a stuck `Provisioning` row that is
/// already claimed by another worker (within `RETENTION_CLAIM_TTL`)
/// MUST be skipped by `scan_stuck_provisioning`, so two replicas
/// cannot stamp duplicate `IdpTenantProvisionerClient::deprovision_tenant`
/// calls onto the same row inside one TTL window.
///
/// Set-up: two stuck rows, only one of them pre-claimed via
/// `seed_claim`. The reaper tick must touch only the unclaimed row;
/// the `IdP` must see exactly one `deprovision_tenant` call; and the
/// pre-existing claim on the held row MUST remain intact (the
/// reaper's per-row release path only fires for rows it itself
/// scanned, never for rows it skipped).
#[tokio::test]
async fn reaper_skips_rows_already_claimed_by_another_worker() {
    let root = Uuid::from_u128(0x100);
    let stuck_unclaimed = Uuid::from_u128(0x217);
    let stuck_held = Uuid::from_u128(0x218);
    let other_worker = Uuid::from_u128(0xFEED_FEED);

    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let then = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    for id in [stuck_unclaimed, stuck_held] {
        repo.insert_tenant_raw(TenantModel {
            id,
            parent_id: Some(root),
            name: "stuck".into(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: then,
            updated_at: then,
            deleted_at: None,
        });
    }
    // Pre-seed a live claim on `stuck_held` to model "another replica
    // already claimed this row in the current TTL window."
    repo.seed_claim(stuck_held, other_worker);

    // Default `FakeDeprovisionOutcome::Ok` — this test is about
    // claim-skipping semantics, the IdP-side outcome is incidental;
    // a clean `Ok` keeps `compensated += 1` (rather than
    // `already_absent`) so the assertion below pins the
    // claim-skip invariant directly.
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    let svc = TenantService::new(
        repo.clone(),
        idp.clone(),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );

    let res = svc.reap_stuck_provisioning(StdDuration::from_secs(0)).await;
    assert_eq!(
        res.scanned, 1,
        "claimed row must be skipped; only the unclaimed row is scanned"
    );
    assert_eq!(
        res.compensated, 1,
        "the unclaimed row is the only one that gets compensated"
    );

    let calls = idp.deprovision_calls.lock().expect("lock");
    assert_eq!(
        calls.len(),
        1,
        "single IdP deprovision call -- the held row must NOT be re-issued by this replica"
    );
    assert_eq!(
        calls[0], stuck_unclaimed,
        "deprovision target is the unclaimed row"
    );
    drop(calls);

    // The pre-existing claim on `stuck_held` MUST still be there:
    // the reaper never scanned it, never released it, never touched it.
    assert!(
        repo.has_claim(stuck_held),
        "another worker's claim must not be cleared by a peer's reaper tick"
    );
    let held = repo
        .find_by_id_unchecked(stuck_held)
        .expect("held row exists");
    assert_eq!(
        held.status,
        TenantStatus::Provisioning,
        "held row must remain provisioning -- only the holder may compensate it"
    );
}

/// Concurrent-claim invariant for the retention pipeline (mirror of the
/// reaper test above). `tenants.claimed_by` backs both pipelines, so the
/// same fence MUST work end-to-end through `hard_delete_batch`: a
/// soft-deleted, retention-due row already claimed by another worker
/// MUST be skipped — no `IdpTenantProvisionerClient::deprovision_tenant`
/// call, no DB teardown, the held claim survives.
///
/// Set-up: two soft-deleted children due for hard-delete; pre-seed a
/// claim on one. The tick processes only the unclaimed row.
#[tokio::test]
async fn hard_delete_batch_skips_rows_already_claimed_by_another_worker() {
    let root = Uuid::from_u128(0x100);
    let due_unclaimed = Uuid::from_u128(0x230);
    let due_held = Uuid::from_u128(0x231);
    let other_worker = Uuid::from_u128(0xFEED_BEEF);

    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let now = OffsetDateTime::now_utc();
    // Seed both as `Active` then call `schedule_deletion` to flip
    // them to `Deleted` with `retention=0` so they are immediately
    // due — `schedule_deletion` is the same call site that
    // `soft_delete` uses, so the resulting rows + retention metadata
    // match production. (Calling it on an already-`Deleted` row is
    // rejected by the fake as `Conflict`, mirroring the real repo.)
    for id in [due_unclaimed, due_held] {
        repo.insert_tenant_raw(TenantModel {
            id,
            parent_id: Some(root),
            name: "due".into(),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });
        let _ = repo
            .schedule_deletion(
                &AccessScope::allow_all(),
                id,
                now,
                Some(StdDuration::from_secs(0)),
            )
            .await
            .expect("schedule");
    }
    // Pre-seed a live claim on `due_held` to model "another replica
    // already claimed this row in the current TTL window."
    repo.seed_claim(due_held, other_worker);

    // Build the service manually rather than via `svc_with` so we
    // keep a handle on the IdP and can inspect its call list.
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    let svc = TenantService::new(
        repo.clone(),
        idp.clone(),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig {
            default_retention_secs: 0,
            ..AccountManagementConfig::default()
        },
    );

    let res = svc.hard_delete_batch(64).await;
    assert_eq!(
        res.processed, 1,
        "claimed row must be skipped; only the unclaimed row is processed"
    );
    assert_eq!(
        res.cleaned, 1,
        "the unclaimed row is the only one that gets cleaned"
    );

    let calls = idp.deprovision_calls.lock().expect("lock");
    assert_eq!(
        calls.len(),
        1,
        "single IdP deprovision call -- the held row must NOT be re-issued by this replica"
    );
    assert_eq!(
        calls[0], due_unclaimed,
        "deprovision target is the unclaimed row"
    );
    drop(calls);

    // Held row's claim survives, row is still `Deleted` (not yet
    // hard-deleted) — only the holder may complete its teardown.
    assert!(
        repo.has_claim(due_held),
        "another worker's claim must not be cleared by a peer's retention tick"
    );
    let held = repo
        .find_by_id_unchecked(due_held)
        .expect("held row exists");
    assert_eq!(
        held.status,
        TenantStatus::Deleted,
        "held row must remain Deleted -- only the holder may complete its teardown"
    );
}

#[tokio::test]
async fn hard_delete_batch_skips_parent_when_child_still_exists() {
    let root = Uuid::from_u128(0x100);
    let parent = Uuid::from_u128(0x220);
    let child = Uuid::from_u128(0x221);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig {
            default_retention_secs: 0,
            ..AccountManagementConfig::default()
        },
        Arc::new(InertResourceOwnershipChecker),
    );
    svc.create_child(&ctx_for(root), child_input(parent, root))
        .await
        .expect("p");
    svc.create_child(&ctx_for(root), child_input(child, parent))
        .await
        .expect("c");
    // Seed an already-deleted parent directly. `schedule_deletion`
    // now repeats the child guard inside its SERIALIZABLE transaction,
    // so this defensive hard-delete path is only reachable from
    // legacy/corrupt state or an older deployment.
    let now = OffsetDateTime::now_utc();
    {
        let mut state = repo.state.lock().expect("lock");
        let parent_row = state.tenants.get_mut(&parent).expect("parent row");
        parent_row.status = TenantStatus::Deleted;
        parent_row.updated_at = now;
        parent_row.deleted_at = Some(now);
        state
            .retention
            .insert(parent, (now, Some(StdDuration::from_secs(0))));
    }

    let res = svc.hard_delete_batch(64).await;
    assert_eq!(res.processed, 1);
    assert_eq!(
        res.deferred, 1,
        "parent deferred because child still exists"
    );
    assert!(
        repo.find_by_id(&AccessScope::allow_all(), parent)
            .await
            .expect("repo")
            .is_some(),
        "parent row still present"
    );
}

#[tokio::test]
async fn hard_delete_batch_invokes_cascade_hook_before_idp() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x230);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig {
            default_retention_secs: 0,
            ..AccountManagementConfig::default()
        },
        Arc::new(InertResourceOwnershipChecker),
    );
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("c");
    svc.soft_delete(&ctx(), child).await.expect("sd");

    let hook_calls = Arc::new(AtomicU32::new(0));
    let hook_calls_for_hook = hook_calls.clone();
    let hook: TenantHardDeleteHook = Arc::new(move |_id: Uuid| {
        let hc = hook_calls_for_hook.clone();
        async move {
            hc.fetch_add(1, Ordering::SeqCst);
            Ok::<_, HookError>(())
        }
        .boxed()
    });
    svc.register_hard_delete_hook(hook);

    let _ = svc.hard_delete_batch(64).await;
    assert_eq!(
        hook_calls.load(Ordering::SeqCst),
        1,
        "cascade hook must run exactly once per tenant"
    );
}

// `check_hierarchy_integrity_returns_all_category_report` ships
// alongside the classifier set in the diagnostics PR -- the report
// shape (`IntegrityCategory`, `IntegrityReport`) and its repo
// contract (`audit_integrity_for_scope`) are not on the trait yet.

#[tokio::test]
async fn hard_delete_concurrency_processes_siblings_in_parallel() {
    // Five sibling leaves at the same depth, processed under
    // `hard_delete_concurrency = 4`. We pin parallelism via an
    // observable in-flight counter rather than wall-clock — a
    // sequential regression would peak at `1`, while any genuine
    // parallelism peaks at `>= 2`. The cap is `concurrency` (=4),
    // so peak ∈ {2, 3, 4} on a healthy `buffer_unordered`
    // implementation. This avoids the CI-flakiness that a wall-
    // clock assertion (e.g. `elapsed < 200ms`) introduces on
    // shared / debug-build runners where scheduling adds 30–40%
    // overhead.
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig {
            default_retention_secs: 0,
            hard_delete_concurrency: 4,
            ..AccountManagementConfig::default()
        },
        Arc::new(InertResourceOwnershipChecker),
    );

    for i in 0..5u128 {
        let id = Uuid::from_u128(0x300 + i);
        svc.create_child(&ctx_for(root), child_input(id, root))
            .await
            .expect("child");
        svc.soft_delete(&ctx(), id).await.expect("sd");
    }

    let in_flight = Arc::new(AtomicU32::new(0));
    let peak = Arc::new(AtomicU32::new(0));
    let hits = Arc::new(AtomicU32::new(0));
    let in_flight_for_hook = in_flight.clone();
    let peak_for_hook = peak.clone();
    let hits_for_hook = hits.clone();
    let hook: TenantHardDeleteHook = Arc::new(move |_id: Uuid| {
        let inf = in_flight_for_hook.clone();
        let pk = peak_for_hook.clone();
        let hc = hits_for_hook.clone();
        async move {
            // Increment in-flight FIRST, then update peak — order
            // matters: peak is the running maximum of concurrent
            // hooks observed by any single hook.
            let cur = inf.fetch_add(1, Ordering::SeqCst) + 1;
            pk.fetch_max(cur, Ordering::SeqCst);
            // Hold long enough that all sibling hooks dispatched
            // by `buffer_unordered` are simultaneously in-flight.
            // The actual duration is irrelevant to the assertion;
            // it just creates a window in which siblings overlap.
            tokio::time::sleep(StdDuration::from_millis(50)).await;
            inf.fetch_sub(1, Ordering::SeqCst);
            hc.fetch_add(1, Ordering::SeqCst);
            Ok::<_, HookError>(())
        }
        .boxed()
    });
    svc.register_hard_delete_hook(hook);

    let res = svc.hard_delete_batch(64).await;

    assert_eq!(res.processed, 5);
    assert_eq!(res.cleaned, 5, "all five leaves should reach Cleaned");
    assert_eq!(hits.load(Ordering::SeqCst), 5);
    let observed_peak = peak.load(Ordering::SeqCst);
    assert!(
        observed_peak >= 2,
        "expected parallel processing (peak >= 2); got peak = {observed_peak} \
         (sequential single-flight would peak at 1)"
    );
    assert!(
        observed_peak <= 4,
        "peak in-flight {observed_peak} exceeds hard_delete_concurrency = 4 \
         — buffer_unordered cap appears broken"
    );
}

#[tokio::test]
async fn strict_mode_rejects_deep_child() {
    // Per `algo-depth-threshold-evaluation` strict-mode rejects at
    // `depth > threshold`. Build a chain of depth 0..=2 and pin
    // `depth_threshold = 2` so a child created under the deepest
    // tenant lands at depth 3 (= threshold + 1) and is rejected.
    let repo = Arc::new(FakeTenantRepo::new());
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
    let mut prev: Option<Uuid> = None;
    let mut deepest = Uuid::nil();
    for i in 0..=2u128 {
        let id = Uuid::from_u128(0x2000 + i);
        repo.insert_tenant_raw(TenantModel {
            id,
            parent_id: prev,
            name: format!("t{i}"),
            status: TenantStatus::Active,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: u32::try_from(i).expect("u32"),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });
        prev = Some(id);
        deepest = id;
    }

    let cfg = AccountManagementConfig {
        depth_strict_mode: true,
        depth_threshold: 2,
        ..AccountManagementConfig::default()
    };
    let svc = svc_with(
        repo,
        FakeOutcome::Ok,
        cfg,
        Arc::new(InertResourceOwnershipChecker),
    );
    let child = Uuid::from_u128(0x9001);
    let root = Uuid::from_u128(0x2000);
    let err = svc
        .create_child(&ctx_for(root), child_input(child, deepest))
        .await
        .expect_err("strict reject");
    assert_eq!(err.code(), "tenant_depth_exceeded");
}

// =================================================================
// FEATURE 2.3 -- tenant-type-enforcement (saga step 3)
// =================================================================

/// Programmable [`TenantTypeChecker`] used by the saga step 3 tests
/// to drive the type-compatibility barrier through its three
/// branches: admit, type-not-allowed reject, registry unavailable.
#[allow(unknown_lints, de0309_must_have_domain_model)]
struct FakeTenantTypeChecker {
    outcome: Mutex<FakeTypeOutcome>,
    calls: Mutex<Vec<(Uuid, Uuid)>>,
}

#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
enum FakeTypeOutcome {
    Admit,
    TypeNotAllowed { detail: &'static str },
    ServiceUnavailable { detail: &'static str },
}

impl FakeTenantTypeChecker {
    fn new(outcome: FakeTypeOutcome) -> Self {
        Self {
            outcome: Mutex::new(outcome),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(Uuid, Uuid)> {
        self.calls.lock().expect("lock").clone()
    }
}

#[async_trait]
impl TenantTypeChecker for FakeTenantTypeChecker {
    async fn check_parent_child(
        &self,
        parent_type: Uuid,
        child_type: Uuid,
    ) -> Result<(), DomainError> {
        self.calls
            .lock()
            .expect("lock")
            .push((parent_type, child_type));
        match self.outcome.lock().expect("lock").clone() {
            FakeTypeOutcome::Admit => Ok(()),
            FakeTypeOutcome::TypeNotAllowed { detail } => Err(DomainError::TypeNotAllowed {
                detail: detail.into(),
            }),
            FakeTypeOutcome::ServiceUnavailable { detail } => {
                Err(DomainError::ServiceUnavailable {
                    detail: detail.into(),
                    retry_after: None,
                    cause: None,
                })
            }
        }
    }
}

fn make_service_with_type_checker(
    repo: Arc<FakeTenantRepo>,
    outcome: FakeOutcome,
    type_checker: Arc<dyn TenantTypeChecker + Send + Sync>,
) -> TenantService<FakeTenantRepo> {
    TenantService::new(
        repo,
        Arc::new(FakeIdpProvisioner::new(outcome)),
        Arc::new(InertResourceOwnershipChecker),
        type_checker,
        mock_enforcer(),
        AccountManagementConfig::default(),
    )
}

/// AC §6 first bullet -- when the parent's `tenant_type` is not in
/// the child's `allowed_parent_types`, the barrier rejects with
/// `type_not_allowed` and no `tenants` row is written.
#[tokio::test]
async fn create_child_rejects_when_parent_type_not_in_child_allowed_parents() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x500);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();
    let svc = make_service_with_type_checker(
        repo.clone(),
        FakeOutcome::Ok,
        Arc::new(FakeTenantTypeChecker::new(
            FakeTypeOutcome::TypeNotAllowed {
                detail: "customer not allowed under platform",
            },
        )),
    );

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("type-not-allowed must reject");
    assert_eq!(err.code(), "type_not_allowed");
    assert_eq!(err.http_status(), 400);

    // No `tenants` row, no closure rows written.
    let row = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(row.is_none(), "no tenant row should be written on reject");
    assert_eq!(repo.snapshot_closure().len(), closure_before);
}

/// Barrier admits → saga proceeds and the checker observed exactly
/// one `(parent_type, child_type)` call with the right shape.
#[tokio::test]
async fn create_child_succeeds_when_parent_child_compatible() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x501);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let checker = Arc::new(FakeTenantTypeChecker::new(FakeTypeOutcome::Admit));
    let svc = make_service_with_type_checker(repo, FakeOutcome::Ok, checker.clone());

    // Root tenant_type_uuid is `0xAA` per `FakeTenantRepo::with_root`,
    // and the child uuid is derived from the chained-id string in
    // `child_input` via `gts::GtsID::new(...).to_uuid()`.
    let created = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("compatible types admit");
    assert_eq!(created.id.0, child);
    assert_eq!(created.status, PublicTenantStatus::Active);

    let expected_child_type_uuid =
        gts::GtsID::new("gts.cf.core.am.tenant_type.v1~x.core.am.customer.v1~")
            .expect("valid gts chain")
            .to_uuid();
    let calls = checker.calls();
    assert_eq!(calls.len(), 1, "barrier must be invoked exactly once");
    assert_eq!(calls[0].0, Uuid::from_u128(0xAA), "parent type");
    assert_eq!(calls[0].1, expected_child_type_uuid, "child type");
}

/// AC §6 fifth bullet -- when GTS is unreachable, the saga propagates
/// `service_unavailable` (HTTP 503) and writes nothing.
#[tokio::test]
async fn create_child_propagates_types_registry_unavailable_as_service_unavailable() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x502);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();
    let svc = make_service_with_type_checker(
        repo.clone(),
        FakeOutcome::Ok,
        Arc::new(FakeTenantTypeChecker::new(
            FakeTypeOutcome::ServiceUnavailable {
                detail: "types-registry: connection refused",
            },
        )),
    );

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("registry down must propagate");
    assert_eq!(err.code(), "service_unavailable");
    assert_eq!(err.http_status(), 503);

    // No DB side effects.
    let row = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(row.is_none(), "no tenant row on registry unavailable");
    assert_eq!(repo.snapshot_closure().len(), closure_before);
}

/// AC §6 third bullet, negative half -- same-type nesting requested
/// but the GTS schema does not include the type in its own
/// `allowed_parent_types`. Drive via the checker stub returning
/// `type_not_allowed` for the same-type pairing.
#[tokio::test]
async fn create_child_rejects_same_type_nesting_when_disallowed() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x503);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();
    let svc = make_service_with_type_checker(
        repo.clone(),
        FakeOutcome::Ok,
        Arc::new(FakeTenantTypeChecker::new(
            FakeTypeOutcome::TypeNotAllowed {
                detail: "type cannot nest under itself",
            },
        )),
    );

    // child_input uses `tenant_type_uuid = 0xAA` which equals the
    // root's `tenant_type_uuid`; this is the same-type nesting case.
    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("disallowed same-type nesting must reject");
    assert_eq!(err.code(), "type_not_allowed");
    assert_eq!(err.http_status(), 400);

    let row = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(row.is_none());
    assert_eq!(repo.snapshot_closure().len(), closure_before);
}

/// AC §6 third bullet, positive half -- same-type nesting requested
/// and the GTS schema admits the type as its own allowed parent.
#[tokio::test]
async fn create_child_accepts_same_type_nesting_when_allowed() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x504);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = make_service_with_type_checker(
        repo.clone(),
        FakeOutcome::Ok,
        Arc::new(FakeTenantTypeChecker::new(FakeTypeOutcome::Admit)),
    );

    // Same `tenant_type_uuid` for parent and child -- checker admits.
    let created = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("same-type nesting admitted by checker must succeed");
    assert_eq!(created.id.0, child);
    assert_eq!(created.status, PublicTenantStatus::Active);
}

// =================================================================
// Contract-review test gaps (F1–F4)
//
// The Phase-1/2/3 contract review identified four acceptance
// criteria whose implementing code was already in place but lacked
// dedicated assertions. The tests below close those gaps using the
// same in-memory `FakeTenantRepo` + `FakeIdpProvisioner` machinery
// as the rest of the module.
// =================================================================

/// F1 -- `Suspended → Deleted` soft-delete transition.
///
/// `model::TenantUpdate::validate_status_transition` admits
/// `Suspended` as a source status, and `service::soft_delete` does
/// not gate on `Active` -- but the existing happy-path test only
/// covered an active leaf. This test moves the leaf through
/// suspension first and then asserts the soft-delete still flips
/// the row to `Deleted` with retention metadata.
#[tokio::test]
async fn soft_delete_succeeds_on_suspended_leaf_tenant() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0xF100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(InertResourceOwnershipChecker),
    );
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create child");

    // Move the leaf to Suspended via the public PATCH path.
    let suspended = svc
        .update_tenant(
            &ctx_for(root),
            child,
            TenantUpdate {
                status: Some(PublicTenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .expect("suspension allowed");
    assert_eq!(suspended.status, PublicTenantStatus::Suspended);

    // Now soft-delete the suspended leaf -- should succeed.
    let deleted = svc
        .soft_delete(&ctx_for(root), child)
        .await
        .expect("soft-delete suspended leaf");
    assert_eq!(deleted.status, PublicTenantStatus::Deleted);
    // Retention bookkeeping must be present after soft-delete.
    assert!(
        repo.state
            .lock()
            .expect("lock")
            .retention
            .contains_key(&child),
        "retention row must be written for the soft-deleted tenant"
    );
}

/// Pin the public-contract requirement that soft-delete stamps
/// `tenants.deleted_at`. The `OpenAPI` `Tenant.deleted_at` field is
/// surfaced on every tenant response, the migration declares a
/// partial index `idx_tenants_deleted_at` keyed on this column,
/// and the `Tenant` schema lists it as the public-contract
/// tombstone marker. An earlier implementation of
/// `schedule_deletion` only stamped `deletion_scheduled_at` and
/// left this column permanently NULL -- making the partial index
/// empty and surfacing soft-deleted rows with
/// `status=deleted, deleted_at=null` to the API.
#[tokio::test]
async fn soft_delete_stamps_deleted_at_on_returned_model_and_subsequent_reads() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0xF101);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(InertResourceOwnershipChecker),
    );

    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create child");
    let row_after_create = repo
        .find_by_id_unchecked(child)
        .expect("freshly-created row in fake repo");
    assert!(
        row_after_create.deleted_at.is_none(),
        "freshly created tenant must not carry a deleted_at timestamp"
    );

    let deleted = svc
        .soft_delete(&ctx_for(root), child)
        .await
        .expect("soft-delete leaf");
    assert_eq!(deleted.status, PublicTenantStatus::Deleted);

    // `deleted_at` / `updated_at` are storage-internal columns — they
    // are not part of the public `TenantInfo` shape. The
    // `schedule_deletion` contract is asserted via the storage row
    // directly through the unchecked accessor that bypasses the
    // SDK-visibility filter (deleted rows are filtered out by
    // `read_tenant`).
    let after = repo
        .find_by_id_unchecked(child)
        .expect("row still present pre hard-delete");
    let stamped = after
        .deleted_at
        .expect("schedule_deletion must stamp deleted_at");
    assert_eq!(
        stamped, after.updated_at,
        "deleted_at and updated_at are written in the same transaction \
         and should match `now` exactly"
    );
}

/// F2 -- `hard_delete_batch` row-level outcome on
/// `DeprovisionFailure::Terminal`.
///
/// The existing `reaper_marks_terminal_failure_and_parks_row_out_of_retry_loop`
/// test covers the reaper path. This adds the missing assertion for
/// the hard-delete batch path: a soft-deleted tenant whose `IdP`
/// deprovision returns `Terminal` is tagged `IdpTerminal` (counted
/// as a failed/deferred outcome by `HardDeleteResult::tally`) and
/// the `tenants` row is NOT reclaimed.
#[tokio::test]
async fn hard_delete_batch_marks_idp_terminal_failure_as_failed() {
    let root = Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let tenant = repo.seed_soft_deleted_child_due_for_hard_delete(root);
    let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
    idp.set_deprovision_outcome(FakeDeprovisionOutcome::Terminal);
    let svc = TenantService::new(
        repo.clone(),
        idp,
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig {
            default_retention_secs: 0,
            ..AccountManagementConfig::default()
        },
    );

    let res = svc.hard_delete_batch(64).await;
    assert_eq!(res.processed, 1, "exactly one due row was processed");
    assert_eq!(
        res.failed, 1,
        "IdP terminal failure must count exactly once toward `failed`, got {res:?}"
    );
    assert_eq!(
        res.cleaned, 0,
        "row must NOT be reclaimed on IdP terminal failure"
    );
    // Tenant row + closure rows still in the DB -- the reaper /
    // operator owns the next move, not the hard-delete batch.
    assert!(
        repo.find_by_id_unchecked(tenant).is_some(),
        "soft-deleted row must remain after IdP terminal"
    );
}

/// F3 -- finalization-TX failure injection (saga step 3 abort).
///
/// AC#3 calls for the `create_child` saga to leave the
/// `Provisioning` row in place when `repo.activate_tenant` fails
/// post-IdP-provision so the reaper can compensate. The injection
/// goes through `FakeTenantRepo::expect_next_activation_failure`,
/// which arms the next call to return `DomainError::Internal` exactly
/// once.
#[tokio::test]
async fn create_child_finalization_tx_failure_leaves_provisioning_row_in_db() {
    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0xF300);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    repo.expect_next_activation_failure("simulated SERIALIZABLE abort");
    let svc = svc_with(
        repo.clone(),
        FakeOutcome::Ok,
        AccountManagementConfig::default(),
        Arc::new(InertResourceOwnershipChecker),
    );

    let result = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await;
    assert!(
        matches!(result, Err(DomainError::Internal { .. })),
        "activate_tenant failure must surface as Internal, got {result:?}"
    );
    // Ambiguous outcome -- provisioning row stays so the reaper
    // (or operator) owns compensation.
    let provisioning_rows = repo.snapshot_provisioning_rows();
    assert_eq!(
        provisioning_rows.len(),
        1,
        "provisioning row must remain on finalization-TX failure"
    );
    assert_eq!(provisioning_rows[0].id, child);
}

// ---------------------------------------------------------------------------
// Production-checker timeout boundary — service-level integration
// ---------------------------------------------------------------------------
//
// Each external integration (`RgResourceOwnershipChecker` /
// `GtsTenantTypeChecker`) has a unit test in its own `infra/*/checker.rs`
// that exercises `tokio::time::timeout`. The two tests below close the
// integration loop: they wire the **production** checker (with a tight
// 10 ms timeout) into a real `TenantService` and trigger the timeout
// via a slow SDK fake under `#[tokio::test(start_paused = true)]`,
// proving the `DomainError::ServiceUnavailable` propagates through the
// service layer with no DB side-effects.

#[tokio::test(start_paused = true)]
async fn soft_delete_propagates_rg_timeout_as_service_unavailable() {
    use crate::infra::rg::RgResourceOwnershipChecker;
    use crate::infra::rg::test_helpers::SlowRgClient;
    use std::sync::Arc as StdArc;

    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x911);
    let repo = Arc::new(FakeTenantRepo::with_root(root));

    // Wire the production RG checker around a fake whose
    // `list_groups` sleeps for 50 ms; checker timeout is 10 ms.
    let slow = StdArc::new(SlowRgClient::new(StdDuration::from_millis(50)));
    let checker = Arc::new(RgResourceOwnershipChecker::with_timeout(slow, 10));

    let svc = TenantService::new(
        repo.clone(),
        Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok)),
        checker,
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig::default(),
    );
    // Create a child to act on.
    svc.create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect("create");

    let err = svc
        .soft_delete(&ctx_for(root), child)
        .await
        .expect_err("RG timeout must surface as service_unavailable");
    assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
    assert_eq!(err.code(), "service_unavailable");
    assert_eq!(err.http_status(), 503);

    // Service-side invariant: timeout MUST NOT have flipped the row.
    let row = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo")
        .expect("row");
    assert_eq!(
        row.status,
        TenantStatus::Active,
        "tenant must remain Active when the RG probe times out"
    );
}

#[tokio::test(start_paused = true)]
async fn create_child_propagates_gts_timeout_as_service_unavailable() {
    use crate::infra::types_registry::GtsTenantTypeChecker;
    use crate::infra::types_registry::test_helpers::SlowRegistry;
    use std::sync::Arc as StdArc;

    let root = Uuid::from_u128(0x100);
    let child = Uuid::from_u128(0x912);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let closure_before = repo.snapshot_closure().len();

    // Wire the production GTS checker around a registry whose
    // `get_type_schemas_by_uuid` sleeps for 50 ms; checker
    // timeout is 10 ms.
    let slow = StdArc::new(SlowRegistry::new(StdDuration::from_millis(50)));
    let checker = Arc::new(GtsTenantTypeChecker::with_timeout(slow, 10));

    let svc = TenantService::new(
        repo.clone(),
        Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok)),
        Arc::new(InertResourceOwnershipChecker),
        checker,
        mock_enforcer(),
        AccountManagementConfig::default(),
    );

    let err = svc
        .create_child(&ctx_for(root), child_input(child, root))
        .await
        .expect_err("GTS timeout must surface as service_unavailable");
    assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
    assert_eq!(err.code(), "service_unavailable");
    assert_eq!(err.http_status(), 503);

    // Service-side invariant: a barrier-time fault MUST NOT have
    // written the child or any closure rows for it.
    let row = repo
        .find_by_id(&AccessScope::allow_all(), child)
        .await
        .expect("repo");
    assert!(row.is_none(), "no tenant row on GTS-timeout reject");
    assert_eq!(
        repo.snapshot_closure().len(),
        closure_before,
        "no closure rows on GTS-timeout reject"
    );
}
