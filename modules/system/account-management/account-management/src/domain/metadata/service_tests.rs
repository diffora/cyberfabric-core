//! Unit tests for [`MetadataService`].
//!
//! Every test wires the service against the in-crate fakes
//! ([`FakeMetadataRepo`], [`FakeTenantRepo`]) plus a
//! [`StubMetadataSchemaRegistry`] and a deterministic `now_fn`. This
//! pins:
//!
//! * Guard ordering: tenant existence + status guard runs BEFORE any
//!   registry / metadata-repo call on every flow.
//! * Distinct-404 disambiguation: `MetadataSchemaNotRegistered` for
//!   unknown schemas, `MetadataEntryNotFound` for unset rows under a
//!   known schema (per FEATURE §6 AC line 392 / `dod-tenant-metadata-distinct-404-codes`).
//! * Walk-up algorithm: own-first short-circuit, `override_only`
//!   short-circuit, start-tenant barrier, mid-walk barrier-stop,
//!   suspended-skip, root-empty terminal.
//! * PUT idempotency: same `(tenant, schema)` written twice returns
//!   `was_inserted = false` on the second call, preserves
//!   `created_at`, advances `updated_at` per FEATURE-doc semantics
//!   surfaced by the Phase 1 fake.
//! * LIST ordering + pagination: stable on `schema_uuid`, in-service
//!   `top` / `skip` slicing per the FEATURE-doc list flow (no
//!   ancestor walk).

#![allow(
    clippy::too_many_lines,
    reason = "service-test fixtures intentionally seed multi-row hierarchies inline so each test reads as a self-contained scenario; splitting them would scatter the seeded shape across helpers and obscure walk-up branch coverage"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-support fakes panic on poisoned mutex; the canonical `expect(\"…\")` form is shared with FakeConversionRepo's tests"
)]

use std::sync::Arc;

use account_management_sdk::{MetadataEntry, MetadataSchemaId};
use modkit_security::AccessScope;
use serde_json::{Value, json};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::metadata::registry::{InheritancePolicy, StubMetadataSchemaRegistry};
use crate::domain::metadata::repo::MetadataRepo;
use crate::domain::metadata::service::{MetadataPagination, MetadataService, PutMetadataOutcome};
use crate::domain::metadata::test_support::FakeMetadataRepo;
use crate::domain::tenant::model::{TenantModel, TenantStatus};
use crate::domain::tenant::test_support::FakeTenantRepo;

const REQUESTER_MARKER: u128 = 0xF1;

// ---- helpers -------------------------------------------------------

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch")
}

fn scope() -> AccessScope {
    AccessScope::allow_all()
}

fn schema_a() -> MetadataSchemaId {
    MetadataSchemaId::try_from("gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1~")
        .expect("valid schema_a chained id")
}

fn schema_b() -> MetadataSchemaId {
    MetadataSchemaId::try_from("gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.billing.v1~")
        .expect("valid schema_b chained id")
}

fn schema_unknown() -> MetadataSchemaId {
    MetadataSchemaId::try_from("gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.absent.v1~")
        .expect("valid schema_unknown chained id")
}

fn requester() -> Uuid {
    Uuid::from_u128(REQUESTER_MARKER)
}

fn make_service(
    md_repo: Arc<FakeMetadataRepo>,
    tenant_repo: Arc<FakeTenantRepo>,
    registry: Arc<StubMetadataSchemaRegistry>,
    now: OffsetDateTime,
) -> MetadataService {
    let now_fn = Arc::new(move || now);
    MetadataService::new(md_repo, tenant_repo, registry).with_now_fn(now_fn)
}

fn seed_tenant(
    fake: &FakeTenantRepo,
    id: Uuid,
    parent_id: Option<Uuid>,
    status: TenantStatus,
    self_managed: bool,
    name: &str,
) {
    let now = fixed_now();
    let depth = u32::from(parent_id.is_some());
    fake.insert_tenant_raw(TenantModel {
        id,
        parent_id,
        name: name.to_owned(),
        status,
        self_managed,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    });
}

async fn seed_metadata_row(
    fake: &FakeMetadataRepo,
    tenant_id: Uuid,
    schema_id: &MetadataSchemaId,
    value: Value,
    when: OffsetDateTime,
) {
    let schema_uuid = account_management_sdk::derive_schema_uuid(schema_id);
    // Drive the seed through the trait's upsert path so the
    // created_at / updated_at semantics match production exactly. We
    // feed `when` as the upsert timestamp; subsequent rewrites stamp
    // a different `now`. Awaiting `upsert_for_tenant` directly (rather
    // than `futures::executor::block_on`) keeps the seed runtime-safe:
    // a future FakeRepo that does real async work won't deadlock the
    // tokio worker.
    let scope = scope();
    fake.upsert_for_tenant(&scope, tenant_id, schema_uuid, value, when)
        .await
        .expect("seed upsert");
}

// ---- list_for_tenant ----------------------------------------------

#[tokio::test]
async fn list_happy_path_returns_only_direct_rows_in_uuid_order() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![
        (schema_a(), InheritancePolicy::OverrideOnly),
        (schema_b(), InheritancePolicy::OverrideOnly),
    ]));
    let parent = Uuid::from_u128(0x1);
    let child = Uuid::from_u128(0x2);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child-1",
    );
    // Seed direct rows on `child` for both schemas, plus a row on
    // the parent that MUST NOT surface (list flow does NOT walk).
    seed_metadata_row(
        &md_repo,
        child,
        &schema_a(),
        json!({"theme": "dark"}),
        fixed_now(),
    )
    .await;
    seed_metadata_row(
        &md_repo,
        child,
        &schema_b(),
        json!({"plan": "pro"}),
        fixed_now(),
    )
    .await;
    seed_metadata_row(
        &md_repo,
        parent,
        &schema_a(),
        json!({"theme": "ancestor"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let page = svc
        .list_for_tenant(&scope(), child, MetadataPagination::first_page())
        .await
        .expect("list happy path");

    assert_eq!(page.items.len(), 2, "two direct rows on child only");
    assert_eq!(page.total, 2, "total reflects rows BEFORE pagination slice");
    // Stable order on schema_uuid mirrors the repo contract; we just
    // assert both schemas are surfaced and each entry carries the
    // re-hydrated chained id.
    let hydrated: Vec<&MetadataSchemaId> = page.items.iter().map(|e| &e.schema_id).collect();
    assert!(hydrated.contains(&&schema_a()), "schema_a hydrated");
    assert!(hydrated.contains(&&schema_b()), "schema_b hydrated");
}

#[tokio::test]
async fn list_pagination_top_skip_slices_rows() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![
        (schema_a(), InheritancePolicy::OverrideOnly),
        (schema_b(), InheritancePolicy::OverrideOnly),
    ]));
    let tid = Uuid::from_u128(0x10);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");
    seed_metadata_row(&md_repo, tid, &schema_a(), json!({}), fixed_now()).await;
    seed_metadata_row(&md_repo, tid, &schema_b(), json!({}), fixed_now()).await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let page = svc
        .list_for_tenant(&scope(), tid, MetadataPagination { top: 1, skip: 1 })
        .await
        .expect("list page");

    assert_eq!(page.items.len(), 1, "top=1 caps the slice");
    assert_eq!(page.total, 2, "total reflects unsliced row count");
    assert_eq!(page.top, 1);
    assert_eq!(page.skip, 1);
}

#[tokio::test]
async fn list_rejects_unknown_tenant_with_not_found() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new());
    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .list_for_tenant(
            &scope(),
            Uuid::from_u128(0xDEAD),
            MetadataPagination::first_page(),
        )
        .await
        .expect_err("unknown tenant must reject");

    assert!(matches!(err, DomainError::NotFound { .. }), "got {err:?}");
}

#[tokio::test]
async fn list_rejects_non_active_tenant_with_validation() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new());
    let tid = Uuid::from_u128(0x100);
    seed_tenant(&tenants, tid, None, TenantStatus::Suspended, false, "susp");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .list_for_tenant(&scope(), tid, MetadataPagination::first_page())
        .await
        .expect_err("suspended tenant must reject list");

    assert!(matches!(err, DomainError::Validation { .. }), "got {err:?}");
}

// ---- get_for_tenant -----------------------------------------------

#[tokio::test]
async fn get_happy_path_returns_entry() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");
    seed_metadata_row(
        &md_repo,
        tid,
        &schema_a(),
        json!({"theme": "dark"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .get_for_tenant(&scope(), tid, schema_a())
        .await
        .expect("get happy path");

    assert_eq!(entry.schema_id, schema_a());
    assert_eq!(entry.value, json!({"theme": "dark"}));
}

#[tokio::test]
async fn get_unregistered_schema_returns_distinct_schema_404() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new()); // empty
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .get_for_tenant(&scope(), tid, schema_unknown())
        .await
        .expect_err("unregistered schema must reject");

    assert!(
        matches!(err, DomainError::MetadataSchemaNotRegistered { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn get_registered_schema_no_row_returns_distinct_entry_404() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .get_for_tenant(&scope(), tid, schema_a())
        .await
        .expect_err("missing entry must reject");

    assert!(
        matches!(err, DomainError::MetadataEntryNotFound { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn get_rejects_unknown_tenant_before_registry_call() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    // Registry is empty: if guard order ever flips, the test would
    // surface MetadataSchemaNotRegistered instead of NotFound.
    let registry = Arc::new(StubMetadataSchemaRegistry::new());
    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .get_for_tenant(&scope(), Uuid::from_u128(0xDEAD), schema_a())
        .await
        .expect_err("unknown tenant must reject");

    assert!(
        matches!(err, DomainError::NotFound { .. }),
        "guard ordering: tenant before registry; got {err:?}"
    );
}

// ---- put_for_tenant -----------------------------------------------

#[tokio::test]
async fn put_happy_path_inserts_then_updates() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo.clone(), tenants, registry, fixed_now());

    let first: PutMetadataOutcome = svc
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect("put insert");
    assert!(first.was_inserted, "first put inserts");
    assert_eq!(first.entry.value, json!({"theme": "dark"}));

    let second = svc
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "light"}),
            requester(),
        )
        .await
        .expect("put update");
    assert!(!second.was_inserted, "second put updates");
    assert_eq!(second.entry.value, json!({"theme": "light"}));
}

#[tokio::test]
async fn put_idempotent_same_value_preserves_created_at_advances_updated_at() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let t0 = fixed_now();
    let svc_t0 = make_service(md_repo.clone(), tenants.clone(), registry.clone(), t0);
    let first = svc_t0
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect("put 1");
    assert!(first.was_inserted);
    assert_eq!(first.entry.updated_at, t0);

    // Re-build the service with a later clock and PUT the SAME value
    // again. Insert path won't fire because the row exists; the
    // update path stamps `updated_at = t1` and preserves
    // `created_at = t0` (verified through the repo snapshot below).
    let t1 = t0 + TimeDuration::seconds(10);
    let svc_t1 = make_service(md_repo.clone(), tenants, registry, t1);
    let second = svc_t1
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect("put 2");
    assert!(
        !second.was_inserted,
        "same key + same value still hits the update path (semantic update)"
    );
    assert_eq!(second.entry.updated_at, t1, "updated_at advanced");

    // Inspect the underlying row through the snapshot helper to
    // verify created_at preservation (the public MetadataEntry only
    // surfaces updated_at).
    let snap = md_repo.snapshot_all();
    let row = snap.into_iter().next().expect("row exists");
    assert_eq!(row.created_at, t0, "created_at preserved");
    assert_eq!(row.updated_at, t1, "updated_at advanced to t1");
}

#[tokio::test]
async fn put_rejects_unknown_tenant_with_not_found() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .put_for_tenant(
            &scope(),
            Uuid::from_u128(0xDEAD),
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect_err("unknown tenant must reject");

    assert!(matches!(err, DomainError::NotFound { .. }), "got {err:?}");
}

#[tokio::test]
async fn put_rejects_unregistered_schema_with_distinct_404() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new()); // empty
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo.clone(), tenants, registry, fixed_now());

    let err = svc
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect_err("unregistered schema must reject");

    assert!(
        matches!(err, DomainError::MetadataSchemaNotRegistered { .. }),
        "got {err:?}"
    );
    // Ensure no row was written.
    assert!(
        md_repo.snapshot_all().is_empty(),
        "no row written when schema unregistered"
    );
}

#[tokio::test]
async fn put_payload_failing_schema_validation_returns_validation_and_writes_nothing() {
    // FEATURE §6 AC line 393: a PUT whose payload fails the registered
    // GTS schema body validation MUST return `code=validation` WITHOUT
    // writing any row. Pin both halves: the error variant AND the
    // empty repo snapshot.
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    // Toggle the stub to reject every payload for `schema_a` — exercises
    // the validate_value branch independently of the JSON Schema body.
    registry.fail_validation_for(schema_a());
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo.clone(), tenants, registry, fixed_now());

    let err = svc
        .put_for_tenant(
            &scope(),
            tid,
            schema_a(),
            json!({"theme": "dark"}),
            requester(),
        )
        .await
        .expect_err("body failing schema validation must reject");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "got {err:?} (expected DomainError::Validation per FEATURE §6 AC line 393)"
    );
    assert!(
        md_repo.snapshot_all().is_empty(),
        "no row written when payload fails schema validation"
    );
}

// ---- delete_for_tenant --------------------------------------------

#[tokio::test]
async fn delete_happy_path_removes_only_target_row() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![
        (schema_a(), InheritancePolicy::OverrideOnly),
        (schema_b(), InheritancePolicy::OverrideOnly),
    ]));
    let parent = Uuid::from_u128(0x1);
    let child = Uuid::from_u128(0x2);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child",
    );
    // Direct row on child + ancestor row on parent. Delete on child
    // MUST leave the parent row intact (FEATURE §2 delete success
    // scenario: ancestor entries are NOT affected).
    seed_metadata_row(&md_repo, child, &schema_a(), json!({"v": 1}), fixed_now()).await;
    seed_metadata_row(&md_repo, child, &schema_b(), json!({"v": 2}), fixed_now()).await;
    seed_metadata_row(&md_repo, parent, &schema_a(), json!({"v": 0}), fixed_now()).await;

    let svc = make_service(md_repo.clone(), tenants, registry, fixed_now());

    svc.delete_for_tenant(&scope(), child, schema_a(), requester())
        .await
        .expect("delete happy path");

    // Snapshot state assertions.
    let rows = md_repo.snapshot_all();
    assert_eq!(
        rows.len(),
        2,
        "child[a] removed; child[b] + parent[a] intact"
    );
    let parent_uuid = account_management_sdk::derive_schema_uuid(&schema_a());
    assert!(
        rows.iter()
            .any(|r| r.tenant_id == parent && r.schema_uuid == parent_uuid),
        "parent ancestor row preserved on child delete"
    );
}

#[tokio::test]
async fn delete_returns_distinct_entry_404_on_missing_row() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .delete_for_tenant(&scope(), tid, schema_a(), requester())
        .await
        .expect_err("missing row must reject");

    assert!(
        matches!(err, DomainError::MetadataEntryNotFound { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn delete_unregistered_schema_returns_distinct_schema_404() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new()); // empty
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .delete_for_tenant(&scope(), tid, schema_unknown(), requester())
        .await
        .expect_err("unregistered schema must reject");

    assert!(
        matches!(err, DomainError::MetadataSchemaNotRegistered { .. }),
        "got {err:?}"
    );
}

// ---- resolve_for_tenant: override_only ----------------------------

#[tokio::test]
async fn resolve_override_only_returns_own_value() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let parent = Uuid::from_u128(0x1);
    let child = Uuid::from_u128(0x2);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child",
    );
    seed_metadata_row(
        &md_repo,
        child,
        &schema_a(),
        json!({"v": "child"}),
        fixed_now(),
    )
    .await;
    seed_metadata_row(
        &md_repo,
        parent,
        &schema_a(),
        json!({"v": "parent"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), child, schema_a())
        .await
        .expect("resolve own");

    let entry: MetadataEntry = entry.expect("own row present");
    assert_eq!(entry.value, json!({"v": "child"}), "own row wins");
}

#[tokio::test]
async fn resolve_override_only_returns_none_when_own_absent_even_if_ancestor_has_value() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::OverrideOnly,
    )]));
    let parent = Uuid::from_u128(0x1);
    let child = Uuid::from_u128(0x2);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child",
    );
    // Only the parent has a row; child has none. override_only must
    // NOT walk up.
    seed_metadata_row(
        &md_repo,
        parent,
        &schema_a(),
        json!({"v": "parent"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let result = svc
        .resolve_for_tenant(&scope(), child, schema_a())
        .await
        .expect("resolve override_only");

    assert!(
        result.is_none(),
        "override_only never inherits: got {result:?}"
    );
}

// ---- resolve_for_tenant: inherit walk-up ---------------------------

#[tokio::test]
async fn resolve_inherit_returns_own_when_present() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let parent = Uuid::from_u128(0x1);
    let child = Uuid::from_u128(0x2);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child",
    );
    seed_metadata_row(
        &md_repo,
        child,
        &schema_a(),
        json!({"v": "child"}),
        fixed_now(),
    )
    .await;
    seed_metadata_row(
        &md_repo,
        parent,
        &schema_a(),
        json!({"v": "parent"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), child, schema_a())
        .await
        .expect("resolve own (inherit)")
        .expect("own row present");

    assert_eq!(
        entry.value,
        json!({"v": "child"}),
        "own row wins under inherit too"
    );
}

#[tokio::test]
async fn resolve_inherit_walks_to_first_ancestor_value() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    // root → mid → leaf; only root has the value.
    let root = Uuid::from_u128(0x1);
    let mid = Uuid::from_u128(0x2);
    let leaf = Uuid::from_u128(0x3);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        mid,
        Some(root),
        TenantStatus::Active,
        false,
        "mid",
    );
    seed_tenant(
        &tenants,
        leaf,
        Some(mid),
        TenantStatus::Active,
        false,
        "leaf",
    );
    seed_metadata_row(
        &md_repo,
        root,
        &schema_a(),
        json!({"v": "root"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("resolve walk-up")
        .expect("root value reached");

    assert_eq!(entry.value, json!({"v": "root"}));
}

#[tokio::test]
async fn resolve_inherit_stops_at_self_managed_start_tenant_barrier() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let root = Uuid::from_u128(0x1);
    let leaf = Uuid::from_u128(0x2);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    // leaf is self-managed -> start-tenant barrier.
    seed_tenant(
        &tenants,
        leaf,
        Some(root),
        TenantStatus::Active,
        true,
        "leaf-sm",
    );
    seed_metadata_row(
        &md_repo,
        root,
        &schema_a(),
        json!({"v": "root"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let result = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("resolve start-barrier");

    assert!(
        result.is_none(),
        "self-managed start tenant never inherits: got {result:?}"
    );
}

#[tokio::test]
async fn resolve_inherit_stops_at_mid_walk_self_managed_ancestor_barrier() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let root = Uuid::from_u128(0x1);
    let mid_sm = Uuid::from_u128(0x2);
    let leaf = Uuid::from_u128(0x3);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    // mid is self-managed -> ancestor barrier-stop BEFORE reading its
    // value (even if mid had a row, the spec says barrier stops the
    // walk before reading the ancestor).
    seed_tenant(
        &tenants,
        mid_sm,
        Some(root),
        TenantStatus::Active,
        true,
        "mid-sm",
    );
    seed_tenant(
        &tenants,
        leaf,
        Some(mid_sm),
        TenantStatus::Active,
        false,
        "leaf",
    );
    seed_metadata_row(
        &md_repo,
        root,
        &schema_a(),
        json!({"v": "root"}),
        fixed_now(),
    )
    .await;
    // Even seed a row on mid_sm to verify the barrier stop fires
    // BEFORE the read.
    seed_metadata_row(
        &md_repo,
        mid_sm,
        &schema_a(),
        json!({"v": "mid"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let result = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("resolve mid-barrier");

    assert!(
        result.is_none(),
        "barrier-stop fires BEFORE reading the self-managed ancestor's value: got {result:?}"
    );
}

#[tokio::test]
async fn resolve_inherit_skips_suspended_ancestor_and_continues_to_grandparent() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let root = Uuid::from_u128(0x1);
    let mid_susp = Uuid::from_u128(0x2);
    let leaf = Uuid::from_u128(0x3);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    // mid is Suspended (not self-managed) -> walk SKIPS mid's read
    // and continues to root per the FEATURE-doc step 10 contract.
    seed_tenant(
        &tenants,
        mid_susp,
        Some(root),
        TenantStatus::Suspended,
        false,
        "mid-susp",
    );
    seed_tenant(
        &tenants,
        leaf,
        Some(mid_susp),
        TenantStatus::Active,
        false,
        "leaf",
    );
    // Even if mid had a value, the walk skips it (suspension is not a
    // barrier; the value is just not consulted on that hop). Verify
    // by seeding both rows and asserting the ROOT value wins.
    seed_metadata_row(
        &md_repo,
        mid_susp,
        &schema_a(),
        json!({"v": "mid"}),
        fixed_now(),
    )
    .await;
    seed_metadata_row(
        &md_repo,
        root,
        &schema_a(),
        json!({"v": "root"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("resolve through suspended ancestor")
        .expect("root value reached");

    assert_eq!(
        entry.value,
        json!({"v": "root"}),
        "suspension is not a barrier: walk skips mid's read and reaches root"
    );
}

#[tokio::test]
async fn resolve_inherit_propagates_through_suspended_ancestor_when_value_lives_above() {
    // Slight variant of the prior test that pins the explicit
    // suspension-skip / continuation path: there is NO row on the
    // suspended ancestor, yet the walk MUST proceed past it (rather
    // than returning empty as a barrier-stop would).
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let grand = Uuid::from_u128(0x10);
    let mid_susp = Uuid::from_u128(0x20);
    let leaf = Uuid::from_u128(0x30);
    seed_tenant(&tenants, grand, None, TenantStatus::Active, false, "grand");
    seed_tenant(
        &tenants,
        mid_susp,
        Some(grand),
        TenantStatus::Suspended,
        false,
        "mid-susp",
    );
    seed_tenant(
        &tenants,
        leaf,
        Some(mid_susp),
        TenantStatus::Active,
        false,
        "leaf",
    );
    seed_metadata_row(
        &md_repo,
        grand,
        &schema_a(),
        json!({"v": "grand"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("walk through suspended -> grand")
        .expect("grand value reached");

    assert_eq!(entry.value, json!({"v": "grand"}));
}

#[tokio::test]
async fn resolve_inherit_returns_empty_when_root_reached_with_no_value() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let root = Uuid::from_u128(0x1);
    let leaf = Uuid::from_u128(0x2);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        leaf,
        Some(root),
        TenantStatus::Active,
        false,
        "leaf",
    );
    // No rows seeded — walk reaches root and returns empty.

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let result = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("resolve root-empty");

    assert!(
        result.is_none(),
        "root reached without value -> empty terminal (NOT 404): got {result:?}"
    );
}

#[tokio::test]
async fn resolve_unregistered_schema_returns_distinct_404() {
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new()); // empty
    let tid = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tid, None, TenantStatus::Active, false, "root");

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .resolve_for_tenant(&scope(), tid, schema_unknown())
        .await
        .expect_err("unregistered schema must reject");

    assert!(
        matches!(err, DomainError::MetadataSchemaNotRegistered { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn resolve_rejects_provisioning_start_tenant_at_guard() {
    // Provisioning is not Active, so the existence guard rejects
    // before any registry / metadata-repo call.
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::new());
    let tid = Uuid::from_u128(0x1);
    seed_tenant(
        &tenants,
        tid,
        None,
        TenantStatus::Provisioning,
        false,
        "prov",
    );

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let err = svc
        .resolve_for_tenant(&scope(), tid, schema_a())
        .await
        .expect_err("provisioning tenant must reject");

    assert!(matches!(err, DomainError::Validation { .. }), "got {err:?}");
}

// ---- defence-in-depth check: own row returned even on self-managed start

#[tokio::test]
async fn resolve_inherit_returns_own_value_even_on_self_managed_start() {
    // FEATURE §3 step 2 says own values are ALWAYS returned
    // regardless of self_managed status — the barrier only blocks
    // INHERITANCE from ancestors.
    let md_repo = Arc::new(FakeMetadataRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let registry = Arc::new(StubMetadataSchemaRegistry::with_seed(vec![(
        schema_a(),
        InheritancePolicy::Inherit,
    )]));
    let root = Uuid::from_u128(0x1);
    let leaf = Uuid::from_u128(0x2);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        leaf,
        Some(root),
        TenantStatus::Active,
        true,
        "leaf-sm",
    );
    seed_metadata_row(
        &md_repo,
        leaf,
        &schema_a(),
        json!({"v": "own"}),
        fixed_now(),
    )
    .await;

    let svc = make_service(md_repo, tenants, registry, fixed_now());

    let entry = svc
        .resolve_for_tenant(&scope(), leaf, schema_a())
        .await
        .expect("own row resolves even when leaf is self-managed")
        .expect("own row present");

    assert_eq!(entry.value, json!({"v": "own"}));
}
