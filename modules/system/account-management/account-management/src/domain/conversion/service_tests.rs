//! Unit tests for [`ConversionService`].
//!
//! Every test wires the service against the in-crate fakes
//! ([`FakeConversionRepo`], [`FakeTenantRepo`]) plus a deterministic
//! `now_fn`. This pins:
//!
//! * Guard ordering: root-tenant refusal before status precondition,
//!   status precondition before single-pending insert
//!   (`request_conversion`); status check before actor-side check
//!   (`cancel` / `reject`).
//! * Error mapping: `RootTenantCannotConvert`, `Validation`,
//!   `NotFound`, `PendingExists`, `AlreadyResolved`, and
//!   `InvalidActorForTransition` all surface with the canonical
//!   shape and lowercase tokens documented on the variants.
//! * Parent-side projection: only direct children appear in
//!   `list_inbound_for_parent`, every projected row carries the
//!   minimal cross-barrier field set, no descendant data leaks.
//! * Retention: `soft_delete_resolved` only touches resolved rows
//!   strictly older than `now - retention_window` whose
//!   `deleted_at` is still `NULL`.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use modkit_security::AccessScope;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use async_trait::async_trait;

use crate::domain::conversion::model::{
    ConversionRequest, ConversionSide, ConversionStatus, TargetMode,
};
use crate::domain::conversion::service::{
    ConversionCaller, ConversionService, ListConversionsQuery, RequestConversionInput,
};
use crate::domain::conversion::test_support::FakeConversionRepo;
use crate::domain::error::DomainError;
use crate::domain::tenant::model::{TenantModel, TenantStatus};
use crate::domain::tenant::test_support::FakeTenantRepo;
use crate::domain::tenant_type::TenantTypeChecker;

const APPROVAL_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
const REQUESTER_MARKER: u128 = 0xF1;
const COUNTERPARTY_MARKER: u128 = 0xC2;

// ---- helpers -------------------------------------------------------

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch")
}

fn scope() -> AccessScope {
    AccessScope::allow_all()
}

fn approval_ttl() -> StdDuration {
    StdDuration::from_secs(APPROVAL_TTL_SECS)
}

fn retention_window() -> StdDuration {
    StdDuration::from_secs(RETENTION_SECS)
}

fn make_service(
    conv_repo: Arc<FakeConversionRepo>,
    tenant_repo: Arc<FakeTenantRepo>,
    now: OffsetDateTime,
) -> ConversionService {
    let now_fn = Arc::new(move || now);
    ConversionService::new(conv_repo, tenant_repo, approval_ttl(), retention_window())
        .with_now_fn(now_fn)
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

fn seeded_request(
    request_id: Uuid,
    tenant_id: Uuid,
    parent_id: Option<Uuid>,
    initiator_side: ConversionSide,
    status: ConversionStatus,
    requested_at: OffsetDateTime,
    resolved_at: Option<OffsetDateTime>,
) -> ConversionRequest {
    ConversionRequest {
        id: request_id,
        tenant_id,
        parent_id,
        child_tenant_name: format!("child-{tenant_id}"),
        initiator_side,
        target_mode: TargetMode::SelfManaged,
        status,
        requested_by: Uuid::from_u128(REQUESTER_MARKER),
        approved_by: matches!(status, ConversionStatus::Approved).then_some(Uuid::from_u128(0xA1)),
        cancelled_by: matches!(status, ConversionStatus::Cancelled)
            .then_some(Uuid::from_u128(0xC1)),
        rejected_by: matches!(status, ConversionStatus::Rejected).then_some(Uuid::from_u128(0xE1)),
        requested_at,
        resolved_at,
        expires_at: requested_at + TimeDuration::days(7),
        deleted_at: None,
    }
}

fn requester() -> Uuid {
    Uuid::from_u128(REQUESTER_MARKER)
}

fn counterparty() -> Uuid {
    Uuid::from_u128(COUNTERPARTY_MARKER)
}

// ---- request_conversion -------------------------------------------

#[tokio::test]
async fn request_conversion_happy_path_child_side() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
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
    let now = fixed_now();
    let svc = make_service(conv.clone(), tenants, now);

    let result = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect("happy path child-side initiation");

    assert_eq!(
        result.tenant_id, child,
        "row carries the converting tenant id"
    );
    assert_eq!(
        result.initiator_side,
        ConversionSide::Child,
        "initiator side mirrors caller_side"
    );
    assert_eq!(
        result.target_mode,
        TargetMode::SelfManaged,
        "non-self-managed tenant flips to self_managed"
    );
    assert_eq!(result.status, ConversionStatus::Pending);
    assert_eq!(
        result.expires_at,
        now + approval_ttl(),
        "expires_at is now + approval_ttl"
    );
    assert_eq!(result.parent_id, Some(parent));
}

#[tokio::test]
async fn request_conversion_happy_path_parent_side() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x10);
    let child = Uuid::from_u128(0x20);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    // Self-managed tenant: target mode should flip back to managed.
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        true,
        "child-2",
    );
    let now = fixed_now();
    let svc = make_service(conv, tenants, now);

    let result = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::parent(parent),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect("happy path parent-side initiation");

    assert_eq!(result.initiator_side, ConversionSide::Parent);
    assert_eq!(
        result.target_mode,
        TargetMode::Managed,
        "self_managed tenant flips to managed"
    );
}

#[tokio::test]
async fn request_conversion_root_tenant_refused() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let root = Uuid::from_u128(0x100);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    let svc = make_service(conv.clone(), tenants, fixed_now());

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: root,
                caller: ConversionCaller::child(root),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect_err("root-tenant initiation must be refused");

    assert!(
        matches!(err, DomainError::RootTenantCannotConvert),
        "expected RootTenantCannotConvert, got {err:?}"
    );
    assert!(
        conv.pending_request_id_for(root).is_none(),
        "no pending row may be inserted on root-tenant refusal"
    );
}

#[tokio::test]
async fn request_conversion_status_suspended_rejected() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x200);
    let child = Uuid::from_u128(0x201);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Suspended,
        false,
        "child-suspended",
    );
    let svc = make_service(conv.clone(), tenants, fixed_now());

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect_err("suspended tenant may not initiate a conversion");

    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("suspended"),
                "validation detail must surface the rejected status; got {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert!(conv.pending_request_id_for(child).is_none());
}

#[tokio::test]
async fn request_conversion_status_deleted_rejected() {
    // The fake `find_by_id` returns the soft-deleted row (it does not
    // filter on `deleted_at IS NULL`), so the service enforces the
    // status precondition and surfaces `Validation`. Production
    // semantics agree because the repo's status precondition runs
    // before any soft-delete filter on this read path.
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x300);
    let child = Uuid::from_u128(0x301);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Deleted,
        false,
        "child-deleted",
    );
    let svc = make_service(conv.clone(), tenants, fixed_now());

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect_err("deleted tenant may not initiate a conversion");

    // The service lifts non-Active rows into `Validation`. If a future
    // FakeTenantRepo update starts filtering soft-deleted rows on
    // `find_by_id`, this branch will start surfacing `NotFound` —
    // both shapes are documented as acceptable in the phase
    // catalogue. We assert specifically `Validation` here because
    // that is the current FakeTenantRepo behaviour.
    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation for deleted tenant, got {err:?}"
    );
    assert!(conv.pending_request_id_for(child).is_none());
}

#[tokio::test]
async fn request_conversion_pending_exists_returns_pending_exists() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x400);
    let child = Uuid::from_u128(0x401);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child-pending",
    );

    let existing_id = Uuid::from_u128(0xBEEF);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        existing_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv.clone(), tenants, now);

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect_err("a second pending row must collide");

    match err {
        DomainError::PendingExists { request_id } => {
            assert_eq!(
                request_id,
                existing_id.to_string(),
                "carries the existing pending row's id"
            );
        }
        other => panic!("expected PendingExists, got {other:?}"),
    }
}

#[tokio::test]
async fn request_conversion_after_resolved_succeeds() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x500);
    let child = Uuid::from_u128(0x501);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "child-after-resolved",
    );

    let now = fixed_now();
    let prior_id = Uuid::from_u128(0xCAFE);
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        prior_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Cancelled,
        now - TimeDuration::days(2),
        Some(now - TimeDuration::days(1)),
    )]));
    let svc = make_service(conv.clone(), tenants, now);

    let row = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect("a resolved prior row must not block a new pending");

    assert_eq!(row.status, ConversionStatus::Pending);
    assert_ne!(
        row.id, prior_id,
        "a fresh request id is allocated for the new pending row"
    );
}

// ---- cancel --------------------------------------------------------

#[tokio::test]
async fn cancel_happy_path_initiator() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x600);
    let child = Uuid::from_u128(0x601);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0xCABA);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let updated = svc
        .cancel(
            &scope(),
            pending_id,
            ConversionCaller::child(child),
            requester(),
        )
        .await
        .expect("initiator-side cancel succeeds");

    assert_eq!(updated.status, ConversionStatus::Cancelled);
    assert_eq!(updated.cancelled_by, Some(requester()));
    assert_eq!(updated.resolved_at, Some(now));
}

#[tokio::test]
async fn cancel_by_counterparty_invalid_actor() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x700);
    let child = Uuid::from_u128(0x701);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0xDADA);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .cancel(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("counterparty-side cancel must be rejected");

    match err {
        DomainError::InvalidActorForTransition {
            attempted_status,
            caller_side,
        } => {
            assert_eq!(attempted_status, "cancelled");
            assert_eq!(caller_side, "parent");
        }
        other => panic!("expected InvalidActorForTransition, got {other:?}"),
    }
}

#[tokio::test]
async fn cancel_on_resolved_returns_already_resolved() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x800);
    let child = Uuid::from_u128(0x801);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let resolved_id = Uuid::from_u128(0xFEED);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        resolved_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Approved,
        now - TimeDuration::days(1),
        Some(now - TimeDuration::hours(1)),
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .cancel(
            &scope(),
            resolved_id,
            ConversionCaller::child(child),
            requester(),
        )
        .await
        .expect_err("cancel on a resolved row must return AlreadyResolved");

    assert!(
        matches!(err, DomainError::AlreadyResolved),
        "expected AlreadyResolved, got {err:?}"
    );
}

// ---- reject --------------------------------------------------------

#[tokio::test]
async fn reject_happy_path_counterparty() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x900);
    let child = Uuid::from_u128(0x901);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x1234_5678);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let updated = svc
        .reject(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect("counterparty-side reject succeeds");

    assert_eq!(updated.status, ConversionStatus::Rejected);
    assert_eq!(updated.rejected_by, Some(counterparty()));
    assert_eq!(updated.resolved_at, Some(now));
}

#[tokio::test]
async fn reject_by_initiator_invalid_actor() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xA00);
    let child = Uuid::from_u128(0xA01);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0xABCD);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .reject(
            &scope(),
            pending_id,
            ConversionCaller::child(child),
            requester(),
        )
        .await
        .expect_err("initiator-side reject must be rejected");

    match err {
        DomainError::InvalidActorForTransition {
            attempted_status,
            caller_side,
        } => {
            assert_eq!(attempted_status, "rejected");
            assert_eq!(caller_side, "child");
        }
        other => panic!("expected InvalidActorForTransition, got {other:?}"),
    }
}

#[tokio::test]
async fn reject_on_resolved_returns_already_resolved() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xB00);
    let child = Uuid::from_u128(0xB01);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let resolved_id = Uuid::from_u128(0xBA5E);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        resolved_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Approved,
        now - TimeDuration::days(1),
        Some(now - TimeDuration::hours(2)),
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .reject(
            &scope(),
            resolved_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("reject on a resolved row must return AlreadyResolved");

    assert!(
        matches!(err, DomainError::AlreadyResolved),
        "expected AlreadyResolved, got {err:?}"
    );
}

// ---- listings ------------------------------------------------------

#[tokio::test]
async fn list_own_for_tenant_pagination_and_status_filter() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xC00);
    let child = Uuid::from_u128(0xC01);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let now = fixed_now();
    // Five rows across statuses; `requested_at` strictly increasing
    // so the stable `(requested_at DESC, id ASC)` order is
    // deterministic.
    let mut seed: Vec<ConversionRequest> = Vec::new();
    for (i, status) in [
        ConversionStatus::Cancelled,
        ConversionStatus::Approved,
        ConversionStatus::Rejected,
        ConversionStatus::Expired,
        ConversionStatus::Approved,
    ]
    .into_iter()
    .enumerate()
    {
        let i_u128 = u128::try_from(i).expect("i fits in u128");
        let i_i64 = i64::try_from(i).expect("i fits in i64");
        let id = Uuid::from_u128(0xD000 + i_u128);
        let requested_at = now - TimeDuration::hours(10 - i_i64);
        let resolved_at = Some(requested_at + TimeDuration::minutes(5));
        seed.push(seeded_request(
            id,
            child,
            Some(parent),
            ConversionSide::Child,
            status,
            requested_at,
            resolved_at,
        ));
    }
    let conv = Arc::new(FakeConversionRepo::with_seed(seed));
    let svc = make_service(conv, tenants, now);

    // Page 1, top=2, no status filter — returns the two newest rows.
    let page1 = svc
        .list_own_for_tenant(&scope(), child, &ListConversionsQuery::all(2, 0))
        .await
        .expect("list page 1");
    assert_eq!(page1.items.len(), 2, "page 1 carries top=2 items");
    assert_eq!(page1.top, 2);
    assert_eq!(page1.skip, 0);

    // Page 2, top=2, skip=2 — returns the next two.
    let page2 = svc
        .list_own_for_tenant(&scope(), child, &ListConversionsQuery::all(2, 2))
        .await
        .expect("list page 2");
    assert_eq!(page2.items.len(), 2);
    // No overlap with page 1.
    let p1_ids: Vec<Uuid> = page1.items.iter().map(|r| r.id).collect();
    for r in &page2.items {
        assert!(
            !p1_ids.contains(&r.id),
            "page 2 must not repeat any page 1 id"
        );
    }

    // Status filter: only `Approved` rows (there are two in the seed).
    let approved = svc
        .list_own_for_tenant(
            &scope(),
            child,
            &ListConversionsQuery::with_status(10, 0, ConversionStatus::Approved),
        )
        .await
        .expect("list approved");
    assert_eq!(approved.items.len(), 2, "two seeded Approved rows");
    for row in &approved.items {
        assert_eq!(row.status, ConversionStatus::Approved);
    }
}

#[tokio::test]
async fn list_inbound_for_parent_only_direct_children() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xE00);
    let child_a = Uuid::from_u128(0xE01);
    let child_b = Uuid::from_u128(0xE02);
    let grandchild_c = Uuid::from_u128(0xE03);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child_a,
        Some(parent),
        TenantStatus::Active,
        false,
        "a",
    );
    seed_tenant(
        &tenants,
        child_b,
        Some(parent),
        TenantStatus::Active,
        false,
        "b",
    );
    // grandchild C has child_a as its parent (depth 2).
    seed_tenant(
        &tenants,
        grandchild_c,
        Some(child_a),
        TenantStatus::Active,
        false,
        "c-grand",
    );

    let now = fixed_now();
    let req_a = seeded_request(
        Uuid::from_u128(0xE0A1),
        child_a,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    let req_b = seeded_request(
        Uuid::from_u128(0xE0B1),
        child_b,
        Some(parent),
        ConversionSide::Parent,
        ConversionStatus::Pending,
        now,
        None,
    );
    // grandchild's request belongs to child_a (its parent), NOT to
    // `parent`. The repo predicate is `parent_id == :parent_id`, so
    // this row must be invisible from `parent`'s parent-side listing.
    let req_c = seeded_request(
        Uuid::from_u128(0xE0C1),
        grandchild_c,
        Some(child_a),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![req_a, req_b, req_c]));
    let svc = make_service(conv, tenants, now);

    let page = svc
        .list_inbound_for_parent(&scope(), parent, &ListConversionsQuery::all(50, 0))
        .await
        .expect("parent-side listing");

    assert_eq!(
        page.items.len(),
        2,
        "only direct children A and B appear; grandchild C is excluded"
    );
    let returned_tenants: Vec<Uuid> = page.items.iter().map(|p| p.tenant_id).collect();
    assert!(returned_tenants.contains(&child_a));
    assert!(returned_tenants.contains(&child_b));
    assert!(!returned_tenants.contains(&grandchild_c));

    // Live name resolution — the projection's `child_tenant_name`
    // came from the tenant row, not from a stale snapshot.
    let proj_a = page
        .items
        .iter()
        .find(|p| p.tenant_id == child_a)
        .expect("projection for child A");
    assert_eq!(proj_a.child_tenant_name, "a");
}

#[tokio::test]
async fn list_inbound_for_parent_projection_drops_subtree() {
    // The projection type is compile-time enforced — there is no
    // `descendant_count`, no `closure`, no `metadata` on
    // `ConversionRequestParentProjection`. This test asserts the
    // visible field set by reading every documented field exactly
    // once; if a field is added or removed in the future, this test
    // is the canonical place where the minimal-surface contract is
    // pinned.
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xF00);
    let child = Uuid::from_u128(0xF01);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "live-name",
    );

    let now = fixed_now();
    let req = seeded_request(
        Uuid::from_u128(0xF0A1),
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![req.clone()]));
    let svc = make_service(conv, tenants, now);

    let page = svc
        .list_inbound_for_parent(&scope(), parent, &ListConversionsQuery::all(10, 0))
        .await
        .expect("listing");
    assert_eq!(page.items.len(), 1);
    let proj = &page.items[0];

    // Read every documented projection field — if a future patch
    // adds a sibling field, this assertion stays compatible (extra
    // fields don't break field-by-field reads); if a field is
    // removed, the compile fails here. That is the intended pin.
    assert_eq!(proj.request_id, req.id);
    assert_eq!(proj.tenant_id, req.tenant_id);
    assert_eq!(proj.child_tenant_name, "live-name");
    assert_eq!(proj.initiator_side, req.initiator_side);
    assert_eq!(proj.target_mode, req.target_mode);
    assert_eq!(proj.status, req.status);
    assert_eq!(proj.requested_by, req.requested_by);
    assert_eq!(proj.approved_by, req.approved_by);
    assert_eq!(proj.cancelled_by, req.cancelled_by);
    assert_eq!(proj.rejected_by, req.rejected_by);
    assert_eq!(proj.created_at, req.requested_at);
    assert_eq!(proj.expires_at, req.expires_at);
    assert_eq!(proj.resolved_at, req.resolved_at);
}

// ---- retention -----------------------------------------------------

#[tokio::test]
async fn soft_delete_resolved_only_touches_resolved_old_rows() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x1100);
    let child = Uuid::from_u128(0x1101);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let now = fixed_now();

    // Pending — must be untouched by retention.
    let pending = seeded_request(
        Uuid::from_u128(0x1101_0001),
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    // Approved resolved 1h ago — within window (7 days), untouched.
    let approved_recent = seeded_request(
        Uuid::from_u128(0x1101_0002),
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Approved,
        now - TimeDuration::hours(2),
        Some(now - TimeDuration::hours(1)),
    );
    // Cancelled resolved 30 days ago — outside window, picked.
    let cancelled_old = seeded_request(
        Uuid::from_u128(0x1101_0003),
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Cancelled,
        now - TimeDuration::days(31),
        Some(now - TimeDuration::days(30)),
    );
    // Rejected already soft-deleted — idempotent, untouched.
    let mut rejected_already_sd = seeded_request(
        Uuid::from_u128(0x1101_0004),
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Rejected,
        now - TimeDuration::days(60),
        Some(now - TimeDuration::days(59)),
    );
    rejected_already_sd.deleted_at = Some(now - TimeDuration::days(50));

    let conv = Arc::new(FakeConversionRepo::with_seed(vec![
        pending,
        approved_recent,
        cancelled_old,
        rejected_already_sd.clone(),
    ]));
    let svc = make_service(conv.clone(), tenants, now);

    let count = svc
        .soft_delete_resolved(&scope(), retention_window(), 100)
        .await
        .expect("retention sweep");

    assert_eq!(count, 1, "exactly one row picked: cancelled-30d");

    // Snapshot to check the deleted_at stamp landed on the right row
    // and ONLY that row.
    let all = conv.snapshot_all();
    let by_id: std::collections::HashMap<Uuid, ConversionRequest> =
        all.into_iter().map(|r| (r.id, r)).collect();

    assert!(
        by_id[&Uuid::from_u128(0x1101_0001)].deleted_at.is_none(),
        "Pending must remain untouched"
    );
    assert!(
        by_id[&Uuid::from_u128(0x1101_0002)].deleted_at.is_none(),
        "Approved within window must remain untouched"
    );
    assert!(
        by_id[&Uuid::from_u128(0x1101_0003)].deleted_at.is_some(),
        "Cancelled-30d must be soft-deleted"
    );
    assert_eq!(
        by_id[&Uuid::from_u128(0x1101_0004)].deleted_at,
        rejected_already_sd.deleted_at,
        "already-soft-deleted Rejected must keep its existing deleted_at (idempotent)"
    );
}

// ---- status-precedes-actor invariant -----------------------------

#[tokio::test]
async fn status_precedes_actor_check_on_resolved_row() {
    // Resolved + wrong-side caller MUST surface `AlreadyResolved`
    // (not `InvalidActorForTransition`). Pin both `cancel` and
    // `reject` paths.
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x1200);
    let child = Uuid::from_u128(0x1201);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let now = fixed_now();
    let resolved_id = Uuid::from_u128(0x1202);
    // Initiator side Child, status Approved (resolved).
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        resolved_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Approved,
        now - TimeDuration::days(1),
        Some(now - TimeDuration::hours(3)),
    )]));
    let svc = make_service(conv, tenants, now);

    // Cancel from the COUNTERPARTY side (wrong actor for cancel).
    // Even though both rules would reject, the status check must win.
    let cancel_err = svc
        .cancel(
            &scope(),
            resolved_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("cancel on resolved + wrong side must error");
    assert!(
        matches!(cancel_err, DomainError::AlreadyResolved),
        "cancel on resolved row MUST return AlreadyResolved (status-before-actor); got {cancel_err:?}"
    );

    // Reject from the INITIATOR side (wrong actor for reject).
    let reject_err = svc
        .reject(
            &scope(),
            resolved_id,
            ConversionCaller::child(child),
            requester(),
        )
        .await
        .expect_err("reject on resolved + wrong side must error");
    assert!(
        matches!(reject_err, DomainError::AlreadyResolved),
        "reject on resolved row MUST return AlreadyResolved (status-before-actor); got {reject_err:?}"
    );
}

// ---- approve -------------------------------------------------------

/// Tenant-type checker that always rejects with `TypeNotAllowed`.
/// Used by the `approve_type_reeval_rejects_leaves_pending_intact`
/// test to drive the type-not-allowed branch of the apply seam.
struct AlwaysReject;

#[async_trait]
impl TenantTypeChecker for AlwaysReject {
    async fn check_parent_child(
        &self,
        _parent_type: Uuid,
        _child_type: Uuid,
    ) -> Result<(), DomainError> {
        Err(DomainError::TypeNotAllowed {
            detail: "type_not_allowed (test fixture)".to_owned(),
        })
    }
}

/// Thin wrapper over [`FakeTenantRepo::seed_closure`] that pins the
/// `descendant_status` to `Active` — every closure row used by these
/// tests is rooted at an active tenant, so the helper sheds the
/// otherwise-uniform argument from each call site.
fn seed_closure(repo: &FakeTenantRepo, ancestor: Uuid, descendant: Uuid, barrier: i16) {
    repo.seed_closure(ancestor, descendant, barrier, TenantStatus::Active);
}

/// Look up a closure row's barrier in the `FakeTenantRepo` state.
fn closure_barrier(repo: &FakeTenantRepo, ancestor: Uuid, descendant: Uuid) -> i16 {
    repo.state
        .lock()
        .expect("lock")
        .closure
        .iter()
        .find(|r| r.ancestor_id == ancestor && r.descendant_id == descendant)
        .map_or_else(
            || panic!("closure row ({ancestor}, {descendant}) not seeded"),
            |r| r.barrier,
        )
}

/// Direct read of `tenants.self_managed`.
fn tenant_self_managed(repo: &FakeTenantRepo, id: Uuid) -> bool {
    repo.find_by_id_unchecked(id)
        .map_or_else(|| panic!("tenant {id} not seeded"), |t| t.self_managed)
}

#[tokio::test]
async fn approve_counterparty_flips_self_managed_and_transitions() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2000);
    let child = Uuid::from_u128(0x2001);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false, // currently managed
        "c",
    );
    seed_closure(&tenants, parent, parent, 0);
    seed_closure(&tenants, child, child, 0);
    seed_closure(&tenants, parent, child, 0);

    let pending_id = Uuid::from_u128(0x2002);
    let now = fixed_now();
    let mut row = seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child, // initiator = child
        ConversionStatus::Pending,
        now,
        None,
    );
    row.target_mode = TargetMode::SelfManaged;
    let conv =
        Arc::new(FakeConversionRepo::with_seed(vec![row]).with_tenant_repo(Arc::clone(&tenants)));
    let svc = make_service(conv.clone(), Arc::clone(&tenants), now);

    let updated = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect("counterparty-side approve succeeds");

    assert_eq!(updated.status, ConversionStatus::Approved);
    assert_eq!(updated.approved_by, Some(counterparty()));
    assert_eq!(updated.resolved_at, Some(now));
    assert!(
        tenant_self_managed(&tenants, child),
        "tenants.self_managed flipped to true on managed -> self_managed"
    );
    // (parent, child) strict path crosses child (the converted
    // tenant) and child.self_managed is now true -> barrier=1.
    assert_eq!(closure_barrier(&tenants, parent, child), 1);
    // Self-rows stay 0 by the closure self-row invariant.
    assert_eq!(closure_barrier(&tenants, child, child), 0);
    assert_eq!(closure_barrier(&tenants, parent, parent), 0);
}

#[tokio::test]
async fn approve_initiator_side_returns_invalid_actor() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2100);
    let child = Uuid::from_u128(0x2101);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x2102);
    let now = fixed_now();
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![seeded_request(
            pending_id,
            child,
            Some(parent),
            ConversionSide::Child, // initiator = child
            ConversionStatus::Pending,
            now,
            None,
        )])
        .with_tenant_repo(Arc::clone(&tenants)),
    );
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        // Initiator side approving its own request -> invalid actor.
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::child(child),
            requester(),
        )
        .await
        .expect_err("initiator-side approve must be rejected");

    match err {
        DomainError::InvalidActorForTransition {
            attempted_status,
            caller_side,
        } => {
            assert_eq!(attempted_status, "approved");
            assert_eq!(caller_side, "child");
        }
        other => panic!("expected InvalidActorForTransition, got {other:?}"),
    }
    assert!(
        !tenant_self_managed(&tenants, child),
        "rejected approve must NOT flip tenants.self_managed"
    );
}

#[tokio::test]
async fn approve_already_resolved_returns_already_resolved() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2200);
    let child = Uuid::from_u128(0x2201);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let resolved_id = Uuid::from_u128(0x2202);
    let now = fixed_now();
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![seeded_request(
            resolved_id,
            child,
            Some(parent),
            ConversionSide::Child,
            ConversionStatus::Approved,
            now - TimeDuration::days(1),
            Some(now - TimeDuration::hours(1)),
        )])
        .with_tenant_repo(Arc::clone(&tenants)),
    );
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            resolved_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("approve on resolved row must surface AlreadyResolved");
    assert!(
        matches!(err, DomainError::AlreadyResolved),
        "expected AlreadyResolved, got {err:?}"
    );
}

#[tokio::test]
async fn approve_type_reeval_rejects_leaves_pending_intact() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2300);
    let child = Uuid::from_u128(0x2301);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );
    seed_closure(&tenants, parent, parent, 0);
    seed_closure(&tenants, child, child, 0);
    seed_closure(&tenants, parent, child, 0);

    let pending_id = Uuid::from_u128(0x2302);
    let now = fixed_now();
    let mut row = seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    row.target_mode = TargetMode::SelfManaged;
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![row])
            .with_tenant_repo(Arc::clone(&tenants))
            .with_tenant_type_checker(Arc::new(AlwaysReject)),
    );
    let svc = make_service(conv.clone(), Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("type re-eval rejection must surface TypeNotAllowed");

    match err {
        DomainError::TypeNotAllowed { .. } => {}
        other => panic!("expected TypeNotAllowed, got {other:?}"),
    }

    // Apply MUST roll back: pending row stays Pending, tenant flag
    // unchanged, closure barrier untouched.
    let row = conv
        .snapshot_all()
        .into_iter()
        .find(|r| r.id == pending_id)
        .expect("row still present");
    assert_eq!(row.status, ConversionStatus::Pending);
    assert!(row.approved_by.is_none());
    assert!(row.resolved_at.is_none());
    assert!(
        !tenant_self_managed(&tenants, child),
        "tenants.self_managed MUST NOT flip on type-not-allowed"
    );
    assert_eq!(closure_barrier(&tenants, parent, child), 0);
}

#[tokio::test]
async fn approve_when_tenant_inactive_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2400);
    let child = Uuid::from_u128(0x2401);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    // Tenant is Suspended at approve time — service-level fence
    // surfaces Validation before any apply runs.
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Suspended,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x2402);
    let now = fixed_now();
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![seeded_request(
            pending_id,
            child,
            Some(parent),
            ConversionSide::Child,
            ConversionStatus::Pending,
            now,
            None,
        )])
        .with_tenant_repo(Arc::clone(&tenants)),
    );
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("approve on non-active tenant must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

// ---- ConversionCaller::parent scope-mismatch matrix ---------------
//
// Pins the `verify_parent_scope` guard documented on
// `service::verify_parent_scope`: a parent-side caller acting on a
// request whose stored `parent_id` is NOT the caller's declared
// `parent_scope_id` MUST be rejected with `Validation`. The guard
// runs BEFORE the state / role matrix, so even a "would-have-been
// `AlreadyResolved`" or "would-have-been `InvalidActorForTransition`"
// row surfaces the scope mismatch first.
//
// Matrix coverage: each of the four service entry points
// (`request_conversion`, `cancel`, `reject`, `approve`) is exercised
// with `ConversionCaller::parent(WRONG_PARENT)` and the underlying
// row's `parent_id` set to a different tenant, including a guard-
// ordering test where the row is also resolved (state would otherwise
// fire first if the scope check ran second).

const WRONG_PARENT_MARKER: u128 = 0xBADD;

#[tokio::test]
async fn request_conversion_parent_scope_mismatch_returns_validation() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9001);
    let child = Uuid::from_u128(0x9002);
    let wrong_parent = Uuid::from_u128(WRONG_PARENT_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );
    let now = fixed_now();
    let svc = make_service(conv, tenants, now);

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::parent(wrong_parent),
                target_mode_override: None,
                requested_by: requester(),
            },
        )
        .await
        .expect_err("parent-side caller scoped to wrong parent must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn cancel_parent_scope_mismatch_wins_over_state_and_actor() {
    // Row is RESOLVED and caller_side matches the initiator (would
    // normally surface `AlreadyResolved` on resolved-row + initiator-
    // matches-cancel rule). A wrong parent_scope_id MUST surface
    // `Validation` first, because `verify_parent_scope` runs before
    // the state / role matrix.
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9101);
    let child = Uuid::from_u128(0x9102);
    let wrong_parent = Uuid::from_u128(WRONG_PARENT_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let resolved_id = Uuid::from_u128(0x9103);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        resolved_id,
        child,
        Some(parent),
        ConversionSide::Parent, // initiator = parent (so child is counterparty)
        ConversionStatus::Cancelled,
        now,
        Some(now),
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .cancel(
            &scope(),
            resolved_id,
            ConversionCaller::parent(wrong_parent),
            counterparty(),
        )
        .await
        .expect_err("parent-side scope mismatch must beat state / actor checks");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "verify_parent_scope MUST run before AlreadyResolved / InvalidActor; got {err:?}"
    );
}

#[tokio::test]
async fn reject_parent_scope_mismatch_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9201);
    let child = Uuid::from_u128(0x9202);
    let wrong_parent = Uuid::from_u128(WRONG_PARENT_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x9203);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .reject(
            &scope(),
            pending_id,
            ConversionCaller::parent(wrong_parent),
            counterparty(),
        )
        .await
        .expect_err("parent-side scope mismatch must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn approve_parent_scope_mismatch_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9301);
    let child = Uuid::from_u128(0x9302);
    let wrong_parent = Uuid::from_u128(WRONG_PARENT_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x9303);
    let now = fixed_now();
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![seeded_request(
            pending_id,
            child,
            Some(parent),
            ConversionSide::Child,
            ConversionStatus::Pending,
            now,
            None,
        )])
        .with_tenant_repo(Arc::clone(&tenants)),
    );
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(wrong_parent),
            counterparty(),
        )
        .await
        .expect_err("parent-side scope mismatch must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

// ---- ConversionCaller::child scope-mismatch matrix ----------------
//
// Symmetric to the parent-side matrix above: a child-side caller
// scoped to `WRONG_CHILD` MUST be rejected with `Validation` on
// every entry point that takes a `request_id`. Closes cypilot-R6
// MINOR (child-scope-mismatch matrix incomplete).

const WRONG_CHILD_MARKER: u128 = 0xBADC;

#[tokio::test]
async fn cancel_child_scope_mismatch_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9401);
    let child = Uuid::from_u128(0x9402);
    let wrong_child = Uuid::from_u128(WRONG_CHILD_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x9403);
    let now = fixed_now();
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .cancel(
            &scope(),
            pending_id,
            ConversionCaller::child(wrong_child),
            requester(),
        )
        .await
        .expect_err("child-side scope mismatch must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn reject_child_scope_mismatch_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9501);
    let child = Uuid::from_u128(0x9502);
    let wrong_child = Uuid::from_u128(WRONG_CHILD_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x9503);
    let now = fixed_now();
    // Initiator = parent, so the legitimate counterparty is the child
    // side — a child-side caller with the wrong child_id MUST still
    // surface scope mismatch BEFORE the role-rule check.
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Parent,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .reject(
            &scope(),
            pending_id,
            ConversionCaller::child(wrong_child),
            requester(),
        )
        .await
        .expect_err("child-side scope mismatch must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn approve_child_scope_mismatch_returns_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x9601);
    let child = Uuid::from_u128(0x9602);
    let wrong_child = Uuid::from_u128(WRONG_CHILD_MARKER);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x9603);
    let now = fixed_now();
    // Initiator = parent so the legitimate counterparty is the child
    // side — confirms the scope check fires before the role / state
    // matrix on the approve entry point too.
    let conv = Arc::new(
        FakeConversionRepo::with_seed(vec![seeded_request(
            pending_id,
            child,
            Some(parent),
            ConversionSide::Parent,
            ConversionStatus::Pending,
            now,
            None,
        )])
        .with_tenant_repo(Arc::clone(&tenants)),
    );
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::child(wrong_child),
            counterparty(),
        )
        .await
        .expect_err("child-side scope mismatch must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
}

// ---- verify_caller_scope data-integrity diagnostic ---------------
//
// `verify_caller_scope` carries a distinct diagnostic for the
// "row.parent_id == None on a parent-side call" case (FEATURE
// root-tenant refusal should have prevented this insert; if a row
// exists somehow it's a data-integrity violation, not a regular
// scope mismatch). Pin the diagnostic so a refactor that collapses
// the branch into the generic `Validation` path is caught.

#[tokio::test]
async fn cancel_parent_side_on_null_parent_id_row_surfaces_data_integrity_diagnostic() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let orphan = Uuid::from_u128(0x9701);
    let any_parent = Uuid::from_u128(0x9702);
    seed_tenant(
        &tenants,
        orphan,
        None,
        TenantStatus::Active,
        false,
        "orphan",
    );

    let pending_id = Uuid::from_u128(0x9703);
    let now = fixed_now();
    // Seed a row whose `parent_id` is `None` directly via
    // `with_seed` — the production service path would never write
    // such a row (root-tenant refusal blocks the insert), so we go
    // through the test-only fake.
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        orphan,
        None, // parent_id intentionally None
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, tenants, now);

    let err = svc
        .cancel(
            &scope(),
            pending_id,
            ConversionCaller::parent(any_parent),
            requester(),
        )
        .await
        .expect_err("parent-side caller on a NULL-parent_id row must surface Validation");

    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("data-integrity"),
                "diagnostic MUST distinguish data-integrity violation from regular scope \
                 mismatch; got: {detail}"
            );
        }
        other => panic!("expected Validation with data-integrity diagnostic, got {other:?}"),
    }
}

// ---- target_mode_override no-op guard ------------------------------
//
// Pins the codex-R3 fix in `request_conversion`: an override that
// resolves to the SAME mode the tenant already has is rejected with
// `Validation` and consumes no partial-unique-pending slot. Both
// directions are covered (managed -> managed, self_managed ->
// self_managed) so a regression that drops the guard for one branch
// is caught.

#[tokio::test]
async fn request_conversion_no_op_managed_to_managed_returns_validation() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xA001);
    let child = Uuid::from_u128(0xA002);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    // child currently managed (`self_managed = false`).
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );
    let now = fixed_now();
    let svc = make_service(Arc::clone(&conv), tenants, now);

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: Some(TargetMode::Managed),
                requested_by: requester(),
            },
        )
        .await
        .expect_err("override matching current mode must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
    // No row consumed the partial-unique-pending slot.
    assert!(
        conv.pending_request_id_for(child).is_none(),
        "no pending row should have been written"
    );
}

#[tokio::test]
async fn request_conversion_no_op_self_managed_to_self_managed_returns_validation() {
    let conv = Arc::new(FakeConversionRepo::new());
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0xA101);
    let child = Uuid::from_u128(0xA102);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    // child currently self-managed.
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        true,
        "c",
    );
    let now = fixed_now();
    let svc = make_service(Arc::clone(&conv), tenants, now);

    let err = svc
        .request_conversion(
            &scope(),
            RequestConversionInput {
                tenant_id: child,
                caller: ConversionCaller::child(child),
                target_mode_override: Some(TargetMode::SelfManaged),
                requested_by: requester(),
            },
        )
        .await
        .expect_err("override matching current mode must surface Validation");

    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );
    assert!(
        conv.pending_request_id_for(child).is_none(),
        "no pending row should have been written"
    );
}

#[tokio::test]
async fn approve_returns_internal_when_fake_repo_missing_tenant_repo_handle() {
    // Pin the `FakeConversionRepo::apply_conversion_approval`
    // contract: when the cross-fake `tenant_repo` handle is absent,
    // the apply path returns `DomainError::Internal` rather than
    // panicking or silently flipping nothing. Mirrors the production
    // SQL impl where a missing collaborator would surface as a
    // typed internal-error.
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2480);
    let child = Uuid::from_u128(0x2481);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );

    let pending_id = Uuid::from_u128(0x2482);
    let now = fixed_now();
    // Note the absence of `with_tenant_repo` — the fake's apply seam
    // checks `self.tenant_repo` and surfaces `Internal` when it is
    // `None`.
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    )]));
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let err = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(parent),
            counterparty(),
        )
        .await
        .expect_err("approve must surface Internal when fake apply seam is unwired");

    assert!(
        matches!(err, DomainError::Internal { .. }),
        "expected Internal, got {err:?}"
    );
}

#[tokio::test]
async fn approve_rewrites_barrier_managed_to_self_managed() {
    // Three-deep tree: root -> mid -> leaf.
    // All managed before approve. Convert `mid` to self-managed.
    // Expected: barrier=1 on every closure row whose strict path
    // crosses `mid`.
    let tenants = Arc::new(FakeTenantRepo::new());
    let root = Uuid::from_u128(0x2500);
    let mid = Uuid::from_u128(0x2501);
    let leaf = Uuid::from_u128(0x2502);
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
    // Closure rows: each tenant's self-row + strict ancestors.
    seed_closure(&tenants, root, root, 0);
    seed_closure(&tenants, mid, mid, 0);
    seed_closure(&tenants, leaf, leaf, 0);
    seed_closure(&tenants, root, mid, 0);
    seed_closure(&tenants, root, leaf, 0);
    seed_closure(&tenants, mid, leaf, 0);

    let pending_id = Uuid::from_u128(0x2503);
    let now = fixed_now();
    let mut row = seeded_request(
        pending_id,
        mid, // converting tenant = mid
        Some(root),
        ConversionSide::Parent, // initiator = parent (root side)
        ConversionStatus::Pending,
        now,
        None,
    );
    row.target_mode = TargetMode::SelfManaged;
    let conv =
        Arc::new(FakeConversionRepo::with_seed(vec![row]).with_tenant_repo(Arc::clone(&tenants)));
    let svc = make_service(conv, Arc::clone(&tenants), now);

    // The initiator was the parent (root) side, so the counterparty
    // is the child side — `ConversionCaller::child(mid)` is the
    // converting tenant's own scope. This exercises the
    // `verify_caller_scope` child-path branch end-to-end on a
    // parent-initiated row, complementing the
    // parent-initiator-on-child-counterparty cases above.
    let _ = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::child(mid),
            counterparty(),
        )
        .await
        .expect("counterparty (child) approve succeeds");

    // (root, mid) strict path = {mid}; mid is now self-managed -> barrier=1.
    assert_eq!(closure_barrier(&tenants, root, mid), 1);
    // (root, leaf) strict path = {mid, leaf}; mid is self-managed -> barrier=1.
    assert_eq!(closure_barrier(&tenants, root, leaf), 1);
    // (mid, leaf) strict path = {leaf}; leaf is managed -> barrier=0.
    // BUT this row's path does NOT cross mid (mid is the ancestor and
    // is excluded from the strict path), so the barrier stays at its
    // pre-approve value of 0.
    assert_eq!(closure_barrier(&tenants, mid, leaf), 0);
    // Self-rows always 0.
    assert_eq!(closure_barrier(&tenants, root, root), 0);
    assert_eq!(closure_barrier(&tenants, mid, mid), 0);
    assert_eq!(closure_barrier(&tenants, leaf, leaf), 0);
}

#[tokio::test]
async fn approve_rewrites_barrier_self_managed_to_managed() {
    // Three-deep tree: root -> mid (self_managed) -> leaf.
    // Convert `mid` back to managed. Expected: barrier=0 on rows
    // whose strict path no longer has any self-managed tenant.
    // Add a self-managed `extra` sibling under root to demonstrate
    // that rows through `extra` retain barrier=1 even after `mid`
    // flips back to managed (path through extra is unaffected).
    let tenants = Arc::new(FakeTenantRepo::new());
    let root = Uuid::from_u128(0x2600);
    let mid = Uuid::from_u128(0x2601);
    let leaf = Uuid::from_u128(0x2602);
    let extra = Uuid::from_u128(0x2603);
    let extra_leaf = Uuid::from_u128(0x2604);
    seed_tenant(&tenants, root, None, TenantStatus::Active, false, "root");
    seed_tenant(&tenants, mid, Some(root), TenantStatus::Active, true, "mid");
    seed_tenant(
        &tenants,
        leaf,
        Some(mid),
        TenantStatus::Active,
        false,
        "leaf",
    );
    seed_tenant(
        &tenants,
        extra,
        Some(root),
        TenantStatus::Active,
        true,
        "extra",
    );
    seed_tenant(
        &tenants,
        extra_leaf,
        Some(extra),
        TenantStatus::Active,
        false,
        "extra-leaf",
    );
    // Pre-approve closure barriers reflect the existing self-managed
    // tenants on each strict path.
    seed_closure(&tenants, root, root, 0);
    seed_closure(&tenants, mid, mid, 0);
    seed_closure(&tenants, leaf, leaf, 0);
    seed_closure(&tenants, extra, extra, 0);
    seed_closure(&tenants, extra_leaf, extra_leaf, 0);
    seed_closure(&tenants, root, mid, 1); // mid self-managed
    seed_closure(&tenants, root, leaf, 1); // mid self-managed on path
    seed_closure(&tenants, mid, leaf, 0); // strict path = {leaf}, managed
    seed_closure(&tenants, root, extra, 1); // extra self-managed
    seed_closure(&tenants, root, extra_leaf, 1); // extra self-managed on path
    seed_closure(&tenants, extra, extra_leaf, 0); // strict path = {extra_leaf}, managed

    let pending_id = Uuid::from_u128(0x2605);
    let now = fixed_now();
    let mut row = seeded_request(
        pending_id,
        mid, // converting tenant = mid
        Some(root),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    row.target_mode = TargetMode::Managed; // flip back to managed
    let conv =
        Arc::new(FakeConversionRepo::with_seed(vec![row]).with_tenant_repo(Arc::clone(&tenants)));
    let svc = make_service(conv, Arc::clone(&tenants), now);

    let _ = svc
        .approve(
            &scope(),
            pending_id,
            ConversionCaller::parent(root),
            counterparty(),
        )
        .await
        .expect("counterparty (parent) approve succeeds");

    // (root, mid): strict path = {mid}, mid is now managed -> barrier=0.
    assert_eq!(closure_barrier(&tenants, root, mid), 0);
    // (root, leaf): strict path = {mid, leaf}, both managed -> barrier=0.
    assert_eq!(closure_barrier(&tenants, root, leaf), 0);
    // (mid, leaf): strict path = {leaf}, managed; row's path does NOT
    // cross `mid` so this row was never re-evaluated.
    assert_eq!(closure_barrier(&tenants, mid, leaf), 0);
    // Rows on the unaffected `extra` subtree retain their pre-approve
    // barrier values — the approve only re-evaluates rows whose
    // strict path crosses `mid`.
    assert_eq!(closure_barrier(&tenants, root, extra), 1);
    assert_eq!(closure_barrier(&tenants, root, extra_leaf), 1);
    assert!(
        !tenant_self_managed(&tenants, mid),
        "tenants.self_managed flipped to false on self_managed -> managed"
    );
}

// ---- expire --------------------------------------------------------

#[tokio::test]
async fn expire_empty_queue_returns_zero() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let conv = Arc::new(FakeConversionRepo::new());
    let svc = make_service(conv, tenants, fixed_now());
    let count = svc
        .expire_pending(&scope(), 100)
        .await
        .expect("empty queue tick");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn expire_one_past_pending_transitions_and_audits() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2700);
    let child = Uuid::from_u128(0x2701);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child,
        Some(parent),
        TenantStatus::Active,
        false, // managed
        "c",
    );

    let pending_id = Uuid::from_u128(0x2702);
    let now = fixed_now();
    let mut row = seeded_request(
        pending_id,
        child,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now - TimeDuration::days(8),
        None,
    );
    // Make it expired: expires_at strictly before now.
    row.expires_at = now - TimeDuration::hours(1);
    let conv = Arc::new(FakeConversionRepo::with_seed(vec![row]));
    let svc = make_service(conv.clone(), Arc::clone(&tenants), now);

    let count = svc
        .expire_pending(&scope(), 100)
        .await
        .expect("expire tick");
    assert_eq!(count, 1, "exactly one row must transition to Expired");

    let snap = conv
        .snapshot_all()
        .into_iter()
        .find(|r| r.id == pending_id)
        .expect("row still present");
    assert_eq!(snap.status, ConversionStatus::Expired);
    assert_eq!(snap.resolved_at, Some(now));
    // Expire MUST NOT mutate `tenants.self_managed`.
    assert!(
        !tenant_self_managed(&tenants, child),
        "expire MUST NOT flip tenants.self_managed"
    );
}

#[tokio::test]
async fn expire_mixed_batch_only_pending_and_expired_transition() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let parent = Uuid::from_u128(0x2800);
    let child_a = Uuid::from_u128(0x2801);
    let child_b = Uuid::from_u128(0x2802);
    let child_c = Uuid::from_u128(0x2803);
    let child_d = Uuid::from_u128(0x2804);
    seed_tenant(&tenants, parent, None, TenantStatus::Active, false, "root");
    seed_tenant(
        &tenants,
        child_a,
        Some(parent),
        TenantStatus::Active,
        false,
        "a",
    );
    seed_tenant(
        &tenants,
        child_b,
        Some(parent),
        TenantStatus::Active,
        false,
        "b",
    );
    seed_tenant(
        &tenants,
        child_c,
        Some(parent),
        TenantStatus::Active,
        false,
        "c",
    );
    seed_tenant(
        &tenants,
        child_d,
        Some(parent),
        TenantStatus::Active,
        false,
        "d",
    );

    let now = fixed_now();
    let id_a = Uuid::from_u128(0x2810);
    let id_b = Uuid::from_u128(0x2811);
    let id_c = Uuid::from_u128(0x2812);
    let id_d = Uuid::from_u128(0x2813);

    // Row A — Pending, expires in past -> should transition.
    let mut row_a = seeded_request(
        id_a,
        child_a,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now - TimeDuration::days(8),
        None,
    );
    row_a.expires_at = now - TimeDuration::hours(1);

    // Row B — Pending, expires in future -> stay.
    let mut row_b = seeded_request(
        id_b,
        child_b,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Pending,
        now,
        None,
    );
    row_b.expires_at = now + TimeDuration::hours(1);

    // Row C — Already approved, even with expires_at in past -> stay.
    let mut row_c = seeded_request(
        id_c,
        child_c,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Approved,
        now - TimeDuration::days(8),
        Some(now - TimeDuration::days(7)),
    );
    row_c.expires_at = now - TimeDuration::hours(1);

    // Row D — Cancelled, expires_at in past -> stay.
    let mut row_d = seeded_request(
        id_d,
        child_d,
        Some(parent),
        ConversionSide::Child,
        ConversionStatus::Cancelled,
        now - TimeDuration::days(8),
        Some(now - TimeDuration::days(7)),
    );
    row_d.expires_at = now - TimeDuration::hours(1);

    let conv = Arc::new(FakeConversionRepo::with_seed(vec![
        row_a, row_b, row_c, row_d,
    ]));
    let svc = make_service(conv.clone(), tenants, now);

    let count = svc
        .expire_pending(&scope(), 100)
        .await
        .expect("expire tick");
    assert_eq!(count, 1, "only row A transitions");

    let by_id: std::collections::HashMap<Uuid, ConversionRequest> =
        conv.snapshot_all().into_iter().map(|r| (r.id, r)).collect();
    assert_eq!(by_id[&id_a].status, ConversionStatus::Expired);
    assert_eq!(by_id[&id_b].status, ConversionStatus::Pending);
    assert_eq!(by_id[&id_c].status, ConversionStatus::Approved);
    assert_eq!(by_id[&id_d].status, ConversionStatus::Cancelled);

    // Idempotency: re-running on the post-expire state returns 0.
    let count2 = svc
        .expire_pending(&scope(), 100)
        .await
        .expect("expire tick #2");
    assert_eq!(count2, 0, "idempotent - no rows left to expire");
}
