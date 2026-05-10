//! Unit tests for [`UserService`].
//!
//! Every test wires the service against [`FakeTenantRepo`] +
//! [`FakeIdpUserProvisioner`]. Pins:
//!
//! * Guard ordering: tenant existence + Active precondition runs
//!   BEFORE any `IdP` call, so a non-existent / non-Active tenant
//!   surfaces as `NotFound` / `Validation` and `idp_call_count == 0`.
//! * Error mapping: `Unavailable` -> [`DomainError::IdpUnavailable`],
//!   `UnsupportedOperation` -> [`DomainError::UnsupportedOperation`],
//!   `Rejected` -> [`DomainError::Validation`] -- per the
//!   `feature-errors-observability` envelope mapping.
//! * Idempotency: `deprovision_user` returning
//!   `DeprovisionUserOutcome::NotFoundInTenant` surfaces as `Ok(())`;
//!   `Unavailable` and `UnsupportedOperation` pass through unchanged.
//! * `list_users` filter: `?user_id=<id>` returns 0 or 1 results
//!   matching the authoritative existence signal contract.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]

use std::sync::Arc;

use account_management_sdk::{NewUserPayload, UserPagination, UserProjection};
use modkit_security::AccessScope;
use time::OffsetDateTime;
use types_registry_sdk::testing::MockTypesRegistryClient;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::tenant::model::{TenantModel, TenantStatus};
use crate::domain::tenant::test_support::FakeTenantRepo;
use crate::domain::user::service::UserService;
use crate::domain::user::test_support::{FakeIdpUserProvisioner, FakeUserOutcome};

const REQUESTER_MARKER: u128 = 0xF1;

// ---- helpers -------------------------------------------------------

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch")
}

fn scope() -> AccessScope {
    AccessScope::allow_all()
}

fn requester() -> Uuid {
    Uuid::from_u128(REQUESTER_MARKER)
}

fn make_service(tenants: Arc<FakeTenantRepo>, idp: Arc<FakeIdpUserProvisioner>) -> UserService {
    // Empty registry: the `gts.cf.core.am.user.v1~` schema is not
    // registered, so `validate_new_user_payload_via_gts` returns
    // `Ok(())` and the AM-side `trim+empty` guard remains the
    // authoritative gate for these tests. A dedicated suite
    // exercising the registered-schema path lives in
    // `gts_validation_tests.rs`.
    let types_registry = Arc::new(MockTypesRegistryClient::new());
    UserService::new(tenants, idp, types_registry)
}

fn seed_tenant(
    fake: &FakeTenantRepo,
    id: Uuid,
    parent_id: Option<Uuid>,
    status: TenantStatus,
    name: &str,
) {
    let now = fixed_now();
    let depth = u32::from(parent_id.is_some());
    fake.insert_tenant_raw(TenantModel {
        id,
        parent_id,
        name: name.to_owned(),
        status,
        self_managed: false,
        tenant_type_uuid: Uuid::from_u128(0xAA),
        depth,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    });
}

fn payload(username: &str) -> NewUserPayload {
    NewUserPayload::new(username.to_owned())
        .with_email(format!("{username}@example.com"))
        .with_display_name(username.to_owned())
}

fn pagination() -> UserPagination {
    UserPagination::new(50, 0).expect("top=50 is valid")
}

/// Pagination shape required by `list_users` when `user_id_filter`
/// is set: AM-side validation pins `top=1, skip=0` so the filtered
/// lookup matches the authoritative-existence-check semantics
/// documented on the SDK.
fn filter_pagination() -> UserPagination {
    UserPagination::new(1, 0).expect("top=1 is valid")
}

// ---- provision_user -----------------------------------------------

#[tokio::test]
async fn provision_user_happy_path_returns_projection() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x1);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");

    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let pinned_id = Uuid::from_u128(0xABCD);
    idp.set_create_projection(
        UserProjection::new(pinned_id, "alice")
            .with_email("alice@example.com")
            .with_display_name("Alice"),
    );
    let svc = make_service(tenants, idp.clone());

    let projection = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect("happy path provision");

    assert_eq!(
        projection.id, pinned_id,
        "service forwards the provider-assigned IdP id verbatim"
    );
    assert_eq!(idp.create_call_count(), 1);
    let calls = idp.create_calls_snapshot();
    assert_eq!(calls[0].0, tenant_id, "tenant scope is forwarded");
    assert_eq!(calls[0].1, "alice");
}

#[tokio::test]
async fn provision_user_rejects_unknown_tenant_with_not_found_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let unknown = Uuid::from_u128(0x2);
    let err = svc
        .provision_user(&scope(), unknown, payload("alice"), requester())
        .await
        .expect_err("unknown tenant must reject");

    match err {
        DomainError::NotFound { resource, .. } => {
            assert_eq!(resource, unknown.to_string());
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
    assert_eq!(
        idp.create_call_count(),
        0,
        "tenant guard runs before any IdP call"
    );
}

#[tokio::test]
async fn provision_user_rejects_suspended_tenant_with_validation_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x10);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Suspended, "frozen");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let err = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect_err("suspended tenant must reject");

    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("suspended"),
                "validation must surface the rejected status; got {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(idp.create_call_count(), 0);
}

#[tokio::test]
async fn provision_user_rejects_provisioning_tenant_with_validation_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x11);
    seed_tenant(
        &tenants,
        tenant_id,
        None,
        TenantStatus::Provisioning,
        "mid-saga",
    );
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let err = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect_err("provisioning tenant must reject");

    assert!(matches!(err, DomainError::Validation { .. }));
    assert_eq!(idp.create_call_count(), 0);
}

#[tokio::test]
async fn provision_user_idp_unavailable_maps_to_idp_unavailable() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x20);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_create_outcome(FakeUserOutcome::Unavailable);
    let svc = make_service(tenants, idp);

    let err = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect_err("unavailable must err");

    assert!(matches!(err, DomainError::IdpUnavailable { .. }));
}

#[tokio::test]
async fn provision_user_idp_unsupported_maps_to_unsupported_operation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x21);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_create_outcome(FakeUserOutcome::Unsupported);
    let svc = make_service(tenants, idp);

    let err = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect_err("unsupported must err");

    assert!(matches!(err, DomainError::UnsupportedOperation { .. }));
}

#[tokio::test]
async fn provision_user_idp_rejects_payload_maps_to_validation() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x22);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_create_outcome(FakeUserOutcome::RejectPayload);
    let svc = make_service(tenants, idp);

    let err = svc
        .provision_user(&scope(), tenant_id, payload("alice"), requester())
        .await
        .expect_err("rejected payload must err");

    assert!(matches!(err, DomainError::Validation { .. }));
}

// ---- deprovision_user ---------------------------------------------

#[tokio::test]
async fn deprovision_user_happy_path_removed() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x30);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let user_id = Uuid::from_u128(0xBEEF);
    svc.deprovision_user(&scope(), tenant_id, user_id, requester())
        .await
        .expect("happy path deprovision returns Ok");
    assert_eq!(idp.delete_call_count(), 1);
    let calls = idp.delete_calls_snapshot();
    assert_eq!(calls[0], (tenant_id, user_id));
}

#[tokio::test]
async fn deprovision_user_absent_target_is_idempotent_success() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x31);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_delete_outcome(FakeUserOutcome::OkNotFound);
    let svc = make_service(tenants, idp);

    let user_id = Uuid::from_u128(0x00C0_FFEE);
    svc.deprovision_user(&scope(), tenant_id, user_id, requester())
        .await
        .expect("absent target must surface as idempotent success");
}

#[tokio::test]
async fn deprovision_user_retry_after_removed_remains_idempotent() {
    // AC #5: a subsequent retry of the same DELETE also returns 204.
    // First call hits `Removed`; second call (with the IdP now
    // reporting the user absent) hits `NotFoundInTenant`. Both MUST
    // surface as `Ok(())` so the endpoint stays retry-safe.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x34);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let user_id = Uuid::from_u128(0xBEEF_BEEF);

    // First call: provider returns Removed.
    svc.deprovision_user(&scope(), tenant_id, user_id, requester())
        .await
        .expect("first delete returns Ok(()) on Removed");

    // Second call: provider now reports the user absent in the
    // tenant scope. The idempotency guard MUST still produce Ok(()).
    idp.set_delete_outcome(FakeUserOutcome::OkNotFound);
    svc.deprovision_user(&scope(), tenant_id, user_id, requester())
        .await
        .expect("retry returns Ok(()) on NotFoundInTenant (idempotent)");

    assert_eq!(
        idp.delete_call_count(),
        2,
        "service forwarded both retry attempts to the IdP"
    );
}

#[tokio::test]
async fn deprovision_user_idp_unavailable_does_not_become_idempotent_success() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x32);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_delete_outcome(FakeUserOutcome::Unavailable);
    let svc = make_service(tenants, idp);

    let user_id = Uuid::from_u128(0xDEAD);
    let err = svc
        .deprovision_user(&scope(), tenant_id, user_id, requester())
        .await
        .expect_err("unavailable must NOT collapse to idempotent success");
    assert!(
        matches!(err, DomainError::IdpUnavailable { .. }),
        "unavailable must surface unchanged; got {err:?}"
    );
}

#[tokio::test]
async fn deprovision_user_unsupported_passes_through() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x33);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_delete_outcome(FakeUserOutcome::Unsupported);
    let svc = make_service(tenants, idp);

    let err = svc
        .deprovision_user(&scope(), tenant_id, Uuid::from_u128(0xBEEF), requester())
        .await
        .expect_err("unsupported must surface unchanged");
    assert!(matches!(err, DomainError::UnsupportedOperation { .. }));
}

#[tokio::test]
async fn deprovision_user_rejects_unknown_tenant_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let unknown = Uuid::from_u128(0x40);
    let err = svc
        .deprovision_user(&scope(), unknown, Uuid::from_u128(0xBEEF), requester())
        .await
        .expect_err("unknown tenant must reject");
    assert!(matches!(err, DomainError::NotFound { .. }));
    assert_eq!(idp.delete_call_count(), 0);
}

// ---- list_users ---------------------------------------------------

#[tokio::test]
async fn list_users_happy_path_returns_page_through_idp() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x50);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_list_items(vec![
        UserProjection::new(Uuid::from_u128(0xA1), "alice"),
        UserProjection::new(Uuid::from_u128(0xA2), "bob"),
    ]);
    let svc = make_service(tenants, idp);

    let page = svc
        .list_users(&scope(), tenant_id, None, pagination())
        .await
        .expect("happy path list");
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.total, Some(2));
}

#[tokio::test]
async fn list_users_user_id_filter_returns_one_or_empty() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x51);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let target = Uuid::from_u128(0xA1);
    let other = Uuid::from_u128(0xA2);
    idp.set_list_items(vec![
        UserProjection::new(target, "alice"),
        UserProjection::new(other, "bob"),
    ]);
    let svc = make_service(tenants, idp);

    let hit = svc
        .list_users(&scope(), tenant_id, Some(target), filter_pagination())
        .await
        .expect("filter by existing user id");
    assert_eq!(hit.items.len(), 1, "single-user filter returns 1 row");
    assert_eq!(hit.items[0].id, target);

    let absent = Uuid::from_u128(0xDEAD);
    let miss = svc
        .list_users(&scope(), tenant_id, Some(absent), filter_pagination())
        .await
        .expect("filter by absent user id is success-with-empty-list");
    assert!(
        miss.items.is_empty(),
        "absent user id must surface as empty list, NOT NotFound"
    );
}

#[tokio::test]
async fn list_users_idp_unavailable_does_not_serve_stale_page() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x52);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    idp.set_list_outcome(FakeUserOutcome::Unavailable);
    let svc = make_service(tenants, idp);

    let err = svc
        .list_users(&scope(), tenant_id, None, pagination())
        .await
        .expect_err("unavailable must err");
    assert!(matches!(err, DomainError::IdpUnavailable { .. }));
}

#[tokio::test]
async fn list_users_rejects_unknown_tenant_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let unknown = Uuid::from_u128(0x53);
    let err = svc
        .list_users(&scope(), unknown, None, pagination())
        .await
        .expect_err("unknown tenant must reject");
    assert!(matches!(err, DomainError::NotFound { .. }));
    assert_eq!(idp.list_call_count(), 0);
}

#[tokio::test]
async fn list_users_rejects_deleted_tenant_no_idp_call() {
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x54);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Deleted, "gone");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let err = svc
        .list_users(&scope(), tenant_id, None, pagination())
        .await
        .expect_err("deleted tenant must reject");
    assert!(matches!(err, DomainError::Validation { .. }));
    assert_eq!(idp.list_call_count(), 0);
}

#[tokio::test]
async fn list_users_with_user_id_filter_and_nonzero_skip_rejects_validation_no_idp_call() {
    // The `user_id_filter = Some(_)` call is an authoritative
    // existence check (see SDK doc on `ListUsersRequest::user_id_filter`).
    // Forwarding `skip > 0` to the provider could skip past the
    // matching row and turn the existence check into a false negative
    // (downstream feature-user-groups would think the user does not
    // exist). The service guard at `service.rs:451` rejects this
    // combination at the AM boundary so the misuse surfaces as HTTP
    // 400 instead of silent miscorrelation. Pin the guard so a future
    // refactor that moves or removes it surfaces here.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x55);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let user_id = Uuid::from_u128(0xA1);
    let paginated = UserPagination::new(50, 10).expect("top=50 is valid");
    let err = svc
        .list_users(&scope(), tenant_id, Some(user_id), paginated)
        .await
        .expect_err("user_id_filter + skip>0 must reject at the AM boundary");
    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("skip MUST be 0"),
                "validation detail MUST name the offending invariant; got: {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(
        idp.list_call_count(),
        0,
        "AM-side guard MUST short-circuit before any IdP call"
    );
}

#[tokio::test]
async fn list_users_with_user_id_filter_and_zero_skip_passes_through() {
    // Happy-path counterpart to the rejection test: `skip = 0` is the
    // valid combo with `user_id_filter` and must reach the IdP.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x56);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let user_id = Uuid::from_u128(0xA2);
    let _ = svc
        .list_users(&scope(), tenant_id, Some(user_id), filter_pagination())
        .await
        .expect("user_id_filter + skip=0 must reach the IdP");
    assert_eq!(idp.list_call_count(), 1);
}

#[tokio::test]
async fn list_users_with_user_id_filter_and_top_gt_one_rejects_validation_no_idp_call() {
    // Existence-check semantics require `top = 1` when a filter is
    // set; an oversized `top` would forward to a vendor that ignores
    // the filter, returning up to `top` unrelated rows, and surface
    // the caller-side bug as `Internal` (HTTP 500) downstream
    // instead of catching it at the AM seam.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x57);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let user_id = Uuid::from_u128(0xA3);
    let err = svc
        .list_users(&scope(), tenant_id, Some(user_id), pagination())
        .await
        .expect_err("user_id_filter + top>1 must reject at the AM boundary");
    match err {
        DomainError::Validation { detail } => assert!(
            detail.contains("top MUST be 1"),
            "validation detail MUST name the offending invariant; got: {detail}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(idp.list_call_count(), 0, "must not reach the IdP");
}

#[tokio::test]
async fn provision_user_rejects_oversized_username_no_idp_call() {
    // AM-side cap of 255 characters fires before the IdP round-trip
    // so the provider never sees megabyte-scale identifiers. This
    // guard is the load-bearing fallback when the GTS user schema
    // is not yet registered (no DB CHECK exists for users).
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x60);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let oversized = "a".repeat(256);
    // Username-only payload: leave `email` / `display_name` / `avatar_url`
    // unset so the oversized-profile-field guard cannot fire first and
    // mask the username-specific cap.
    let p = NewUserPayload::new(oversized);
    let err = svc
        .provision_user(&scope(), tenant_id, p, requester())
        .await
        .expect_err("256-char username must reject");
    match err {
        DomainError::Validation { detail } => assert!(
            detail.contains("username") && detail.contains("255 characters"),
            "validation detail MUST name the username cap; got: {detail}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(idp.create_call_count(), 0, "must not reach the IdP");
}

#[tokio::test]
async fn provision_user_rejects_whitespace_only_username_no_idp_call() {
    // `"   "` passes the schema's `minLength: 1` but is semantically
    // empty for a login identifier — caught explicitly at the AM
    // service layer so two callers writing `"alice"` and
    // `"  alice  "` cannot create one or two users depending on
    // vendor whitespace semantics.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x61);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    // Username-only payload: leave the optional profile fields unset
    // so a sibling guard cannot fire first and mask the username-
    // specific "all-whitespace" check.
    let p = NewUserPayload::new("   ");
    let err = svc
        .provision_user(&scope(), tenant_id, p, requester())
        .await
        .expect_err("whitespace-only username must reject");
    match err {
        DomainError::Validation { detail } => assert!(
            detail.contains("all-whitespace"),
            "validation detail MUST name the offending invariant; got: {detail}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(idp.create_call_count(), 0, "must not reach the IdP");
}

#[tokio::test]
async fn provision_user_rejects_oversized_profile_fields_no_idp_call() {
    // Defence-in-depth caps on `email`, `display_name`, `avatar_url`
    // run AFTER tenant guard but BEFORE GTS round-trip / IdP call so
    // megabyte-scale optional fields don't reach the provider when
    // the GTS user schema is not registered.
    let tenants = Arc::new(FakeTenantRepo::new());
    let tenant_id = Uuid::from_u128(0x62);
    seed_tenant(&tenants, tenant_id, None, TenantStatus::Active, "acme");
    let idp = Arc::new(FakeIdpUserProvisioner::new());
    let svc = make_service(tenants, idp.clone());

    let oversized = "a".repeat(256);

    let p_email = NewUserPayload::new("alice").with_email(oversized.clone());
    let err = svc
        .provision_user(&scope(), tenant_id, p_email, requester())
        .await
        .expect_err("oversized email must reject");
    assert!(
        matches!(&err, DomainError::Validation { detail } if detail.contains("email")),
        "expected Validation naming email; got: {err:?}"
    );

    let p_display = NewUserPayload::new("alice").with_display_name(oversized.clone());
    let err = svc
        .provision_user(&scope(), tenant_id, p_display, requester())
        .await
        .expect_err("oversized display_name must reject");
    assert!(
        matches!(&err, DomainError::Validation { detail } if detail.contains("display_name")),
        "expected Validation naming display_name; got: {err:?}"
    );

    let p_avatar = NewUserPayload::new("alice").with_avatar_url(oversized);
    let err = svc
        .provision_user(&scope(), tenant_id, p_avatar, requester())
        .await
        .expect_err("oversized avatar_url must reject");
    assert!(
        matches!(&err, DomainError::Validation { detail } if detail.contains("avatar_url")),
        "expected Validation naming avatar_url; got: {err:?}"
    );

    assert_eq!(idp.create_call_count(), 0, "no IdP call on any reject path");
}
