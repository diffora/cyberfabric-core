//! Tests for the SDK tenant input/output contract.

use super::*;

#[test]
fn list_children_query_rejects_zero_top() {
    let err =
        ListChildrenQuery::new(uuid::Uuid::nil(), None, 0, 0).expect_err("top=0 must be rejected");
    assert_eq!(err, ListChildrenQueryError::TopMustBePositive);
}

#[test]
fn list_children_query_accepts_sdk_visible_filters() {
    let q = ListChildrenQuery::new(
        uuid::Uuid::nil(),
        Some(vec![
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::Deleted,
        ]),
        10,
        0,
    )
    .expect("sdk-visible filter accepted");
    assert_eq!(q.status_filter().expect("filter").len(), 3);
}

#[test]
fn list_children_query_accepts_none_filter() {
    let q = ListChildrenQuery::new(uuid::Uuid::nil(), None, 10, 0).expect("none accepted");
    assert!(q.status_filter().is_none());
    assert_eq!(q.parent_id, uuid::Uuid::nil());
    assert_eq!(q.top, 10);
    assert_eq!(q.skip, 0);
}

#[test]
fn tenant_update_default_is_empty() {
    let u = TenantUpdate::default();
    assert!(u.is_empty());
}

#[test]
fn tenant_update_with_name_is_not_empty() {
    let u = TenantUpdate {
        name: Some("x".into()),
        ..Default::default()
    };
    assert!(!u.is_empty());
}

#[test]
fn tenant_update_with_status_is_not_empty() {
    let u = TenantUpdate {
        status: Some(TenantStatus::Active),
        ..Default::default()
    };
    assert!(!u.is_empty());
}
