//! SDK-level unit tests for the user-operations contract types.
//!
//! Cover the small surface owned by the SDK alone: constructor
//! invariants, metric-label stability, and serde round-trips on the
//! published projection / payload shapes. Plugin behaviour is tested
//! at the impl-side seams (AM `UserService` against
//! `FakeIdpUserProvisioner`).

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test helpers")]

use super::*;

#[test]
fn tenant_context_new_carries_inputs_verbatim() {
    let id = Uuid::from_u128(0x42);
    let ctx = TenantContext::new(id, "acme");
    assert_eq!(ctx.tenant_id, id);
    assert_eq!(ctx.tenant_name, "acme");
}

#[test]
fn user_operation_failure_metric_labels_are_stable() {
    assert_eq!(
        UserOperationFailure::Unavailable { detail: "x".into() }.as_metric_label(),
        "unavailable"
    );
    assert_eq!(
        UserOperationFailure::UnsupportedOperation { detail: "x".into() }.as_metric_label(),
        "unsupported_operation"
    );
    assert_eq!(
        UserOperationFailure::Rejected { detail: "x".into() }.as_metric_label(),
        "rejected"
    );
}

#[test]
fn delete_user_outcome_variants_are_distinguishable() {
    assert_ne!(
        DeleteUserOutcome::Removed,
        DeleteUserOutcome::NotFoundInTenant
    );
}

#[test]
fn user_projection_serde_roundtrip_matches_published_schema() {
    let id = Uuid::from_u128(0x1234_5678_9ABC);
    let projection = UserProjection {
        id,
        username: "alice".into(),
        email: Some("alice@example.com".into()),
        display_name: Some("Alice Example".into()),
        avatar_url: Some("https://example.com/a.png".into()),
        attributes: None,
    };
    let json = serde_json::to_value(&projection).expect("serialise");
    // Required schema keys present; absent optional `attributes` is
    // skipped so the wire shape stays minimal.
    assert!(json.get("id").is_some());
    assert!(json.get("username").is_some());
    assert!(json.get("email").is_some());
    assert!(json.get("attributes").is_none());

    let back: UserProjection = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back.id, projection.id);
    assert_eq!(back.username, projection.username);
    assert_eq!(back.email, projection.email);
    assert_eq!(back.display_name, projection.display_name);
    assert_eq!(back.avatar_url, projection.avatar_url);
    assert!(back.attributes.is_none());
}

#[test]
fn user_pagination_new_rejects_zero_top() {
    assert_eq!(
        UserPagination::new(0, 0).unwrap_err(),
        UserPaginationError::TopMustBePositive
    );
    let valid = UserPagination::new(25, 100).expect("top=25 is valid");
    assert_eq!(valid.top(), 25);
    assert_eq!(valid.skip, 100);
}

#[test]
fn user_pagination_default_uses_default_top_not_zero() {
    let p = UserPagination::default();
    assert_eq!(p.top(), UserPagination::DEFAULT_TOP);
    assert!(
        p.top() > 0,
        "Default::default() MUST NOT yield top=0 (would silently empty list_users \
         existence checks for providers that honor literal 0)"
    );
}

#[test]
fn user_pagination_deserialize_rejects_zero_top() {
    // The wire path (REST query string, plugin RPC, etc.) routes
    // through `RawUserPagination` + `TryFrom` so the same `top > 0`
    // invariant is enforced on every deserialisation input.
    let bad = serde_json::json!({"top": 0, "skip": 0});
    assert!(
        serde_json::from_value::<UserPagination>(bad).is_err(),
        "top=0 MUST fail to deserialise"
    );
    let good = serde_json::json!({"top": 10, "skip": 5});
    let parsed: UserPagination = serde_json::from_value(good).expect("top=10 is valid");
    assert_eq!(parsed.top(), 10);
    assert_eq!(parsed.skip, 5);
}

#[test]
fn user_projection_attributes_must_be_a_json_object() {
    // Schema declares `attributes: {"type": "object"}`; the typed
    // `UserAttributes = BTreeMap<String, Value>` makes a non-object
    // payload (integer, array, string) a deserialisation error rather
    // than silently widening the shape.
    let with_object = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "username": "alice",
        "attributes": {"role": "admin", "seat": 7}
    });
    let parsed: UserProjection =
        serde_json::from_value(with_object).expect("object attributes deserialise");
    let attrs = parsed.attributes.expect("attributes present");
    assert_eq!(
        attrs.get("role").and_then(serde_json::Value::as_str),
        Some("admin")
    );

    let with_array = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "username": "alice",
        "attributes": [1, 2, 3]
    });
    assert!(
        serde_json::from_value::<UserProjection>(with_array).is_err(),
        "non-object attributes payloads MUST fail to deserialise"
    );
}

#[test]
fn new_user_payload_serde_skips_absent_optionals() {
    let payload = NewUserPayload {
        username: "bob".into(),
        email: None,
        display_name: None,
        avatar_url: None,
        attributes: None,
    };
    let json = serde_json::to_value(&payload).expect("serialise");
    let map = json.as_object().expect("json object");
    assert!(map.contains_key("username"));
    assert!(!map.contains_key("email"));
    assert!(!map.contains_key("attributes"));
}
