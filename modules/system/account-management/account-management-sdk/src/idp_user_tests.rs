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
fn tenant_context_new_without_type_carries_inputs_verbatim() {
    let id = Uuid::from_u128(0x42);
    let ctx = TenantContext::new(id, "acme", None);
    assert_eq!(ctx.tenant_id, id);
    assert_eq!(ctx.tenant_name, "acme");
    assert!(
        ctx.tenant_type.is_none(),
        "`new(.., None)` MUST leave tenant_type as None"
    );
}

#[test]
fn tenant_context_new_with_tenant_type_populates_field() {
    let id = Uuid::from_u128(0x43);
    let tenant_type =
        gts::GtsSchemaId::new("gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~");
    let ctx = TenantContext::new(id, "acme", Some(tenant_type.clone()));
    assert_eq!(ctx.tenant_id, id);
    assert_eq!(ctx.tenant_name, "acme");
    assert_eq!(ctx.tenant_type.as_ref(), Some(&tenant_type));
}

#[test]
fn tenant_context_serde_skips_absent_tenant_type() {
    // `tenant_type = None` is the default-and-most-common shape
    // (test fakes, dev deployments without types-registry); make
    // sure the wire payload stays minimal in that case.
    let ctx = TenantContext::new(Uuid::from_u128(0x44), "acme", None);
    let json = serde_json::to_value(&ctx).expect("serialise");
    let obj = json.as_object().expect("object");
    assert!(obj.contains_key("tenant_id"));
    assert!(obj.contains_key("tenant_name"));
    assert!(
        !obj.contains_key("tenant_type"),
        "absent tenant_type MUST NOT appear on the wire"
    );

    let with_type = TenantContext::new(
        Uuid::from_u128(0x44),
        "acme",
        Some(gts::GtsSchemaId::new(
            "gts.cf.core.am.tenant_type.v1~cf.core.am.x.v1~",
        )),
    );
    let json = serde_json::to_value(&with_type).expect("serialise");
    assert!(
        json.get("tenant_type").is_some(),
        "populated tenant_type MUST surface on the wire"
    );
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
fn user_operation_failure_detail_and_display() {
    let f = UserOperationFailure::Unavailable {
        detail: "timeout".into(),
    };
    assert_eq!(f.detail(), "timeout");
    // Same `"<metric_label>: <detail>"` shape as the sibling `IdP`
    // failure enums in `crate::idp` so audit / structured-log
    // consumers see a uniform format across tenant and user ops.
    assert_eq!(f.to_string(), "unavailable: timeout");
    let f2 = UserOperationFailure::Rejected {
        detail: "dup username".into(),
    };
    assert_eq!(f2.to_string(), "rejected: dup username");
}

#[test]
fn user_operation_failure_implements_std_error_trait() {
    let f = UserOperationFailure::UnsupportedOperation { detail: "x".into() };
    let _: &dyn core::error::Error = &f;
}

#[test]
fn deprovision_user_outcome_variants_are_distinguishable() {
    assert_ne!(
        DeprovisionUserOutcome::Removed,
        DeprovisionUserOutcome::NotFoundInTenant
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
    assert_eq!(valid.skip(), 100);
}

#[test]
fn user_pagination_new_rejects_top_above_max() {
    // `top` exactly at the cap is accepted.
    let at_cap =
        UserPagination::new(UserPagination::MAX_TOP, 0).expect("top == MAX_TOP must be accepted");
    assert_eq!(at_cap.top(), UserPagination::MAX_TOP);

    // `top` one past the cap is rejected with the structured error
    // (caller can format `requested` / `max` for the audit envelope).
    assert_eq!(
        UserPagination::new(UserPagination::MAX_TOP + 1, 0).unwrap_err(),
        UserPaginationError::TopExceedsMax {
            requested: UserPagination::MAX_TOP + 1,
            max: UserPagination::MAX_TOP
        }
    );

    // `u32::MAX` is the realistic abuse case — a caller forwarding an
    // unvalidated wire value MUST NOT reach the `IdP` plugin layer.
    assert_eq!(
        UserPagination::new(u32::MAX, 0).unwrap_err(),
        UserPaginationError::TopExceedsMax {
            requested: u32::MAX,
            max: UserPagination::MAX_TOP
        }
    );
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
fn user_pagination_deserialize_uses_default_top_when_absent() {
    // Wire payload omits `top` (a common REST query like `?skip=10`).
    // Without `#[serde(default = "UserPagination::default_top")]` on
    // `RawUserPagination::top`, this would fail deserialization with
    // "missing field `top`" — contradicting the documented default.
    let only_skip = serde_json::json!({"skip": 10});
    let parsed: UserPagination =
        serde_json::from_value(only_skip).expect("missing top must use the documented default");
    assert_eq!(parsed.top(), UserPagination::DEFAULT_TOP);
    assert_eq!(parsed.skip(), 10);

    let empty = serde_json::json!({});
    let parsed: UserPagination =
        serde_json::from_value(empty).expect("empty object must use both defaults");
    assert_eq!(parsed.top(), UserPagination::DEFAULT_TOP);
    assert_eq!(parsed.skip(), 0);
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
    assert_eq!(parsed.skip(), 5);
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
