//! Unit tests for [`super::validate_new_user_payload_via_gts`] and
//! [`super::validate_tenant_name_via_gts`].
//!
//! Pin the documented failure-mode arms (mirrors the production
//! module doc on `gts_validation.rs`):
//!
//! 1. Schema not registered (`TypesRegistryError::GtsTypeSchemaNotFound`)
//!    against either AM-OWNED schema → `Ok(())` (AM-side guards +
//!    DB CHECK constraints remain authoritative).
//! 2. Other `TypesRegistryError` (transport / availability) →
//!    `DomainError::ServiceUnavailable`.
//! 3. Schema returned but `jsonschema::validator_for` rejects it
//!    (catalog drift) → `DomainError::Internal` — schema published
//!    by the deploy bundle is not a valid JSON Schema; operator
//!    action required. Exercised implicitly by the production
//!    `Internal` arm in the helpers.
//! 4. Schema returned + instance fails validation →
//!    `DomainError::Validation` (HTTP 400 — the client can retry
//!    with a corrected payload).
//! 5. Schema returned + valid instance → `Ok(())` (happy path).
//!
//! `MockTypesRegistryClient::with_type_schemas` is the seam used to
//! pin the registered-schema path; it pre-links the chain so
//! `effective_properties()` returns the merged property map the
//! helper validates against.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]

use account_management_sdk::NewUser;
use async_trait::async_trait;
use serde_json::{Value, json};
use types_registry_sdk::testing::MockTypesRegistryClient;
use types_registry_sdk::{
    GtsInstance, GtsTypeId, GtsTypeSchema, RegisterResult, TypesRegistryClient, TypesRegistryError,
};
use uuid::Uuid;

use crate::domain::error::DomainError;

// ---- helpers -------------------------------------------------------

fn user_payload(username: &str) -> NewUser {
    NewUser::new(username.to_owned())
}

fn user_schema_with_username_max(max_chars: usize) -> GtsTypeSchema {
    let body = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "username"],
        "properties": {
            "id": { "type": "string", "format": "uuid" },
            "username": {
                "type": "string",
                "minLength": 1,
                "maxLength": max_chars,
            },
            "email": { "type": "string", "format": "email" },
            "display_name": { "type": "string", "minLength": 1, "maxLength": 255 },
            "avatar_url": { "type": "string", "format": "uri" },
            "attributes": { "type": "object", "additionalProperties": true },
        },
    });
    GtsTypeSchema::try_new(GtsTypeId::new(super::USER_TYPE_ID), body, None, None)
        .expect("synthetic user schema is valid")
}

fn tenant_schema_with_name_max(max_chars: usize) -> GtsTypeSchema {
    let body = json!({
        "type": "object",
        "additionalProperties": true,
        "required": ["id", "name"],
        "properties": {
            "id": { "type": "string", "format": "uuid" },
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": max_chars,
            },
            "parent_id": { "type": ["string", "null"], "format": "uuid" },
        },
    });
    GtsTypeSchema::try_new(GtsTypeId::new(super::TENANT_TYPE_ID), body, None, None)
        .expect("synthetic tenant schema is valid")
}

/// Registry stub: every read returns `ServiceUnavailable`. Used to
/// pin the transport-error arm of the GTS-validation helper without
/// reaching for the heavier `MockTypesRegistryClient` (which always
/// returns `GtsTypeSchemaNotFound` for unknown ids and offers no
/// inject-error seam).
///
/// Methods that the helper does not exercise return empty / not-found
/// to keep the impl narrow; a full `TypesRegistryClient` mock lives in
/// `types-registry-sdk::testing`.
#[derive(Debug, Default)]
struct UnavailableRegistry;

fn unavailable() -> TypesRegistryError {
    TypesRegistryError::ServiceUnavailable {
        message: "registry transport down (test stub)".to_owned(),
        retry_after: std::time::Duration::from_secs(0),
    }
}

#[async_trait]
impl TypesRegistryClient for UnavailableRegistry {
    async fn register(
        &self,
        _entities: Vec<Value>,
    ) -> Result<Vec<RegisterResult>, TypesRegistryError> {
        Err(unavailable())
    }
    async fn register_type_schemas(
        &self,
        _schemas: Vec<Value>,
    ) -> Result<Vec<RegisterResult>, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_type_schema(&self, _type_id: &str) -> Result<GtsTypeSchema, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_type_schema_by_uuid(
        &self,
        _type_uuid: Uuid,
    ) -> Result<GtsTypeSchema, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_type_schemas(
        &self,
        _ids: Vec<String>,
    ) -> std::collections::HashMap<String, Result<GtsTypeSchema, TypesRegistryError>> {
        std::collections::HashMap::new()
    }
    async fn get_type_schemas_by_uuid(
        &self,
        _ids: Vec<Uuid>,
    ) -> std::collections::HashMap<Uuid, Result<GtsTypeSchema, TypesRegistryError>> {
        std::collections::HashMap::new()
    }
    async fn list_type_schemas(
        &self,
        _query: types_registry_sdk::TypeSchemaQuery,
    ) -> Result<Vec<GtsTypeSchema>, TypesRegistryError> {
        Ok(Vec::new())
    }
    async fn register_instances(
        &self,
        _instances: Vec<Value>,
    ) -> Result<Vec<RegisterResult>, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_instance(&self, _id: &str) -> Result<GtsInstance, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_instance_by_uuid(&self, _uuid: Uuid) -> Result<GtsInstance, TypesRegistryError> {
        Err(unavailable())
    }
    async fn get_instances(
        &self,
        _ids: Vec<String>,
    ) -> std::collections::HashMap<String, Result<GtsInstance, TypesRegistryError>> {
        std::collections::HashMap::new()
    }
    async fn get_instances_by_uuid(
        &self,
        _ids: Vec<Uuid>,
    ) -> std::collections::HashMap<Uuid, Result<GtsInstance, TypesRegistryError>> {
        std::collections::HashMap::new()
    }
    async fn list_instances(
        &self,
        _query: types_registry_sdk::InstanceQuery,
    ) -> Result<Vec<GtsInstance>, TypesRegistryError> {
        Ok(Vec::new())
    }
}

// ---- validate_new_user_payload_via_gts ----------------------------

#[tokio::test]
async fn user_payload_schema_not_registered_short_circuits_to_ok() {
    let registry = MockTypesRegistryClient::new();
    let payload = user_payload("alice");
    super::validate_new_user_payload_via_gts(&payload, &registry)
        .await
        .expect("schema-not-found short-circuits to Ok");
}

#[tokio::test]
async fn user_payload_valid_username_passes_registered_schema() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([user_schema_with_username_max(255)]);
    let payload = user_payload("alice");
    super::validate_new_user_payload_via_gts(&payload, &registry)
        .await
        .expect("valid username passes the registered schema");
}

#[tokio::test]
async fn user_payload_oversized_username_rejects_with_validation() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([user_schema_with_username_max(255)]);
    let payload = user_payload(&"x".repeat(256));
    let err = super::validate_new_user_payload_via_gts(&payload, &registry)
        .await
        .expect_err("oversize username must be rejected by the registered schema");
    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("username"),
                "diagnostic must name the violating field; got: {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn user_payload_registry_transport_error_surfaces_as_service_unavailable() {
    let registry = UnavailableRegistry;
    let payload = user_payload("alice");
    let err = super::validate_new_user_payload_via_gts(&payload, &registry)
        .await
        .expect_err("registry transport error must surface");
    assert!(
        matches!(err, DomainError::ServiceUnavailable { .. }),
        "expected ServiceUnavailable, got {err:?}"
    );
}

// ---- DoS surface coverage -----------------------------------------
//
// The `attributes` field on `NewUser` is a free-form `BTreeMap<String,
// Value>` — until the deploy bundle pins a tighter schema, the JSON-
// Schema validator must walk whatever the caller submits. These tests
// pin the load-bearing boundary that aviator5 flagged on deep review:
// the validator handles megabyte-scale string values and deeply
// nested object structures without panicking, exhausting the stack,
// or hanging. If a later PR adds an AM-side cap (e.g. max
// `attributes` byte size or recursion depth), these tests flip to
// asserting `DomainError::Validation` — either outcome is acceptable;
// what's NOT acceptable is a panic / stack overflow / unbounded
// runtime, which would let a malicious caller DoS the validator.

#[tokio::test]
async fn user_payload_huge_attribute_value_does_not_panic_validator() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([user_schema_with_username_max(255)]);
    // 1 MB string in one `attributes` key. The schema declares
    // `attributes: { type: "object", additionalProperties: true }`,
    // so any object passes today; tomorrow a cap may reject it.
    let mut attrs: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    attrs.insert("biography".to_owned(), Value::String("x".repeat(1_048_576)));
    let payload = NewUser::new("alice".to_owned()).with_attributes(attrs);
    let outcome = super::validate_new_user_payload_via_gts(&payload, &registry).await;
    match outcome {
        Ok(()) | Err(DomainError::Validation { .. }) => {}
        other => {
            panic!("huge-attribute payload MUST surface either Ok or Validation; got {other:?}")
        }
    }
}

#[tokio::test]
async fn user_payload_deeply_nested_attribute_does_not_overflow_validator() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([user_schema_with_username_max(255)]);
    // Build a 256-level nested object: `{"k": {"k": ... {"k": 1}}}`.
    // 256 is well above any realistic legitimate nesting depth and
    // catches naive recursive walks before they explode the stack.
    let mut deep = Value::Number(serde_json::Number::from(1_i64));
    for _ in 0..256 {
        let mut obj = serde_json::Map::new();
        obj.insert("k".to_owned(), deep);
        deep = Value::Object(obj);
    }
    let mut attrs: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    attrs.insert("nested".to_owned(), deep);
    let payload = NewUser::new("alice".to_owned()).with_attributes(attrs);
    let outcome = super::validate_new_user_payload_via_gts(&payload, &registry).await;
    match outcome {
        Ok(()) | Err(DomainError::Validation { .. }) => {}
        other => {
            panic!("deeply-nested payload MUST surface either Ok or Validation; got {other:?}")
        }
    }
}

// ---- validate_tenant_name_via_gts ---------------------------------

#[tokio::test]
async fn tenant_name_schema_not_registered_short_circuits_to_ok() {
    let registry = MockTypesRegistryClient::new();
    super::validate_tenant_name_via_gts("acme", &registry)
        .await
        .expect("schema-not-found short-circuits to Ok");
}

#[tokio::test]
async fn tenant_name_valid_passes_registered_schema() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([tenant_schema_with_name_max(255)]);
    super::validate_tenant_name_via_gts("acme", &registry)
        .await
        .expect("valid name passes the registered schema");
}

#[tokio::test]
async fn tenant_name_oversized_rejects_with_validation() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([tenant_schema_with_name_max(255)]);
    let oversized = "x".repeat(256);
    let err = super::validate_tenant_name_via_gts(&oversized, &registry)
        .await
        .expect_err("oversize name must be rejected");
    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("name"),
                "diagnostic must name the violating field; got: {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn tenant_name_empty_rejects_with_validation() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([tenant_schema_with_name_max(255)]);
    let err = super::validate_tenant_name_via_gts("", &registry)
        .await
        .expect_err("empty name must be rejected");
    assert!(matches!(err, DomainError::Validation { .. }));
}

#[tokio::test]
async fn tenant_name_registry_transport_error_surfaces_as_service_unavailable() {
    let registry = UnavailableRegistry;
    let err = super::validate_tenant_name_via_gts("acme", &registry)
        .await
        .expect_err("registry transport error must surface");
    assert!(
        matches!(err, DomainError::ServiceUnavailable { .. }),
        "expected ServiceUnavailable, got {err:?}"
    );
}
