//! Unit tests for [`super::validate_new_user_payload_via_gts`],
//! [`super::validate_tenant_name_via_gts`],
//! [`super::validate_provision_metadata_entries_via_gts`], and
//! [`super::validate_provision_input_metadata_via_gts`].
//!
//! Pin the documented failure-mode arms (mirrors the production
//! module doc on `gts_validation.rs`):
//!
//! 1. Schema not registered (`TypesRegistryError::GtsTypeSchemaNotFound`):
//!    * Caller input against AM-OWNED schema
//!      (`validate_new_user_payload_via_gts`,
//!      `validate_tenant_name_via_gts`) → `Ok(())` (AM-side guards +
//!      DB CHECK constraints remain authoritative).
//!    * Caller input against PLUGIN-ADVERTISED schema
//!      (`validate_provision_input_metadata_via_gts`) →
//!      `DomainError::Internal` (deploy-time prerequisite — plugin
//!      advertised a schema id that the operator did not pre-register;
//!      caller cannot fix it by retrying).
//!    * IdP-produced data (`validate_provision_metadata_entries_via_gts`)
//!      → `DomainError::NotFound` qualified with the missing
//!      `schema_id` (DESIGN.md §10 deploy-time prerequisite —
//!      saga finalization fails, reaper compensates).
//! 2. Other `TypesRegistryError` (transport / availability) →
//!    `DomainError::ServiceUnavailable`.
//! 3. Schema returned but `jsonschema::validator_for` rejects it
//!    (catalog drift) → `DomainError::Internal` — schema published
//!    by the deploy bundle is not a valid JSON Schema; operator
//!    action required. Exercised implicitly by the production
//!    `Internal` arm in the helpers; no dedicated test fixture
//!    today because constructing a syntactically valid `GtsTypeSchema`
//!    with an INVALID inner JSON Schema requires bypassing the
//!    `effective_*` resolvers in `types-registry-sdk`. If those
//!    helpers gain a test seam, add a fixture here that pins the
//!    `Internal { diagnostic.contains("catalog drift") }` shape.
//! 4. Schema returned + instance fails validation:
//!     * For caller-supplied input (`validate_new_user_payload_via_gts`,
//!       `validate_tenant_name_via_gts`,
//!       `validate_provision_input_metadata_via_gts`) →
//!       `DomainError::Validation` (HTTP 400 — the client can retry
//!       with a corrected payload).
//!     * For IdP-produced data
//!       (`validate_provision_metadata_entries_via_gts`) →
//!       `DomainError::Internal` (HTTP 500 — plugin contract drift;
//!       the caller did not produce the bad value and cannot fix it
//!       by retrying). See the production module doc for the
//!       input-vs-trusted-upstream split.
//! 5. Schema returned + valid instance → `Ok(())` (happy path).
//! 6. `validate_provision_input_metadata_via_gts` normalizes `None`
//!    metadata to an empty object `{}` and validates that against the
//!    registered schema. A lenient schema with no `required`
//!    constraint accepts `{}` trivially → `Ok(())`; a schema that
//!    declares `required: [...]` rejects with `DomainError::Validation`
//!    at the AM boundary BEFORE the `IdP` call, so callers get the
//!    actionable "missing field X" diagnostic instead of a downstream
//!    plugin error masquerading as `idp_unsupported_operation`.
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

use account_management_sdk::{NewUserPayload, ProvisionMetadataEntry};
use async_trait::async_trait;
use gts::GtsSchemaId;
use serde_json::{Value, json};
use types_registry_sdk::testing::MockTypesRegistryClient;
use types_registry_sdk::{
    GtsInstance, GtsTypeId, GtsTypeSchema, RegisterResult, TypesRegistryClient, TypesRegistryError,
};
use uuid::Uuid;

use crate::domain::error::DomainError;

// ---- helpers -------------------------------------------------------

fn user_payload(username: &str) -> NewUserPayload {
    NewUserPayload::new(username.to_owned())
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

// ---- validate_provision_metadata_entries_via_gts ------------------

const METADATA_TYPE_ID: &str = "gts.cf.core.am.tenant_metadata.v1~cf.core.am.platform.v1~";

fn metadata_schema_with_max_count(max_count: u64) -> GtsTypeSchema {
    let body = json!({
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "count": {
                "type": "integer",
                "minimum": 0,
                "maximum": max_count,
            },
        },
    });
    let parent = GtsTypeSchema::derive_parent_type_id(METADATA_TYPE_ID)
        .map(|p| std::sync::Arc::new(stub_parent(p.as_ref())));
    GtsTypeSchema::try_new(GtsTypeId::new(METADATA_TYPE_ID), body, None, parent)
        .expect("synthetic metadata schema is valid")
}

fn stub_parent(type_id: &str) -> GtsTypeSchema {
    let parent = GtsTypeSchema::derive_parent_type_id(type_id)
        .map(|p| std::sync::Arc::new(stub_parent(p.as_ref())));
    GtsTypeSchema::try_new(GtsTypeId::new(type_id), json!({}), None, parent)
        .expect("synthetic parent schema is valid")
}

/// Schema that pins a single required field. Used by the
/// `provision_input_metadata_none_rejects_against_required_field_schema`
/// test to prove that omitted `provisioning_metadata` surfaces as
/// `Validation` at the AM boundary instead of being forwarded as
/// `None` to the plugin.
fn metadata_schema_with_required_field(field: &str) -> GtsTypeSchema {
    let body = json!({
        "type": "object",
        "additionalProperties": true,
        "required": [field],
        "properties": {
            field: { "type": "string", "minLength": 1 },
        },
    });
    let parent = GtsTypeSchema::derive_parent_type_id(METADATA_TYPE_ID)
        .map(|p| std::sync::Arc::new(stub_parent(p.as_ref())));
    GtsTypeSchema::try_new(GtsTypeId::new(METADATA_TYPE_ID), body, None, parent)
        .expect("synthetic required-field schema is valid")
}

fn metadata_entry(value: Value) -> ProvisionMetadataEntry {
    ProvisionMetadataEntry::new(GtsSchemaId::new(METADATA_TYPE_ID), value)
}

#[tokio::test]
async fn metadata_entries_empty_short_circuits_to_ok() {
    let registry = UnavailableRegistry;
    super::validate_provision_metadata_entries_via_gts(&[], &registry)
        .await
        .expect("empty entries short-circuits regardless of registry health");
}

#[tokio::test]
async fn metadata_entry_unknown_schema_rejects_with_not_found() {
    // Per DESIGN.md §10 (Bootstrap config table, deploy-time
    // prerequisite row): every metadata `schema_id` the IdP plugin
    // may return MUST be pre-registered in GTS. An unregistered
    // `schema_id` is a deploy-time error, not a degraded-mode
    // acceptance — fail closed with `NotFound` qualified by the
    // offending `schema_id` so the saga finalization step aborts
    // and the provisioning reaper compensates.
    let registry = MockTypesRegistryClient::new();
    let entries = [metadata_entry(json!({ "count": 9999 }))];
    let err = super::validate_provision_metadata_entries_via_gts(&entries, &registry)
        .await
        .expect_err("unknown schema MUST fail closed per DESIGN.md");
    match err {
        DomainError::NotFound { resource, detail } => {
            assert_eq!(
                resource, METADATA_TYPE_ID,
                "NotFound.resource MUST carry the unregistered schema_id, got: {resource}"
            );
            assert!(
                detail.contains(METADATA_TYPE_ID),
                "NotFound.detail SHOULD name the unregistered schema_id; got: {detail}"
            );
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn metadata_entry_valid_passes_registered_schema() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([metadata_schema_with_max_count(100)]);
    let entries = [metadata_entry(json!({ "count": 42 }))];
    super::validate_provision_metadata_entries_via_gts(&entries, &registry)
        .await
        .expect("valid metadata passes the registered schema");
}

#[tokio::test]
async fn metadata_entry_invalid_rejects_with_internal() {
    // IdP-produced metadata that fails its declared schema is plugin
    // contract drift, NOT caller input — the gate maps this to
    // `Internal` (HTTP 500) instead of `Validation` (HTTP 400) so the
    // public envelope signals "server-side problem, retry will not
    // help" rather than blaming the caller for the plugin's bad
    // output. See module-level docs for the input-vs-trusted-upstream
    // split.
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([metadata_schema_with_max_count(100)]);
    let entries = [metadata_entry(json!({ "count": 9999 }))];
    let err = super::validate_provision_metadata_entries_via_gts(&entries, &registry)
        .await
        .expect_err("entry exceeding maximum must reject");
    match err {
        DomainError::Internal { diagnostic, .. } => {
            assert!(
                diagnostic.contains(METADATA_TYPE_ID),
                "diagnostic must name the violated schema; got: {diagnostic}"
            );
        }
        other => panic!("expected Internal, got {other:?}"),
    }
}

#[tokio::test]
async fn metadata_entry_registry_transport_error_surfaces_as_service_unavailable() {
    let registry = UnavailableRegistry;
    let entries = [metadata_entry(json!({ "count": 42 }))];
    let err = super::validate_provision_metadata_entries_via_gts(&entries, &registry)
        .await
        .expect_err("registry transport error must surface");
    assert!(
        matches!(err, DomainError::ServiceUnavailable { .. }),
        "expected ServiceUnavailable, got {err:?}"
    );
}

// ---- validate_provision_input_metadata_via_gts --------------------
//
// The input-side helper is the symmetric counterpart of
// `validate_provision_metadata_entries_via_gts`: same registry seam,
// but validates CALLER input against a PLUGIN-ADVERTISED schema id.
// Failure-mode taxonomy intentionally diverges from the response-
// side helper (see production doc on the helper):
//   * unregistered advertised schema → `Internal` (deploy-time
//     prerequisite failure, not a payload problem),
//   * caller-supplied metadata violates the schema → `Validation`
//     (HTTP 400, the caller can correct and retry),
//   * `None` metadata short-circuits to `Ok(())`.

fn provision_input_schema_id() -> GtsSchemaId {
    GtsSchemaId::new(METADATA_TYPE_ID)
}

#[tokio::test]
async fn provision_input_metadata_none_validates_as_empty_object_against_lenient_schema() {
    // `None` input is normalized to an empty object and validated
    // against the registered schema. A schema with no `required`
    // constraint (the most common case for opt-in plugin-advertised
    // schemas today) accepts `{}` trivially → `Ok(())`.
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([metadata_schema_with_max_count(100)]);
    let schema_id = provision_input_schema_id();
    super::validate_provision_input_metadata_via_gts(None, &schema_id, &registry)
        .await
        .expect("None metadata validates as `{}` and a no-required schema accepts it");
}

#[tokio::test]
async fn provision_input_metadata_none_rejects_against_required_field_schema() {
    // Load-bearing contract: when the plugin's schema declares
    // `required: [...]`, omitting `metadata` MUST surface as
    // `Validation` at the AM boundary BEFORE the IdP call —
    // otherwise the plugin sees `None`, fails with a generic
    // provider error, and the caller gets a confusing
    // `idp_unsupported_operation` / `idp_unavailable` instead of
    // the actionable "missing field X" diagnostic.
    let registry = MockTypesRegistryClient::new()
        .with_type_schemas([metadata_schema_with_required_field("realm")]);
    let schema_id = provision_input_schema_id();
    let err = super::validate_provision_input_metadata_via_gts(None, &schema_id, &registry)
        .await
        .expect_err("None against a required-field schema MUST reject");
    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains("realm"),
                "Validation.detail MUST name the missing required field; got: {detail}"
            );
            assert!(
                detail.contains(METADATA_TYPE_ID),
                "Validation.detail MUST name the advertised schema_id; got: {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn provision_input_metadata_valid_passes_registered_schema() {
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([metadata_schema_with_max_count(100)]);
    let schema_id = provision_input_schema_id();
    let metadata = json!({ "count": 42 });
    super::validate_provision_input_metadata_via_gts(Some(&metadata), &schema_id, &registry)
        .await
        .expect("valid metadata passes the registered schema");
}

#[tokio::test]
async fn provision_input_metadata_invalid_rejects_with_validation() {
    // Caller-supplied input that violates the plugin-advertised schema
    // → `Validation` (HTTP 400). Diverges from the response-side
    // helper which maps the same failure to `Internal` (HTTP 500)
    // because the caller cannot fix a plugin's contract drift, but
    // CAN fix their own malformed input. The diagnostic MUST name
    // both the offending schema_id (so the caller can fetch the
    // schema for debugging) and the JSON-Schema violation list.
    let registry =
        MockTypesRegistryClient::new().with_type_schemas([metadata_schema_with_max_count(100)]);
    let schema_id = provision_input_schema_id();
    let metadata = json!({ "count": 9999 });
    let err =
        super::validate_provision_input_metadata_via_gts(Some(&metadata), &schema_id, &registry)
            .await
            .expect_err("oversize count must be rejected by the registered schema");
    match err {
        DomainError::Validation { detail } => {
            assert!(
                detail.contains(METADATA_TYPE_ID),
                "Validation.detail MUST name the advertised schema_id; got: {detail}"
            );
            assert!(
                detail.contains("provisioning_metadata"),
                "Validation.detail SHOULD identify the violating field family; got: {detail}"
            );
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn provision_input_metadata_unregistered_schema_rejects_with_internal() {
    // Plugin advertised a `provision_input_schema_id` but the operator
    // forgot to register the schema. This is a deploy-time prerequisite
    // failure (analogue of the response-side helper's `NotFound` arm),
    // but mapped to `Internal` rather than `NotFound` because the
    // caller cannot triage operator configuration via the `resource`
    // hint — the gap is upstream of the request.
    let registry = MockTypesRegistryClient::new();
    let schema_id = provision_input_schema_id();
    let metadata = json!({ "count": 1 });
    let err =
        super::validate_provision_input_metadata_via_gts(Some(&metadata), &schema_id, &registry)
            .await
            .expect_err("unregistered advertised schema MUST fail closed");
    match err {
        DomainError::Internal { diagnostic, .. } => {
            assert!(
                diagnostic.contains(METADATA_TYPE_ID),
                "Internal.diagnostic MUST name the missing schema_id; got: {diagnostic}"
            );
            assert!(
                diagnostic.contains("not registered"),
                "Internal.diagnostic SHOULD describe the registration gap; got: {diagnostic}"
            );
        }
        other => panic!("expected Internal, got {other:?}"),
    }
}

#[tokio::test]
async fn provision_input_metadata_registry_transport_error_surfaces_as_service_unavailable() {
    let registry = UnavailableRegistry;
    let schema_id = provision_input_schema_id();
    let metadata = json!({ "count": 1 });
    let err =
        super::validate_provision_input_metadata_via_gts(Some(&metadata), &schema_id, &registry)
            .await
            .expect_err("registry transport error must surface");
    assert!(
        matches!(err, DomainError::ServiceUnavailable { .. }),
        "expected ServiceUnavailable, got {err:?}"
    );
}
