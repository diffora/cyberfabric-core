//! GTS-runtime payload validation.
//!
//! AM resource shapes (`tenant`, `user`) are pinned by JSON Schemas
//! published under `modules/system/account-management/docs/schemas/`
//! and registered in the GTS Types Registry at deployment time. This
//! module is the single AM-side seam that fetches a resolved schema
//! from `TypesRegistryClient` and runs `jsonschema::validator_for`
//! against the supplied field values — adapting the
//! `cf-resource-group::domain::validation::validate_metadata_via_gts`
//! pattern to AM's needs with one deliberate divergence: AM maps a
//! non-not-found `TypesRegistryError` to
//! [`DomainError::ServiceUnavailable`] (HTTP 503) rather than
//! `DomainError::validation` (HTTP 400). A registry outage is an
//! infrastructure event, not a payload problem, and the 503 envelope
//! lets clients distinguish "your input is bad" from "our dependency
//! is sick" without reading the detail string.
//!
//! Unlike the resource-group helper, AM validates per-property
//! (`username`, `name`, etc.) rather than against the full instance
//! schema. The published `gts.cf.core.am.user.v1~` and
//! `gts.cf.core.am.tenant.v1~` schemas describe the resource as
//! seen on read (with required identifiers like `id`), but the
//! create-payload shapes deliberately omit those server-assigned
//! fields. Validating per-property keeps the structural bounds
//! authoritative without forcing synthetic `id` placeholders that
//! couple the helper to the schema's `required` list.
//!
//! Service layers MUST call into this module instead of hardcoding
//! length / format constants at the call site so the schema files
//! remain the single source of truth. AM business rules that are
//! *wider* than the JSON Schema (e.g. "username MUST not be
//! all-whitespace" — which the schema's `minLength: 1` does not
//! reject) stay in the service layer; this module only enforces the
//! structural contract.
//!
//! # Behaviour when a schema is not registered
//!
//! Mirrors the resource-group helper: if the registry has no entry
//! for the type id, the helper returns `Ok(())` and the AM service
//! layer falls through to its own AM-specific guards (trim+empty,
//! tenant-existence, etc.). This keeps deployments that have not yet
//! registered the schema booting; once the schema is registered the
//! same code path becomes load-bearing without touching callers.
//!
//! Failures fall into three categories:
//! * `TypesRegistryError::GtsTypeSchemaNotFound` for the AM-owned
//!   resource schemas (`validate_new_user_payload_via_gts`,
//!   `validate_tenant_name_via_gts`) → `Ok(())` (schema not registered
//!   yet; AM-side guards + DB CHECK constraints remain authoritative).
//! * Other `TypesRegistryError` (transport / availability) →
//!   [`DomainError::ServiceUnavailable`] (the registry is a hard
//!   dependency declared in `module.rs::deps`; treat outages
//!   uniformly with the rest of the AM-on-registry path).
//! * Schema returned but `jsonschema::validator_for` rejects it →
//!   [`DomainError::Internal`] (catalog drift — operator action
//!   required).
//! * Instance fails validation against the schema →
//!   [`DomainError::Validation`] (HTTP 400 — the client can retry
//!   with a corrected payload).
//!
//! # Plugin-private metadata is opaque to AM
//!
//! Earlier revisions exposed `validate_provision_input_metadata_via_gts`
//! and `validate_provision_metadata_entries_via_gts` so AM could
//! schema-check both caller-supplied provisioning metadata and the
//! payload the `IdP` plugin returned from
//! `provision_tenant`. Both were removed when AM's contract with the
//! plugin was reshaped to treat plugin metadata as a fully opaque
//! blob persisted in `tenant_idp_metadata` and echoed back on every
//! subsequent `IdP` call. The plugin owns the shape (input and output)
//! end-to-end; AM does not interpret it.

use account_management_sdk::NewUser;
use serde_json::Value;
use types_registry_sdk::{TypesRegistryClient, TypesRegistryError};

use crate::domain::error::DomainError;

/// GTS type id of the Account Management user resource. Pinned to the
/// same string the published JSON Schema declares as its `$id`.
pub(crate) const USER_TYPE_ID: &str = "gts.cf.core.am.user.v1~";

/// GTS type id of the Account Management tenant resource. Pinned to
/// the same string the published JSON Schema declares as its `$id`.
pub(crate) const TENANT_TYPE_ID: &str = "gts.cf.core.am.tenant.v1~";

/// Validate the structural fields of a [`NewUser`] against the
/// registered `gts.cf.core.am.user.v1~` schema.
///
/// The schema describes the FULL user projection (`id`, `username`,
/// `email`, `display_name`, `attributes`) and pins
/// `required: ["id", "username"]` because `id` is the IdP-issued
/// authoritative identifier on read. The create payload deliberately
/// omits `id` (the `IdP` assigns it on success), so we cannot validate
/// `NewUser` as a full instance — that would always fail the
/// `required` rule. Instead, fetch the schema once and run each
/// supplied STRING field against the matching property sub-schema; this
/// keeps the structural bounds (`minLength`, `maxLength`, `format`)
/// authoritative without forcing a synthetic `id`.
///
/// `attributes` is intentionally NOT validated here. The published
/// schema's `{"type": "object", "additionalProperties": true}` is
/// already enforced at the SDK boundary by the Rust type
/// (`Option<UserAttributes>`, a string-keyed `Value` map), and the
/// helper's per-property strategy is shaped for string sub-schemas
/// (`Value::String` round-trip); routing the map through
/// `validate_property_value` would require a different shape.
/// Response-side validation of the IdP-returned `User` is
/// intentionally NOT performed: AM trusts the plugin's published
/// contract, and a fail-closed response-side gate would either
/// break listings on a single drifted row or invent phantom-absent
/// users — both worse than the gap they would close.
///
/// AM-business rules wider than the JSON Schema (e.g. "username MUST
/// not be all-whitespace") stay in the calling service.
///
/// # Errors
///
/// See module-level docs.
pub async fn validate_new_user_payload_via_gts(
    payload: &NewUser,
    types_registry: &dyn TypesRegistryClient,
) -> Result<(), DomainError> {
    let Some(properties) = lookup_effective_properties(USER_TYPE_ID, types_registry).await? else {
        // Schema not registered for `gts.cf.core.am.user.v1~`. Unlike
        // the tenant create path, user operations have NO storage-side
        // fallback (`cpt-cf-account-management-constraint-no-user-storage`
        // — AM never persists users), so a missing schema would
        // otherwise turn into environment-dependent acceptance:
        // arbitrary-length / malformed fields could flow straight
        // through to the IdP. Run a minimal local validator here so
        // the AM boundary remains a deterministic gate even when the
        // registry is mid-deploy. The service layer
        // (`crate::domain::user::service`) ALSO applies these caps;
        // duplicating them here makes this function self-contained,
        // so a future call site cannot accidentally bypass the
        // boundary by skipping the service layer.
        return validate_new_user_payload_local_fallback(payload);
    };
    validate_property_value(
        USER_TYPE_ID,
        "username",
        &Value::String(payload.username.clone()),
        &properties,
    )?;
    if let Some(email) = payload.email.as_deref() {
        validate_property_value(
            USER_TYPE_ID,
            "email",
            &Value::String(email.to_owned()),
            &properties,
        )?;
    }
    if let Some(display_name) = payload.display_name.as_deref() {
        validate_property_value(
            USER_TYPE_ID,
            "display_name",
            &Value::String(display_name.to_owned()),
            &properties,
        )?;
    }
    Ok(())
}

/// Per-field upper bound applied by [`validate_new_user_payload_local_fallback`]
/// when the `gts.cf.core.am.user.v1~` schema is not registered. Mirrors
/// `crate::domain::user::service::MAX_USERNAME_CHARS` /
/// `MAX_PROFILE_FIELD_CHARS` (both 255) so the boundary cap is uniform
/// whether the validation flows through the schema-backed path or the
/// schema-missing fallback. Counts Unicode scalars to match the
/// schema's `maxLength` semantics.
const LOCAL_USER_FIELD_MAX_CHARS: usize = 255;

/// Minimal local validator applied when the registry does not have
/// `gts.cf.core.am.user.v1~`. Per-field upper bound only; no format
/// checks (those vary by schema and would diverge from the registered-
/// schema gate). Failing closed on oversize is enough to prevent
/// arbitrary-length payloads from reaching the `IdP` plugin when the
/// boundary is in degraded validation mode.
fn validate_new_user_payload_local_fallback(payload: &NewUser) -> Result<(), DomainError> {
    fn cap(field: &str, value: &str) -> Result<(), DomainError> {
        if value.chars().count() > LOCAL_USER_FIELD_MAX_CHARS {
            return Err(DomainError::Validation {
                detail: format!(
                    "user payload field `{field}` exceeds the \
                     {LOCAL_USER_FIELD_MAX_CHARS}-character AM-boundary cap \
                     (`gts.cf.core.am.user.v1~` not registered; fallback cap \
                     is defence-in-depth)"
                ),
            });
        }
        Ok(())
    }
    cap("username", &payload.username)?;
    if let Some(email) = payload.email.as_deref() {
        cap("email", email)?;
    }
    if let Some(display_name) = payload.display_name.as_deref() {
        cap("display_name", display_name)?;
    }
    Ok(())
}

/// Validate a tenant `name` against the `name` sub-schema of the
/// registered `gts.cf.core.am.tenant.v1~` (`minLength: 1, maxLength:
/// 255`).
///
/// # Errors
///
/// See module-level docs.
pub async fn validate_tenant_name_via_gts(
    name: &str,
    types_registry: &dyn TypesRegistryClient,
) -> Result<(), DomainError> {
    let Some(properties) = lookup_effective_properties(TENANT_TYPE_ID, types_registry).await?
    else {
        return Ok(());
    };
    validate_property_value(
        TENANT_TYPE_ID,
        "name",
        &Value::String(name.to_owned()),
        &properties,
    )
}

/// Fetch the effective property map for `type_id`, returning `None`
/// when the schema is not registered (so callers can short-circuit
/// to AM-side guards). See module-level docs for the failure-mode
/// contract on other registry errors.
async fn lookup_effective_properties(
    type_id: &'static str,
    types_registry: &dyn TypesRegistryClient,
) -> Result<Option<std::collections::BTreeMap<String, Value>>, DomainError> {
    match types_registry.get_type_schema(type_id).await {
        Ok(schema) => Ok(Some(schema.effective_properties())),
        Err(TypesRegistryError::GtsTypeSchemaNotFound(_)) => Ok(None),
        Err(err) => Err(DomainError::service_unavailable(format!(
            "GTS type schema lookup failed for `{type_id}`: {err}"
        ))),
    }
}

/// Compile the property sub-schema for `field_name` and validate
/// `field_value` against it.
///
/// A field that has no entry in the schema's `properties` map is
/// treated as **catalog drift**, not as "this field is unconstrained".
/// Every caller passes a hardcoded field name (`name`, `username`,
/// `email`, ...) that AM expects the published schema to declare;
/// a missing entry means the deployed schema is stale or
/// misregistered relative to the AM build. Surfacing this as
/// `Internal` (HTTP 500) makes the catalog-vs-code skew visible to
/// operators instead of silently disabling validation for the
/// drifted field and persisting / forwarding out-of-contract data.
fn validate_property_value(
    type_id: &'static str,
    field_name: &str,
    field_value: &Value,
    properties: &std::collections::BTreeMap<String, Value>,
) -> Result<(), DomainError> {
    let Some(field_schema) = properties.get(field_name) else {
        return Err(DomainError::Internal {
            diagnostic: format!(
                "GTS schema `{type_id}` does not declare property `{field_name}` (catalog drift: \
                 deployed schema is stale or misregistered relative to the AM build — the field \
                 is hardcoded by the AM service layer and MUST be present in the published \
                 schema's `properties` map)"
            ),
            cause: None,
        });
    };
    let validator =
        jsonschema::validator_for(field_schema).map_err(|err| DomainError::Internal {
            diagnostic: format!(
                "GTS schema `{type_id}` property `{field_name}` is not a valid JSON Schema \
             (catalog drift): {err}"
            ),
            cause: None,
        })?;
    let errors: Vec<String> = validator
        .iter_errors(field_value)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(DomainError::Validation {
            detail: format!(
                "field `{field_name}` violates `{type_id}` schema: {}",
                errors.join("; ")
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "gts_validation_tests.rs"]
mod gts_validation_tests;
