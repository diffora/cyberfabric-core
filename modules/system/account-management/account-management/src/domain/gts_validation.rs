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
//! Failures fall into four categories:
//! * `TypesRegistryError::GtsTypeSchemaNotFound`:
//!     * For **caller-supplied input** validated against an AM-owned
//!       resource schema (`validate_new_user_payload_via_gts`,
//!       `validate_tenant_name_via_gts`) → `Ok(())` (schema not
//!       registered yet; AM-side guards + DB CHECK constraints
//!       remain authoritative).
//!     * For **caller-supplied input** validated against a plugin-
//!       advertised schema (`validate_provision_input_metadata_via_gts`)
//!       → [`DomainError::Internal`] qualified with the missing
//!       `schema_id`. The plugin advertised a schema via
//!       `IdpPluginClient::provision_input_schema_id`
//!       but the operator did not pre-register it; this is a deploy-
//!       time prerequisite failure (mirrors the
//!       `validate_provision_metadata_entries_via_gts` posture for
//!       IdP-side schemas), so it is `Internal` rather than
//!       `Validation` — the caller cannot fix it by retrying with a
//!       different payload.
//!     * For **IdP-produced data** (`validate_provision_metadata_entries_via_gts`)
//!       → [`DomainError::NotFound`] qualified with the missing
//!       `schema_id`. Per DESIGN.md §10 (Bootstrap config table,
//!       deploy-time prerequisite row) every metadata `schema_id`
//!       the `IdP` plugin may return MUST be pre-registered in GTS;
//!       unknown ids fail the saga finalization step so the
//!       provisioning reaper compensates instead of letting opaque
//!       rows land in `tenant_metadata` and surface through
//!       retention. The asymmetry vs caller input is intentional:
//!       caller input has a DB CHECK as a last-line guard,
//!       IdP-produced metadata has none.
//! * Other `TypesRegistryError` (transport / availability) →
//!   [`DomainError::ServiceUnavailable`] (the registry is a hard
//!   dependency declared in `module.rs::deps`; treat outages
//!   uniformly with the rest of the AM-on-registry path).
//! * Schema returned but `jsonschema::validator_for` rejects it →
//!   [`DomainError::Internal`] (catalog drift — operator action
//!   required).
//! * Instance fails validation against the schema:
//!     * For **caller-supplied input** (`validate_new_user_payload_via_gts`,
//!       `validate_tenant_name_via_gts`,
//!       `validate_provision_input_metadata_via_gts`) →
//!       [`DomainError::Validation`] (HTTP 400 — the client can
//!       retry with a corrected payload).
//!     * For **IdP-produced data** (`validate_provision_metadata_entries_via_gts`)
//!       → [`DomainError::Internal`] (HTTP 500 — plugin contract drift;
//!       the caller did not produce the bad value and cannot fix it
//!       by retrying). The split mirrors the
//!       `cf-resource-group::validate_metadata_via_gts` posture for
//!       "trusted-upstream" data.

use account_management_sdk::{NewUserPayload, ProvisionMetadataEntry};
use gts::GtsSchemaId;
use serde_json::Value;
use types_registry_sdk::{TypesRegistryClient, TypesRegistryError};

use crate::domain::error::DomainError;

/// GTS type id of the Account Management user resource. Pinned to the
/// same string the published JSON Schema declares as its `$id`.
pub(crate) const USER_TYPE_ID: &str = "gts.cf.core.am.user.v1~";

/// GTS type id of the Account Management tenant resource. Pinned to
/// the same string the published JSON Schema declares as its `$id`.
pub(crate) const TENANT_TYPE_ID: &str = "gts.cf.core.am.tenant.v1~";

/// Validate the structural fields of a [`NewUserPayload`] against the
/// registered `gts.cf.core.am.user.v1~` schema.
///
/// The schema describes the FULL user projection (`id`, `username`,
/// `email`, `display_name`, `avatar_url`, `attributes`) and pins
/// `required: ["id", "username"]` because `id` is the IdP-issued
/// authoritative identifier on read. The create payload deliberately
/// omits `id` (the `IdP` assigns it on success), so we cannot validate
/// `NewUserPayload` as a full instance — that would always fail the
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
/// Response-side validation of the IdP-returned `UserProjection` is
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
    payload: &NewUserPayload,
    types_registry: &dyn TypesRegistryClient,
) -> Result<(), DomainError> {
    let Some(properties) = lookup_effective_properties(USER_TYPE_ID, types_registry).await? else {
        // Schema not registered — caller falls back to AM-side guards.
        return Ok(());
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
    if let Some(avatar_url) = payload.avatar_url.as_deref() {
        validate_property_value(
            USER_TYPE_ID,
            "avatar_url",
            &Value::String(avatar_url.to_owned()),
            &properties,
        )?;
    }
    Ok(())
}

/// Validate every [`ProvisionMetadataEntry`] returned by the `IdP`
/// plugin against its declared `schema_id` before AM persists it via
/// `repo.activate_tenant`. Mirrors the
/// `cf-resource-group::validate_metadata_via_gts` posture: each entry
/// resolves its own derived metadata schema (descendant of
/// `gts.cf.core.am.tenant_metadata.v1~`) and the JSON-Schema
/// `iter_errors` contract gates persistence.
///
/// AM-side validation seam, NOT IdP-side. The plugin owns its own
/// produce-correct-metadata contract; this fence catches plugin bugs
/// (or a misregistered schema) before the bad payload lands in the
/// `tenant_metadata` table where retention reads it back.
///
/// Schema-not-registered for a given entry's `schema_id` is treated
/// as a **fail-closed** error per DESIGN.md §10 (Bootstrap config
/// table, deploy-time prerequisite row): "All metadata schemas that
/// the `IdP` provider may return in `ProvisionResult` entries must be
/// pre-registered in GTS before bootstrap runs. … unregistered
/// `schema_id`s are rejected with `not_found`, causing the saga
/// finalization step to fail and the provisioning reaper to
/// compensate." This is the load-bearing contract that prevents a
/// drifted / misconfigured plugin from quietly persisting opaque
/// metadata rows that retention then reads back. Diverges from the
/// per-property helpers above (which short-circuit on
/// schema-not-registered for caller-supplied input) — the
/// asymmetry is intentional: caller input has a DB CHECK as a
/// last-line guard, IdP-produced metadata has none.
///
/// # Errors
///
/// See module-level docs. `GtsTypeSchemaNotFound` produces
/// [`DomainError::NotFound`] qualified with the missing `schema_id`
/// so the saga's compensation pipeline can correlate operator
/// triage by the same identifier the provider returned.
pub async fn validate_provision_metadata_entries_via_gts(
    entries: &[ProvisionMetadataEntry],
    types_registry: &dyn TypesRegistryClient,
) -> Result<(), DomainError> {
    for entry in entries {
        let schema_id = entry.schema_id.as_ref();
        let schema = match types_registry.get_type_schema(schema_id).await {
            Ok(schema) => schema,
            // Unknown derived schema — fail closed per DESIGN.md.
            // Surfaces as `NotFound` so the canonical envelope
            // distinguishes "metadata schema id not in GTS" from
            // "schema known but entry violates it" (the latter
            // routes to `Internal` below). Emit an `am.idp` warn so
            // operators see the same signal the compensating
            // reaper consumes — log line carries the offending
            // `schema_id` for triage.
            Err(TypesRegistryError::GtsTypeSchemaNotFound(_)) => {
                tracing::warn!(
                    target: "am.idp",
                    schema_id = schema_id,
                    "GTS type schema not registered; rejecting tenant_metadata entry (saga finalization fails, reaper compensates)"
                );
                return Err(DomainError::NotFound {
                    detail: format!(
                        "IdP-returned tenant_metadata entry references unregistered GTS \
                         type schema `{schema_id}` (deploy-time prerequisite: every \
                         schema_id returned by the IdP plugin MUST be pre-registered \
                         in GTS — see DESIGN.md §10)"
                    ),
                    resource: schema_id.to_owned(),
                });
            }
            Err(err) => {
                return Err(DomainError::service_unavailable(format!(
                    "GTS type schema lookup failed for `{schema_id}`: {err}"
                )));
            }
        };
        let resolved = schema.effective_schema();
        let validator =
            jsonschema::validator_for(&resolved).map_err(|err| DomainError::Internal {
                diagnostic: format!(
                    "GTS type schema `{schema_id}` is not a valid JSON Schema (catalog drift): {err}"
                ),
                cause: None,
            })?;
        let errors: Vec<String> = validator
            .iter_errors(&entry.value)
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
            // IdP-produced metadata, not caller input — a schema
            // mismatch here is a plugin contract drift (or a
            // misregistered derived schema), NOT something the public
            // caller can correct by retrying with a different request.
            // Surface as `Internal` (HTTP 500) so the public envelope
            // signals "server-side problem, retry will not help"
            // instead of `Validation` (HTTP 400) which semantically
            // says "fix your input". Mirrors the rationale for
            // declining response-side validation on `UserProjection`
            // in `user/service.rs`: AM never wants to blame the
            // caller for the plugin's contract drift.
            return Err(DomainError::Internal {
                diagnostic: format!(
                    "IdP metadata entry violates `{schema_id}` schema: {}",
                    errors.join("; ")
                ),
                cause: None,
            });
        }
    }
    Ok(())
}

/// Validate caller-supplied `provisioning_metadata` against the JSON
/// Schema the `IdP` plugin advertises via
/// [`account_management_sdk::IdpPluginClient::provision_input_schema_id`].
///
/// Symmetric input-side counterpart of
/// [`validate_provision_metadata_entries_via_gts`]: that helper
/// validates the plugin's RETURNED metadata against each entry's
/// declared schema; this one validates the caller's INPUT metadata
/// against the plugin's single advertised request schema BEFORE the
/// `IdP` call. The point is to convert a typo / drift in caller input
/// into a clean `Validation` (HTTP 400) at the AM boundary instead of
/// letting it surface as a downstream plugin error (often `Internal`).
///
/// `None` metadata is treated as `Value::Object(Map::new())` (empty
/// object) and validated against the schema rather than
/// short-circuiting. This is the load-bearing behaviour for the
/// "reject malformed input BEFORE invoking the plugin" contract:
/// if the plugin's schema declares `required: [...]` and the
/// caller omits `metadata` entirely, AM produces a
/// `Validation` (HTTP 400) detail naming the missing fields
/// instead of forwarding `None` to the plugin and letting it
/// surface a generic provider error. Schemas with no `required`
/// constraint (or with `additionalProperties: true` and nothing
/// else) accept an empty object trivially, so the previous
/// "omitted → Ok" behaviour is preserved for those.
///
/// # Failure-mode mapping (deliberately asymmetric to the response-
/// side helper)
///
/// * `GtsTypeSchemaNotFound` → [`DomainError::Internal`] (HTTP 500).
///   The plugin advertised a schema id but the operator forgot to
///   register it — a deploy-time prerequisite failure, not a payload
///   problem the caller can fix. Emits a `warn!` on `am.idp` so the
///   operator sees the same signal needed to triage the missing
///   registration.
/// * Other `TypesRegistryError` → [`DomainError::ServiceUnavailable`]
///   (HTTP 503), uniform with the rest of the AM-on-registry path.
/// * `jsonschema::validator_for` rejects the schema → catalog drift
///   ([`DomainError::Internal`], HTTP 500).
/// * Instance fails validation → [`DomainError::Validation`]
///   (HTTP 400). The detail names the offending `schema_id` and the
///   joined `iter_errors` list so callers can correct their payload
///   and retry; this is the load-bearing path the helper exists for.
///
/// The `GtsTypeSchemaNotFound` arm diverges from
/// [`validate_new_user_payload_via_gts`] / [`validate_tenant_name_via_gts`]
/// (which short-circuit to `Ok(())` on unregistered schemas) because
/// those validators run against AM-OWNED schemas with a DB CHECK as
/// last-line guard; here the schema is plugin-OWNED and there is no
/// AM-side fallback, so an unregistered advertisement is a hard
/// configuration error rather than a degraded-mode acceptance.
///
/// # Errors
///
/// See module-level docs.
pub async fn validate_provision_input_metadata_via_gts(
    metadata: Option<&Value>,
    schema_id: &GtsSchemaId,
    types_registry: &dyn TypesRegistryClient,
) -> Result<(), DomainError> {
    // Treat omitted metadata as an empty object: when the plugin's
    // schema declares `required: [...]`, `iter_errors` against `{}`
    // surfaces those missing-field violations as `Validation` at
    // the AM boundary BEFORE the IdP call (the load-bearing
    // contract for this helper). Schemas with no required fields
    // accept `{}` trivially, so the previous "omitted → Ok" path
    // is preserved for that common case. We bind a stable `Value`
    // here rather than borrow `Value::Object(Map::new())` because
    // `jsonschema::iter_errors` takes `&Value`.
    let empty_object = Value::Object(serde_json::Map::new());
    let metadata = metadata.unwrap_or(&empty_object);
    let schema_id_str = schema_id.as_ref();
    let schema = match types_registry.get_type_schema(schema_id_str).await {
        Ok(schema) => schema,
        // Plugin advertised a schema id but the operator did not
        // pre-register it. Surface as `Internal` (not `Validation`):
        // the caller cannot correct this by changing their payload.
        // The `warn!` carries the offending `schema_id` so the
        // operator can correlate the missing registration with the
        // deploy bundle.
        Err(TypesRegistryError::GtsTypeSchemaNotFound(_)) => {
            tracing::warn!(
                target: "am.idp",
                schema_id = schema_id_str,
                "IdP plugin advertised provision_input_schema_id that is not registered in GTS; \
                 rejecting caller-supplied provisioning_metadata as Internal (deploy-time prerequisite)"
            );
            return Err(DomainError::Internal {
                diagnostic: format!(
                    "IdP plugin advertised provision input schema `{schema_id_str}` \
                     but the schema is not registered in GTS (deploy-time prerequisite: \
                     every schema id advertised by `provision_input_schema_id` MUST be \
                     pre-registered in GTS before the plugin is wired in)"
                ),
                cause: None,
            });
        }
        Err(err) => {
            return Err(DomainError::service_unavailable(format!(
                "GTS type schema lookup failed for `{schema_id_str}`: {err}"
            )));
        }
    };
    let resolved = schema.effective_schema();
    let validator = jsonschema::validator_for(&resolved).map_err(|err| DomainError::Internal {
        diagnostic: format!(
            "GTS type schema `{schema_id_str}` is not a valid JSON Schema (catalog drift): {err}"
        ),
        cause: None,
    })?;
    let errors: Vec<String> = validator
        .iter_errors(metadata)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        // Caller-supplied input — map to `Validation` so the public
        // envelope says "fix your payload and retry" (HTTP 400),
        // mirroring `validate_new_user_payload_via_gts` /
        // `validate_tenant_name_via_gts`. Detail names the advertised
        // `schema_id` so the caller can fetch the schema themselves
        // for debugging and includes the joined `iter_errors` list.
        return Err(DomainError::Validation {
            detail: format!(
                "provisioning_metadata violates plugin-advertised schema `{schema_id_str}`: {}",
                errors.join("; ")
            ),
        });
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
