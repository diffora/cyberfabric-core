//! Tenant Metadata SDK contract.
//!
//! Public input/output contract for the AM tenant-metadata feature
//! (`feature-tenant-metadata`). Exposed shapes:
//!
//! * [`MetadataSchemaId`] -- typed wrapper around [`gts::GtsSchemaId`]
//!   that pins the chained-id invariant required by AM (root segment
//!   MUST be `gts.cf.core.am.tenant_metadata.v1` and at least one
//!   chained user-registered schema segment MUST follow). Wire shape
//!   stays a JSON string; validation runs through `try_from = "..."`
//!   so every deserialise path enforces the invariant.
//! * [`MetadataEntry`] -- per-tenant metadata projection returned by
//!   reads. `value` is the opaque GTS-validated payload, kept as
//!   [`serde_json::Value`] so downstream consumers do not need a typed
//!   schema dependency. `updated_at` is wire-serialised as RFC 3339.
//! * [`PutMetadataInput`] -- request body for the upsert flow. SDK-side
//!   validation rejects only the trivially-empty case
//!   (`Value::Null`); the GTS schema validation against the registered
//!   schema lives at the impl-side service layer.
//! * [`MetadataValidationError`] -- the discriminated validation
//!   failures surfaced by [`MetadataSchemaId::try_from`] and
//!   [`PutMetadataInput::try_from`].
//! * [`derive_schema_uuid`] -- deterministic `UUIDv5` helper that maps
//!   the public chained `MetadataSchemaId` onto the storage-side
//!   `schema_uuid` PK component used by `(tenant_id, schema_uuid)`
//!   reads / writes.
//!
//! # Determinism + namespace contract
//!
//! @cpt-cf-account-management-algo-tenant-metadata-schema-uuid-derivation
//!
//! [`derive_schema_uuid`] is a pure computation: no Types Registry
//! lookup, no cache, no I/O. The function MUST return the same UUID
//! for the same `MetadataSchemaId` across process restarts,
//! deployments, and replica sets so AM CRUD keyed by `(tenant_id,
//! schema_uuid)` stays stable.
//!
//! The namespace is the same UUID the upstream `gts` crate uses
//! internally for [`gts::GtsID::to_uuid`]: `Uuid::new_v5(&
//! Uuid::NAMESPACE_URL, b"gts")`. Re-using that namespace here means
//! `derive_schema_uuid(&MetadataSchemaId::try_from(s)?)` and
//! `gts::GtsID::new(s)?.to_uuid()` agree on the resulting UUID for
//! every chained id valid under both validators. AM and any sibling
//! that uses the `gts` crate directly therefore share a single
//! equivalence class on the `schema_id` -> `schema_uuid` mapping.

use std::sync::LazyLock;

use gts::{GtsID, GtsSchemaId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::serde::rfc3339;
use uuid::Uuid;

/// Namespace used for the deterministic `UUIDv5` derivation in
/// [`derive_schema_uuid`].
///
/// Mirrors the upstream `gts` crate's internal namespace verbatim
/// (`gts/src/gts.rs::GTS_NS`). Recomputed once at first use via
/// [`LazyLock`] so the per-call derivation stays a `Uuid::new_v5`
/// hash with no allocation.
static GTS_NAMESPACE: LazyLock<Uuid> = LazyLock::new(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts"));

/// AM tenant-metadata root segment that every [`MetadataSchemaId`]
/// chain MUST start with.
///
/// Differs from [`crate::gts::TENANT_METADATA_RESOURCE_TYPE`]
/// (`gts.cf.core.am.tenant_metadata.v1~`) in two ways:
///
/// * The leading `gts.` prefix is stripped: the upstream `gts_id`
///   parser strips `GTS_PREFIX` before splitting into segments, so
///   `GtsIdSegment.segment` for the root carries only the
///   `vendor.package.namespace.type.vMAJOR` body.
/// * The trailing `~` chain-terminator is stripped: the chained
///   `MetadataSchemaId` re-attaches its own `~` after the root as
///   part of the chain syntax (e.g. `gts.cf.core.am.tenant_metadata
///   .v1~vendor.package.metadata.theme.v1~`).
///
/// Comparing against this stripped form keeps the validator aligned
/// with what the upstream parser actually exposes via
/// [`gts::GtsIdSegment::segment`].
const METADATA_ROOT_SEGMENT: &str = "cf.core.am.tenant_metadata.v1";

/// Validation errors raised by [`MetadataSchemaId::try_from`] and
/// [`PutMetadataInput::try_from`].
///
/// The enum is `#[non_exhaustive]` so AM may add finer-grained
/// validation variants without a `SemVer` break (e.g. once the impl-side
/// schema registry is wired in Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataValidationError {
    /// The chained id failed [`gts::GtsID::new`] validation. `reason`
    /// carries the upstream parser's display string for diagnostics.
    MalformedSchemaId { reason: String },
    /// The first segment of the chain was not the AM tenant-metadata
    /// root (`gts.cf.core.am.tenant_metadata.v1`). `actual` carries the
    /// observed first segment so consumers can surface a useful
    /// message.
    WrongRootSegment { actual: String },
    /// Only the root segment was supplied; a chained user-registered
    /// schema segment is required (e.g. `gts.cf.core.am.tenant_metadata
    /// .v1~vendor.app.theme.v1~`).
    MissingChainedSegment,
    /// The supplied id parses as a valid GTS identifier but is not a
    /// schema id — i.e. the last segment does not end with `~`, which
    /// per the GTS shape contract means it is an instance id rather
    /// than a chain of type segments. `derive_schema_uuid` and the
    /// downstream Types Registry lookup both require a schema-shaped
    /// id; rejecting at the SDK boundary keeps the failure mode at
    /// the wire-input gate rather than at a downstream 503.
    NotASchemaId { actual: String },
    /// [`PutMetadataInput::value`] was [`Value::Null`]. The SDK
    /// rejects only the trivially-empty case; full GTS schema
    /// validation runs at the impl-side service layer.
    EmptyValue,
}

impl core::fmt::Display for MetadataValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedSchemaId { reason } => {
                write!(f, "malformed metadata schema id: {reason}")
            }
            Self::WrongRootSegment { actual } => write!(
                f,
                "metadata schema id must start with `gts.{METADATA_ROOT_SEGMENT}`, got `gts.{actual}`",
            ),
            Self::MissingChainedSegment => f.write_str(
                "metadata schema id must chain a user-registered schema after the root segment",
            ),
            Self::NotASchemaId { actual } => write!(
                f,
                "metadata schema id must be a chain of type segments (each ending with `~`); \
                 got `{actual}` whose last segment is an instance id",
            ),
            Self::EmptyValue => f.write_str("metadata value must not be null"),
        }
    }
}

impl core::error::Error for MetadataValidationError {}

/// Typed chained schema identifier for tenant metadata.
///
/// Wraps [`gts::GtsSchemaId`] but enforces two AM-specific invariants
/// on construction:
///
/// 1. The chain MUST parse via [`gts::GtsID::new`] (full GTS chain
///    validation).
/// 2. The first segment MUST equal [`METADATA_ROOT_SEGMENT`]
///    (`gts.cf.core.am.tenant_metadata.v1`) and at least one chained
///    user-registered segment MUST follow.
///
/// Wire shape is a JSON string identical to the underlying chained
/// id; deserialisation routes through [`TryFrom<String>`] so the
/// invariants are enforced on every input path (REST handler, event
/// payload, inter-module call).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MetadataSchemaId(GtsSchemaId);

impl MetadataSchemaId {
    /// Borrow the chained id as a string slice (verbatim, no
    /// re-formatting).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Borrow the underlying [`gts::GtsSchemaId`].
    #[must_use]
    pub const fn as_gts(&self) -> &GtsSchemaId {
        &self.0
    }

    /// Consume into the underlying [`gts::GtsSchemaId`].
    #[must_use]
    pub fn into_gts(self) -> GtsSchemaId {
        self.0
    }
}

impl TryFrom<String> for MetadataSchemaId {
    type Error = MetadataValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for MetadataSchemaId {
    type Error = MetadataValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parsed =
            GtsID::new(value).map_err(|err| MetadataValidationError::MalformedSchemaId {
                reason: err.to_string(),
            })?;

        let segments = &parsed.gts_id_segments;
        if segments.len() < 2 {
            return Err(MetadataValidationError::MissingChainedSegment);
        }

        let root_segment = &segments[0];
        // `GtsIdSegment.segment` includes the trailing `~`; strip it
        // before comparison against the root segment constant.
        let root_str = root_segment.segment.trim_end_matches('~');
        if root_str != METADATA_ROOT_SEGMENT {
            return Err(MetadataValidationError::WrongRootSegment {
                actual: root_str.to_owned(),
            });
        }

        // Schema-shape check: every segment of a schema id ends with
        // `~` (the chain is "type[~type]*"). An instance id whose
        // tail segment lacks `~` parses cleanly as a `GtsID` but is
        // NOT a schema id — `derive_schema_uuid` would still hash
        // it, but the resulting UUID would not match any row the
        // Types Registry has under the corresponding schema, so the
        // downstream lookup would surface as a 503 / missing-schema
        // 404 instead of a clean wire-input rejection.
        if !parsed.is_type() {
            return Err(MetadataValidationError::NotASchemaId {
                actual: parsed.as_ref().to_owned(),
            });
        }

        // Use the **trimmed normalized** id from the parsed result
        // (`GtsID::new` trims leading / trailing whitespace
        // internally) when constructing `GtsSchemaId`. Without this,
        // an input like `" gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1~ "`
        // would store the un-trimmed string verbatim, and
        // `derive_schema_uuid` would hash a value that differs from
        // a trimmed-equivalent input — two callers passing
        // semantically identical ids would derive different UUIDs.
        Ok(Self(GtsSchemaId::new(parsed.as_ref())))
    }
}

impl From<MetadataSchemaId> for String {
    fn from(value: MetadataSchemaId) -> Self {
        value.0.into()
    }
}

impl core::fmt::Display for MetadataSchemaId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for MetadataSchemaId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// Public projection of one direct-on-tenant metadata entry.
///
/// Returned by the GET / list endpoints. Mirrors
/// `cf-account-management::domain::metadata::MetadataRow` minus the
/// internal `tenant_id` (the tenant scope is implicit in the request
/// path) and minus the storage `schema_uuid` (the public surface
/// always speaks chained `schema_id` and re-derives the UUID via
/// [`derive_schema_uuid`]).
///
/// `created_at` is intentionally omitted from the public projection:
/// FEATURE §3.1 / §6 only surfaces `updated_at` for cache-validation;
/// keeping the projection minimal avoids leaking row-history details
/// the public contract has not committed to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MetadataEntry {
    pub schema_id: MetadataSchemaId,
    pub value: Value,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl MetadataEntry {
    /// Build a new [`MetadataEntry`]. The `#[non_exhaustive]` marker
    /// requires consumers to use this constructor (or struct-update
    /// syntax) so future field additions stay SemVer-safe.
    #[must_use]
    pub const fn new(
        schema_id: MetadataSchemaId,
        value: Value,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            schema_id,
            value,
            updated_at,
        }
    }
}

/// Request shape for `PUT /tenants/{tenant_id}/metadata/{schema_id}`.
///
/// Construction validates that `value` is not [`Value::Null`]; full
/// GTS schema validation against the registered schema runs at the
/// impl-side service layer against the resolved `MetadataSchemaId`
/// after Types Registry lookup.
///
/// Deserialise routes through [`RawPutMetadataInput`] + [`TryFrom`]
/// so the same invariant is enforced on every wire-input path, not
/// just constructor calls. The struct is NOT `#[non_exhaustive]` —
/// at pre-1.0 SDK maturity, exposing the two-field literal shape lets
/// callers build the request directly (and the wire payload mirrors
/// the public fields verbatim); future field additions are SDK
/// breaking-changes and bump the minor version explicitly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawPutMetadataInput")]
pub struct PutMetadataInput {
    pub schema_id: MetadataSchemaId,
    pub value: Value,
}

impl PutMetadataInput {
    /// Construct a validated [`PutMetadataInput`].
    ///
    /// # Errors
    ///
    /// Returns [`MetadataValidationError::EmptyValue`] when `value`
    /// is [`Value::Null`].
    pub fn new(schema_id: MetadataSchemaId, value: Value) -> Result<Self, MetadataValidationError> {
        if value.is_null() {
            return Err(MetadataValidationError::EmptyValue);
        }
        Ok(Self { schema_id, value })
    }
}

/// Wire shape for [`PutMetadataInput`] deserialisation. Mirrors the
/// public fields but skips the non-null `value` invariant -- the
/// [`TryFrom`] impl below routes through [`PutMetadataInput::new`] so
/// every wire-input path enforces the invariant.
#[derive(Debug, Clone, Deserialize)]
struct RawPutMetadataInput {
    schema_id: MetadataSchemaId,
    value: Value,
}

impl TryFrom<RawPutMetadataInput> for PutMetadataInput {
    type Error = MetadataValidationError;

    fn try_from(raw: RawPutMetadataInput) -> Result<Self, Self::Error> {
        Self::new(raw.schema_id, raw.value)
    }
}

/// Deterministic `UUIDv5` derivation for the chained metadata schema id.
///
/// Pure computation: hashes [`MetadataSchemaId::as_str`] under the
/// shared GTS namespace ([`GTS_NAMESPACE`]) and returns the resulting
/// `UUIDv5`. No Types Registry lookup, no cache, no I/O.
///
/// The function is the single mapping between the public
/// `schema_id` (URL / SDK / `AuthZ` / audit) and the storage
/// `schema_uuid` (DB PK component on `(tenant_id, schema_uuid)`).
/// Determinism is mandatory -- the same input MUST yield the same
/// UUID across process restarts, deployments, and replicas.
#[must_use]
pub fn derive_schema_uuid(schema_id: &MetadataSchemaId) -> Uuid {
    Uuid::new_v5(&GTS_NAMESPACE, schema_id.as_str().as_bytes())
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
