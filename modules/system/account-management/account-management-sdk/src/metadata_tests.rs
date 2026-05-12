//! SDK-level unit tests for the tenant-metadata contract types.
//!
//! Cover the small surface owned by the SDK alone:
//!
//! * Determinism + namespace pin for [`derive_schema_uuid`] -- the
//!   namespace-pin test asserts a hardcoded `UUIDv5` literal so a future
//!   namespace or algorithm change trips immediately.
//! * Serde round-trip on [`MetadataEntry`] and [`MetadataSchemaId`].
//! * Validation paths on [`MetadataSchemaId::try_from`] and
//!   [`PutMetadataInput::new`] / serde.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test helpers")]

use super::*;
use serde_json::json;
use time::OffsetDateTime;
use time::macros::datetime;

/// Canonical valid chained schema id used across positive-path tests.
const VALID_SCHEMA_ID: &str = "gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.branding.v1~";

/// `UUIDv5` expected for [`VALID_SCHEMA_ID`] under the shared GTS
/// namespace (`Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts")`).
///
/// Hardcoding the literal pins the namespace + algorithm choice: any
/// future change to the namespace constant or the hashed-input bytes
/// trips this test immediately, even on a clean rebuild.
const PINNED_UUID_FOR_VALID_SCHEMA_ID: Uuid =
    Uuid::from_u128(0x1908_c97f_00d4_5e43_9c33_d390_4e7b_cfa6);

#[test]
fn derive_schema_uuid_is_deterministic_across_calls() {
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    let first = derive_schema_uuid(&id);
    let second = derive_schema_uuid(&id);
    let third = derive_schema_uuid(&id);
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn derive_schema_uuid_pins_namespace_choice() {
    // The pinned literal locks in BOTH the UUIDv5 namespace
    // (`Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts")`) and the byte-for
    // -byte hashed input (`schema_id.as_str()`). A future drift on
    // either side trips here, not silently in production.
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    let derived = derive_schema_uuid(&id);
    assert_eq!(derived, PINNED_UUID_FOR_VALID_SCHEMA_ID);
}

#[test]
fn derive_schema_uuid_distinct_inputs_yield_distinct_uuids() {
    let a =
        MetadataSchemaId::try_from("gts.cf.core.am.tenant_metadata.v1~acme.app.metadata.theme.v1~")
            .expect("valid schema id A");
    let b = MetadataSchemaId::try_from(
        "gts.cf.core.am.tenant_metadata.v1~acme.app.metadata.feature_flags.v1~",
    )
    .expect("valid schema id B");
    assert_ne!(derive_schema_uuid(&a), derive_schema_uuid(&b));
}

#[test]
fn metadata_entry_serde_roundtrip() {
    let entry = MetadataEntry::new(
        MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id"),
        json!({"primary_color": "#112233", "logo_url": "https://example.com/l.png"}),
        datetime!(2026-05-08 12:34:56 UTC),
    );
    let serialised = serde_json::to_value(&entry).expect("serialise");

    // Wire shape sanity: schema_id is a JSON string (not a struct);
    // updated_at uses RFC 3339; value is forwarded verbatim.
    assert_eq!(
        serialised
            .get("schema_id")
            .and_then(serde_json::Value::as_str),
        Some(VALID_SCHEMA_ID)
    );
    assert_eq!(
        serialised
            .get("updated_at")
            .and_then(serde_json::Value::as_str),
        Some("2026-05-08T12:34:56Z")
    );
    assert!(serialised.get("value").is_some());

    let back: MetadataEntry = serde_json::from_value(serialised).expect("deserialise");
    assert_eq!(back, entry);
}

#[test]
fn metadata_schema_id_serde_roundtrip() {
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    let serialised = serde_json::to_string(&id).expect("serialise");
    assert_eq!(serialised, format!("\"{VALID_SCHEMA_ID}\""));

    let back: MetadataSchemaId = serde_json::from_str(&serialised).expect("deserialise");
    assert_eq!(back, id);
}

#[test]
fn metadata_schema_id_rejects_non_metadata_root() {
    // Tenant root segment instead of tenant_metadata root -- valid
    // GTS chain syntax (5-token segments throughout), but wrong AM
    // resource type.
    let err = MetadataSchemaId::try_from("gts.cf.core.am.tenant.v1~acme.app.metadata.theme.v1~")
        .expect_err("non-metadata root must be rejected");
    match err {
        MetadataValidationError::WrongRootSegment { actual } => {
            assert_eq!(actual, "cf.core.am.tenant.v1");
        }
        other => panic!("expected WrongRootSegment, got {other:?}"),
    }
}

#[test]
fn metadata_schema_id_rejects_single_segment() {
    // The root segment alone -- valid as a standalone schema id
    // under the gts crate but invalid as a chained tenant-metadata
    // id because no user-registered schema follows.
    let err = MetadataSchemaId::try_from("gts.cf.core.am.tenant_metadata.v1~")
        .expect_err("single-segment id must be rejected");
    assert_eq!(err, MetadataValidationError::MissingChainedSegment);
}

#[test]
fn metadata_schema_id_rejects_malformed_gts() {
    // Missing `gts.` prefix -- fails the upstream GtsID parser
    // outright.
    let err = MetadataSchemaId::try_from("not.a.gts.identifier")
        .expect_err("malformed id must be rejected");
    match err {
        MetadataValidationError::MalformedSchemaId { reason } => {
            assert!(
                !reason.is_empty(),
                "MalformedSchemaId reason should carry diagnostic text"
            );
        }
        other => panic!("expected MalformedSchemaId, got {other:?}"),
    }
}

#[test]
fn metadata_schema_id_rejects_instance_id_shape() {
    // A chain whose tail segment is missing the trailing `~` parses
    // as a valid GTS identifier (instance id) but is NOT a schema
    // id. `derive_schema_uuid` would still hash it, producing a UUID
    // that won't match any registered schema row -- the downstream
    // Types Registry lookup would surface as a missing-schema 404
    // instead of a clean wire-input rejection. Pin the rejection at
    // the SDK boundary.
    let err = MetadataSchemaId::try_from(
        "gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1",
    )
    .expect_err("instance-shaped id must be rejected");
    match err {
        MetadataValidationError::NotASchemaId { actual } => {
            assert!(
                actual.contains("vendor.app.metadata.theme.v1"),
                "NotASchemaId.actual should carry the offending id, got `{actual}`"
            );
        }
        other => panic!("expected NotASchemaId, got {other:?}"),
    }
}

#[test]
fn metadata_schema_id_normalises_leading_trailing_whitespace() {
    // `GtsID::new` trims input; without using the trimmed normalized
    // form when constructing `GtsSchemaId`, two callers passing
    // semantically identical ids (one padded, one not) would derive
    // different UUIDs via `derive_schema_uuid`. Pin that the same
    // id with surrounding whitespace yields the same hashable
    // payload as the trimmed form.
    let padded = MetadataSchemaId::try_from(
        "  gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1~  ",
    )
    .expect("padded id must parse");
    let clean = MetadataSchemaId::try_from(
        "gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1~",
    )
    .expect("clean id must parse");
    assert_eq!(
        padded.as_str(),
        clean.as_str(),
        "padded and clean ids must normalise to the same value"
    );
}

#[test]
fn metadata_schema_id_deserialise_rejects_invalid_chain() {
    // The serde path MUST route through `try_from = "String"` so the
    // invariant is enforced on every input path, not just constructor
    // calls.
    let bad = serde_json::json!("gts.cf.core.am.tenant.v1~acme.app.metadata.theme.v1~");
    let err = serde_json::from_value::<MetadataSchemaId>(bad)
        .expect_err("non-metadata root MUST fail to deserialise");
    assert!(err.to_string().contains("cf.core.am.tenant_metadata.v1"));
}

#[test]
fn put_metadata_input_rejects_null_value() {
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    let err = PutMetadataInput::new(id, serde_json::Value::Null)
        .expect_err("null value must be rejected");
    assert_eq!(err, MetadataValidationError::EmptyValue);
}

#[test]
fn put_metadata_input_deserialise_rejects_null_value() {
    // The wire path (REST body) routes through `RawPutMetadataInput`
    // + `TryFrom` so the same `value != null` invariant is enforced
    // on every deserialisation input.
    let bad = serde_json::json!({
        "schema_id": VALID_SCHEMA_ID,
        "value": null,
    });
    let err = serde_json::from_value::<PutMetadataInput>(bad)
        .expect_err("null value MUST fail to deserialise");
    assert!(err.to_string().contains("must not be null"));
}

#[test]
fn put_metadata_input_accepts_non_null_payload() {
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    let input = PutMetadataInput::new(id.clone(), json!({"flag": true})).expect("non-null value");
    assert_eq!(input.schema_id, id);
    assert_eq!(input.value, json!({"flag": true}));
}

#[test]
fn metadata_validation_error_display_strings_are_pinned() {
    // Exact strings — `Display` output is load-bearing for the public
    // `Problem.detail` field. A refactor that rewords any arm changes
    // the wire shape and trips these snapshots.
    assert_eq!(
        MetadataValidationError::MalformedSchemaId {
            reason: "boom".into(),
        }
        .to_string(),
        "malformed metadata schema id: boom"
    );

    assert_eq!(
        MetadataValidationError::WrongRootSegment {
            actual: "cf.core.am.tenant.v1".into(),
        }
        .to_string(),
        "metadata schema id must start with `gts.cf.core.am.tenant_metadata.v1`, \
         got `gts.cf.core.am.tenant.v1`"
    );

    assert_eq!(
        MetadataValidationError::MissingChainedSegment.to_string(),
        "metadata schema id must chain a user-registered schema after the root segment"
    );

    assert_eq!(
        MetadataValidationError::NotASchemaId {
            actual: "gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1".into(),
        }
        .to_string(),
        "metadata schema id must be a chain of type segments (each ending with `~`); \
         got `gts.cf.core.am.tenant_metadata.v1~vendor.app.metadata.theme.v1` whose last \
         segment is an instance id"
    );

    assert_eq!(
        MetadataValidationError::EmptyValue.to_string(),
        "metadata value must not be null"
    );
}

#[test]
fn metadata_schema_id_as_str_matches_input() {
    let id = MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id");
    assert_eq!(id.as_str(), VALID_SCHEMA_ID);
    assert_eq!(
        <MetadataSchemaId as AsRef<str>>::as_ref(&id),
        VALID_SCHEMA_ID
    );
    assert_eq!(id.to_string(), VALID_SCHEMA_ID);
}

#[test]
fn metadata_entry_updated_at_uses_rfc3339_wire_shape() {
    // Pinned to ensure the wire shape is human-readable RFC 3339,
    // not the default `time` tuple representation -- a regression
    // here would silently change every public response body.
    let entry = MetadataEntry::new(
        MetadataSchemaId::try_from(VALID_SCHEMA_ID).expect("valid schema id"),
        json!({"x": 1}),
        OffsetDateTime::UNIX_EPOCH,
    );
    let serialised = serde_json::to_value(&entry).expect("serialise");
    assert_eq!(
        serialised
            .get("updated_at")
            .and_then(serde_json::Value::as_str),
        Some("1970-01-01T00:00:00Z")
    );
}
