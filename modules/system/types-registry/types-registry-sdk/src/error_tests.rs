//! Unit tests for [`TypesRegistryError`](super::TypesRegistryError).
//!
//! Kept in a sibling `_tests.rs` file per the `de1101_tests_in_separate_files`
//! repo lint. Linked into `error.rs` via `#[path = "error_tests.rs"] mod tests;`,
//! so the module sees `error.rs` as `super`.

use std::time::Duration;

use super::TypesRegistryError;

#[test]
fn test_invalid_query_constructor() {
    let err = TypesRegistryError::invalid_query("bad pattern: too many wildcards");
    assert!(err.is_invalid_query());
    assert!(err.to_string().contains("bad pattern"));
}

#[test]
fn test_invalid_query_distinct_from_invalid_gts_ids() {
    let err = TypesRegistryError::invalid_query("foo");
    assert!(!err.is_invalid_gts_type_id());
    assert!(!err.is_invalid_gts_instance_id());
}

#[test]
fn test_error_constructors() {
    let err = TypesRegistryError::invalid_gts_type_id("missing vendor");
    assert!(err.is_invalid_gts_type_id());
    assert!(err.to_string().contains("missing vendor"));

    let err = TypesRegistryError::invalid_gts_instance_id("no chain prefix");
    assert!(err.is_invalid_gts_instance_id());

    let err = TypesRegistryError::gts_type_schema_not_found("gts.acme.core.events.test.v1~");
    assert!(err.is_gts_type_schema_not_found());
    assert!(err.is_not_found());

    let err = TypesRegistryError::gts_instance_not_found(
        "gts.acme.core.events.test.v1~acme.core.instances.u1.v1",
    );
    assert!(err.is_gts_instance_not_found());
    assert!(err.is_not_found());

    let err = TypesRegistryError::parent_type_schema_not_registered(
        "gts.acme.core.events.base.v1~",
        "gts.acme.core.events.base.v1~acme.core.events.derived.v1.0~",
    );
    assert!(err.is_parent_type_schema_not_registered());

    let err = TypesRegistryError::already_exists("gts.acme.core.events.test.v1~");
    assert!(err.is_already_exists());

    let err = TypesRegistryError::validation_failed("schema invalid");
    assert!(err.is_validation_failed());

    let err =
        TypesRegistryError::service_unavailable("registry is initializing", Duration::from_secs(1));
    assert!(err.is_service_unavailable());

    let err = TypesRegistryError::internal("database error");
    assert!(matches!(err, TypesRegistryError::Internal(_)));
}

#[test]
fn test_error_display() {
    let err = TypesRegistryError::InvalidGtsTypeId("bad format".to_owned());
    assert_eq!(err.to_string(), "Invalid GTS type-schema id: bad format");

    let err = TypesRegistryError::InvalidGtsInstanceId("bad format".to_owned());
    assert_eq!(err.to_string(), "Invalid GTS instance id: bad format");

    let err = TypesRegistryError::GtsTypeSchemaNotFound("gts.cf.core.events.test.v1~".to_owned());
    assert_eq!(
        err.to_string(),
        "GTS type-schema not found: gts.cf.core.events.test.v1~"
    );

    let err = TypesRegistryError::GtsInstanceNotFound(
        "gts.cf.core.events.test.v1~cf.core.instances.u1.v1".to_owned(),
    );
    assert_eq!(
        err.to_string(),
        "GTS instance not found: gts.cf.core.events.test.v1~cf.core.instances.u1.v1"
    );

    let err = TypesRegistryError::AlreadyExists("gts.cf.core.events.test.v1~".to_owned());
    assert_eq!(
        err.to_string(),
        "Entity already exists: gts.cf.core.events.test.v1~"
    );

    let err = TypesRegistryError::ValidationFailed("missing required field".to_owned());
    assert_eq!(err.to_string(), "Validation failed: missing required field");

    let err = TypesRegistryError::ServiceUnavailable {
        message: "registry is initializing".to_owned(),
        retry_after: Duration::from_secs(2),
    };
    assert_eq!(
        err.to_string(),
        "Service unavailable: registry is initializing (retry after 2s)"
    );

    let err = TypesRegistryError::Internal("unexpected".to_owned());
    assert_eq!(err.to_string(), "Internal error: unexpected");
}
