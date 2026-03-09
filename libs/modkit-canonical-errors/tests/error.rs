extern crate cf_modkit_errors;

use cf_modkit_errors::{CanonicalError, Problem, resource_error};

#[test]
fn not_found_gts_type() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("Resource not found")
        .with_resource("user-123")
        .create();
    assert_eq!(
        err.gts_type(),
        "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~"
    );
}

#[test]
fn not_found_status_code() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("Resource not found")
        .with_resource("user-123")
        .create();
    assert_eq!(err.status_code(), 404);
}

#[test]
fn not_found_title() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("Resource not found")
        .with_resource("user-123")
        .create();
    assert_eq!(err.title(), "Not Found");
}

#[test]
fn display_includes_category_and_detail() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("User not found")
        .with_resource("user-123")
        .create();
    assert_eq!(format!("{err}"), "not_found: User not found");
}

#[test]
fn with_detail_overrides_default() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("custom detail")
        .with_resource("user-123")
        .create();
    assert_eq!(err.detail(), "custom detail");
}

#[test]
fn all_16_categories_convert_to_problem() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;

    let errors: Vec<CanonicalError> = vec![
        R::cancelled().create(),
        R::unknown("unknown error").create(),
        R::invalid_argument()
            .with_field_violation("field", "bad format", "INVALID_FORMAT")
            .create(),
        R::deadline_exceeded("timed out").create(),
        R::not_found("Resource not found")
            .with_resource("user-123")
            .create(),
        R::already_exists("Resource already exists")
            .with_resource("user-123")
            .create(),
        R::permission_denied().create(),
        R::resource_exhausted("Quota exceeded")
            .with_quota_violation("requests", "limit reached")
            .create(),
        R::failed_precondition()
            .with_precondition_violation("state", "not ready", "STATE")
            .create(),
        R::aborted("concurrency conflict")
            .with_reason("OPTIMISTIC_LOCK_FAILURE")
            .create(),
        R::out_of_range("Value out of range")
            .with_field_violation("page", "beyond last page", "OUT_OF_RANGE")
            .create(),
        R::unimplemented("not implemented").create(),
        CanonicalError::internal("bug").create(),
        CanonicalError::service_unavailable()
            .with_retry_after_seconds(10)
            .create(),
        R::data_loss("data loss").with_resource("user-123").create(),
        CanonicalError::unauthenticated()
            .with_reason("MISSING_CREDENTIALS")
            .create(),
    ];
    assert_eq!(errors.len(), 16);
    for err in errors {
        let problem = Problem::from(err);
        assert!(!problem.problem_type.is_empty());
        assert!(!problem.title.is_empty());
        assert!(problem.status > 0);
    }
}

// =========================================================================
// GTS ID validation — ensures all IDs in the crate are valid GTS identifiers
// =========================================================================

#[test]
fn validate_all_gts_ids() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;

    let errors = vec![
        R::cancelled().create(),
        R::unknown("e").create(),
        R::invalid_argument()
            .with_field_violation("f", "bad", "INVALID")
            .create(),
        R::deadline_exceeded("timed out").create(),
        R::not_found("not found").with_resource("user-123").create(),
        R::already_exists("exists")
            .with_resource("user-123")
            .create(),
        R::permission_denied().create(),
        R::resource_exhausted("quota")
            .with_quota_violation("req", "limit")
            .create(),
        R::failed_precondition()
            .with_precondition_violation("s", "d", "STATE")
            .create(),
        R::aborted("conflict")
            .with_reason("OPTIMISTIC_LOCK_FAILURE")
            .create(),
        R::out_of_range("range")
            .with_field_violation("page", "too high", "OUT_OF_RANGE")
            .create(),
        R::unimplemented("n").create(),
        CanonicalError::internal("d").create(),
        CanonicalError::service_unavailable()
            .with_retry_after_seconds(1)
            .create(),
        R::data_loss("d").with_resource("user-123").create(),
        CanonicalError::unauthenticated()
            .with_reason("MISSING_CREDENTIALS")
            .create(),
    ];
    for err in &errors {
        let id = err.gts_type();
        assert!(id.ends_with('~'), "GTS type ID must end with ~: {id}");
        gts_id::validate_gts_id(id, false)
            .unwrap_or_else(|e| panic!("Invalid GTS type ID '{id}': {e}"));
    }
}
