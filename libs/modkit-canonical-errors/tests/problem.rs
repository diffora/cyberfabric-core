extern crate cf_modkit_errors;

use cf_modkit_errors::{CanonicalError, Problem, resource_error};

#[test]
fn problem_from_not_found_has_correct_fields() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct R;
    let err = R::not_found("Resource not found")
        .with_resource("user-123")
        .create();
    let problem = Problem::from(err);
    assert_eq!(
        problem.problem_type,
        "gts://gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~"
    );
    assert_eq!(problem.title, "Not Found");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.detail, "Resource not found");
    assert_eq!(
        problem.context["resource_type"],
        "gts.cf.core.users.user.v1~"
    );
    assert_eq!(problem.context["resource_name"], "user-123");
}

#[test]
fn problem_json_excludes_none_fields() {
    let err = CanonicalError::service_unavailable()
        .with_retry_after_seconds(30)
        .create();
    let problem = Problem::from(err);
    let json = serde_json::to_value(&problem).unwrap();
    assert!(json.get("trace_id").is_none());
}

#[test]
fn direct_constructor_has_no_resource_type() {
    let err = CanonicalError::service_unavailable()
        .with_retry_after_seconds(30)
        .create();
    assert_eq!(err.resource_type(), None);
    let _problem = Problem::from(err);
}

#[test]
fn problem_json_excludes_resource_type_when_none() {
    let err = CanonicalError::internal("some error").create();
    let problem = Problem::from(err);
    let json = serde_json::to_value(&problem).unwrap();
    assert!(json["context"].get("resource_type").is_none());
}
