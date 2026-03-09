extern crate cf_modkit_errors;

use cf_modkit_errors::{Problem, resource_error};

#[test]
fn macro_not_found_has_correct_resource_type_and_resource_info() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct TestUserResourceError;

    let err = TestUserResourceError::not_found("User not found")
        .with_resource("user-123")
        .create();
    assert_eq!(err.resource_type(), Some("gts.cf.core.users.user.v1~"));
    assert_eq!(
        err.gts_type(),
        "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~"
    );
    let problem = Problem::from(err);
    assert_eq!(
        problem.context["resource_type"],
        "gts.cf.core.users.user.v1~"
    );
    assert_eq!(problem.context["resource_name"], "user-123");
}

#[test]
fn macro_permission_denied_has_correct_resource_type() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct TestUserResourceError;

    let err = TestUserResourceError::permission_denied().create();
    assert_eq!(err.resource_type(), Some("gts.cf.core.users.user.v1~"));
    assert_eq!(
        err.gts_type(),
        "gts.cf.core.errors.err.v1~cf.core.err.permission_denied.v1~"
    );
}

#[test]
fn problem_json_includes_resource_type_when_set() {
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct TestUserResourceError;

    let err = TestUserResourceError::not_found("User not found")
        .with_resource("user-123")
        .create();
    let problem = Problem::from(err);
    let json = serde_json::to_value(&problem).unwrap();
    assert_eq!(
        json["context"]["resource_type"],
        "gts.cf.core.users.user.v1~"
    );
}
