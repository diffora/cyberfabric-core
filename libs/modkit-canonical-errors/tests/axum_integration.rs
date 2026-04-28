#![cfg(feature = "axum")]

use axum::response::IntoResponse;
use modkit_canonical_errors::problem::APPLICATION_PROBLEM_JSON;
use modkit_canonical_errors::resource_error;
use modkit_canonical_errors::{CanonicalError, Problem};

#[resource_error("gts.cf.core.test.axum.v1~")]
struct AxumTestR;

#[test]
fn problem_into_response_sets_status_and_content_type() {
    let err = AxumTestR::not_found("missing")
        .with_resource("abc")
        .create();
    let response = Problem::from(err).into_response();

    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(APPLICATION_PROBLEM_JSON)
    );
}

#[test]
fn canonical_error_into_response_delegates_through_problem() {
    let err = CanonicalError::internal("db failure").create();
    let response = err.into_response();

    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(APPLICATION_PROBLEM_JSON)
    );
}

#[test]
fn invalid_argument_maps_to_400() {
    let err = AxumTestR::invalid_argument()
        .with_field_violation("name", "must not be empty", "REQUIRED")
        .create();
    let response = err.into_response();
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
}
