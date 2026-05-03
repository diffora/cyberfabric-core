//! Tests for the DB-error → `DomainError` classification ladder.
//!
//! Lives in `infra/` so the test code can import `sea_orm::DbErr`
//! and `modkit_db::DbError` directly — both forbidden inside `domain/`
//! by Dylint rules. The tests pin the contract that
//! `with_serializable_retry`'s post-retry classifier and
//! `From<DbError> for DomainError` produce the right typed
//! `DomainError` variants for each SQLSTATE / outage signal.

use modkit_canonical_errors::{CanonicalError, Problem};

use super::classify_db_err_to_domain;
use crate::domain::error::DomainError;

#[test]
fn classify_serialization_conflict_yields_aborted() {
    use sea_orm::{DbErr, RuntimeErr};
    // Mirrors `infra::error_conv::is_serialization_failure` detection:
    // a Postgres SQLSTATE 40001 surfaced through `RuntimeErr::Internal`
    // after `with_serializable_retry` exhausted its budget.
    let db_err = DbErr::Exec(RuntimeErr::Internal(
        "error returned from database: error with SQLSTATE 40001".into(),
    ));
    let domain = classify_db_err_to_domain(db_err);
    let DomainError::Aborted { reason, .. } = domain else {
        panic!("expected DomainError::Aborted");
    };
    assert_eq!(reason, "SERIALIZATION_CONFLICT");
}

#[test]
fn classify_serialization_conflict_canonical_status_409() {
    use sea_orm::{DbErr, RuntimeErr};
    let db_err = DbErr::Exec(RuntimeErr::Internal(
        "error returned from database: error with SQLSTATE 40001".into(),
    ));
    let canonical: CanonicalError = classify_db_err_to_domain(db_err).into();
    assert_eq!(canonical.status_code(), 409);
    let CanonicalError::Aborted { ctx, .. } = canonical else {
        panic!("expected Aborted");
    };
    assert_eq!(ctx.reason, "SERIALIZATION_CONFLICT");
}

#[test]
fn classify_unique_violation_yields_already_exists() {
    use sea_orm::{DbErr, RuntimeErr};
    // String-based fallback path of `is_unique_violation` — Postgres
    // duplicate-key text surfaced through `RuntimeErr::Internal`.
    let db_err = DbErr::Exec(RuntimeErr::Internal(
        "duplicate key value violates unique constraint \"ux_tenants\"".into(),
    ));
    let domain = classify_db_err_to_domain(db_err);
    assert!(matches!(domain, DomainError::AlreadyExists { .. }));
    let canonical: CanonicalError = domain.into();
    assert_eq!(canonical.status_code(), 409);
    assert!(matches!(canonical, CanonicalError::AlreadyExists { .. }));
}

#[test]
fn classify_availability_yields_service_unavailable() {
    use sea_orm::{ConnAcquireErr, DbErr};
    let db_err = DbErr::ConnectionAcquire(ConnAcquireErr::Timeout);
    let domain = classify_db_err_to_domain(db_err);
    assert!(matches!(domain, DomainError::ServiceUnavailable { .. }));
    let canonical: CanonicalError = domain.into();
    assert_eq!(canonical.status_code(), 503);
}

#[test]
fn classify_unclassified_yields_internal() {
    use sea_orm::DbErr;
    let db_err = DbErr::Custom("unclassified".into());
    let domain = classify_db_err_to_domain(db_err);
    assert!(matches!(domain, DomainError::Internal { .. }));
    let canonical: CanonicalError = domain.into();
    assert_eq!(canonical.status_code(), 500);
}

#[test]
fn dberror_sea_routes_through_classifier() {
    use modkit_db::DbError;
    use sea_orm::DbErr;
    // `DbError::Sea(_)` non-transactional path runs through
    // `classify_db_err_to_domain`; an unclassified inner `DbErr`
    // therefore lands in `Internal`.
    let lifted: DomainError = DbError::Sea(DbErr::Custom("any".into())).into();
    assert!(matches!(lifted, DomainError::Internal { .. }));
}

#[test]
fn dberror_io_routes_to_service_unavailable() {
    use modkit_db::DbError;
    // Regression guard: a transient IO outage MUST surface as 503
    // (ServiceUnavailable), not 500 (Internal). Earlier the `non-Sea`
    // arm fell through to `Internal` and lost the availability signal.
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer");
    let lifted: DomainError = DbError::Io(io_err).into();
    let canonical: CanonicalError = lifted.into();
    assert_eq!(canonical.status_code(), 503);
    assert!(matches!(
        canonical,
        CanonicalError::ServiceUnavailable { .. }
    ));
}

#[test]
fn dberror_other_routes_to_internal_with_redacted_diagnostic() {
    use modkit_db::DbError;
    // Non-Sea, non-availability variants fall through to `Internal`.
    // The diagnostic field MUST come from `redacted_db_diagnostic`
    // (no raw DSN / config text leaks).
    let lifted: DomainError =
        DbError::UnknownDsn("postgres://secret_user:secret_pass@host/db".into()).into();
    let canonical: CanonicalError = lifted.into();
    assert_eq!(canonical.status_code(), 500);
    let CanonicalError::Internal { ctx, .. } = canonical else {
        panic!("expected Internal");
    };
    let description = &ctx.description;
    assert!(
        !description.contains("secret_user"),
        "raw DSN leaked into description: {description}"
    );
    assert!(
        !description.contains("secret_pass"),
        "raw DSN leaked into description: {description}"
    );
    assert!(
        description.contains("redacted"),
        "description must come from redacted_db_diagnostic: {description}"
    );
}

/// `DomainError::Internal { diagnostic, .. }` carries the diagnostic
/// string as input to `CanonicalError::internal(...)`. The
/// `feature-errors-observability` contract states the diagnostic
/// **MUST NOT** reach the public `Problem` body — it is meant for
/// audit-only consumption (the `Internal` variant's docstring on
/// `domain::error::DomainError` says so explicitly).
///
/// Pin that contract here by constructing an `Internal` with a
/// distinctive sentinel diagnostic, lifting it into a
/// `CanonicalError`, and asserting the sentinel never appears in the
/// JSON-serialized envelope. This guards against any future change to
/// `modkit_canonical_errors::context::InternalV1` that would drop the
/// `#[serde(skip)]` on `description` and start leaking diagnostics
/// into HTTP responses.
#[test]
fn internal_diagnostic_is_not_serialized_into_canonical_envelope() {
    let sentinel = "INTERNAL-DIAGNOSTIC-SENTINEL-7f3a2c";
    let domain = DomainError::Internal {
        diagnostic: sentinel.to_owned(),
        cause: None,
    };
    let canonical = CanonicalError::from(domain);
    // The public HTTP boundary serializes through `Problem` (RFC 9457
    // envelope), not `CanonicalError` directly. Drive the conversion
    // and serde-encode the resulting envelope to mirror what a REST
    // consumer actually receives over the wire.
    let problem = Problem::from(canonical);
    let envelope = serde_json::to_string(&problem).expect("problem envelope must serialize");
    assert!(
        !envelope.contains(sentinel),
        "Internal diagnostic leaked into the public Problem envelope: {envelope}"
    );
}
