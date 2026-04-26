//! Infrastructure-layer conversions between `modkit-db` errors and the
//! public AM domain error taxonomy.
//!
//! This module is the ONLY place where `modkit_db::DbError` reaches into
//! AM's domain layer. Phase 1's `domain/error.rs` stays strictly pure —
//! the `DBProvider<AmError>` parameterization picked in Phase 2 funnels
//! every database-side failure through this mapping so that no
//! low-level driver variant ever leaks through the public contract.

use modkit_db::DbError;
use modkit_db::deadlock::is_serialization_failure;
use modkit_db::secure::is_unique_violation;
use sea_orm::DbErr;
use tracing::warn;

use crate::domain::error::AmError;

/// Returns `true` iff `err` is a typed database connectivity / outage
/// signal — pool acquire timeout, connection closed, connection-level
/// runtime error, or a raw `std::io::Error` surfaced through
/// [`DbError::Io`]. Used to route those failures to
/// [`AmError::ServiceUnavailable`] (HTTP 503) rather than
/// [`AmError::Internal`] (HTTP 500), so clients see a "retry later,
/// transient infra outage" status that matches reality.
///
/// Classification is deliberately conservative: only **typed** signals
/// from `sea_orm::DbErr` and the modkit-db wrapper count. Unstructured
/// `RuntimeErr::Internal(String)` text — including driver messages like
/// `"connection closed by peer"` — stays in the `Internal` bucket;
/// string-matching driver text is fragile and the project's existing
/// classifiers (`is_serialization_failure`, `is_unique_violation`) are
/// SQLSTATE-typed for the same reason.
fn is_db_availability_error(err: &DbError) -> bool {
    // `DbError::Io(_)`: modkit-db's typed `std::io::Error` wrapper —
    // only emitted for genuine system-level IO failures (socket reset, etc.).
    // `DbErr::ConnectionAcquire(_)` covers `Timeout` and `ConnectionClosed`
    // (the only `ConnAcquireErr` variants).
    // `DbErr::Conn(_)` is sea-orm's documented "problem with the database
    // connection" discriminant — connection-level by definition.
    // `DbErr::Exec(_)` / `DbErr::Query(_)` wrap a `RuntimeErr` whose
    // layering hides whether the failure was connectivity or query-level,
    // so they fall through to the `Internal` bucket rather than guess.
    matches!(
        err,
        DbError::Io(_) | DbError::Sea(DbErr::ConnectionAcquire(_) | DbErr::Conn(_))
    )
}

/// Wrap a [`DbError`] into the appropriate [`AmError`] variant.
///
/// The raw `DbError` is logged via `tracing::warn!` (correlatable by
/// trace-id) and, for the `Internal` fallback, stored in the
/// audit-visible `diagnostic` field. It MUST NOT reach the
/// client-facing Problem `detail` for `Conflict`,
/// `SerializationConflict`, or `ServiceUnavailable`: those carry a
/// generic, non-leaky message only — driver text can expose table
/// names / SQL fragments / dialect hints on conflicts, and connection
/// errors can leak hostnames / IP addresses / ports. Operators read
/// the raw error from the `am.db` `warn!` log (correlatable by
/// trace-id), not the public Problem envelope.
///
/// Classification ladder (most specific first):
///
/// 1. `Postgres` SQLSTATE `40001` / `MySQL` `InnoDB` deadlock →
///    [`AmError::SerializationConflict`]. The SERIALIZABLE-retry helper
///    in `infra/storage/repo_impl.rs` matches on the discriminant.
/// 2. Unique-constraint violation (`Postgres` SQLSTATE `23505`,
///    `SQLite` extended `2067`, `MySQL` `1062`) → [`AmError::Conflict`]. Required
///    by `feature-tenant-hierarchy-management.md` AC §15 line 711:
///    racing creates "rely on the unique index on `tenants(id)` …
///    losing writers MUST receive a deterministic `conflict` or
///    `validation`". Without this branch, closure-row-insert
///    collisions in `activate_tenant` and similar paths bleed through
///    as 500.
/// 3. Typed connectivity / outage signal (see [`is_db_availability_error`])
///    → [`AmError::ServiceUnavailable`] (HTTP 503). Aligns the DB
///    transient-outage path with how AM already classifies outages
///    from every other dependency (Resource Group, Types Registry,
///    `AuthZ` PDP) so a transient pool-timeout doesn't masquerade as a
///    generic 500.
/// 4. Anything else → [`AmError::Internal`]. The Problem envelope's
///    public `detail` is empty; the diagnostic stays in the
///    audit-visible field only.
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-db-error-classification
impl From<DbError> for AmError {
    #[allow(clippy::cognitive_complexity)] // flat classification ladder; branchy warn! paths, no logic
    fn from(err: DbError) -> Self {
        if let DbError::Sea(ref db_err) = err {
            if is_serialization_failure(db_err) {
                warn!(
                    target: "am.db",
                    error = %err,
                    "serialization failure mapped to AmError::SerializationConflict"
                );
                return AmError::SerializationConflict {
                    detail: "transient serialization conflict; safe to retry".to_owned(),
                };
            }
            if is_unique_violation(db_err) {
                warn!(
                    target: "am.db",
                    error = %err,
                    "unique-constraint violation mapped to AmError::Conflict"
                );
                return AmError::Conflict {
                    detail: "request conflicts with existing state".to_owned(),
                };
            }
        }
        if is_db_availability_error(&err) {
            warn!(
                target: "am.db",
                error = %err,
                "db connectivity failure mapped to AmError::ServiceUnavailable"
            );
            // Generic, non-leaky detail — connection errors can carry
            // hostnames, IP addresses, or port numbers in their text.
            // Operators get the raw `err` from the `warn!` above.
            return AmError::ServiceUnavailable {
                detail: "database unavailable; retry later".to_owned(),
            };
        }
        warn!(target: "am.db", error = %err, "db error mapped to AmError::Internal");
        AmError::Internal {
            diagnostic: format!("db error: {err}"),
        }
    }
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-db-error-classification

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use sea_orm::{ConnAcquireErr, DbErr, RuntimeErr};

    #[test]
    fn db_error_maps_to_internal_am_error() {
        let db_err = DbError::InvalidConfig("bad dsn".into());
        let am_err: AmError = db_err.into();
        assert_eq!(am_err.sub_code(), "internal");
    }

    #[test]
    fn sqlstate_40001_maps_to_serialization_conflict() {
        // Pin the typed mapping that the SERIALIZABLE-retry helper in
        // `infra/storage/repo_impl.rs` depends on: a Postgres SQLSTATE
        // 40001 error MUST surface as `AmError::SerializationConflict`,
        // not the generic `Internal` bucket. If `is_serialization_failure`
        // ever stops matching this shape, the retry loop silently stops
        // retrying and writes appear to fail at random under contention.
        let sea_err = DbErr::Exec(RuntimeErr::Internal(
            "error returned from database: 40001: could not serialize access".to_owned(),
        ));
        let am_err: AmError = DbError::Sea(sea_err).into();
        assert_eq!(am_err.sub_code(), "serialization_conflict");
        assert!(matches!(am_err, AmError::SerializationConflict { .. }));
    }

    #[test]
    fn unique_violation_maps_to_conflict() {
        // Pin the AC §15 requirement: racing creates rely on the
        // `tenants(id)` UNIQUE index; the losing writer MUST receive a
        // deterministic `conflict` envelope (HTTP 409), not `internal`
        // / 500. Postgres SQLSTATE 23505 / "duplicate key" surfaces
        // here. The diagnostic carries the raw error for ops, but the
        // sub_code must be `conflict`.
        let sea_err = DbErr::Exec(RuntimeErr::Internal(
            "duplicate key value violates unique constraint".to_owned(),
        ));
        let am_err: AmError = DbError::Sea(sea_err).into();
        assert_eq!(am_err.sub_code(), "conflict");
        assert!(matches!(am_err, AmError::Conflict { .. }));
        assert_eq!(am_err.http_status(), 409);
    }

    #[test]
    fn unrelated_sea_errors_still_map_to_internal() {
        // Untyped runtime errors — i.e. `RuntimeErr::Internal(String)`
        // wrapping arbitrary driver text, even text that *mentions* a
        // connection problem — stay in the `Internal` bucket. The
        // typed availability classifier deliberately does not
        // string-match driver messages; only typed sea-orm signals
        // (`ConnectionAcquire`, `Conn`) and `DbError::Io` are
        // re-routed to `ServiceUnavailable`. See
        // `is_db_availability_error` for the rationale.
        let sea_err = DbErr::Exec(RuntimeErr::Internal("connection closed by peer".to_owned()));
        let am_err: AmError = DbError::Sea(sea_err).into();
        assert_eq!(am_err.sub_code(), "internal");
        assert!(matches!(am_err, AmError::Internal { .. }));
    }

    #[test]
    fn pool_acquire_timeout_maps_to_service_unavailable() {
        // Typed availability signal: a pool-timeout from sea-orm's
        // `ConnectionAcquire(Timeout)` is unambiguously a transient
        // outage and must surface as 503, not 500. Aligns the DB
        // transient-outage path with how AM already classifies outages
        // from RG / Types-Registry / AuthZ PDP.
        let am_err: AmError =
            DbError::Sea(DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)).into();
        assert_eq!(am_err.sub_code(), "service_unavailable");
        assert!(matches!(am_err, AmError::ServiceUnavailable { .. }));
        assert_eq!(am_err.http_status(), 503);
    }

    #[test]
    fn connection_closed_during_acquire_maps_to_service_unavailable() {
        let am_err: AmError =
            DbError::Sea(DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed)).into();
        assert_eq!(am_err.sub_code(), "service_unavailable");
        assert_eq!(am_err.http_status(), 503);
    }

    #[test]
    fn sea_orm_conn_variant_maps_to_service_unavailable() {
        // `DbErr::Conn(_)` is sea-orm's typed "problem with the
        // database connection" discriminant — connection-level by
        // definition, regardless of the inner runtime payload.
        let am_err: AmError =
            DbError::Sea(DbErr::Conn(RuntimeErr::Internal("link broken".to_owned()))).into();
        assert_eq!(am_err.sub_code(), "service_unavailable");
        assert_eq!(am_err.http_status(), 503);
    }

    #[test]
    fn modkit_db_io_error_maps_to_service_unavailable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let am_err: AmError = DbError::Io(io_err).into();
        assert_eq!(am_err.sub_code(), "service_unavailable");
        assert_eq!(am_err.http_status(), 503);
    }

    #[test]
    fn service_unavailable_detail_does_not_leak_db_error_text() {
        // Pin the no-leak invariant for 503: the public Problem
        // `detail` must not echo the raw driver / connection error,
        // which can carry hostnames, IP addresses, or port numbers.
        // Operators read the raw error from the `am.db` `warn!` log
        // (correlatable by trace-id), not the Problem envelope.
        let io_err = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "tcp connect to db.internal.example:5432 refused",
        );
        let am_err: AmError = DbError::Io(io_err).into();
        let AmError::ServiceUnavailable { detail } = am_err else {
            panic!("expected ServiceUnavailable variant");
        };
        assert!(
            !detail.contains("db.internal.example") && !detail.contains("5432"),
            "503 detail must not echo connection-error text; got: {detail:?}"
        );
        assert_eq!(detail, "database unavailable; retry later");
    }

    #[test]
    fn conflict_detail_does_not_leak_db_error_text() {
        // Pin the no-leak invariant: the public Problem `detail` must
        // not contain the raw driver message. The audit-visible
        // diagnostic still carries the raw error via the `tracing`
        // log emitted in `From<DbError> for AmError`.
        let sea_err = DbErr::Exec(RuntimeErr::Internal(
            "duplicate key value violates unique constraint \"tenants_pkey\"".to_owned(),
        ));
        let am_err: AmError = DbError::Sea(sea_err).into();
        let AmError::Conflict { detail } = am_err else {
            panic!("expected AmError::Conflict variant");
        };
        assert!(
            !detail.contains("duplicate key") && !detail.contains("tenants_pkey"),
            "conflict detail must not echo the raw DB error; got: {detail:?}"
        );
    }

    #[test]
    fn serialization_conflict_detail_does_not_leak_db_error_text() {
        let sea_err = DbErr::Exec(RuntimeErr::Internal(
            "error returned from database: 40001: could not serialize access due to concurrent update"
                .to_owned(),
        ));
        let am_err: AmError = DbError::Sea(sea_err).into();
        let AmError::SerializationConflict { detail } = am_err else {
            panic!("expected AmError::SerializationConflict variant");
        };
        assert!(
            !detail.contains("40001") && !detail.contains("concurrent update"),
            "serialization-conflict detail must not echo the raw DB error; got: {detail:?}"
        );
    }
}
