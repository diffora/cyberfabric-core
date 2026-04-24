//! Infrastructure-layer conversions between `modkit-db` errors and the
//! public AM domain error taxonomy.
//!
//! This module is the ONLY place where `modkit_db::DbError` reaches into
//! AM's domain layer. Phase 1's `domain/error.rs` stays strictly pure —
//! the `DBProvider<AmError>` parameterization picked in Phase 2 routes
//! every database-side failure through [`AmError::Internal`] here so
//! that no low-level driver variant ever leaks through the public
//! contract.

use modkit_db::DbError;
use modkit_db::deadlock::is_serialization_failure;
use modkit_db::secure::is_unique_violation;
use tracing::warn;

use crate::domain::error::AmError;

/// Wrap a [`DbError`] into the appropriate [`AmError`] variant.
///
/// The raw `DbError` is logged via `tracing::warn!` (correlatable by
/// trace-id) and, for the `Internal` fallback, stored in the
/// audit-visible `diagnostic` field. It MUST NOT reach the
/// client-facing Problem `detail` for `Conflict` or
/// `SerializationConflict`: those carry a generic, non-leaky message
/// only — exposing driver text (table names, SQL fragments, dialect
/// hints) on every retryable conflict is an information disclosure.
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
/// 3. Anything else → [`AmError::Internal`]. The Problem envelope's
///    public `detail` is empty; the diagnostic stays in the
///    audit-visible field only.
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-db-error-classification
impl From<DbError> for AmError {
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
    use sea_orm::{DbErr, RuntimeErr};

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
        // A DB error that is neither a serialization failure nor a
        // unique-constraint violation funnels into `Internal`/500 —
        // the public contract preserves the existing fallback path.
        let sea_err = DbErr::Exec(RuntimeErr::Internal("connection closed by peer".to_owned()));
        let am_err: AmError = DbError::Sea(sea_err).into();
        assert_eq!(am_err.sub_code(), "internal");
        assert!(matches!(am_err, AmError::Internal { .. }));
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
