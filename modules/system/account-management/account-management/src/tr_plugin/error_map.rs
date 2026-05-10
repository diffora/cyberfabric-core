//! Error-mapping helpers between `modkit-db` / `sea_orm` failures and
//! the SDK error taxonomy.
//!
//! The plugin only ever surfaces two SDK variants from these helpers:
//! [`TenantResolverError::TenantNotFound`] (constructed by call sites
//! that distinguish "no row" from "transient failure") and
//! [`TenantResolverError::Internal`] (every transient backend failure —
//! DESIGN §3.8 + FEATURE §5 "Error-Taxonomy Delegation"). DB and pool
//! failures map to `Internal` rather than `ServiceUnavailable` because
//! `ServiceUnavailable` is reserved for recoverable outages with a
//! retry hint; opaque storage failures do not carry that hint so
//! `Internal` is the safer surface.
//!
//! # Information leakage
//!
//! These helpers deliberately surface **opaque** strings on the SDK
//! boundary — backend error details (SQL fragments, connection-pool
//! state, scope diagnostics) are emitted via `tracing::warn!` for
//! operator visibility but never returned to the plugin caller.
//! Otherwise the same plugin in front of, e.g., a misconfigured pool
//! would leak DSN-shaped strings to gateway clients.

use modkit_db::DbError;
use modkit_db::secure::ScopeError;
use sea_orm::DbErr;
use tenant_resolver_sdk::TenantResolverError;

const STORAGE_INTERNAL_MSG: &str = "tenant resolver storage failure";
const SCOPE_INTERNAL_MSG: &str = "tenant resolver scope failure";

/// Convert a raw `sea_orm::DbErr` into a transient SDK error. The
/// detailed cause is logged server-side; only an opaque marker is
/// returned to the plugin caller.
#[must_use]
pub(super) fn db_err_to_tr_err(err: &DbErr) -> TenantResolverError {
    tracing::warn!(
        target: "tr_plugin",
        error = %err,
        "tr-plugin storage read failed"
    );
    TenantResolverError::Internal(STORAGE_INTERNAL_MSG.to_owned())
}

/// Convert a `modkit-db` `DbError` (covers `Sea`, `Pool`,
/// `ConnRequestedInsideTx`, etc.) into a transient SDK error.
#[must_use]
pub(super) fn modkit_db_err_to_tr_err(err: &DbError) -> TenantResolverError {
    tracing::warn!(
        target: "tr_plugin",
        error = %err,
        "tr-plugin storage unavailable"
    );
    TenantResolverError::Internal(STORAGE_INTERNAL_MSG.to_owned())
}

/// Convert a `ScopeError` produced by the secure-extension layer into
/// a transient SDK error. The plugin always passes
/// `AccessScope::allow_all()`, so `Invalid` / `Denied` /
/// `TenantNotInScope` are not expected on the SDK path; if they ever
/// surface they indicate an invariant violation and are logged as
/// `warn` for operator audit while the SDK boundary still receives an
/// opaque message.
#[must_use]
pub(super) fn scope_err_to_tr_err(err: &ScopeError) -> TenantResolverError {
    if let ScopeError::Db(db) = err {
        return db_err_to_tr_err(db);
    }
    let (event, reason): (&'static str, Option<&'static str>) = match err {
        ScopeError::Db(_) => unreachable!("handled above"),
        ScopeError::Invalid(msg) => ("tr-plugin storage scope invalid", Some(msg)),
        ScopeError::Denied(msg) => ("tr-plugin storage scope denied", Some(msg)),
        ScopeError::TenantNotInScope { .. } => (
            "tr-plugin storage scope tenant_not_in_scope (allow_all expected)",
            None,
        ),
    };
    tracing::warn!(target: "tr_plugin", reason = ?reason, "{event}");
    TenantResolverError::Internal(SCOPE_INTERNAL_MSG.to_owned())
}
