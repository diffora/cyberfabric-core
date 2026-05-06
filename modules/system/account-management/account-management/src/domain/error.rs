//! Account Management domain error type.
//!
//! Internal-only — never crosses module boundaries. On every boundary
//! (REST handlers, inter-module SDK callers via `ClientHub`) this type
//! is converted to [`modkit_canonical_errors::CanonicalError`] via
//! [`From<DomainError> for CanonicalError`], following the AIP-193 error
//! model. Public HTTP status codes and the stable error-code taxonomy
//! are defined by the canonical-errors contract; AM's role is to map
//! domain failures onto AIP-193 categories, not to invent its own
//! HTTP-status table.
//!
//! # Layering
//!
//! `DomainError` is pure — no `sea_orm::DbErr`, no `modkit_db` types,
//! no `crate::infra` imports. The DB-aware classification ladder
//! (SQLSTATE 40001 / 23505 / availability / unclassified) lives in
//! [`crate::infra::canonical_mapping`] together with the `From` impls
//! that produce `DomainError` from raw DB errors and from `DomainError`
//! into `CanonicalError`. AM's `with_serializable_retry` wraps the raw
//! `DbErr` in an infra-internal `TxError` until the retry budget is
//! exhausted, then translates the surviving `DbErr` into a typed
//! `DomainError` (`Aborted`, `AlreadyExists`, `ServiceUnavailable`, or
//! `Internal`) before returning to the caller.

use std::time::Duration;

use modkit_macros::domain_model;
use thiserror::Error;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// AM domain-internal error.
///
/// Variants are grouped by the AIP-193 category they map to at the
/// boundary; the grouping is preserved in declaration order so reviewers
/// can eyeball-check exhaustiveness against
/// [`From<DomainError> for CanonicalError`] in
/// [`crate::infra::canonical_mapping`].
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-error-taxonomy-and-envelope:p1:inst-dod-error-taxonomy-enum
#[domain_model]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    // ---- InvalidArgument (HTTP 400) ----
    #[error("invalid tenant type: {detail}")]
    InvalidTenantType { detail: String },

    #[error("validation failed: {detail}")]
    Validation { detail: String },

    #[error("root tenant cannot be deleted")]
    RootTenantCannotDelete,

    #[error("root tenant cannot be converted")]
    RootTenantCannotConvert,

    // ---- NotFound (HTTP 404) ----
    /// `resource` is the stable resource identifier (typically a UUID
    /// rendered as a string) that the AIP-193 `NotFound` envelope
    /// surfaces through `with_resource`. `detail` is the human-readable
    /// summary; both fields are populated by the construction site
    /// (where the id is in scope) so the boundary mapping does not have
    /// to parse it back out of the message.
    #[error("resource not found: {detail}")]
    NotFound { detail: String, resource: String },

    #[error("metadata schema not registered: {detail}")]
    MetadataSchemaNotRegistered { detail: String, schema: String },

    #[error("metadata entry not found: {detail}")]
    MetadataEntryNotFound { detail: String, entry: String },

    // ---- AlreadyExists (HTTP 409) ----
    /// Produced by the storage layer's DB-error classifier when the
    /// underlying engine reports a unique-constraint violation
    /// (`SQLSTATE 23505` on Postgres, `SQLITE_CONSTRAINT_UNIQUE` /
    /// extended code 2067 on `SQLite`). The classifier lives in
    /// [`crate::infra::canonical_mapping`] so domain code stays free of
    /// `sea_orm` / `modkit_db` references.
    #[error("already exists: {detail}")]
    AlreadyExists { detail: String },

    // ---- Aborted (HTTP 409) ----
    /// Retry-budget-exhausted serialization failure surfaced by
    /// [`crate::infra::storage::repo_impl::helpers::with_serializable_retry`]
    /// after the underlying engine returned `SQLSTATE 40001` (or the
    /// `SQLite` analogue) for every attempt. `reason` is the canonical
    /// machine-readable token (e.g. `"SERIALIZATION_CONFLICT"`),
    /// `detail` is the human-readable summary surfaced through the
    /// canonical envelope.
    #[error("aborted: {detail}")]
    Aborted { reason: String, detail: String },

    // ---- FailedPrecondition (HTTP 400) ----
    #[error("tenant type not allowed for parent: {detail}")]
    TypeNotAllowed { detail: String },

    #[error("tenant hierarchy depth exceeded: {detail}")]
    TenantDepthExceeded { detail: String },

    #[error("tenant has child tenants")]
    TenantHasChildren,

    #[error("tenant still owns resources")]
    TenantHasResources,

    #[error("a pending conversion request already exists: {request_id}")]
    PendingExists { request_id: String },

    #[error(
        "invalid actor for conversion transition: attempted={attempted_status} caller_side={caller_side}"
    )]
    InvalidActorForTransition {
        attempted_status: String,
        caller_side: String,
    },

    #[error("conversion request already resolved")]
    AlreadyResolved,

    /// Generic precondition failure not covered by a more specific
    /// variant — used by repo paths that detect a state precondition
    /// violation (tenant deleted, type immutable, etc.) without a
    /// dedicated typed variant. Maps to
    /// [`modkit_canonical_errors::CanonicalError::FailedPrecondition`].
    #[error("precondition failed: {detail}")]
    Conflict { detail: String },

    // ---- PermissionDenied (HTTP 403) ----
    /// `cause` is `Some` only when the denial originates upstream
    /// (e.g. `From<authz_resolver_sdk::EnforcerError::Denied>`); plain
    /// AM-side ancestry rejections leave it `None`.
    #[error("cross-tenant access denied")]
    CrossTenantDenied {
        #[source]
        cause: Option<BoxError>,
    },

    // ---- ServiceUnavailable (HTTP 503) ----
    /// Covers transient infrastructure outages, generic `IdP` plugin
    /// failures, and PDP transport errors (per AIP-193). `retry_after`
    /// populates
    /// [`modkit_canonical_errors::context::ServiceUnavailable::retry_after_seconds`]
    /// when the caller has a defensible retry budget hint.
    ///
    /// `cause` carries the upstream error chain for non-DB sources
    /// (`From<authz_resolver_sdk::EnforcerError::EvaluationFailed>`,
    /// `IdP` plugin wrappers); the DB connectivity path deliberately
    /// leaves `cause: None` to avoid leaking DSN / hostname / port
    /// fragments through `Display`.
    #[error("service unavailable: {detail}")]
    ServiceUnavailable {
        detail: String,
        retry_after: Option<Duration>,
        #[source]
        cause: Option<BoxError>,
    },

    /// `IdP` plugin reports a transient/retry-safe outage. Distinct from
    /// the generic [`Self::ServiceUnavailable`] variant because the
    /// bootstrap saga retry loop pattern-matches on this variant
    /// specifically to decide whether to keep waiting on the
    /// `idp_wait_timeout_secs` budget vs. surfacing a fatal failure.
    /// Maps to the same AIP-193 `ServiceUnavailable` (HTTP 503) at the
    /// boundary as [`Self::ServiceUnavailable`].
    #[error("idp unavailable: {detail}")]
    IdpUnavailable { detail: String },

    // ---- Unimplemented (HTTP 501) ----
    /// Former `IdpUnsupportedOperation` — the `IdP` plugin signalled the
    /// requested administrative operation is not supported in its
    /// current implementation profile.
    #[error("operation not supported: {detail}")]
    UnsupportedOperation { detail: String },

    // ---- ResourceExhausted (HTTP 429) ----
    /// Hierarchy-integrity check refused because another check on the
    /// same scope is already in progress. Maps to HTTP 429 (retry-after
    /// semantics, not a state conflict). The `scope` field carries the
    /// `IntegrityScope` identity (`"whole"` or `"subtree:<uuid>"`) for
    /// the caller to match on.
    ///
    /// Constructed by the storage layer (`run_integrity_check_for_scope`)
    /// when the per-scope single-flight gate is held — both backends
    /// surface the conflict as a unique-violation on the
    /// `integrity_check_runs.scope_key` PRIMARY KEY (`Postgres` `23505`,
    /// `SQLite` extended `2067`).
    #[error("integrity check already in progress for scope: {scope}")]
    IntegrityCheckInProgress { scope: String },

    // ---- Internal (HTTP 500) ----
    /// Unclassified internal failure. The `diagnostic` field is
    /// recorded in the audit trail but **MUST NOT** be leaked through
    /// any public `Problem` body. `cause` carries the upstream error
    /// chain when available.
    #[error("internal error")]
    Internal {
        diagnostic: String,
        #[source]
        cause: Option<BoxError>,
    },
}
// @cpt-end:cpt-cf-account-management-dod-errors-observability-error-taxonomy-and-envelope:p1:inst-dod-error-taxonomy-enum

impl DomainError {
    /// Convenience constructor for [`Self::ServiceUnavailable`] without
    /// a retry-after hint or upstream cause.
    #[must_use]
    pub fn service_unavailable(detail: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            detail: detail.into(),
            retry_after: None,
            cause: None,
        }
    }

    /// Convenience constructor for [`Self::Internal`] without an
    /// upstream cause.
    #[must_use]
    pub fn internal(diagnostic: impl Into<String>) -> Self {
        Self::Internal {
            diagnostic: diagnostic.into(),
            cause: None,
        }
    }
}

impl From<authz_resolver_sdk::EnforcerError> for DomainError {
    /// Map PEP enforcement failures into AM's domain error model.
    ///
    /// Per the `ModKit` `AuthZ` fail-closed invariant
    /// (`docs/modkit_unified_system/06_authn_authz_secure_orm.md`):
    /// **denied PDP decisions, unreachable PDP, and missing /
    /// unsupported constraints all surface as 403 Forbidden** — never
    /// 500. AM follows that invariant here:
    ///
    /// - `Denied` → [`DomainError::CrossTenantDenied`] (HTTP 403). The
    ///   PDP refused the action; AM does not leak the deny reason to
    ///   the public envelope.
    /// - `EvaluationFailed` → [`DomainError::ServiceUnavailable`]
    ///   (HTTP 503). The PDP transport failed; per DESIGN §4.3
    ///   protected operations fail closed — there is no local
    ///   authorization fallback. (This is the one place `ModKit`'s
    ///   contract diverges from a strict 403: AM exposes the
    ///   transient-outage signal via 503 + `retry_after`, while the
    ///   guarantee that the protected operation does *not* run is
    ///   identical.)
    /// - `CompileFailed` → [`DomainError::CrossTenantDenied`] (HTTP
    ///   403). A compile failure means the PDP returned a constraint
    ///   shape AM cannot enforce locally — by the fail-closed rule
    ///   that MUST be a deny, not a 500. Raw compile error is kept on
    ///   the `cause` chain for the audit trail.
    fn from(err: authz_resolver_sdk::EnforcerError) -> Self {
        use authz_resolver_sdk::EnforcerError;
        match err {
            denied @ EnforcerError::Denied { .. } => Self::CrossTenantDenied {
                cause: Some(Box::new(denied)),
            },
            EnforcerError::EvaluationFailed(source) => Self::ServiceUnavailable {
                // Generic, non-leaky detail — `source` is the AuthZ
                // Resolver SDK's transport error and can carry the
                // PDP host / port / gRPC method name in its `Display`
                // text. Operators get the raw cause from the `cause`
                // chain (audit log) and the public envelope stays clean.
                detail: "authorization evaluation failed".to_owned(),
                retry_after: None,
                cause: Some(Box::new(EnforcerError::EvaluationFailed(source))),
            },
            compile_failed @ EnforcerError::CompileFailed(_) => Self::CrossTenantDenied {
                cause: Some(Box::new(compile_failed)),
            },
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "error_tests.rs"]
mod error_tests;
