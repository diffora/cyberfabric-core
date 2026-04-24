//! Account Management domain error taxonomy.
//!
//! Implements the authoritative 8-category / N-code public error contract
//! from PRD §5.8 and DESIGN §3.8. Every failure surfaced by any AM feature
//! **MUST** map to exactly one variant of [`AmError`]; unclassified paths
//! fall through to [`AmError::Internal`] per `algo-error-to-problem-mapping`
//! step 9.

use modkit_macros::domain_model;
use thiserror::Error;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The 9 stable public error categories enumerated by PRD §5.8 plus the
/// Phase-5 `TooManyRequests` extension (HTTP 429 — single-flight refusal
/// for the hierarchy-integrity audit).
///
/// The string returned by [`ErrorCategory::as_str`] appears verbatim in the
/// public Problem envelope `code` field and in the `OpenAPI` `Problem.code`
/// enum. Renaming requires a contract-version bump (per
/// `dod-errors-observability-versioning-discipline`).
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    Validation,
    NotFound,
    Conflict,
    CrossTenantDenied,
    IdpUnavailable,
    IdpUnsupportedOperation,
    /// HTTP 429. A retry-after-style refusal — distinct from `Conflict`
    /// (HTTP 409) which signals state precondition violations. Currently
    /// only emitted when the hierarchy-integrity audit single-flight gate
    /// observes another in-flight audit on the same scope.
    TooManyRequests,
    ServiceUnavailable,
    Internal,
}

impl ErrorCategory {
    /// Public token exactly as it appears in the `OpenAPI` `Problem.code` enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::CrossTenantDenied => "cross_tenant_denied",
            Self::IdpUnavailable => "idp_unavailable",
            Self::IdpUnsupportedOperation => "idp_unsupported_operation",
            Self::TooManyRequests => "too_many_requests",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal => "internal",
        }
    }

    /// HTTP status enforced by the category→status mapping in PRD §5.8 / DESIGN §3.8.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Validation => 422,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::CrossTenantDenied => 403,
            Self::IdpUnavailable | Self::ServiceUnavailable => 503,
            Self::IdpUnsupportedOperation => 501,
            Self::TooManyRequests => 429,
            Self::Internal => 500,
        }
    }
}

/// Account Management domain error.
///
/// Variants are grouped below by the 8 public categories from PRD §5.8; the
/// grouping is preserved in the order of declaration so reviewers can
/// eyeball-check the exhaustiveness promise. Unknown / unclassified upstream
/// failures **MUST** funnel into [`AmError::Internal`] to preserve
/// public-contract stability per `algo-error-to-problem-mapping` step 9.
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-error-taxonomy-and-envelope:p1:inst-dod-error-taxonomy-enum
#[domain_model]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AmError {
    // ---- validation (HTTP 422) ----
    #[error("invalid tenant type: {detail}")]
    InvalidTenantType { detail: String },

    #[error("validation failed: {detail}")]
    Validation { detail: String },

    #[error("root tenant cannot be deleted")]
    RootTenantCannotDelete,

    #[error("root tenant cannot be converted")]
    RootTenantCannotConvert,

    // ---- not_found (HTTP 404) ----
    #[error("resource not found: {detail}")]
    NotFound { detail: String },

    #[error("metadata schema not registered: {detail}")]
    MetadataSchemaNotRegistered { detail: String },

    #[error("metadata entry not found: {detail}")]
    MetadataEntryNotFound { detail: String },

    // ---- conflict (HTTP 409) ----
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

    #[error("conflict: {detail}")]
    Conflict { detail: String },

    // ---- cross_tenant_denied (HTTP 403) ----
    #[error("cross-tenant access denied")]
    CrossTenantDenied,

    #[error("cross-tenant access denied")]
    CrossTenantDeniedSource {
        #[source]
        cause: BoxError,
    },

    // ---- idp_unavailable (HTTP 503) ----
    #[error("IdP unavailable: {detail}")]
    IdpUnavailable { detail: String },

    // ---- idp_unsupported_operation (HTTP 501) ----
    #[error("IdP unsupported operation: {detail}")]
    IdpUnsupportedOperation { detail: String },

    // ---- too_many_requests (HTTP 429) ----
    /// Hierarchy-integrity audit refused because another audit on the
    /// same scope is already in progress. Maps to HTTP 429 (retry-after
    /// semantics, not a state conflict). The `scope` field carries the
    /// `IntegrityScope` identity (`"whole"` or `"subtree:<uuid>"`) for
    /// the caller to match on.
    ///
    /// Constructed by the storage layer (`audit_integrity_for_scope`)
    /// when the per-scope single-flight gate is held — Postgres uses
    /// `pg_try_advisory_xact_lock`, `SQLite` uses an `INSERT INTO
    /// running_audits ON CONFLICT DO NOTHING` row. There is no
    /// `From<DbError>` mapping for this variant; it is emitted directly
    /// based on lock-acquisition semantics, not converted from a
    /// database error.
    #[error("integrity audit already running for scope: {scope}")]
    AuditAlreadyRunning { scope: String },

    // ---- service_unavailable (HTTP 503) ----
    #[error("service unavailable: {detail}")]
    ServiceUnavailable { detail: String },

    #[error("service unavailable: {detail}")]
    ServiceUnavailableSource {
        detail: String,
        #[source]
        cause: BoxError,
    },

    /// Database serialization failure (SQLSTATE `40001` / `Postgres`
    /// `could not serialize access` / `MySQL` `InnoDB` deadlock).
    /// Always safe to retry. Funneled through `From<DbError>` in
    /// `infra/error_conv.rs` so the SERIALIZABLE-retry helper in
    /// `infra/storage/repo_impl.rs` can match a typed variant instead
    /// of doing string-match on a flattened `Internal` diagnostic.
    ///
    /// Surfaces as `conflict` (HTTP 409, `code = serialization_conflict`)
    /// when the retry budget is exhausted, per
    /// `feature-tenant-hierarchy-management §6 / DoD-concurrency`
    /// (line 679 / AC line 711): "losing writers MUST receive a
    /// deterministic error category (`conflict` or `validation`)".
    /// Operators retain `serialization_conflict` as a finer-grained
    /// `code` so retry-exhaustion is distinguishable from
    /// precondition-driven conflicts (`tenant_has_children`,
    /// `type_not_allowed`, etc.) in monitoring.
    #[error("serialization conflict: {detail}")]
    SerializationConflict { detail: String },

    // ---- internal (HTTP 500) ----
    /// Unclassified internal failure. The `diagnostic` field is recorded in
    /// the audit trail (via [`crate::domain::audit`]) but **MUST NOT** be
    /// leaked through any future public Problem body.
    #[error("internal error")]
    Internal { diagnostic: String },

    #[error("internal error")]
    InternalSource {
        diagnostic: String,
        #[source]
        cause: BoxError,
    },
}
// @cpt-end:cpt-cf-account-management-dod-errors-observability-error-taxonomy-and-envelope:p1:inst-dod-error-taxonomy-enum

impl From<authz_resolver_sdk::EnforcerError> for AmError {
    /// Map PEP enforcement failures into AM's public error taxonomy.
    ///
    /// - `Denied` → [`AmError::CrossTenantDenied`] (HTTP 403). The PDP
    ///   refused the action; AM does not leak the deny reason to the
    ///   public envelope.
    /// - `EvaluationFailed` → [`AmError::ServiceUnavailable`] (HTTP 503).
    ///   The PDP transport failed; per DESIGN §4.3 protected operations
    ///   fail closed — there is no local authorization fallback.
    /// - `CompileFailed` → [`AmError::Internal`] (HTTP 500). Constraint
    ///   compilation only fails when the PEP/PDP contract is broken
    ///   (missing or unsupported constraint shape) — that is an AM
    ///   integration bug, not a transient outage.
    fn from(err: authz_resolver_sdk::EnforcerError) -> Self {
        use authz_resolver_sdk::EnforcerError;
        match err {
            denied @ EnforcerError::Denied { .. } => Self::CrossTenantDeniedSource {
                cause: Box::new(denied),
            },
            EnforcerError::EvaluationFailed(source) => Self::ServiceUnavailableSource {
                detail: format!("authz evaluation failed: {source}"),
                cause: Box::new(EnforcerError::EvaluationFailed(source)),
            },
            EnforcerError::CompileFailed(source) => Self::InternalSource {
                diagnostic: format!("authz constraint compile failed: {source}"),
                cause: Box::new(EnforcerError::CompileFailed(source)),
            },
        }
    }
}

impl AmError {
    /// Classifies the error into one of the 8 public categories per
    /// `algo-error-to-problem-mapping`.
    // @cpt-begin:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-domain-classification
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidTenantType { .. }
            | Self::Validation { .. }
            | Self::RootTenantCannotDelete
            | Self::RootTenantCannotConvert => ErrorCategory::Validation,

            Self::NotFound { .. }
            | Self::MetadataSchemaNotRegistered { .. }
            | Self::MetadataEntryNotFound { .. } => ErrorCategory::NotFound,

            Self::TypeNotAllowed { .. }
            | Self::TenantDepthExceeded { .. }
            | Self::TenantHasChildren
            | Self::TenantHasResources
            | Self::PendingExists { .. }
            | Self::InvalidActorForTransition { .. }
            | Self::AlreadyResolved
            | Self::Conflict { .. }
            | Self::SerializationConflict { .. } => ErrorCategory::Conflict,

            Self::CrossTenantDenied | Self::CrossTenantDeniedSource { .. } => {
                ErrorCategory::CrossTenantDenied
            }
            Self::IdpUnavailable { .. } => ErrorCategory::IdpUnavailable,
            Self::IdpUnsupportedOperation { .. } => ErrorCategory::IdpUnsupportedOperation,
            Self::AuditAlreadyRunning { .. } => ErrorCategory::TooManyRequests,
            Self::ServiceUnavailable { .. } | Self::ServiceUnavailableSource { .. } => {
                ErrorCategory::ServiceUnavailable
            }
            Self::Internal { .. } | Self::InternalSource { .. } => ErrorCategory::Internal,
        }
    }

    /// Stable public `code` exposed through the Problem envelope per
    /// DESIGN §3.8 / `OpenAPI` `Problem.code`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTenantType { .. } => "invalid_tenant_type",
            Self::Validation { .. } => "validation",
            Self::RootTenantCannotDelete => "root_tenant_cannot_delete",
            Self::RootTenantCannotConvert => "root_tenant_cannot_convert",

            Self::NotFound { .. } => "not_found",
            Self::MetadataSchemaNotRegistered { .. } => "metadata_schema_not_registered",
            Self::MetadataEntryNotFound { .. } => "metadata_entry_not_found",

            Self::TypeNotAllowed { .. } => "type_not_allowed",
            Self::TenantDepthExceeded { .. } => "tenant_depth_exceeded",
            Self::TenantHasChildren => "tenant_has_children",
            Self::TenantHasResources => "tenant_has_resources",
            Self::PendingExists { .. } => "pending_exists",
            Self::InvalidActorForTransition { .. } => "invalid_actor_for_transition",
            Self::AlreadyResolved => "already_resolved",
            Self::Conflict { .. } => "conflict",

            Self::CrossTenantDenied | Self::CrossTenantDeniedSource { .. } => "cross_tenant_denied",
            Self::IdpUnavailable { .. } => "idp_unavailable",
            Self::IdpUnsupportedOperation { .. } => "idp_unsupported_operation",
            Self::AuditAlreadyRunning { .. } => "audit_already_running",
            Self::ServiceUnavailable { .. } | Self::ServiceUnavailableSource { .. } => {
                "service_unavailable"
            }
            Self::Internal { .. } | Self::InternalSource { .. } => "internal",
            Self::SerializationConflict { .. } => "serialization_conflict",
        }
    }
    // @cpt-end:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-domain-classification

    /// HTTP status inherited from the enclosing category.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        self.category().http_status()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn every_category_token_matches_expected_string() {
        assert_eq!(ErrorCategory::Validation.as_str(), "validation");
        assert_eq!(ErrorCategory::NotFound.as_str(), "not_found");
        assert_eq!(ErrorCategory::Conflict.as_str(), "conflict");
        assert_eq!(
            ErrorCategory::CrossTenantDenied.as_str(),
            "cross_tenant_denied"
        );
        assert_eq!(ErrorCategory::IdpUnavailable.as_str(), "idp_unavailable");
        assert_eq!(
            ErrorCategory::IdpUnsupportedOperation.as_str(),
            "idp_unsupported_operation"
        );
        assert_eq!(
            ErrorCategory::TooManyRequests.as_str(),
            "too_many_requests"
        );
        assert_eq!(
            ErrorCategory::ServiceUnavailable.as_str(),
            "service_unavailable"
        );
        assert_eq!(ErrorCategory::Internal.as_str(), "internal");
    }

    #[test]
    fn http_status_mapping_matches_design_3_8() {
        assert_eq!(
            AmError::InvalidTenantType { detail: "x".into() }.http_status(),
            422
        );
        assert_eq!(AmError::RootTenantCannotDelete.http_status(), 422);
        assert_eq!(
            AmError::TypeNotAllowed { detail: "x".into() }.http_status(),
            409
        );
        assert_eq!(AmError::TenantHasChildren.http_status(), 409);
        assert_eq!(AmError::CrossTenantDenied.http_status(), 403);
        assert_eq!(
            AmError::CrossTenantDeniedSource {
                cause: Box::new(authz_resolver_sdk::EnforcerError::Denied { deny_reason: None }),
            }
            .http_status(),
            403
        );
        assert_eq!(
            AmError::IdpUnavailable { detail: "x".into() }.http_status(),
            503
        );
        assert_eq!(
            AmError::IdpUnsupportedOperation { detail: "x".into() }.http_status(),
            501
        );
        assert_eq!(
            AmError::ServiceUnavailable { detail: "x".into() }.http_status(),
            503
        );
        assert_eq!(
            AmError::ServiceUnavailableSource {
                detail: "x".into(),
                cause: Box::new(authz_resolver_sdk::EnforcerError::EvaluationFailed(
                    authz_resolver_sdk::AuthZResolverError::NoPluginAvailable,
                )),
            }
            .http_status(),
            503
        );
        assert_eq!(
            AmError::Internal {
                diagnostic: "x".into()
            }
            .http_status(),
            500
        );
        assert_eq!(
            AmError::InternalSource {
                diagnostic: "x".into(),
                cause: Box::new(authz_resolver_sdk::EnforcerError::CompileFailed(
                    authz_resolver_sdk::pep::compiler::ConstraintCompileError::ConstraintsRequiredButAbsent,
                )),
            }
            .http_status(),
            500
        );
        // SerializationConflict: losing concurrent mutators must
        // surface as `conflict` (HTTP 409) per
        // `feature-tenant-hierarchy-management §6` / AC line 711, not
        // `internal` (HTTP 500). The finer-grained `code` stays
        // `serialization_conflict` so retry-exhaustion stays
        // distinguishable from precondition conflicts in monitoring.
        let serialization_conflict = AmError::SerializationConflict { detail: "x".into() };
        assert_eq!(serialization_conflict.http_status(), 409);
        assert_eq!(serialization_conflict.category(), ErrorCategory::Conflict);
        assert_eq!(serialization_conflict.code(), "serialization_conflict");

        // AuditAlreadyRunning: the Phase-5 single-flight gate refusal
        // surfaces as 429 (`too_many_requests`) — retry-after semantics,
        // distinct from the 409 conflict band. The `scope` field is the
        // `IntegrityScope` identity surfaced unchanged through the
        // Problem detail.
        let already_running = AmError::AuditAlreadyRunning {
            scope: "whole".into(),
        };
        assert_eq!(already_running.http_status(), 429);
        assert_eq!(
            already_running.category(),
            ErrorCategory::TooManyRequests
        );
        assert_eq!(already_running.code(), "audit_already_running");
        let already_running_subtree = AmError::AuditAlreadyRunning {
            scope: "subtree:00000000-0000-0000-0000-000000000001".into(),
        };
        assert_eq!(already_running_subtree.http_status(), 429);
    }

    #[test]
    fn code_tokens_match_openapi_problem_enum() {
        // Acceptance criterion §6: every stable public `code` from DESIGN
        // §3.8 appears as an exactly-matching string constant and is covered
        // by at least one test. This test enumerates every variant.
        let s = "x".to_owned();
        let cases: &[(AmError, &str)] = &[
            (
                AmError::InvalidTenantType { detail: s.clone() },
                "invalid_tenant_type",
            ),
            (AmError::Validation { detail: s.clone() }, "validation"),
            (AmError::RootTenantCannotDelete, "root_tenant_cannot_delete"),
            (
                AmError::RootTenantCannotConvert,
                "root_tenant_cannot_convert",
            ),
            (AmError::NotFound { detail: s.clone() }, "not_found"),
            (
                AmError::MetadataSchemaNotRegistered { detail: s.clone() },
                "metadata_schema_not_registered",
            ),
            (
                AmError::MetadataEntryNotFound { detail: s.clone() },
                "metadata_entry_not_found",
            ),
            (
                AmError::TypeNotAllowed { detail: s.clone() },
                "type_not_allowed",
            ),
            (
                AmError::TenantDepthExceeded { detail: s.clone() },
                "tenant_depth_exceeded",
            ),
            (AmError::TenantHasChildren, "tenant_has_children"),
            (AmError::TenantHasResources, "tenant_has_resources"),
            (
                AmError::PendingExists {
                    request_id: s.clone(),
                },
                "pending_exists",
            ),
            (
                AmError::InvalidActorForTransition {
                    attempted_status: s.clone(),
                    caller_side: s.clone(),
                },
                "invalid_actor_for_transition",
            ),
            (AmError::AlreadyResolved, "already_resolved"),
            (AmError::Conflict { detail: s.clone() }, "conflict"),
            (AmError::CrossTenantDenied, "cross_tenant_denied"),
            (
                AmError::CrossTenantDeniedSource {
                    cause: Box::new(authz_resolver_sdk::EnforcerError::Denied { deny_reason: None }),
                },
                "cross_tenant_denied",
            ),
            (
                AmError::IdpUnavailable { detail: s.clone() },
                "idp_unavailable",
            ),
            (
                AmError::IdpUnsupportedOperation { detail: s.clone() },
                "idp_unsupported_operation",
            ),
            (
                AmError::ServiceUnavailable { detail: s.clone() },
                "service_unavailable",
            ),
            (
                AmError::ServiceUnavailableSource {
                    detail: s.clone(),
                    cause: Box::new(authz_resolver_sdk::EnforcerError::EvaluationFailed(
                        authz_resolver_sdk::AuthZResolverError::NoPluginAvailable,
                    )),
                },
                "service_unavailable",
            ),
            (
                AmError::Internal {
                    diagnostic: s.clone(),
                },
                "internal",
            ),
            (
                AmError::InternalSource {
                    diagnostic: s.clone(),
                    cause: Box::new(authz_resolver_sdk::EnforcerError::CompileFailed(
                        authz_resolver_sdk::pep::compiler::ConstraintCompileError::ConstraintsRequiredButAbsent,
                    )),
                },
                "internal",
            ),
            (
                AmError::SerializationConflict { detail: s.clone() },
                "serialization_conflict",
            ),
            (
                AmError::AuditAlreadyRunning { scope: s },
                "audit_already_running",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), *expected, "variant {err:?}");
        }
    }

    #[test]
    fn enforcer_error_conversion_preserves_source_chain() {
        let cases = vec![
            (
                authz_resolver_sdk::EnforcerError::Denied { deny_reason: None },
                ErrorCategory::CrossTenantDenied,
                "cross_tenant_denied",
                "access denied by PDP",
            ),
            (
                authz_resolver_sdk::EnforcerError::EvaluationFailed(
                    authz_resolver_sdk::AuthZResolverError::NoPluginAvailable,
                ),
                ErrorCategory::ServiceUnavailable,
                "service_unavailable",
                "authorization evaluation failed",
            ),
            (
                authz_resolver_sdk::EnforcerError::CompileFailed(
                    authz_resolver_sdk::pep::compiler::ConstraintCompileError::ConstraintsRequiredButAbsent,
                ),
                ErrorCategory::Internal,
                "internal",
                "constraint compilation failed",
            ),
        ];

        for (source, category, code, source_message) in cases {
            let err = AmError::from(source);
            assert_eq!(err.category(), category, "converted error: {err:?}");
            assert_eq!(err.code(), code, "converted error: {err:?}");
            let actual_source = err.source().expect("converted error should keep source");
            assert!(
                actual_source.to_string().contains(source_message),
                "source message should contain {source_message:?}, got {actual_source}"
            );
        }
    }
}
