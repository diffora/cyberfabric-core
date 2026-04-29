//! Account Management domain error taxonomy.
//!
//! Implements the authoritative 9-category / N-code public error contract
//! from PRD §5.8 + the `TooManyRequests` extension (HTTP 429 — single-flight
//! refusal for the hierarchy-integrity audit). Every failure surfaced by any
//! AM feature
//! **MUST** map to exactly one variant of [`AmError`]; unclassified paths
//! fall through to [`AmError::Internal`] per `algo-error-to-problem-mapping`
//! step 10 (the `too_many_requests` branch added at step 9 shifted the
//! `internal` fallthrough from step 9 to step 10).

use modkit_macros::domain_model;
use thiserror::Error;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The 9 stable public error categories enumerated by PRD §5.8 plus the
/// Phase-5 `TooManyRequests` extension (HTTP 429 — single-flight refusal
/// for the hierarchy-integrity audit).
///
/// The token returned by [`ErrorCategory::as_str`] is the *category*
/// discriminator. The wire-level `Problem.code` field on a public error
/// response is produced by [`AmError::code`], **not** by this method —
/// some error variants (`SerializationConflict`, `AuditAlreadyRunning`)
/// carry their own finer-grained `code` token while still belonging to a
/// broader category here. Renaming either taxonomy requires a
/// contract-version bump (per
/// `dod-errors-observability-versioning-discipline`).
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// Stable category token. Note this is **not** the wire-level
    /// `Problem.code` for every variant — see [`AmError::code`].
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
/// Variants are grouped below by the 9 public categories from PRD §5.8 + the
/// `TooManyRequests` extension; the
/// grouping is preserved in the order of declaration so reviewers can
/// eyeball-check the exhaustiveness promise. Unknown / unclassified upstream
/// failures **MUST** funnel into [`AmError::Internal`] to preserve
/// public-contract stability per `algo-error-to-problem-mapping` step 10.
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
    /// `cause` is `Some` only when the denial originates upstream
    /// (e.g. `From<authz_resolver_sdk::EnforcerError::Denied>`); plain
    /// AM-side ancestry rejections leave it `None`.
    #[error("cross-tenant access denied")]
    CrossTenantDenied {
        #[source]
        cause: Option<BoxError>,
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
    /// `cause` carries the upstream error chain for non-DB sources
    /// (`From<authz_resolver_sdk::EnforcerError::EvaluationFailed>`,
    /// future plugin / dependency wrappers); the `From<DbError>`
    /// connectivity path in [`crate::infra::error_conv`] deliberately
    /// drops the cause via `cause: None` to avoid leaking DSN /
    /// hostname / port fragments through `Display`. Plain `detail`-only
    /// constructions also leave it `None`.
    #[error("service unavailable: {detail}")]
    ServiceUnavailable {
        detail: String,
        #[source]
        cause: Option<BoxError>,
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
    /// Unclassified internal failure. The `diagnostic` field is
    /// recorded in the audit trail (via the audit module landing in a
    /// later PR) but **MUST NOT** be leaked through any future public
    /// Problem body. `cause` carries the upstream error chain when
    /// available.
    #[error("internal error")]
    Internal {
        diagnostic: String,
        #[source]
        cause: Option<BoxError>,
    },
}
// @cpt-end:cpt-cf-account-management-dod-errors-observability-error-taxonomy-and-envelope:p1:inst-dod-error-taxonomy-enum

impl From<AmError> for account_management_sdk::AccountManagementError {
    /// Flatten the runtime taxonomy onto the 9 stable public categories.
    ///
    /// Mirrors `resource-group-sdk`'s `ResourceGroupError`:
    /// inter-module Rust callers see one variant per category and
    /// receive the human-readable detail through `message`. Internal
    /// causes (`BoxError` chains, audit-only `diagnostic` strings,
    /// `cf-modkit-db` `DbErr` payloads) are intentionally dropped —
    /// REST handlers convert `AmError` directly to the platform
    /// `Problem` envelope, so finer-grained `code` tokens
    /// (`serialization_conflict`, `audit_already_running`, …) stay on
    /// the wire while the SDK surface remains stable.
    fn from(err: AmError) -> Self {
        use account_management_sdk::AccountManagementError as Public;
        match err {
            // ---- validation (HTTP 422) ----
            AmError::InvalidTenantType { detail } | AmError::Validation { detail } => {
                Public::Validation { message: detail }
            }
            AmError::RootTenantCannotDelete => Public::Validation {
                message: "root tenant cannot be deleted".to_owned(),
            },
            AmError::RootTenantCannotConvert => Public::Validation {
                message: "root tenant cannot be converted".to_owned(),
            },

            // ---- not_found (HTTP 404) ----
            AmError::NotFound { detail }
            | AmError::MetadataSchemaNotRegistered { detail }
            | AmError::MetadataEntryNotFound { detail } => Public::NotFound { message: detail },

            // ---- conflict (HTTP 409) ----
            AmError::TypeNotAllowed { detail }
            | AmError::TenantDepthExceeded { detail }
            | AmError::Conflict { detail }
            | AmError::SerializationConflict { detail } => Public::Conflict { message: detail },
            AmError::TenantHasChildren => Public::Conflict {
                message: "tenant has child tenants".to_owned(),
            },
            AmError::TenantHasResources => Public::Conflict {
                message: "tenant still owns resources".to_owned(),
            },
            AmError::PendingExists { request_id } => Public::Conflict {
                message: format!("a pending conversion request already exists: {request_id}"),
            },
            AmError::InvalidActorForTransition {
                attempted_status,
                caller_side,
            } => Public::Conflict {
                message: format!(
                    "invalid actor for conversion transition: \
                     attempted={attempted_status} caller_side={caller_side}"
                ),
            },
            AmError::AlreadyResolved => Public::Conflict {
                message: "conversion request already resolved".to_owned(),
            },

            // ---- cross_tenant_denied (HTTP 403) ----
            AmError::CrossTenantDenied { .. } => Public::CrossTenantDenied,

            // ---- idp_unavailable / idp_unsupported_operation ----
            AmError::IdpUnavailable { detail } => Public::IdpUnavailable { message: detail },
            AmError::IdpUnsupportedOperation { detail } => {
                Public::IdpUnsupportedOperation { message: detail }
            }

            // ---- too_many_requests (HTTP 429) ----
            AmError::AuditAlreadyRunning { scope } => Public::TooManyRequests {
                message: format!("integrity audit already running for scope: {scope}"),
            },

            // ---- service_unavailable (HTTP 503) ----
            AmError::ServiceUnavailable { detail, .. } => {
                Public::ServiceUnavailable { message: detail }
            }

            // ---- internal (HTTP 500) ----
            AmError::Internal { .. } => Public::Internal,
        }
    }
}

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
            denied @ EnforcerError::Denied { .. } => Self::CrossTenantDenied {
                cause: Some(Box::new(denied)),
            },
            EnforcerError::EvaluationFailed(source) => Self::ServiceUnavailable {
                detail: format!("authz evaluation failed: {source}"),
                cause: Some(Box::new(EnforcerError::EvaluationFailed(source))),
            },
            EnforcerError::CompileFailed(source) => Self::Internal {
                diagnostic: format!("authz constraint compile failed: {source}"),
                cause: Some(Box::new(EnforcerError::CompileFailed(source))),
            },
        }
    }
}

impl AmError {
    /// Classifies the error into one of the 9 public categories per
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

            Self::CrossTenantDenied { .. } => ErrorCategory::CrossTenantDenied,
            Self::IdpUnavailable { .. } => ErrorCategory::IdpUnavailable,
            Self::IdpUnsupportedOperation { .. } => ErrorCategory::IdpUnsupportedOperation,
            Self::AuditAlreadyRunning { .. } => ErrorCategory::TooManyRequests,
            Self::ServiceUnavailable { .. } => ErrorCategory::ServiceUnavailable,
            Self::Internal { .. } => ErrorCategory::Internal,
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

            Self::CrossTenantDenied { .. } => "cross_tenant_denied",
            Self::IdpUnavailable { .. } => "idp_unavailable",
            Self::IdpUnsupportedOperation { .. } => "idp_unsupported_operation",
            Self::AuditAlreadyRunning { .. } => "audit_already_running",
            Self::ServiceUnavailable { .. } => "service_unavailable",
            Self::Internal { .. } => "internal",
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
        assert_eq!(
            AmError::CrossTenantDenied { cause: None }.http_status(),
            403
        );
        assert_eq!(
            AmError::CrossTenantDenied {
                cause: Some(Box::new(authz_resolver_sdk::EnforcerError::Denied {
                    deny_reason: None
                })),
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
            AmError::ServiceUnavailable {
                detail: "x".into(),
                cause: None,
            }
            .http_status(),
            503
        );
        assert_eq!(
            AmError::ServiceUnavailable {
                detail: "x".into(),
                cause: Some(Box::new(authz_resolver_sdk::EnforcerError::EvaluationFailed(
                    authz_resolver_sdk::AuthZResolverError::NoPluginAvailable,
                ))),
            }
            .http_status(),
            503
        );
        assert_eq!(
            AmError::Internal {
                diagnostic: "x".into(),
                cause: None,
            }
            .http_status(),
            500
        );
        assert_eq!(
            AmError::Internal {
                diagnostic: "x".into(),
                cause: Some(Box::new(authz_resolver_sdk::EnforcerError::CompileFailed(
                    authz_resolver_sdk::pep::compiler::ConstraintCompileError::ConstraintsRequiredButAbsent,
                ))),
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
            (
                AmError::CrossTenantDenied { cause: None },
                "cross_tenant_denied",
            ),
            (
                AmError::CrossTenantDenied {
                    cause: Some(Box::new(authz_resolver_sdk::EnforcerError::Denied {
                        deny_reason: None,
                    })),
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
                AmError::ServiceUnavailable {
                    detail: s.clone(),
                    cause: None,
                },
                "service_unavailable",
            ),
            (
                AmError::ServiceUnavailable {
                    detail: s.clone(),
                    cause: Some(Box::new(authz_resolver_sdk::EnforcerError::EvaluationFailed(
                        authz_resolver_sdk::AuthZResolverError::NoPluginAvailable,
                    ))),
                },
                "service_unavailable",
            ),
            (
                AmError::Internal {
                    diagnostic: s.clone(),
                    cause: None,
                },
                "internal",
            ),
            (
                AmError::Internal {
                    diagnostic: s.clone(),
                    cause: Some(Box::new(authz_resolver_sdk::EnforcerError::CompileFailed(
                        authz_resolver_sdk::pep::compiler::ConstraintCompileError::ConstraintsRequiredButAbsent,
                    ))),
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

    /// Every `AmError` variant must flatten onto a public SDK variant
    /// whose discriminant matches the runtime-side category. The pair
    /// is the inter-module Rust contract; it is what downstream
    /// modules consuming AM through `ClientHub` see.
    #[test]
    fn am_error_flattens_to_sdk_per_category() {
        use account_management_sdk::AccountManagementError as Public;

        let s = "x".to_owned();
        // (variant, expected SDK discriminant tag)
        let cases: Vec<(AmError, &str)> = vec![
            (AmError::InvalidTenantType { detail: s.clone() }, "validation"),
            (AmError::Validation { detail: s.clone() }, "validation"),
            (AmError::RootTenantCannotDelete, "validation"),
            (AmError::RootTenantCannotConvert, "validation"),
            (AmError::NotFound { detail: s.clone() }, "not_found"),
            (
                AmError::MetadataSchemaNotRegistered { detail: s.clone() },
                "not_found",
            ),
            (
                AmError::MetadataEntryNotFound { detail: s.clone() },
                "not_found",
            ),
            (AmError::TypeNotAllowed { detail: s.clone() }, "conflict"),
            (
                AmError::TenantDepthExceeded { detail: s.clone() },
                "conflict",
            ),
            (AmError::TenantHasChildren, "conflict"),
            (AmError::TenantHasResources, "conflict"),
            (
                AmError::PendingExists {
                    request_id: s.clone(),
                },
                "conflict",
            ),
            (
                AmError::InvalidActorForTransition {
                    attempted_status: s.clone(),
                    caller_side: s.clone(),
                },
                "conflict",
            ),
            (AmError::AlreadyResolved, "conflict"),
            (AmError::Conflict { detail: s.clone() }, "conflict"),
            (
                AmError::SerializationConflict { detail: s.clone() },
                "conflict",
            ),
            (AmError::CrossTenantDenied { cause: None }, "cross_tenant_denied"),
            (
                AmError::CrossTenantDenied {
                    cause: Some(Box::new(authz_resolver_sdk::EnforcerError::Denied {
                        deny_reason: None,
                    })),
                },
                "cross_tenant_denied",
            ),
            (AmError::IdpUnavailable { detail: s.clone() }, "idp_unavailable"),
            (
                AmError::IdpUnsupportedOperation { detail: s.clone() },
                "idp_unsupported_operation",
            ),
            (
                AmError::AuditAlreadyRunning { scope: s.clone() },
                "too_many_requests",
            ),
            (
                AmError::ServiceUnavailable {
                    detail: s.clone(),
                    cause: None,
                },
                "service_unavailable",
            ),
            (
                AmError::Internal {
                    diagnostic: s,
                    cause: None,
                },
                "internal",
            ),
        ];
        for (am_err, expected_tag) in cases {
            let public = Public::from(am_err);
            let actual_tag = match public {
                Public::Validation { .. } => "validation",
                Public::NotFound { .. } => "not_found",
                Public::Conflict { .. } => "conflict",
                Public::CrossTenantDenied => "cross_tenant_denied",
                Public::IdpUnavailable { .. } => "idp_unavailable",
                Public::IdpUnsupportedOperation { .. } => "idp_unsupported_operation",
                Public::TooManyRequests { .. } => "too_many_requests",
                Public::ServiceUnavailable { .. } => "service_unavailable",
                Public::Internal => "internal",
                _ => unreachable!("AccountManagementError variant added without flatten coverage"),
            };
            assert_eq!(actual_tag, expected_tag, "flatten target tag");
        }
    }
}
