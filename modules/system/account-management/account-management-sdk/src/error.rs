//! Public inter-module error type for the Account Management module.
//!
//! Mirrors the pattern in `resource-group-sdk` (`ResourceGroupError`)
//! and `tenant-resolver-sdk`: a small, lossy enum that downstream
//! modules consume through the `ClientHub`-exposed AM trait. The full
//! taxonomy with infrastructure-level causes (`sea_orm::DbErr`, PEP
//! enforcement chain, etc.) lives in the runtime crate as `AmError`;
//! the runtime carries `impl From<AmError> for AccountManagementError`
//! that flattens the rich type onto the 9 stable categories from PRD
//! §5.8.
//!
//! REST handlers do **not** go through this type — they convert
//! runtime `AmError` directly into the platform `Problem` envelope so
//! the wire format keeps the finer-grained public `code` tokens
//! (`serialization_conflict`, `audit_already_running`,
//! `tenant_has_children`, …). This SDK type is the boundary for
//! Rust-side inter-module callers, where category granularity is
//! sufficient.

use thiserror::Error;

/// Stable inter-module error surface for AM.
///
/// Each variant lines up with one of the 9 categories defined in
/// `domain::error::ErrorCategory`. Internal-only variants (e.g.
/// `SerializationConflict` retry exhaustion, `AuditAlreadyRunning`)
/// flatten into the broader category at the SDK boundary; their
/// finer-grained `code` token is preserved through the REST `Problem`
/// envelope, not here.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum AccountManagementError {
    /// HTTP 422. Caller-side input or precondition violation.
    #[error("validation failed: {message}")]
    Validation { message: String },

    /// HTTP 404. Tenant, metadata schema, or metadata entry missing.
    #[error("not found: {message}")]
    NotFound { message: String },

    /// HTTP 409. State precondition violation — tenant has children,
    /// has resources, depth threshold exceeded, racing serialization
    /// conflict, etc.
    #[error("conflict: {message}")]
    Conflict { message: String },

    /// HTTP 403. PDP denied the action (or the AM ancestry gate
    /// rejected a cross-tenant reach).
    #[error("cross-tenant access denied")]
    CrossTenantDenied,

    /// HTTP 503. The `IdP` plugin is unreachable or refused the
    /// operation in a clean-failure mode.
    #[error("IdP unavailable: {message}")]
    IdpUnavailable { message: String },

    /// HTTP 501. The `IdP` plugin signalled the requested operation is
    /// not supported.
    #[error("IdP unsupported operation: {message}")]
    IdpUnsupportedOperation { message: String },

    /// HTTP 429. Single-flight refusal — currently only the
    /// hierarchy-integrity audit gate.
    #[error("too many requests: {message}")]
    TooManyRequests { message: String },

    /// HTTP 503. Database or upstream dependency outage.
    #[error("service unavailable: {message}")]
    ServiceUnavailable { message: String },

    /// HTTP 500. Unclassified internal failure. The diagnostic stays
    /// in the runtime audit trail and is not surfaced through this
    /// type.
    #[error("internal error")]
    Internal,
}

impl AccountManagementError {
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn cross_tenant_denied() -> Self {
        Self::CrossTenantDenied
    }

    #[must_use]
    pub fn idp_unavailable(message: impl Into<String>) -> Self {
        Self::IdpUnavailable {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn idp_unsupported_operation(message: impl Into<String>) -> Self {
        Self::IdpUnsupportedOperation {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::TooManyRequests {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::Internal
    }
}
