//! Domain error types for the Types Registry module.

use modkit_macros::domain_model;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use types_registry_sdk::TypesRegistryError;

/// A structured validation error with typed fields.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    /// The GTS ID of the entity that failed validation.
    pub gts_id: String,
    /// The validation error message.
    pub message: String,
}

impl ValidationError {
    /// Creates a new validation error.
    #[must_use]
    pub fn new(gts_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            gts_id: gts_id.into(),
            message: message.into(),
        }
    }

    /// Parses a validation error from a string in the format "`gts_id`: message".
    #[must_use]
    pub fn from_string(s: &str) -> Self {
        if let Some((gts_id, message)) = s.split_once(": ") {
            Self::new(gts_id, message)
        } else {
            Self::new("unknown", s)
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.gts_id, self.message)
    }
}

/// Domain-level errors for the Types Registry module.
///
/// This enum is intentionally **kind-agnostic** — the storage layer doesn't
/// know whether a string identifies a type-schema or an instance, it just
/// stores and retrieves entities by their GTS ID. The kind context is added
/// at the SDK boundary by the local client, which knows what kind the caller
/// asked for and converts via [`Self::into_sdk_for_type_schema`] /
/// [`Self::into_sdk_for_instance`].
#[domain_model]
#[derive(Error, Debug)]
pub enum DomainError {
    /// The GTS ID format is invalid.
    #[error("Invalid GTS ID: {0}")]
    InvalidGtsId(String),

    /// The requested entity was not found. `kind` records which lookup
    /// surface the caller used (GTS id vs. UUID v5) so the REST layer
    /// renders an accurate "No entity with X: …" message and SDK
    /// conversions stay symmetric.
    #[error("Entity not found ({kind}): {target}")]
    NotFound { kind: LookupKind, target: String },

    /// An entity with the same GTS ID already exists.
    #[error("Entity already exists: {0}")]
    AlreadyExists(String),

    /// The list/query parameters are syntactically invalid (e.g. an
    /// out-of-spec wildcard pattern). Distinct from `InvalidGtsId`, which
    /// covers id-shaped inputs.
    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    /// Validation of the entity content failed.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// The operation requires ready mode but registry is in configuration mode.
    #[error("Not in ready mode")]
    NotInReadyMode,

    /// Multiple validation errors occurred during `switch_to_ready`.
    #[error("Ready commit failed with {} errors", .0.len())]
    ReadyCommitFailed(Vec<ValidationError>),

    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Indicates which kind of entity the caller was looking up, so kind-agnostic
/// `DomainError`s can be lifted into kind-specific [`TypesRegistryError`]
/// variants at the SDK boundary.
#[domain_model]
#[derive(Debug, Clone, Copy)]
pub enum SdkErrorKind {
    /// The caller asked for a type-schema.
    TypeSchema,
    /// The caller asked for an instance.
    Instance,
}

/// Identifies which surface a `NotFound` lookup used. Carried inside
/// [`DomainError::NotFound`] so renderers (REST, logs) can produce
/// accurate "No entity with X" messages.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    /// Lookup by canonical GTS id string.
    GtsId,
    /// Lookup by deterministic UUID v5.
    Uuid,
}

impl std::fmt::Display for LookupKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GtsId => f.write_str("GTS ID"),
            Self::Uuid => f.write_str("UUID"),
        }
    }
}

impl DomainError {
    /// Creates an `InvalidGtsId` error.
    #[must_use]
    pub fn invalid_gts_id(message: impl Into<String>) -> Self {
        Self::InvalidGtsId(message.into())
    }

    /// Creates a `NotFound` error for a GTS-id-keyed lookup miss.
    #[must_use]
    pub fn not_found_by_id(gts_id: impl Into<String>) -> Self {
        Self::NotFound {
            kind: LookupKind::GtsId,
            target: gts_id.into(),
        }
    }

    /// Creates a `NotFound` error for a UUID-keyed lookup miss.
    #[must_use]
    pub fn not_found_by_uuid(uuid: uuid::Uuid) -> Self {
        Self::NotFound {
            kind: LookupKind::Uuid,
            target: uuid.to_string(),
        }
    }

    /// Creates an `AlreadyExists` error.
    #[must_use]
    pub fn already_exists(gts_id: impl Into<String>) -> Self {
        Self::AlreadyExists(gts_id.into())
    }

    /// Creates an `InvalidQuery` error.
    #[must_use]
    pub fn invalid_query(message: impl Into<String>) -> Self {
        Self::InvalidQuery(message.into())
    }

    /// Creates a `ValidationFailed` error.
    #[must_use]
    pub fn validation_failed(message: impl Into<String>) -> Self {
        Self::ValidationFailed(message.into())
    }

    /// Returns the list of validation errors if this is a `ReadyCommitFailed` error.
    #[must_use]
    pub fn validation_errors(&self) -> Option<&[ValidationError]> {
        match self {
            Self::ReadyCommitFailed(errors) => Some(errors),
            _ => None,
        }
    }

    /// Converts to [`TypesRegistryError`] under the assumption that the caller
    /// was looking up a **type-schema**.
    ///
    /// `NotFound` becomes `GtsTypeSchemaNotFound`; `InvalidGtsId` becomes
    /// `InvalidGtsTypeId`; the rest map straight.
    #[must_use]
    pub fn into_sdk_for_type_schema(self) -> TypesRegistryError {
        self.into_sdk(SdkErrorKind::TypeSchema)
    }

    /// Converts to [`TypesRegistryError`] under the assumption that the caller
    /// was looking up an **instance**.
    ///
    /// `NotFound` becomes `GtsInstanceNotFound`; `InvalidGtsId` becomes
    /// `InvalidGtsInstanceId`; the rest map straight.
    #[must_use]
    pub fn into_sdk_for_instance(self) -> TypesRegistryError {
        self.into_sdk(SdkErrorKind::Instance)
    }

    fn into_sdk(self, kind: SdkErrorKind) -> TypesRegistryError {
        match (self, kind) {
            (Self::InvalidGtsId(msg), SdkErrorKind::TypeSchema) => {
                TypesRegistryError::invalid_gts_type_id(msg)
            }
            (Self::InvalidGtsId(msg), SdkErrorKind::Instance) => {
                TypesRegistryError::invalid_gts_instance_id(msg)
            }
            (Self::NotFound { target, .. }, SdkErrorKind::TypeSchema) => {
                TypesRegistryError::gts_type_schema_not_found(target)
            }
            (Self::NotFound { target, .. }, SdkErrorKind::Instance) => {
                TypesRegistryError::gts_instance_not_found(target)
            }
            (Self::AlreadyExists(id), _) => TypesRegistryError::already_exists(id),
            (Self::InvalidQuery(msg), _) => TypesRegistryError::invalid_query(msg),
            (Self::ValidationFailed(msg), _) => TypesRegistryError::validation_failed(msg),
            (Self::NotInReadyMode, _) => TypesRegistryError::service_unavailable(
                "types registry is still initializing",
                std::time::Duration::from_secs(1),
            ),
            (Self::ReadyCommitFailed(errors), _) => {
                let error_strings: Vec<String> = errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                TypesRegistryError::validation_failed(format!(
                    "Ready commit failed with {} errors: {}",
                    errors.len(),
                    error_strings.join("; ")
                ))
            }
            (Self::Internal(e), _) => TypesRegistryError::internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_constructors() {
        let err = DomainError::invalid_gts_id("missing vendor");
        assert!(matches!(err, DomainError::InvalidGtsId(_)));

        let err = DomainError::not_found_by_id("gts.acme.core.events.test.v1~");
        assert!(matches!(
            err,
            DomainError::NotFound {
                kind: LookupKind::GtsId,
                ..
            }
        ));

        let err = DomainError::not_found_by_uuid(uuid::Uuid::nil());
        assert!(matches!(
            err,
            DomainError::NotFound {
                kind: LookupKind::Uuid,
                ..
            }
        ));

        let err = DomainError::already_exists("gts.acme.core.events.test.v1~");
        assert!(matches!(err, DomainError::AlreadyExists(_)));

        let err = DomainError::validation_failed("schema invalid");
        assert!(matches!(err, DomainError::ValidationFailed(_)));
    }

    #[test]
    fn test_domain_to_sdk_error_conversion_for_type_schema() {
        let sdk_err =
            DomainError::not_found_by_id("gts.cf.core.events.test.v1~").into_sdk_for_type_schema();
        assert!(sdk_err.is_gts_type_schema_not_found());

        // UUID-keyed not-found also surfaces as `GtsTypeSchemaNotFound` —
        // the SDK error doesn't model the lookup kind, only the kind of
        // the entity the caller was after. The lookup-kind distinction
        // matters only for REST rendering.
        let sdk_err = DomainError::not_found_by_uuid(uuid::Uuid::nil()).into_sdk_for_type_schema();
        assert!(sdk_err.is_gts_type_schema_not_found());

        let sdk_err = DomainError::invalid_gts_id("bad format").into_sdk_for_type_schema();
        assert!(sdk_err.is_invalid_gts_type_id());

        let sdk_err =
            DomainError::already_exists("gts.cf.core.events.test.v1~").into_sdk_for_type_schema();
        assert!(sdk_err.is_already_exists());

        let sdk_err = DomainError::validation_failed("bad schema").into_sdk_for_type_schema();
        assert!(sdk_err.is_validation_failed());
    }

    #[test]
    fn test_domain_to_sdk_error_conversion_for_instance() {
        let sdk_err =
            DomainError::not_found_by_id("gts.cf.core.events.test.v1~cf.core.instances.u1.v1")
                .into_sdk_for_instance();
        assert!(sdk_err.is_gts_instance_not_found());

        let sdk_err = DomainError::invalid_gts_id("no chain prefix").into_sdk_for_instance();
        assert!(sdk_err.is_invalid_gts_instance_id());
    }

    #[test]
    fn test_domain_to_sdk_error_not_in_ready_mode() {
        let sdk_err = DomainError::NotInReadyMode.into_sdk_for_type_schema();
        assert!(sdk_err.is_service_unavailable());
    }

    #[test]
    fn test_domain_to_sdk_error_ready_commit_failed() {
        let errors = vec![
            ValidationError::new("gts.test1~", "error1"),
            ValidationError::new("gts.test2~", "error2"),
        ];
        let sdk_err = DomainError::ReadyCommitFailed(errors).into_sdk_for_type_schema();
        assert!(sdk_err.is_validation_failed());
    }

    #[test]
    fn test_domain_to_sdk_error_internal() {
        let sdk_err =
            DomainError::Internal(anyhow::anyhow!("test error")).into_sdk_for_type_schema();
        assert!(matches!(sdk_err, TypesRegistryError::Internal(_)));
    }

    #[test]
    fn test_domain_to_sdk_error_invalid_query() {
        let sdk_err = DomainError::invalid_query("bad pattern").into_sdk_for_type_schema();
        assert!(sdk_err.is_invalid_query());
        let sdk_err = DomainError::invalid_query("bad pattern").into_sdk_for_instance();
        assert!(sdk_err.is_invalid_query());
    }

    #[test]
    fn test_error_display() {
        let err = DomainError::InvalidGtsId("bad format".to_owned());
        assert_eq!(err.to_string(), "Invalid GTS ID: bad format");

        let err = DomainError::not_found_by_id("gts.cf.core.events.test.v1~");
        assert_eq!(
            err.to_string(),
            "Entity not found (GTS ID): gts.cf.core.events.test.v1~"
        );

        let err = DomainError::not_found_by_uuid(uuid::Uuid::nil());
        assert_eq!(
            err.to_string(),
            "Entity not found (UUID): 00000000-0000-0000-0000-000000000000"
        );

        let err = DomainError::AlreadyExists("gts.cf.core.events.test.v1~".to_owned());
        assert_eq!(
            err.to_string(),
            "Entity already exists: gts.cf.core.events.test.v1~"
        );

        let err = DomainError::ValidationFailed("schema invalid".to_owned());
        assert_eq!(err.to_string(), "Validation failed: schema invalid");

        let err = DomainError::NotInReadyMode;
        assert_eq!(err.to_string(), "Not in ready mode");

        let err = DomainError::ReadyCommitFailed(vec![
            ValidationError::new("gts.test1~", "error1"),
            ValidationError::new("gts.test2~", "error2"),
            ValidationError::new("gts.test3~", "error3"),
        ]);
        assert_eq!(err.to_string(), "Ready commit failed with 3 errors");
    }

    #[test]
    fn test_internal_error_from_anyhow() {
        let anyhow_err = anyhow::anyhow!("test error");
        let domain_err: DomainError = anyhow_err.into();
        assert!(matches!(domain_err, DomainError::Internal(_)));
    }
}
