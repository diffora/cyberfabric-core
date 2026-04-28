use modkit_canonical_errors::{CanonicalError, Problem, resource_error};

use crate::domain::error::DomainError;

#[resource_error("gts.cf.file_parser.parser.file.v1~")]
pub struct FileParserError;

/// Convert domain errors to HTTP Problem responses
#[must_use]
pub fn domain_error_to_problem(err: DomainError) -> Problem {
    match err {
        DomainError::FileNotFound { path } => FileParserError::not_found("File not found")
            .with_resource(path)
            .create()
            .into(),

        DomainError::UnsupportedFileType { extension } => FileParserError::invalid_argument()
            .with_field_violation(
                "content_type",
                format!("Unsupported file type: {extension}"),
                "UNSUPPORTED_CONTENT_TYPE",
            )
            .create()
            .into(),

        DomainError::NoParserAvailable { extension } => FileParserError::invalid_argument()
            .with_field_violation(
                "content_type",
                format!("No parser available for extension: {extension}"),
                "UNSUPPORTED_CONTENT_TYPE",
            )
            .create()
            .into(),

        DomainError::ParseError { message } => FileParserError::invalid_argument()
            .with_field_violation("body", message, "PARSE_ERROR")
            .create()
            .into(),

        DomainError::IoError { message } => {
            tracing::error!(error = %message, "file-parser I/O error");
            CanonicalError::internal(message).create().into()
        }

        DomainError::InvalidRequest { message } => FileParserError::invalid_argument()
            .with_constraint(message)
            .create()
            .into(),

        DomainError::PathTraversalBlocked { message } => {
            tracing::warn!(error = %message, "path traversal blocked");
            FileParserError::permission_denied()
                .with_reason("PATH_TRAVERSAL_BLOCKED")
                .create()
                .into()
        }
    }
}

/// Implement Into<Problem> for `DomainError` so `?` works in handlers
impl From<DomainError> for Problem {
    fn from(e: DomainError) -> Self {
        domain_error_to_problem(e)
    }
}
