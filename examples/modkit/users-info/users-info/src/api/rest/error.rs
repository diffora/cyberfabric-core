use modkit::api::canonical_prelude::*;

use crate::domain::error::DomainError;

#[resource_error("gts.cf.example1.users.user.v1~")]
struct UserResourceError;

#[resource_error("gts.cf.example1.users.city.v1~")]
struct CityResourceError;

#[resource_error("gts.cf.example1.users.address.v1~")]
struct AddressResourceError;

/// Convert a [`DomainError`] into a [`CanonicalError`].
fn domain_error_to_canonical(e: &DomainError) -> CanonicalError {
    match e {
        DomainError::UserNotFound { id } => {
            UserResourceError::not_found(format!("User with id {id} was not found"))
                .with_resource(id.to_string())
                .create()
        }

        DomainError::NotFound { entity_type, id } => {
            let detail = format!("{entity_type} with id {id} was not found");
            match entity_type.as_str() {
                "City" => CityResourceError::not_found(detail)
                    .with_resource(id.to_string())
                    .create(),
                "Address" => AddressResourceError::not_found(detail)
                    .with_resource(id.to_string())
                    .create(),
                _ => UserResourceError::not_found(detail)
                    .with_resource(id.to_string())
                    .create(),
            }
        }

        DomainError::EmailAlreadyExists { email } => {
            UserResourceError::already_exists(format!("Email '{email}' is already in use"))
                .with_resource(email.clone())
                .create()
        }

        DomainError::InvalidEmail { email } => UserResourceError::invalid_argument()
            .with_field_violation(
                "email",
                format!("Email '{email}' is invalid"),
                "INVALID_FORMAT",
            )
            .create(),

        DomainError::EmptyDisplayName => UserResourceError::invalid_argument()
            .with_field_violation("display_name", "Display name cannot be empty", "REQUIRED")
            .create(),

        DomainError::DisplayNameTooLong { len, max } => UserResourceError::invalid_argument()
            .with_field_violation(
                "display_name",
                format!("Display name too long: {len} characters (max: {max})"),
                "MAX_LENGTH",
            )
            .create(),

        DomainError::Validation { field, message } => UserResourceError::invalid_argument()
            .with_field_violation(field, message, "VALIDATION")
            .create(),

        DomainError::Database { .. } => {
            tracing::error!(error = ?e, "Database error occurred");
            CanonicalError::internal("An internal database error occurred").create()
        }

        DomainError::Forbidden => UserResourceError::permission_denied()
            .with_reason("ACCESS_DENIED")
            .create(),

        DomainError::InternalError => {
            tracing::error!(error = ?e, "Internal error occurred");
            CanonicalError::internal("An internal error occurred").create()
        }
    }
}

impl From<DomainError> for Problem {
    fn from(e: DomainError) -> Self {
        let ce = domain_error_to_canonical(&e);

        if let Some(diag) = ce.diagnostic() {
            tracing::debug!(diagnostic = %diag, "Canonical error diagnostic");
        }

        let mut problem = Problem::from(ce);

        if let Some(span_id) = tracing::Span::current().id() {
            problem = problem.with_trace_id(span_id.into_u64().to_string());
        }

        problem
    }
}
