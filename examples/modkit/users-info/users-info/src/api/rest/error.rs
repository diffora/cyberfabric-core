use modkit::api::problem::{Problem, ValidationViolation};
use modkit_canonical_errors::{CanonicalError, FieldViolation, InvalidArgument};

use crate::domain::error::DomainError;

// Resource-scoped canonical error types for each entity in this module.
#[modkit_canonical_errors::resource_error("gts.hx.example1.users.user.v1~")]
struct UserResourceError;

#[modkit_canonical_errors::resource_error("gts.hx.example1.users.city.v1~")]
struct CityResourceError;

#[modkit_canonical_errors::resource_error("gts.hx.example1.users.address.v1~")]
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

/// Convert a [`CanonicalError`] into the axum-compatible [`Problem`].
fn canonical_to_problem(ce: &CanonicalError) -> Problem {
    let status = http::StatusCode::from_u16(ce.status_code())
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut problem =
        Problem::new(status, ce.title(), ce.detail()).with_type(format!("gts://{}", ce.gts_type()));

    if let Some(diag) = ce.diagnostic() {
        tracing::debug!(diagnostic = %diag, "Canonical error diagnostic");
    }

    // Build context from canonical error metadata
    let mut ctx = serde_json::Map::new();
    if let Some(rt) = ce.resource_type() {
        ctx.insert(
            "resource_type".to_owned(),
            serde_json::Value::String(rt.to_owned()),
        );
    }
    if let Some(rn) = ce.resource_name() {
        ctx.insert(
            "resource_name".to_owned(),
            serde_json::Value::String(rn.to_owned()),
        );
    }
    if !ctx.is_empty() {
        problem = problem.with_context(serde_json::Value::Object(ctx));
    }

    // Extract structured violations from applicable error categories
    let errors = extract_violations(ce);
    if !errors.is_empty() {
        problem = problem.with_errors(errors);
    }

    // Enrich trace_id from current span
    if let Some(span_id) = tracing::Span::current().id() {
        problem = problem.with_trace_id(span_id.into_u64().to_string());
    }

    problem
}

/// Implement `Into<Problem>` for `DomainError` so `?` works in handlers
impl From<DomainError> for Problem {
    fn from(e: DomainError) -> Self {
        let ce = domain_error_to_canonical(&e);
        canonical_to_problem(&ce)
    }
}

/// Map a [`FieldViolation`] to a [`ValidationViolation`].
fn field_violation_to_validation(fv: &FieldViolation) -> ValidationViolation {
    ValidationViolation {
        field: fv.field.clone(),
        message: fv.description.clone(),
        code: Some(fv.reason.clone()),
    }
}

/// Extract structured violations from a [`CanonicalError`] into a flat
/// [`ValidationViolation`] list.  Covers every category that carries
/// violation arrays: `InvalidArgument`, `OutOfRange`, `FailedPrecondition`,
/// and `ResourceExhausted`.
fn extract_violations(ce: &CanonicalError) -> Vec<ValidationViolation> {
    match ce {
        CanonicalError::InvalidArgument {
            ctx: InvalidArgument::FieldViolations { field_violations },
            ..
        } => field_violations
            .iter()
            .map(field_violation_to_validation)
            .collect(),

        CanonicalError::OutOfRange { ctx, .. } => ctx
            .field_violations
            .iter()
            .map(field_violation_to_validation)
            .collect(),

        CanonicalError::FailedPrecondition { ctx, .. } => ctx
            .violations
            .iter()
            .map(|pv| ValidationViolation {
                field: pv.subject.clone(),
                message: pv.description.clone(),
                code: Some(pv.type_.clone()),
            })
            .collect(),

        CanonicalError::ResourceExhausted { ctx, .. } => ctx
            .violations
            .iter()
            .map(|qv| ValidationViolation {
                field: qv.subject.clone(),
                message: qv.description.clone(),
                code: None,
            })
            .collect(),

        _ => Vec::new(),
    }
}
