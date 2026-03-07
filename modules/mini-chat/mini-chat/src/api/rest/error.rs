use http::StatusCode;
use modkit::api::problem::Problem;

use crate::domain::error::DomainError;

impl From<DomainError> for Problem {
    fn from(e: DomainError) -> Self {
        let trace_id = tracing::Span::current()
            .id()
            .map(|id| id.into_u64().to_string());
        match &e {
            DomainError::ChatNotFound { id } => Problem::new(
                StatusCode::NOT_FOUND,
                "Chat Not Found",
                format!("Chat with id {id} was not found"),
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::InvalidModel { model } => Problem::new(
                StatusCode::BAD_REQUEST,
                "Invalid Model",
                format!("Model '{model}' is not available in the catalog"),
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::Validation { message } => {
                Problem::new(StatusCode::BAD_REQUEST, "Validation Error", message.clone())
                    .with_trace_id(trace_id.unwrap_or_default())
            }

            DomainError::Forbidden => Problem::new(
                StatusCode::FORBIDDEN,
                "Access denied",
                "You do not have permission to perform this action",
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::Conflict { code, message } => {
                Problem::new(StatusCode::CONFLICT, code.clone(), message.clone())
                    .with_trace_id(trace_id.unwrap_or_default())
            }

            DomainError::NotFound { entity, id } => Problem::new(
                StatusCode::NOT_FOUND,
                format!("{entity} not found"),
                format!("{entity} with id {id} was not found"),
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::MessageNotFound { id } => Problem::new(
                StatusCode::NOT_FOUND,
                "Message Not Found",
                format!("Message with id {id} was not found"),
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::InvalidReactionTarget { id } => Problem::new(
                StatusCode::BAD_REQUEST,
                "Invalid Reaction Target",
                format!("Message {id} is not an assistant message"),
            )
            .with_trace_id(trace_id.unwrap_or_default()),

            DomainError::Database { .. } | DomainError::InternalError { .. } => {
                tracing::error!(error = ?e, "Internal error occurred");
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Error",
                    "An internal error occurred",
                )
                .with_trace_id(trace_id.unwrap_or_default())
            }
        }
    }
}
