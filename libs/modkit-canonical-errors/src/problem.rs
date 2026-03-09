use serde::{Deserialize, Serialize};

use crate::error::CanonicalError;

// ---------------------------------------------------------------------------
// Problem (RFC 9457)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub context: serde_json::Value,
}

impl Problem {
    /// Convert a `CanonicalError` to a `Problem`.
    #[must_use]
    pub fn from_error(err: &CanonicalError) -> Self {
        let problem_type = format!("gts://{}", err.gts_type());
        let title = err.title().to_owned();
        let status = err.status_code();
        let detail = err.detail().to_owned();

        let mut context = serialize_context(err);

        if let Some(rt) = err.resource_type() {
            context["resource_type"] = serde_json::Value::String(rt.to_owned());
        }

        if let Some(rn) = err.resource_name() {
            context["resource_name"] = serde_json::Value::String(rn.to_owned());
        }

        Problem {
            problem_type,
            title,
            status,
            detail,
            instance: None,
            trace_id: None,
            context,
        }
    }

    /// Set the `trace_id` field, returning `self` for chaining.
    #[must_use]
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the `instance` field, returning `self` for chaining.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
}

fn serialize_context(err: &CanonicalError) -> serde_json::Value {
    match err {
        CanonicalError::Cancelled { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unknown { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::InvalidArgument { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::DeadlineExceeded { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::NotFound { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::AlreadyExists { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::PermissionDenied { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::ResourceExhausted { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::FailedPrecondition { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Aborted { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::OutOfRange { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unimplemented { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Internal { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::ServiceUnavailable { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::DataLoss { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unauthenticated { ctx, .. } => serde_json::to_value(ctx),
    }
    .unwrap_or_default()
}

impl From<CanonicalError> for Problem {
    fn from(err: CanonicalError) -> Self {
        Problem::from_error(&err)
    }
}
