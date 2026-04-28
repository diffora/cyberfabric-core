use serde::{Deserialize, Serialize};

use crate::error::CanonicalError;

/// Media type for RFC 9457 `application/problem+json` responses.
pub const APPLICATION_PROBLEM_JSON: &str = "application/problem+json";

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
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the error-category context type
    /// fails to serialize.  Built-in context types are plain structs and
    /// should never fail, but this keeps the failure visible rather than
    /// silently producing an empty `"context": {}`.
    pub fn from_error(err: &CanonicalError) -> Result<Self, serde_json::Error> {
        let problem_type = format!("gts://{}", err.gts_type());
        let title = err.title().to_owned();
        let status = err.status_code();
        let detail = err.detail().to_owned();

        let mut context = serialize_context(err)?;

        if let Some(rt) = err.resource_type() {
            context["resource_type"] = serde_json::Value::String(rt.to_owned());
        }

        if let Some(rn) = err.resource_name() {
            context["resource_name"] = serde_json::Value::String(rn.to_owned());
        }

        Ok(Problem {
            problem_type,
            title,
            status,
            detail,
            instance: None,
            trace_id: None,
            context,
        })
    }

    /// Convert a `CanonicalError` to a `Problem`, including the internal
    /// diagnostic string in the `context` for `Internal` and `Unknown`
    /// variants.
    ///
    /// **This method MUST NOT be used in production.** It exists so that
    /// development and test environments can surface the real error cause
    /// in the wire response for easier debugging.
    ///
    /// In production, use [`from_error`](Self::from_error) instead — it
    /// never leaks the diagnostic string.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the context fails to serialize.
    pub fn from_error_debug(err: &CanonicalError) -> Result<Self, serde_json::Error> {
        let mut problem = Self::from_error(err)?;

        if let Some(diag) = err.diagnostic() {
            problem.context["description"] = serde_json::Value::String(diag.to_owned());
        }

        Ok(problem)
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

fn serialize_context(err: &CanonicalError) -> Result<serde_json::Value, serde_json::Error> {
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
}

impl From<CanonicalError> for Problem {
    fn from(err: CanonicalError) -> Self {
        match Problem::from_error(&err) {
            Ok(p) => p,
            Err(ser_err) => Problem {
                problem_type: format!("gts://{}", err.gts_type()),
                title: err.title().to_owned(),
                status: err.status_code(),
                detail: err.detail().to_owned(),
                instance: None,
                trace_id: None,
                context: serde_json::Value::String(ser_err.to_string()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// axum integration (feature = "axum")
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for Problem {
    fn into_response(self) -> axum::response::Response {
        match serde_json::to_vec(&self) {
            Ok(body) => {
                let status = http::StatusCode::from_u16(self.status)
                    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
                (
                    status,
                    [(http::header::CONTENT_TYPE, APPLICATION_PROBLEM_JSON)],
                    body,
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    problem_type = %self.problem_type,
                    status = self.status,
                    "failed to serialize Problem; emitting fallback body",
                );
                let body: &[u8] = br#"{"type":"gts://gts.cf.core.errors.err.v1~cf.core.err.internal.v1~","title":"Internal","status":500,"detail":"failed to serialize problem","context":{}}"#;
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    [(http::header::CONTENT_TYPE, APPLICATION_PROBLEM_JSON)],
                    body,
                )
                    .into_response()
            }
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for CanonicalError {
    fn into_response(self) -> axum::response::Response {
        Problem::from(self).into_response()
    }
}

// ---------------------------------------------------------------------------
// utoipa integration (feature = "utoipa")
// ---------------------------------------------------------------------------

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Problem {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, SchemaType, Type};

        ObjectBuilder::new()
            .property(
                "type",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::String)),
            )
            .required("type")
            .property(
                "title",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::String)),
            )
            .required("title")
            .property(
                "status",
                ObjectBuilder::new()
                    .schema_type(SchemaType::Type(Type::Integer))
                    .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int32))),
            )
            .required("status")
            .property(
                "detail",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::String)),
            )
            .required("detail")
            .property(
                "instance",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::String)),
            )
            .property(
                "trace_id",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::String)),
            )
            .property(
                "context",
                ObjectBuilder::new().schema_type(SchemaType::Type(Type::Object)),
            )
            .required("context")
            .description(Some(
                "RFC 9457 problem+json. `context` varies by error category.",
            ))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Problem {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Problem")
    }
}
