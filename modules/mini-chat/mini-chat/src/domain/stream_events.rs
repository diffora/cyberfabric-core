//! Domain-level SSE stream event types.
//!
//! These types are the canonical representation of streaming events used by
//! the domain service layer. Axum-specific SSE conversion lives in
//! `api::rest::sse`.

use modkit_macros::domain_model;
use serde::Serialize;
use utoipa::ToSchema;

use crate::infra::llm::{Citation, ToolPhase, Usage};

// ════════════════════════════════════════════════════════════════════════════
// StreamEvent — domain-level event envelope
// ════════════════════════════════════════════════════════════════════════════

/// Stream event envelope for the `messages:stream` pipeline.
///
/// Each variant maps to a distinct SSE `event:` name and `data:` JSON payload.
/// Ordering grammar: `ping* (delta | tool)* citations? (done | error)`.
#[domain_model]
#[derive(Debug, Clone, ToSchema)]
pub enum StreamEvent {
    Ping,
    Delta(DeltaData),
    Tool(ToolData),
    Citations(CitationsData),
    Done(Box<DoneData>),
    Error(ErrorData),
}

/// Delta text chunk.
#[domain_model]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeltaData {
    pub r#type: &'static str,
    pub content: String,
}

/// Tool lifecycle event.
#[domain_model]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ToolData {
    pub phase: ToolPhase,
    pub name: String,
    pub details: serde_json::Value,
}

/// Citations from provider annotations.
#[domain_model]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CitationsData {
    pub items: Vec<Citation>,
}

/// Successful stream completion.
#[domain_model]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DoneData {
    pub message_id: Option<String>,
    pub usage: Option<Usage>,
    pub effective_model: String,
    pub selected_model: String,
    pub quota_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrade_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrade_reason: Option<String>,
}

/// Stream error (terminal).
#[domain_model]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorData {
    pub code: String,
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// StreamEventKind — coarse classification for ordering enforcement
// ════════════════════════════════════════════════════════════════════════════

/// Coarse event classification for ordering enforcement.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEventKind {
    Ping,
    Delta,
    Tool,
    Citations,
    Terminal,
}

impl StreamEvent {
    /// Classify this event for the [`StreamPhase`](crate::api::rest::sse::StreamPhase)
    /// state machine.
    #[must_use]
    pub fn event_kind(&self) -> StreamEventKind {
        match self {
            StreamEvent::Ping => StreamEventKind::Ping,
            StreamEvent::Delta(_) => StreamEventKind::Delta,
            StreamEvent::Tool(_) => StreamEventKind::Tool,
            StreamEvent::Citations(_) => StreamEventKind::Citations,
            StreamEvent::Done(_) | StreamEvent::Error(_) => StreamEventKind::Terminal,
        }
    }

    /// Whether this is a terminal event (done or error).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, StreamEvent::Done(_) | StreamEvent::Error(_))
    }
}
