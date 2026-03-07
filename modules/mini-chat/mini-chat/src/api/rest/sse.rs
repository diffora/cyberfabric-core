//! SSE wire conversion and event ordering enforcement.
//!
//! - `into_sse_event()`: converts domain `StreamEvent` to Axum SSE `Event`
//! - `From<ClientSseEvent>`: translates provider events to domain events
//! - `StreamPhase`: state machine enforcing the ordering grammar
//!   `ping* (delta | tool)* citations? (done | error)`

use axum::response::sse::Event;

use crate::domain::stream_events::{CitationsData, DeltaData, StreamEvent, ToolData};
use crate::infra::llm::ClientSseEvent;

pub(crate) use crate::domain::stream_events::StreamEventKind;

// ════════════════════════════════════════════════════════════════════════════
// SSE wire conversion
// ════════════════════════════════════════════════════════════════════════════

impl StreamEvent {
    /// Convert to an Axum SSE [`Event`] with the correct `event:` name
    /// and `data:` JSON payload.
    pub fn into_sse_event(self) -> Result<Event, axum::Error> {
        match self {
            StreamEvent::Ping => Ok(Event::default().event("ping").data("{}")),
            StreamEvent::Delta(d) => Event::default().event("delta").json_data(&d),
            StreamEvent::Tool(t) => Event::default().event("tool").json_data(&t),
            StreamEvent::Citations(c) => Event::default().event("citations").json_data(&c),
            StreamEvent::Done(d) => Event::default().event("done").json_data(&*d),
            StreamEvent::Error(e) => Event::default().event("error").json_data(&e),
        }
    }
}

impl modkit::api::api_dto::ResponseApiDto for StreamEvent {}

// ════════════════════════════════════════════════════════════════════════════
// Provider → domain conversion
// ════════════════════════════════════════════════════════════════════════════

impl From<ClientSseEvent> for StreamEvent {
    fn from(event: ClientSseEvent) -> Self {
        match event {
            ClientSseEvent::Delta { r#type, content } => {
                StreamEvent::Delta(DeltaData { r#type, content })
            }
            ClientSseEvent::Tool {
                phase,
                name,
                details,
            } => StreamEvent::Tool(ToolData {
                phase,
                name: name.to_owned(),
                details,
            }),
            ClientSseEvent::Citations { items } => StreamEvent::Citations(CitationsData { items }),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// StreamEventKind — Display
// ════════════════════════════════════════════════════════════════════════════

impl std::fmt::Display for StreamEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ping => f.write_str("Ping"),
            Self::Delta => f.write_str("Delta"),
            Self::Tool => f.write_str("Tool"),
            Self::Citations => f.write_str("Citations"),
            Self::Terminal => f.write_str("Terminal"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// StreamPhase — event ordering state machine
// ════════════════════════════════════════════════════════════════════════════

/// Enforces the SSE ordering grammar: `ping* (delta | tool)* citations? (done | error)`.
///
/// Delta and tool events may interleave freely within the `Streaming` phase.
/// Only forward transitions are allowed. Out-of-order events produce an
/// [`OrderingViolation`] error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    /// Before any events. Accepts ping, delta, tool, citations, terminal.
    Idle,
    /// After one or more pings. Accepts ping, delta, tool, citations, terminal.
    Pinging,
    /// After first delta or tool. Accepts delta, tool, citations, terminal.
    Streaming,
    /// After citations. Accepts terminal only.
    Citations,
    /// Terminal event emitted. No further events accepted.
    Terminal,
}

/// An event that violates the ordering grammar.
#[derive(Debug)]
pub struct OrderingViolation {
    pub phase: StreamPhase,
    pub event: StreamEventKind,
}

impl std::fmt::Display for OrderingViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SSE ordering violation: {} event in {} phase",
            self.event, self.phase
        )
    }
}

impl std::fmt::Display for StreamPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Pinging => f.write_str("Pinging"),
            Self::Streaming => f.write_str("Streaming"),
            Self::Citations => f.write_str("Citations"),
            Self::Terminal => f.write_str("Terminal"),
        }
    }
}

impl StreamPhase {
    /// Whether this phase represents a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, StreamPhase::Terminal)
    }

    /// Attempt to advance the phase based on the incoming event kind.
    ///
    /// Returns the new phase on success, or an [`OrderingViolation`] if the
    /// event would break the grammar.
    pub fn try_advance(self, kind: StreamEventKind) -> Result<StreamPhase, OrderingViolation> {
        match (self, kind) {
            // Terminal phase rejects everything
            (StreamPhase::Terminal, _) => Err(OrderingViolation {
                phase: self,
                event: kind,
            }),

            // Terminal events are always accepted from non-terminal phases
            (_, StreamEventKind::Terminal) => Ok(StreamPhase::Terminal),

            // Ping: only from Idle or Pinging
            (StreamPhase::Idle | StreamPhase::Pinging, StreamEventKind::Ping) => {
                Ok(StreamPhase::Pinging)
            }

            // Delta or Tool: from Idle, Pinging, or Streaming
            (
                StreamPhase::Idle | StreamPhase::Pinging | StreamPhase::Streaming,
                StreamEventKind::Delta | StreamEventKind::Tool,
            ) => Ok(StreamPhase::Streaming),

            // Citations: from Idle, Pinging, or Streaming (at most once)
            (
                StreamPhase::Idle | StreamPhase::Pinging | StreamPhase::Streaming,
                StreamEventKind::Citations,
            ) => Ok(StreamPhase::Citations),

            // Everything else is a violation
            _ => Err(OrderingViolation {
                phase: self,
                event: kind,
            }),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::stream_events::{DoneData, ErrorData};
    use crate::infra::llm::Usage;

    // ── SSE serialization tests ──

    #[test]
    fn ping_converts_to_sse_event() {
        assert!(StreamEvent::Ping.into_sse_event().is_ok());
    }

    #[test]
    fn delta_converts_to_sse_event() {
        assert!(
            StreamEvent::Delta(DeltaData {
                r#type: "text",
                content: "hello".into(),
            })
            .into_sse_event()
            .is_ok()
        );
    }

    #[test]
    fn delta_data_serializes_correctly() {
        let data = DeltaData {
            r#type: "text",
            content: "hello".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"content\":\"hello\""));
    }

    #[test]
    fn done_serializes_without_optional_fields() {
        let data = DoneData {
            message_id: None,
            usage: None,
            effective_model: "gpt-4o".into(),
            selected_model: "gpt-4o".into(),
            quota_decision: "allow".into(),
            downgrade_from: None,
            downgrade_reason: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"effective_model\":\"gpt-4o\""));
        assert!(!json.contains("downgrade_from"));
        assert!(!json.contains("downgrade_reason"));
    }

    #[test]
    fn done_serializes_with_downgrade() {
        let data = DoneData {
            message_id: Some("msg-123".into()),
            usage: Some(Usage {
                input_tokens: 100,
                output_tokens: 50,
            }),
            effective_model: "gpt-4o-mini".into(),
            selected_model: "gpt-4o".into(),
            quota_decision: "downgrade".into(),
            downgrade_from: Some("gpt-4o".into()),
            downgrade_reason: Some("premium_quota_exhausted".into()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"downgrade_reason\":\"premium_quota_exhausted\""));
        assert!(json.contains("\"downgrade_from\":\"gpt-4o\""));
    }

    #[test]
    fn done_converts_to_sse_event() {
        assert!(
            StreamEvent::Done(Box::new(DoneData {
                message_id: None,
                usage: None,
                effective_model: "gpt-4o".into(),
                selected_model: "gpt-4o".into(),
                quota_decision: "allow".into(),
                downgrade_from: None,
                downgrade_reason: None,
            }))
            .into_sse_event()
            .is_ok()
        );
    }

    #[test]
    fn error_data_serializes_correctly() {
        let data = ErrorData {
            code: "provider_error".into(),
            message: "Something went wrong".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"code\":\"provider_error\""));
        assert!(json.contains("\"message\":\"Something went wrong\""));
    }

    #[test]
    fn error_converts_to_sse_event() {
        assert!(
            StreamEvent::Error(ErrorData {
                code: "provider_error".into(),
                message: "Something went wrong".into(),
            })
            .into_sse_event()
            .is_ok()
        );
    }

    // ── StreamPhase tests ──

    #[test]
    fn phase_idle_accepts_all_kinds() {
        assert_eq!(
            StreamPhase::Idle
                .try_advance(StreamEventKind::Ping)
                .unwrap(),
            StreamPhase::Pinging
        );
        assert_eq!(
            StreamPhase::Idle
                .try_advance(StreamEventKind::Delta)
                .unwrap(),
            StreamPhase::Streaming
        );
        assert_eq!(
            StreamPhase::Idle
                .try_advance(StreamEventKind::Tool)
                .unwrap(),
            StreamPhase::Streaming
        );
        assert_eq!(
            StreamPhase::Idle
                .try_advance(StreamEventKind::Citations)
                .unwrap(),
            StreamPhase::Citations
        );
        assert_eq!(
            StreamPhase::Idle
                .try_advance(StreamEventKind::Terminal)
                .unwrap(),
            StreamPhase::Terminal
        );
    }

    #[test]
    fn phase_streaming_rejects_ping() {
        assert!(
            StreamPhase::Streaming
                .try_advance(StreamEventKind::Ping)
                .is_err()
        );
    }

    #[test]
    fn phase_citations_rejects_non_terminal() {
        assert!(
            StreamPhase::Citations
                .try_advance(StreamEventKind::Ping)
                .is_err()
        );
        assert!(
            StreamPhase::Citations
                .try_advance(StreamEventKind::Delta)
                .is_err()
        );
        assert!(
            StreamPhase::Citations
                .try_advance(StreamEventKind::Tool)
                .is_err()
        );
        assert!(
            StreamPhase::Citations
                .try_advance(StreamEventKind::Citations)
                .is_err()
        );
    }

    #[test]
    fn phase_terminal_rejects_everything() {
        assert!(
            StreamPhase::Terminal
                .try_advance(StreamEventKind::Ping)
                .is_err()
        );
        assert!(
            StreamPhase::Terminal
                .try_advance(StreamEventKind::Terminal)
                .is_err()
        );
    }

    #[test]
    fn phase_citations_accepts_terminal() {
        assert_eq!(
            StreamPhase::Citations
                .try_advance(StreamEventKind::Terminal)
                .unwrap(),
            StreamPhase::Terminal
        );
    }

    #[test]
    fn normal_stream_sequence() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Ping).unwrap();
        assert_eq!(phase, StreamPhase::Pinging);
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Terminal).unwrap();
        assert_eq!(phase, StreamPhase::Terminal);
    }

    #[test]
    fn tool_stream_sequence() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Citations).unwrap();
        assert_eq!(phase, StreamPhase::Citations);
        phase = phase.try_advance(StreamEventKind::Terminal).unwrap();
        assert_eq!(phase, StreamPhase::Terminal);
    }

    // ── New interleaving tests ──

    #[test]
    fn interleaved_delta_tool_delta() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Terminal).unwrap();
        assert_eq!(phase, StreamPhase::Terminal);
    }

    #[test]
    fn tool_then_delta_accepted() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert_eq!(phase, StreamPhase::Streaming);
    }

    #[test]
    fn ping_rejected_after_first_delta() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Delta).unwrap();
        assert!(phase.try_advance(StreamEventKind::Ping).is_err());
    }

    #[test]
    fn ping_rejected_after_first_tool() {
        let mut phase = StreamPhase::Idle;
        phase = phase.try_advance(StreamEventKind::Tool).unwrap();
        assert!(phase.try_advance(StreamEventKind::Ping).is_err());
    }
}
