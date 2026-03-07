use modkit_macros::domain_model;
use time::OffsetDateTime;
use uuid::Uuid;

// ── Chat ──

/// A chat conversation.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub model: String,
    pub title: Option<String>,
    pub is_temporary: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Enriched chat response with message count (no `tenant_id/user_id`).
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatDetail {
    pub id: Uuid,
    pub model: String,
    pub title: Option<String>,
    pub is_temporary: bool,
    pub message_count: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Data for creating a new chat.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChat {
    pub model: Option<String>,
    pub title: Option<String>,
    pub is_temporary: bool,
}

/// Partial update data for a chat.
///
/// Uses `Option<Option<String>>` for nullable fields to distinguish
/// "not provided" (None) from "set to null" (Some(None)).
///
/// Note: `model` is immutable for the chat lifetime
/// (`cpt-cf-mini-chat-constraint-model-locked-per-chat`).
/// `is_temporary` toggling is a P2 feature (`:temporary` endpoint).
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::option_option)]
pub struct ChatPatch {
    pub title: Option<Option<String>>,
}

// ── Message ──

/// A chat message as returned by the list endpoint.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: Uuid,
    pub request_id: Uuid,
    pub role: String,
    pub content: String,
    pub attachments: Vec<AttachmentSummary>,
    pub model: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub created_at: OffsetDateTime,
}

/// Lightweight attachment metadata embedded in Message objects.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentSummary {
    pub attachment_id: Uuid,
    pub kind: String,
    pub filename: String,
    pub status: String,
    pub img_thumbnail: Option<ImgThumbnail>,
}

/// Server-generated preview thumbnail for an image attachment.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImgThumbnail {
    pub content_type: String,
    pub width: i32,
    pub height: i32,
    pub data_base64: String,
}

// ── Reaction ──

/// Binary like/dislike reaction value.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionKind {
    Like,
    Dislike,
}

impl ReactionKind {
    /// Parse from a string value ("like" / "dislike").
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "like" => Some(Self::Like),
            "dislike" => Some(Self::Dislike),
            _ => None,
        }
    }

    /// Wire representation used in DB and REST.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Like => "like",
            Self::Dislike => "dislike",
        }
    }
}

impl std::fmt::Display for ReactionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reaction on an assistant message.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    pub message_id: Uuid,
    pub kind: ReactionKind,
    pub created_at: OffsetDateTime,
}
