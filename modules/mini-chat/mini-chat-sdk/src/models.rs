use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Current policy version metadata for a user.
#[derive(Debug, Clone)]
pub struct PolicyVersionInfo {
    pub user_id: Uuid,
    pub policy_version: u64,
    pub generated_at: OffsetDateTime,
}

/// Full policy snapshot for a given version, including the model catalog.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub user_id: Uuid,
    pub policy_version: u64,
    pub model_catalog: Vec<ModelCatalogEntry>,
    pub kill_switches: KillSwitches,
}

/// Tenant-level kill switches from the policy snapshot.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KillSwitches {
    pub disable_premium_tier: bool,
    pub force_standard_tier: bool,
    pub disable_web_search: bool,
    pub disable_file_search: bool,
}

/// A single model in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCatalogEntry {
    pub model_id: String,
    pub display_name: String,
    pub tier: ModelTier,
    pub global_enabled: bool,
    pub is_default: bool,
    /// Credit multiplier for input tokens (micro-credits per 1000 tokens).
    pub input_tokens_credit_multiplier_micro: u64,
    /// Credit multiplier for output tokens (micro-credits per 1000 tokens).
    pub output_tokens_credit_multiplier_micro: u64,
    /// Model capabilities, e.g. `VISION_INPUT`, `IMAGE_GENERATION`.
    pub multimodal_capabilities: Vec<String>,
    /// Maximum context window size in tokens.
    pub context_window: u32,
    /// Maximum output tokens the model can generate.
    pub max_output_tokens: u32,
    /// Human-readable model description.
    pub description: String,
    /// Display name for the provider (e.g. `OpenAI`).
    pub provider_display_name: String,
    /// Human-readable multiplier display string (e.g. "1x", "3x").
    pub multiplier_display: String,
    /// Routing identifier for provider resolution. Maps to a key in
    /// `MiniChatConfig.providers`. Values: `"openai"`, `"azure_openai"`.
    pub provider_id: String,
}

/// Model pricing/capability tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelTier {
    Standard,
    Premium,
}

/// Per-user credit allocations for a specific policy version.
/// NOT part of the immutable shared `PolicySnapshot` (DESIGN.md §5.2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLimits {
    pub user_id: Uuid,
    pub policy_version: u64,
    pub standard: TierLimits,
    pub premium: TierLimits,
}

/// Credit limits for a single tier within a billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierLimits {
    pub limit_daily_credits_micro: i64,
    pub limit_monthly_credits_micro: i64,
}

/// Token usage reported by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTokens {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Canonical usage event payload published via the outbox after finalization.
///
/// Single canonical type — both the outbox enqueuer (infra) and the plugin
/// `publish_usage()` method use this same struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub chat_id: Uuid,
    pub turn_id: Uuid,
    pub request_id: Uuid,
    pub effective_model: String,
    pub selected_model: String,
    pub terminal_state: String,
    pub billing_outcome: String,
    pub usage: Option<UsageTokens>,
    pub actual_credits_micro: i64,
    pub settlement_method: String,
    pub policy_version_applied: i64,
    pub timestamp: OffsetDateTime,
}
