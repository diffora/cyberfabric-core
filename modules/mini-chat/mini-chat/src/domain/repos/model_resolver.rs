use async_trait::async_trait;
use uuid::Uuid;

use modkit_macros::domain_model;

use crate::domain::error::DomainError;

/// Result of model resolution — model ID plus routing metadata.
#[domain_model]
pub struct ResolvedModel {
    pub model_id: String,
    /// Maps to a key in `MiniChatConfig.providers` (e.g. `"openai"`, `"azure_openai"`).
    pub provider_id: String,
}

/// Resolves and validates model IDs against the user's policy catalog.
///
/// If `model` is `None`, returns the default model for the given `user_id`.
/// If `model` is `Some`, validates it is non-empty and exists in the catalog.
///
/// # Errors
///
/// Returns [`DomainError`] if the model is empty, not found in the catalog,
/// or the policy snapshot for `user_id` cannot be retrieved.
#[async_trait]
pub trait ModelResolver: Send + Sync {
    async fn resolve_model(
        &self,
        user_id: Uuid,
        model: Option<String>,
    ) -> Result<ResolvedModel, DomainError>;
}
