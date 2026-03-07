use thiserror::Error;

/// Errors returned by `MiniChatModelPolicyPluginClientV1` methods.
#[derive(Debug, Error)]
pub enum MiniChatModelPolicyPluginError {
    #[error("policy not found for the given tenant/version")]
    NotFound,

    #[error("internal policy plugin error: {0}")]
    Internal(String),
}

/// Errors returned by `publish_usage()`.
#[derive(Debug, Error)]
pub enum PublishError {
    /// Transient failure — safe to retry.
    #[error("transient publish error: {0}")]
    Transient(String),

    /// Permanent failure — do not retry.
    #[error("permanent publish error: {0}")]
    Permanent(String),
}

impl PublishError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}
