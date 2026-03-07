use std::collections::HashMap;

use async_trait::async_trait;
use modkit_macros::domain_model;
use modkit_security::SecurityContext;

// ---------------------------------------------------------------------------
// Plugin errors
// ---------------------------------------------------------------------------

/// Errors returned by auth plugins.
#[domain_model]
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("authentication failed: {0}")]
    #[allow(dead_code)] // Part of plugin trait API; no current plugin constructs this.
    AuthFailed(String),
    #[error("request rejected: {0}")]
    #[allow(dead_code)] // Part of plugin trait API; no current plugin constructs this.
    Rejected(String),
    #[error("invalid plugin configuration: {0}")]
    InvalidConfig(String),
    #[error("plugin error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Auth plugin
// ---------------------------------------------------------------------------

/// Request context passed to an auth plugin for header injection.
#[domain_model]
pub struct AuthContext {
    /// Outbound request headers (modified in-place by the plugin).
    pub headers: HashMap<String, String>,
    /// Plugin-specific configuration key/value pairs.
    pub config: HashMap<String, String>,
    /// Security context of the calling subject.
    pub security_context: SecurityContext,
}

/// Trait for outbound authentication plugins.
///
/// Implementations mutate [`AuthContext`] to inject authentication material
/// (e.g., API keys, bearer tokens) into the outbound request headers.
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Apply authentication to the outbound request context.
    async fn authenticate(&self, ctx: &mut AuthContext) -> Result<(), PluginError>;
}
