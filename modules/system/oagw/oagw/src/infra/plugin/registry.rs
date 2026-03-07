use std::collections::HashMap;
use std::sync::Arc;

use modkit_auth::oauth2::types::ClientAuthMethod;

use crate::config::TokenCacheConfig;
use crate::domain::plugin::{AuthPlugin, PluginError};
use credstore_sdk::CredStoreClientV1;

use super::apikey_auth::ApiKeyAuthPlugin;
use super::noop_auth::NoopAuthPlugin;
use super::oauth2_client_cred_auth::OAuth2ClientCredAuthPlugin;
use crate::domain::gts_helpers::{
    APIKEY_AUTH_PLUGIN_ID, NOOP_AUTH_PLUGIN_ID, OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID,
    OAUTH2_CLIENT_CRED_BASIC_AUTH_PLUGIN_ID,
};

/// Registry that resolves auth plugin GTS identifiers to plugin implementations.
pub struct AuthPluginRegistry {
    plugins: HashMap<String, Arc<dyn AuthPlugin>>,
}

impl AuthPluginRegistry {
    /// Create a registry with the built-in plugins (apikey, noop, oauth2 CC).
    #[must_use]
    pub fn with_builtins(
        credstore: Arc<dyn CredStoreClientV1>,
        token_http_config: Option<modkit_http::HttpClientConfig>,
        token_cache_config: TokenCacheConfig,
    ) -> Self {
        let mut plugins: HashMap<String, Arc<dyn AuthPlugin>> = HashMap::new();
        plugins.insert(
            APIKEY_AUTH_PLUGIN_ID.to_string(),
            Arc::new(ApiKeyAuthPlugin::new(credstore.clone())),
        );
        plugins.insert(NOOP_AUTH_PLUGIN_ID.to_string(), Arc::new(NoopAuthPlugin));

        let mut form_plugin = OAuth2ClientCredAuthPlugin::new(
            credstore.clone(),
            ClientAuthMethod::Form,
            token_cache_config.ttl,
            token_cache_config.capacity,
        );
        let mut basic_plugin = OAuth2ClientCredAuthPlugin::new(
            credstore.clone(),
            ClientAuthMethod::Basic,
            token_cache_config.ttl,
            token_cache_config.capacity,
        );
        if let Some(ref cfg) = token_http_config {
            form_plugin = form_plugin.with_http_config(cfg.clone());
            basic_plugin = basic_plugin.with_http_config(cfg.clone());
        }

        plugins.insert(
            OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID.to_string(),
            Arc::new(form_plugin),
        );
        plugins.insert(
            OAUTH2_CLIENT_CRED_BASIC_AUTH_PLUGIN_ID.to_string(),
            Arc::new(basic_plugin),
        );
        Self { plugins }
    }

    /// Resolve a plugin by its GTS identifier.
    ///
    /// # Errors
    /// Returns `PluginError::Internal` if the plugin is not registered.
    pub fn resolve(&self, plugin_id: &str) -> Result<Arc<dyn AuthPlugin>, PluginError> {
        self.plugins
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| PluginError::Internal(format!("unknown auth plugin: {plugin_id}")))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::domain::test_support::MockCredStoreClient;

    use super::*;

    fn make_registry() -> AuthPluginRegistry {
        AuthPluginRegistry::with_builtins(
            Arc::new(MockCredStoreClient::empty()),
            None,
            TokenCacheConfig::default(),
        )
    }

    #[test]
    fn resolves_apikey_plugin() {
        let registry = make_registry();
        assert!(registry.resolve(APIKEY_AUTH_PLUGIN_ID).is_ok());
    }

    #[test]
    fn resolves_noop_plugin() {
        let registry = make_registry();
        assert!(registry.resolve(NOOP_AUTH_PLUGIN_ID).is_ok());
    }

    #[test]
    fn resolves_oauth2_client_cred_form_plugin() {
        let registry = make_registry();
        assert!(registry.resolve(OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID).is_ok());
    }

    #[test]
    fn resolves_oauth2_client_cred_basic_plugin() {
        let registry = make_registry();
        assert!(
            registry
                .resolve(OAUTH2_CLIENT_CRED_BASIC_AUTH_PLUGIN_ID)
                .is_ok()
        );
    }

    #[test]
    fn unknown_plugin_returns_error() {
        let registry = make_registry();
        let err = registry.resolve("gts.x.core.oagw.auth_plugin.v1~x.core.oagw.unknown.v1");
        assert!(err.is_err());
    }
}
