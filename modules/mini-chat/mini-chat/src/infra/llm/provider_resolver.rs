//! Runtime resolution of LLM provider adapter + OAGW upstream alias.
//!
//! Built once at module startup from `MiniChatConfig.providers`.
//! Used per turn to resolve which adapter and OAGW alias to use
//! based on the model's `provider_id`.

use std::collections::HashMap;
use std::sync::Arc;

use oagw_sdk::ServiceGatewayClientV1;

use super::providers::{ProviderKind, create_provider};
use super::{LlmProvider, LlmProviderError};
use crate::config::ProviderEntry;

/// Result of resolving a `provider_id`.
pub struct ResolvedProvider<'a> {
    pub adapter: Arc<dyn LlmProvider>,
    pub upstream_alias: &'a str,
    /// API path template (may contain `{model}` placeholder).
    pub api_path: &'a str,
}

/// Resolves `(provider adapter, upstream alias)` from a `provider_id`.
pub struct ProviderResolver {
    /// One adapter per distinct `ProviderKind`.
    adapters: HashMap<ProviderKind, Arc<dyn LlmProvider>>,
    /// `provider_id` → `ProviderEntry` from config.
    registry: HashMap<String, ProviderEntry>,
}

impl ProviderResolver {
    /// Build from config + OAGW gateway. Creates one adapter per distinct
    /// `ProviderKind` (not per `provider_id`).
    pub fn new(
        gateway: &Arc<dyn ServiceGatewayClientV1>,
        providers: HashMap<String, ProviderEntry>,
    ) -> Self {
        let mut adapters = HashMap::new();
        for entry in providers.values() {
            adapters
                .entry(entry.kind)
                .or_insert_with(|| create_provider(Arc::clone(gateway), entry.kind));
        }
        Self {
            adapters,
            registry: providers,
        }
    }

    /// Resolve the provider adapter, upstream alias, and API path template
    /// for a `provider_id`.
    pub fn resolve(&self, provider_id: &str) -> Result<ResolvedProvider<'_>, LlmProviderError> {
        let entry =
            self.registry
                .get(provider_id)
                .ok_or_else(|| LlmProviderError::ProviderError {
                    code: "configuration_error".to_owned(),
                    message: format!("unknown provider_id: {provider_id}"),
                    raw_detail: None,
                })?;

        let adapter =
            self.adapters
                .get(&entry.kind)
                .ok_or_else(|| LlmProviderError::ProviderError {
                    code: "configuration_error".to_owned(),
                    message: format!("no adapter for kind {:?}", entry.kind),
                    raw_detail: None,
                })?;

        Ok(ResolvedProvider {
            adapter: Arc::clone(adapter),
            upstream_alias: entry.effective_alias(),
            api_path: &entry.api_path,
        })
    }

    /// All registered provider entries (for startup validation / logging).
    #[must_use]
    pub fn entries(&self) -> &HashMap<String, ProviderEntry> {
        &self.registry
    }

    /// Create a resolver with a single pre-built provider adapter.
    /// Used in tests to wrap a mock `LlmProvider` without needing a gateway.
    #[cfg(test)]
    pub fn single_provider(provider: Arc<dyn LlmProvider>) -> Self {
        let kind = ProviderKind::OpenAiResponses;
        let mut adapters = HashMap::new();
        adapters.insert(kind, provider);
        let mut registry = HashMap::new();
        registry.insert(
            "openai".to_owned(),
            ProviderEntry {
                kind,
                upstream_alias: None,
                host: "test-host".to_owned(),
                api_path: "/v1/responses".to_owned(),
                auth_plugin_type: None,
                auth_config: None,
            },
        );
        Self { adapters, registry }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oagw_sdk::error::ServiceGatewayError;

    /// Minimal no-op gateway for tests that only need `Arc<dyn ServiceGatewayClientV1>`.
    struct NullGateway;

    #[async_trait::async_trait]
    impl ServiceGatewayClientV1 for NullGateway {
        async fn create_upstream(
            &self,
            _: modkit_security::SecurityContext,
            _: oagw_sdk::CreateUpstreamRequest,
        ) -> Result<oagw_sdk::Upstream, ServiceGatewayError> {
            unimplemented!()
        }
        async fn get_upstream(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
        ) -> Result<oagw_sdk::Upstream, ServiceGatewayError> {
            unimplemented!()
        }
        async fn list_upstreams(
            &self,
            _: modkit_security::SecurityContext,
            _: &oagw_sdk::ListQuery,
        ) -> Result<Vec<oagw_sdk::Upstream>, ServiceGatewayError> {
            unimplemented!()
        }
        async fn update_upstream(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
            _: oagw_sdk::UpdateUpstreamRequest,
        ) -> Result<oagw_sdk::Upstream, ServiceGatewayError> {
            unimplemented!()
        }
        async fn delete_upstream(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
        ) -> Result<(), ServiceGatewayError> {
            unimplemented!()
        }
        async fn create_route(
            &self,
            _: modkit_security::SecurityContext,
            _: oagw_sdk::CreateRouteRequest,
        ) -> Result<oagw_sdk::Route, ServiceGatewayError> {
            unimplemented!()
        }
        async fn get_route(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
        ) -> Result<oagw_sdk::Route, ServiceGatewayError> {
            unimplemented!()
        }
        async fn list_routes(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
            _: &oagw_sdk::ListQuery,
        ) -> Result<Vec<oagw_sdk::Route>, ServiceGatewayError> {
            unimplemented!()
        }
        async fn update_route(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
            _: oagw_sdk::UpdateRouteRequest,
        ) -> Result<oagw_sdk::Route, ServiceGatewayError> {
            unimplemented!()
        }
        async fn delete_route(
            &self,
            _: modkit_security::SecurityContext,
            _: uuid::Uuid,
        ) -> Result<(), ServiceGatewayError> {
            unimplemented!()
        }
        async fn resolve_proxy_target(
            &self,
            _: modkit_security::SecurityContext,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(oagw_sdk::Upstream, oagw_sdk::Route), ServiceGatewayError> {
            unimplemented!()
        }
        async fn proxy_request(
            &self,
            _: modkit_security::SecurityContext,
            _: http::Request<oagw_sdk::Body>,
        ) -> Result<http::Response<oagw_sdk::Body>, ServiceGatewayError> {
            unimplemented!()
        }
    }

    fn null_gw() -> Arc<dyn ServiceGatewayClientV1> {
        Arc::new(NullGateway)
    }

    fn mock_providers() -> HashMap<String, ProviderEntry> {
        let mut m = HashMap::new();
        m.insert(
            "openai".to_owned(),
            ProviderEntry {
                kind: ProviderKind::OpenAiResponses,
                upstream_alias: None, // defaults to host
                host: "api.openai.com".to_owned(),
                api_path: "/v1/responses".to_owned(),
                auth_plugin_type: None,
                auth_config: None,
            },
        );
        m.insert(
            "azure_openai".to_owned(),
            ProviderEntry {
                kind: ProviderKind::OpenAiResponses,
                upstream_alias: Some("my-azure.openai.azure.com".to_owned()),
                host: "my-azure.openai.azure.com".to_owned(),
                api_path: "/openai/v1/responses".to_owned(),
                auth_plugin_type: None,
                auth_config: None,
            },
        );
        m
    }

    #[test]
    fn resolve_openai() {
        let resolver = ProviderResolver::new(&null_gw(), mock_providers());
        let r = resolver.resolve("openai").unwrap();
        assert_eq!(r.upstream_alias, "api.openai.com");
        assert_eq!(r.api_path, "/v1/responses");
    }

    #[test]
    fn resolve_azure() {
        let resolver = ProviderResolver::new(&null_gw(), mock_providers());
        let r = resolver.resolve("azure_openai").unwrap();
        assert_eq!(r.upstream_alias, "my-azure.openai.azure.com");
        assert_eq!(r.api_path, "/openai/v1/responses");
    }

    #[test]
    fn alias_defaults_to_host() {
        let entry = ProviderEntry {
            kind: ProviderKind::OpenAiResponses,
            upstream_alias: None,
            host: "example.openai.azure.com".to_owned(),
            api_path: "/v1/responses".to_owned(),
            auth_plugin_type: None,
            auth_config: None,
        };
        assert_eq!(entry.effective_alias(), "example.openai.azure.com");
    }

    #[test]
    fn explicit_alias_overrides_host() {
        let entry = ProviderEntry {
            kind: ProviderKind::OpenAiResponses,
            upstream_alias: Some("custom-alias".to_owned()),
            host: "example.openai.azure.com".to_owned(),
            api_path: "/v1/responses".to_owned(),
            auth_plugin_type: None,
            auth_config: None,
        };
        assert_eq!(entry.effective_alias(), "custom-alias");
    }

    #[test]
    fn resolve_unknown_fails() {
        let resolver = ProviderResolver::new(&null_gw(), mock_providers());
        let result = resolver.resolve("anthropic");
        assert!(result.is_err());
    }

    #[test]
    fn same_kind_shares_adapter() {
        let resolver = ProviderResolver::new(&null_gw(), mock_providers());
        let r1 = resolver.resolve("openai").unwrap();
        let r2 = resolver.resolve("azure_openai").unwrap();
        assert!(Arc::ptr_eq(&r1.adapter, &r2.adapter));
    }
}
