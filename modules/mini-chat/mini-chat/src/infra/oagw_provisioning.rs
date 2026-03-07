//! OAGW upstream and route registration for configured LLM providers.
//!
//! Called once during `Module::init()` to ensure every provider entry
//! has a corresponding OAGW upstream (with auth config) and route.

use std::collections::HashMap;
use std::sync::Arc;

use oagw_sdk::ServiceGatewayClientV1;
use tracing::{info, warn};

use crate::config::ProviderEntry;

/// Register OAGW upstreams and routes for each configured provider.
///
/// Uses a default-tenant `SecurityContext`. If the upstream already exists
/// (e.g. re-init), the error is logged and skipped.
pub async fn register_oagw_upstreams(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    providers: &HashMap<String, ProviderEntry>,
) -> anyhow::Result<()> {
    let ctx = modkit_security::SecurityContext::builder()
        .subject_tenant_id(modkit_security::constants::DEFAULT_TENANT_ID)
        .subject_id(modkit_security::constants::DEFAULT_SUBJECT_ID)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build security context: {e}"))?;

    for (provider_id, entry) in providers {
        let Some(upstream) = create_upstream(gateway, &ctx, provider_id, entry).await else {
            continue;
        };
        register_route(gateway, &ctx, provider_id, entry, &upstream).await;
    }

    Ok(())
}

/// Create an OAGW upstream for a single provider entry.
/// Returns `None` (with a warning log) if registration fails.
async fn create_upstream(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &modkit_security::SecurityContext,
    provider_id: &str,
    entry: &ProviderEntry,
) -> Option<oagw_sdk::Upstream> {
    use oagw_sdk::{AuthConfig, CreateUpstreamRequest, Endpoint, Scheme, Server};

    let server = Server {
        endpoints: vec![Endpoint {
            scheme: Scheme::Https,
            host: entry.host.clone(),
            port: 443,
        }],
    };

    let mut builder =
        CreateUpstreamRequest::builder(server, "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1")
            .alias(entry.effective_alias())
            .enabled(true);

    if let (Some(plugin_type), Some(config)) = (&entry.auth_plugin_type, &entry.auth_config) {
        builder = builder.auth(AuthConfig {
            plugin_type: plugin_type.clone(),
            sharing: oagw_sdk::SharingMode::Inherit,
            config: Some(config.clone()),
        });
    }

    match gateway.create_upstream(ctx.clone(), builder.build()).await {
        Ok(u) => {
            info!(
                provider_id,
                alias = %entry.effective_alias(),
                upstream_id = %u.id,
                "OAGW upstream registered"
            );
            Some(u)
        }
        Err(e) => {
            warn!(
                provider_id,
                alias = %entry.effective_alias(),
                error = %e,
                "OAGW upstream registration failed (may already exist)"
            );
            None
        }
    }
}

/// Derive route match rules from `api_path` and register the OAGW route.
async fn register_route(
    gateway: &Arc<dyn ServiceGatewayClientV1>,
    ctx: &modkit_security::SecurityContext,
    provider_id: &str,
    entry: &ProviderEntry,
    upstream: &oagw_sdk::Upstream,
) {
    use oagw_sdk::{CreateRouteRequest, HttpMatch, HttpMethod, MatchRules};

    let (route_prefix, suffix_mode) = derive_route_match(&entry.api_path);
    let query_allowlist = extract_query_allowlist(&entry.api_path);

    let match_rules = MatchRules {
        http: Some(HttpMatch {
            methods: vec![HttpMethod::Post],
            path: route_prefix.clone(),
            query_allowlist,
            path_suffix_mode: suffix_mode,
        }),
        grpc: None,
    };

    match gateway
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(upstream.id, match_rules)
                .enabled(true)
                .build(),
        )
        .await
    {
        Ok(route) => {
            info!(
                provider_id,
                route_id = %route.id,
                route_path = %route_prefix,
                "OAGW route registered"
            );
        }
        Err(e) => {
            warn!(
                provider_id,
                error = %e,
                "OAGW route registration failed"
            );
        }
    }
}

/// Derive route prefix and suffix mode from an `api_path` template.
///
/// Strips query string, replaces `{model}` with `*`, and returns
/// `(prefix, suffix_mode)` for OAGW route matching.
fn derive_route_match(api_path: &str) -> (String, oagw_sdk::PathSuffixMode) {
    let route_path = api_path
        .split('?')
        .next()
        .unwrap_or(api_path)
        .replace("{model}", "*");

    let route_prefix = if let Some(pos) = route_path.find('*') {
        route_path[..pos].trim_end_matches('/').to_owned()
    } else {
        route_path.clone()
    };

    let suffix_mode = if route_path.contains('*') {
        oagw_sdk::PathSuffixMode::Append
    } else {
        oagw_sdk::PathSuffixMode::Disabled
    };

    (route_prefix, suffix_mode)
}

/// Extract query parameter names from an `api_path` template's query string.
fn extract_query_allowlist(api_path: &str) -> Vec<String> {
    api_path
        .split('?')
        .nth(1)
        .map(|qs| {
            qs.split('&')
                .filter_map(|pair| pair.split('=').next().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_simple_path() {
        let (prefix, mode) = derive_route_match("/v1/responses");
        assert_eq!(prefix, "/v1/responses");
        assert!(matches!(mode, oagw_sdk::PathSuffixMode::Disabled));
    }

    #[test]
    fn derive_path_with_model_placeholder() {
        let (prefix, mode) =
            derive_route_match("/openai/deployments/{model}/responses?api-version=2025-03-01");
        assert_eq!(prefix, "/openai/deployments");
        assert!(matches!(mode, oagw_sdk::PathSuffixMode::Append));
    }

    #[test]
    fn derive_azure_openai_path() {
        let (prefix, mode) = derive_route_match("/openai/v1/responses");
        assert_eq!(prefix, "/openai/v1/responses");
        assert!(matches!(mode, oagw_sdk::PathSuffixMode::Disabled));
    }

    #[test]
    fn extract_empty_query() {
        assert!(extract_query_allowlist("/v1/responses").is_empty());
    }

    #[test]
    fn extract_single_query_param() {
        let params =
            extract_query_allowlist("/openai/deployments/{model}/responses?api-version=2025-03-01");
        assert_eq!(params, vec!["api-version"]);
    }

    #[test]
    fn extract_multiple_query_params() {
        let params = extract_query_allowlist("/path?foo=1&bar=2&baz=3");
        assert_eq!(params, vec!["foo", "bar", "baz"]);
    }
}
