use std::sync::Arc;

use super::ControlPlaneService;
use std::net::IpAddr;

use crate::domain::error::DomainError;
use crate::domain::model::{
    CreateRouteRequest, CreateUpstreamRequest, Endpoint, ListQuery, Route, UpdateRouteRequest,
    UpdateUpstreamRequest, Upstream,
};
use crate::domain::repo::{RouteRepository, UpstreamRepository};

use async_trait::async_trait;
use modkit_macros::domain_model;
use modkit_security::SecurityContext;
use uuid::Uuid;

/// Control Plane service implementation backed by in-memory repositories.
#[domain_model]
pub(crate) struct ControlPlaneServiceImpl {
    upstreams: Arc<dyn UpstreamRepository>,
    routes: Arc<dyn RouteRepository>,
}

impl ControlPlaneServiceImpl {
    #[must_use]
    pub(crate) fn new(
        upstreams: Arc<dyn UpstreamRepository>,
        routes: Arc<dyn RouteRepository>,
    ) -> Self {
        Self { upstreams, routes }
    }
}

/// Validate the endpoint list for a server configuration.
///
/// Rules:
/// - At least one endpoint is required.
/// - All endpoints must use either IP addresses or hostnames — no mixing.
/// - All endpoints must share the same scheme (upstream-level invariant).
fn validate_endpoints(endpoints: &[Endpoint]) -> Result<(), DomainError> {
    if endpoints.is_empty() {
        return Err(DomainError::validation(
            "server must have at least one endpoint",
        ));
    }

    // TODO(hardening): add configurable SSRF deny-list for private IPv4 ranges
    // (loopback, RFC 1918, link-local, 169.254.169.254 metadata). Should be
    // opt-in (many deployments legitimately proxy to internal services) and also
    // enforced at DNS resolution time in DnsDiscovery::resolve() to cover
    // hostnames that resolve to private IPs.

    // IPv6 endpoints are not yet supported — reject early with a clear message.
    // Enabling IPv6 requires SSRF protections (deny-lists for link-local, private
    // ranges, IPv4-mapped addresses).
    for (i, ep) in endpoints.iter().enumerate() {
        if strip_brackets(&ep.host)
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
        {
            return Err(DomainError::validation(format!(
                "endpoint[{i}] uses IPv6 address '{}'; IPv6 endpoints are not yet supported",
                ep.host
            )));
        }
    }

    // Check all-IP vs all-hostname consistency.
    let ip_count = endpoints
        .iter()
        .filter(|ep| strip_brackets(&ep.host).parse::<IpAddr>().is_ok())
        .count();
    if ip_count != 0 && ip_count != endpoints.len() {
        return Err(DomainError::validation(
            "all endpoints must use either IP addresses or hostnames; mixed configurations are not allowed",
        ));
    }

    // Enforce identical scheme and port across the pool.
    if endpoints.len() > 1 {
        let first_scheme = &endpoints[0].scheme;
        let first_port = endpoints[0].port;
        for (i, ep) in endpoints.iter().enumerate().skip(1) {
            if ep.scheme != *first_scheme {
                return Err(DomainError::validation(format!(
                    "endpoint[{i}] scheme {:?} differs from endpoint[0] scheme {:?}; all endpoints must share the same scheme",
                    ep.scheme, first_scheme
                )));
            }
            if ep.port != first_port {
                return Err(DomainError::validation(format!(
                    "endpoint[{i}] port {} differs from endpoint[0] port {}; all endpoints must share the same port",
                    ep.port, first_port
                )));
            }
        }
    }

    Ok(())
}

/// Maximum length for an upstream alias.
const MAX_ALIAS_LENGTH: usize = 253;

/// Validate an alias: non-empty, max length, safe charset (alphanumeric + `.:-_`).
fn validate_alias(alias: &str) -> Result<(), DomainError> {
    if alias.is_empty() {
        return Err(DomainError::validation("alias must not be empty"));
    }
    if alias.len() > MAX_ALIAS_LENGTH {
        return Err(DomainError::validation(format!(
            "alias must not exceed {MAX_ALIAS_LENGTH} characters"
        )));
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
    {
        return Err(DomainError::validation(
            "alias contains invalid characters; only alphanumeric, '.', ':', '-', '_' are allowed",
        ));
    }
    Ok(())
}

/// Strip surrounding `[` and `]` from a host string so that bracketed IPv6
/// literals (e.g. `[2001:db8::1]`) can be parsed by `Ipv6Addr` / `IpAddr`.
fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

/// Generate an alias from the upstream's server endpoints.
/// Single endpoint: host (standard port omitted) or host:port.
fn generate_alias(upstream: &Upstream) -> String {
    let endpoints = &upstream.server.endpoints;
    if endpoints.is_empty() {
        return String::new();
    }
    // Use the first endpoint for alias generation.
    endpoints[0].alias_contribution()
}

#[async_trait]
impl ControlPlaneService for ControlPlaneServiceImpl {
    // -- Upstream CRUD --

    async fn create_upstream(
        &self,
        ctx: &SecurityContext,
        req: CreateUpstreamRequest,
    ) -> Result<Upstream, DomainError> {
        validate_endpoints(&req.server.endpoints)?;

        let tenant_id = ctx.subject_tenant_id();
        let id = Uuid::new_v4();

        let upstream = Upstream {
            id,
            tenant_id,
            alias: String::new(),
            server: req.server.clone(),
            protocol: req.protocol.clone(),
            enabled: req.enabled,
            auth: req.auth.clone(),
            headers: req.headers.clone(),
            plugins: req.plugins.clone(),
            rate_limit: req.rate_limit.clone(),
            tags: req.tags.clone(),
        };

        let alias = req
            .alias
            .clone()
            .unwrap_or_else(|| generate_alias(&upstream));

        validate_alias(&alias)?;

        let upstream = Upstream { alias, ..upstream };

        self.upstreams
            .create(upstream)
            .await
            .map_err(DomainError::from)
    }

    async fn get_upstream(&self, ctx: &SecurityContext, id: Uuid) -> Result<Upstream, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.upstreams
            .get_by_id(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("upstream", id))
    }

    async fn list_upstreams(
        &self,
        ctx: &SecurityContext,
        query: &ListQuery,
    ) -> Result<Vec<Upstream>, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.upstreams
            .list(tenant_id, query)
            .await
            .map_err(DomainError::from)
    }

    async fn update_upstream(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        req: UpdateUpstreamRequest,
    ) -> Result<Upstream, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        let mut existing = self
            .upstreams
            .get_by_id(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("upstream", id))?;

        // Apply partial update.
        if let Some(server) = req.server {
            validate_endpoints(&server.endpoints)?;
            existing.server = server;
        }
        if let Some(protocol) = req.protocol {
            existing.protocol = protocol;
        }
        if let Some(alias) = req.alias {
            validate_alias(&alias)?;
            existing.alias = alias;
        }
        if let Some(auth) = req.auth {
            existing.auth = Some(auth);
        }
        if let Some(headers) = req.headers {
            existing.headers = Some(headers);
        }
        if let Some(plugins) = req.plugins {
            existing.plugins = Some(plugins);
        }
        if let Some(rate_limit) = req.rate_limit {
            existing.rate_limit = Some(rate_limit);
        }
        if let Some(tags) = req.tags {
            existing.tags = tags;
        }
        if let Some(enabled) = req.enabled {
            existing.enabled = enabled;
        }

        self.upstreams
            .update(existing)
            .await
            .map_err(DomainError::from)
    }

    async fn delete_upstream(&self, ctx: &SecurityContext, id: Uuid) -> Result<(), DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        // Cascade delete routes.
        let _ = self.routes.delete_by_upstream(tenant_id, id).await;
        self.upstreams
            .delete(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("upstream", id))
    }

    // -- Route CRUD --

    async fn create_route(
        &self,
        ctx: &SecurityContext,
        req: CreateRouteRequest,
    ) -> Result<Route, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        // Validate that the upstream exists and belongs to this tenant.
        self.upstreams
            .get_by_id(tenant_id, req.upstream_id)
            .await
            .map_err(|_| {
                DomainError::validation(format!(
                    "upstream '{}' not found for this tenant",
                    req.upstream_id
                ))
            })?;

        let route = Route {
            id: Uuid::new_v4(),
            tenant_id,
            upstream_id: req.upstream_id,
            match_rules: req.match_rules,
            plugins: req.plugins,
            rate_limit: req.rate_limit,
            tags: req.tags,
            priority: req.priority,
            enabled: req.enabled,
        };

        self.routes.create(route).await.map_err(DomainError::from)
    }

    async fn get_route(&self, ctx: &SecurityContext, id: Uuid) -> Result<Route, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.routes
            .get_by_id(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("route", id))
    }

    async fn list_routes(
        &self,
        ctx: &SecurityContext,
        upstream_id: Uuid,
        query: &ListQuery,
    ) -> Result<Vec<Route>, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.routes
            .list_by_upstream(tenant_id, upstream_id, query)
            .await
            .map_err(DomainError::from)
    }

    async fn update_route(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        req: UpdateRouteRequest,
    ) -> Result<Route, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        let mut existing = self
            .routes
            .get_by_id(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("route", id))?;

        if let Some(match_rules) = req.match_rules {
            existing.match_rules = match_rules;
        }
        if let Some(plugins) = req.plugins {
            existing.plugins = Some(plugins);
        }
        if let Some(rate_limit) = req.rate_limit {
            existing.rate_limit = Some(rate_limit);
        }
        if let Some(tags) = req.tags {
            existing.tags = tags;
        }
        if let Some(priority) = req.priority {
            existing.priority = priority;
        }
        if let Some(enabled) = req.enabled {
            existing.enabled = enabled;
        }

        self.routes
            .update(existing)
            .await
            .map_err(DomainError::from)
    }

    async fn delete_route(&self, ctx: &SecurityContext, id: Uuid) -> Result<(), DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.routes
            .delete(tenant_id, id)
            .await
            .map_err(|_| DomainError::not_found("route", id))
    }

    // -- Resolution --

    async fn resolve_upstream(
        &self,
        ctx: &SecurityContext,
        alias: &str,
    ) -> Result<Upstream, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        let upstream = self
            .upstreams
            .get_by_alias(tenant_id, alias)
            .await
            .map_err(|_| DomainError::not_found("upstream", Uuid::nil()))?;

        if !upstream.enabled {
            return Err(DomainError::upstream_disabled(alias));
        }

        Ok(upstream)
    }

    async fn resolve_route(
        &self,
        ctx: &SecurityContext,
        upstream_id: Uuid,
        method: &str,
        path: &str,
    ) -> Result<Route, DomainError> {
        let tenant_id = ctx.subject_tenant_id();
        self.routes
            .find_matching(tenant_id, upstream_id, method, path)
            .await
            .map_err(|_| DomainError::not_found("route", Uuid::nil()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::domain::model::{
        Endpoint, HttpMatch, HttpMethod, MatchRules, PathSuffixMode, Scheme, Server,
    };

    use super::*;
    use crate::infra::storage::{InMemoryRouteRepo, InMemoryUpstreamRepo};

    fn make_service() -> ControlPlaneServiceImpl {
        ControlPlaneServiceImpl::new(
            Arc::new(InMemoryUpstreamRepo::new()),
            Arc::new(InMemoryRouteRepo::new()),
        )
    }

    fn test_ctx(tenant_id: Uuid) -> SecurityContext {
        SecurityContext::builder()
            .subject_tenant_id(tenant_id)
            .subject_id(Uuid::new_v4())
            .build()
            .expect("test security context")
    }

    fn make_create_upstream(alias: Option<&str>) -> CreateUpstreamRequest {
        CreateUpstreamRequest {
            server: Server {
                endpoints: vec![Endpoint {
                    scheme: Scheme::Https,
                    host: "api.openai.com".into(),
                    port: 443,
                }],
            },
            protocol: "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1".into(),
            alias: alias.map(String::from),
            auth: None,
            headers: None,
            plugins: None,
            rate_limit: None,
            tags: vec![],
            enabled: true,
        }
    }

    fn make_create_route(upstream_id: Uuid) -> CreateRouteRequest {
        CreateRouteRequest {
            upstream_id,
            match_rules: MatchRules {
                http: Some(HttpMatch {
                    methods: vec![HttpMethod::Post],
                    path: "/v1/chat/completions".into(),
                    query_allowlist: vec![],
                    path_suffix_mode: PathSuffixMode::Append,
                }),
                grpc: None,
            },
            plugins: None,
            rate_limit: None,
            tags: vec![],
            priority: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn upstream_crud_lifecycle() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        // Create
        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();
        assert_eq!(u.alias, "openai");

        // Get
        let fetched = svc.get_upstream(&ctx, u.id).await.unwrap();
        assert_eq!(fetched.id, u.id);

        // Update
        let updated = svc
            .update_upstream(
                &ctx,
                u.id,
                UpdateUpstreamRequest {
                    alias: Some("openai-v2".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.alias, "openai-v2");
        assert_eq!(updated.id, u.id);

        // List
        let list = svc
            .list_upstreams(&ctx, &ListQuery::default())
            .await
            .unwrap();
        assert_eq!(list.len(), 1);

        // Delete
        svc.delete_upstream(&ctx, u.id).await.unwrap();
        assert!(svc.get_upstream(&ctx, u.id).await.is_err());
    }

    #[tokio::test]
    async fn alias_auto_generation() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        // Standard port (443) — port omitted in alias.
        let u1 = svc
            .create_upstream(&ctx, make_create_upstream(None))
            .await
            .unwrap();
        assert_eq!(u1.alias, "api.openai.com");

        // Non-standard port — port included.
        let req = CreateUpstreamRequest {
            server: Server {
                endpoints: vec![Endpoint {
                    scheme: Scheme::Https,
                    host: "api.openai.com".into(),
                    port: 8443,
                }],
            },
            protocol: "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1".into(),
            alias: None,
            auth: None,
            headers: None,
            plugins: None,
            rate_limit: None,
            tags: vec![],
            enabled: true,
        };
        let u2 = svc.create_upstream(&ctx, req).await.unwrap();
        assert_eq!(u2.alias, "api.openai.com:8443");
    }

    #[tokio::test]
    async fn alias_rejects_path_traversal() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let err = svc
            .create_upstream(&ctx, make_create_upstream(Some("../../admin")))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[tokio::test]
    async fn alias_rejects_empty() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let err = svc
            .create_upstream(&ctx, make_create_upstream(Some("")))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[tokio::test]
    async fn alias_rejects_slashes() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let err = svc
            .create_upstream(&ctx, make_create_upstream(Some("foo/bar")))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[tokio::test]
    async fn duplicate_alias_conflict() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        svc.create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();

        let err = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Conflict { .. }));
    }

    #[tokio::test]
    async fn route_create_with_wrong_tenant_upstream() {
        let svc = make_service();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let ctx1 = test_ctx(t1);
        let ctx2 = test_ctx(t2);

        let u = svc
            .create_upstream(&ctx1, make_create_upstream(Some("openai")))
            .await
            .unwrap();

        // Try to create route in different tenant referencing t1's upstream.
        let err = svc
            .create_route(&ctx2, make_create_route(u.id))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[tokio::test]
    async fn alias_resolution_enabled() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();

        let resolved = svc.resolve_upstream(&ctx, "openai").await.unwrap();
        assert_eq!(resolved.id, u.id);
    }

    #[tokio::test]
    async fn alias_resolution_disabled_returns_503() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();

        // Disable the upstream.
        svc.update_upstream(
            &ctx,
            u.id,
            UpdateUpstreamRequest {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let err = svc.resolve_upstream(&ctx, "openai").await.unwrap_err();
        assert!(matches!(err, DomainError::UpstreamDisabled { .. }));
    }

    #[tokio::test]
    async fn alias_resolution_nonexistent_returns_404() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let err = svc.resolve_upstream(&ctx, "nonexistent").await.unwrap_err();
        assert!(matches!(err, DomainError::NotFound { .. }));
    }

    #[tokio::test]
    async fn route_matching_through_cp() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();
        let r = svc
            .create_route(&ctx, make_create_route(u.id))
            .await
            .unwrap();

        let matched = svc
            .resolve_route(&ctx, u.id, "POST", "/v1/chat/completions")
            .await
            .unwrap();
        assert_eq!(matched.id, r.id);
    }

    #[tokio::test]
    async fn route_matching_no_match_returns_404() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();

        let err = svc
            .resolve_route(&ctx, u.id, "GET", "/v1/unknown")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound { .. }));
    }

    // -- validate_endpoints tests --

    #[test]
    fn validate_endpoints_rejects_empty() {
        let err = validate_endpoints(&[]).unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[test]
    fn validate_endpoints_rejects_mixed_ip_and_hostname() {
        let endpoints = vec![
            Endpoint {
                scheme: Scheme::Https,
                host: "10.0.0.1".into(),
                port: 443,
            },
            Endpoint {
                scheme: Scheme::Https,
                host: "api.example.com".into(),
                port: 443,
            },
        ];
        let err = validate_endpoints(&endpoints).unwrap_err();
        match err {
            DomainError::Validation { detail, .. } => {
                assert!(
                    detail.contains("mixed"),
                    "expected mixed error, got: {detail}"
                );
            }
            _ => panic!("expected Validation, got: {err:?}"),
        }
    }

    #[test]
    fn validate_endpoints_rejects_mixed_scheme() {
        let endpoints = vec![
            Endpoint {
                scheme: Scheme::Https,
                host: "a.example.com".into(),
                port: 443,
            },
            Endpoint {
                scheme: Scheme::Http,
                host: "b.example.com".into(),
                port: 443,
            },
        ];
        let err = validate_endpoints(&endpoints).unwrap_err();
        match err {
            DomainError::Validation { detail, .. } => {
                assert!(
                    detail.contains("scheme"),
                    "expected scheme error, got: {detail}"
                );
            }
            _ => panic!("expected Validation, got: {err:?}"),
        }
    }

    #[test]
    fn validate_endpoints_accepts_all_ip() {
        let endpoints = vec![
            Endpoint {
                scheme: Scheme::Https,
                host: "10.0.0.1".into(),
                port: 443,
            },
            Endpoint {
                scheme: Scheme::Https,
                host: "10.0.0.2".into(),
                port: 443,
            },
        ];
        assert!(validate_endpoints(&endpoints).is_ok());
    }

    #[test]
    fn validate_endpoints_accepts_all_hostname() {
        let endpoints = vec![
            Endpoint {
                scheme: Scheme::Https,
                host: "a.example.com".into(),
                port: 443,
            },
            Endpoint {
                scheme: Scheme::Https,
                host: "b.example.com".into(),
                port: 443,
            },
        ];
        assert!(validate_endpoints(&endpoints).is_ok());
    }

    #[test]
    fn validate_endpoints_rejects_mixed_ports() {
        let endpoints = vec![
            Endpoint {
                scheme: Scheme::Https,
                host: "a.example.com".into(),
                port: 443,
            },
            Endpoint {
                scheme: Scheme::Https,
                host: "b.example.com".into(),
                port: 8443,
            },
        ];
        let err = validate_endpoints(&endpoints).unwrap_err();
        assert!(
            err.to_string().contains("port"),
            "expected port error, got: {err}"
        );
    }

    #[test]
    fn validate_endpoints_accepts_single() {
        let endpoints = vec![Endpoint {
            scheme: Scheme::Https,
            host: "api.openai.com".into(),
            port: 443,
        }];
        assert!(validate_endpoints(&endpoints).is_ok());
    }

    #[test]
    fn validate_endpoints_rejects_ipv6() {
        let endpoints = vec![Endpoint {
            scheme: Scheme::Https,
            host: "::1".into(),
            port: 443,
        }];
        let err = validate_endpoints(&endpoints).unwrap_err();
        match err {
            DomainError::Validation { detail, .. } => {
                assert!(
                    detail.contains("IPv6"),
                    "expected IPv6 error, got: {detail}"
                );
                assert!(
                    detail.contains("not yet supported"),
                    "expected 'not yet supported', got: {detail}"
                );
            }
            _ => panic!("expected Validation, got: {err:?}"),
        }
    }

    #[test]
    fn validate_endpoints_rejects_ipv6_full_address() {
        let endpoints = vec![Endpoint {
            scheme: Scheme::Https,
            host: "2001:db8::1".into(),
            port: 8443,
        }];
        let err = validate_endpoints(&endpoints).unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[test]
    fn validate_endpoints_rejects_bracketed_ipv6() {
        let endpoints = vec![Endpoint {
            scheme: Scheme::Https,
            host: "[2001:db8::1]".into(),
            port: 8443,
        }];
        let err = validate_endpoints(&endpoints).unwrap_err();
        match err {
            DomainError::Validation { detail, .. } => {
                assert!(
                    detail.contains("IPv6"),
                    "expected IPv6 error, got: {detail}"
                );
                assert!(
                    detail.contains("not yet supported"),
                    "expected 'not yet supported', got: {detail}"
                );
            }
            _ => panic!("expected Validation, got: {err:?}"),
        }
    }

    #[tokio::test]
    async fn delete_upstream_cascades_routes() {
        let svc = make_service();
        let tenant = Uuid::new_v4();
        let ctx = test_ctx(tenant);

        let u = svc
            .create_upstream(&ctx, make_create_upstream(Some("openai")))
            .await
            .unwrap();
        let r = svc
            .create_route(&ctx, make_create_route(u.id))
            .await
            .unwrap();

        svc.delete_upstream(&ctx, u.id).await.unwrap();

        // Route should be gone.
        assert!(svc.get_route(&ctx, r.id).await.is_err());
    }
}
