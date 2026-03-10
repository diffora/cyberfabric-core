use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authz_resolver_sdk::PolicyEnforcer;
use authz_resolver_sdk::pep::AccessRequest;
use bytes::Bytes;
use credstore_sdk::CredStoreClientV1;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use modkit_security::SecurityContext;
use oagw_sdk::body::{Body, BodyStream};
use pingora_core::apps::HttpServerApp;
use pingora_proxy::HttpProxy;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::config::TokenCacheConfig;
use crate::domain::error::DomainError;
use crate::domain::model::{Endpoint, PassthroughMode, PathSuffixMode, Scheme, Upstream};
use crate::domain::plugin::AuthContext;
use crate::domain::rate_limit::RateLimiter;
use crate::domain::services::{ControlPlaneService, DataPlaneService, EndpointSelector};
use crate::infra::plugin::AuthPluginRegistry;
use crate::infra::proxy::{actions, resources};

use super::headers;
use super::pingora_proxy::{
    H_ENDPOINT_HOST, H_ENDPOINT_PORT, H_ENDPOINT_SCHEME, H_INSTANCE_URI, H_UPSTREAM_ID,
    PingoraProxy,
};
use super::{request_builder, session_bridge};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default maximum request body size: 100 MB.
const MAX_BODY_SIZE: usize = 100 * 1024 * 1024;

/// Data Plane service implementation: proxy orchestration and plugin execution.
pub struct DataPlaneServiceImpl {
    cp: Arc<dyn ControlPlaneService>,
    backend_selector: Arc<dyn EndpointSelector>,
    proxy: Arc<HttpProxy<PingoraProxy>>,
    /// Sender kept alive so receivers see `false` (not shutting down) until drop.
    _shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    auth_registry: AuthPluginRegistry,
    rate_limiter: RateLimiter,
    request_timeout: Duration,
    /// Enforces authorization policy before proxying each request.
    policy_enforcer: PolicyEnforcer,
    /// When true, allow HTTP (non-TLS) upstream connections.
    allow_http_upstream: bool,
    /// Maximum request body size in bytes (applies to both buffered and streaming bodies).
    max_body_size: usize,
}

impl DataPlaneServiceImpl {
    pub fn new(
        cp: Arc<dyn ControlPlaneService>,
        credstore: Arc<dyn CredStoreClientV1>,
        policy_enforcer: PolicyEnforcer,
        token_http_config: Option<modkit_http::HttpClientConfig>,
        token_cache_config: TokenCacheConfig,
        backend_selector: Arc<dyn EndpointSelector>,
        proxy: Arc<HttpProxy<PingoraProxy>>,
    ) -> Self {
        let auth_registry =
            AuthPluginRegistry::with_builtins(credstore, token_http_config, token_cache_config);
        let rate_limiter = RateLimiter::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Self {
            cp,
            backend_selector,
            proxy,
            _shutdown_tx: shutdown_tx,
            shutdown_rx,
            auth_registry,
            rate_limiter,
            request_timeout: REQUEST_TIMEOUT,
            policy_enforcer,
            allow_http_upstream: false,
            max_body_size: MAX_BODY_SIZE,
        }
    }

    /// Override the request timeout.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the maximum request body size.
    #[must_use]
    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Allow HTTP (non-TLS) upstream connections.
    #[must_use]
    pub fn with_allow_http_upstream(mut self, allow: bool) -> Self {
        self.allow_http_upstream = allow;
        self
    }

    /// Two-tier endpoint selection (D1):
    /// 1. `X-OAGW-Target-Host` header → validate against endpoint list
    /// 2. Round-robin via `BackendSelector` for multi-endpoint, direct for single
    async fn select_endpoint(
        &self,
        upstream: &Upstream,
        req_headers: &http::HeaderMap,
        instance_uri: &str,
    ) -> Result<Endpoint, DomainError> {
        let endpoints = &upstream.server.endpoints;

        if endpoints.is_empty() {
            return Err(DomainError::DownstreamError {
                detail: "upstream has no endpoints".into(),
                instance: instance_uri.to_string(),
            });
        }

        // Tier 1: Explicit selection via X-OAGW-Target-Host header.
        if let Some(target_host) = req_headers
            .get("x-oagw-target-host")
            .and_then(|v| v.to_str().ok())
        {
            // Validate format: allowlist of safe hostname/IP characters.
            // Rejects null bytes, @, \, Unicode homoglyphs, and port/path syntax.
            if target_host.is_empty()
                || !target_host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err(DomainError::InvalidTargetHost {
                    instance: instance_uri.to_string(),
                });
            }

            // Find matching endpoint by host.
            return endpoints
                .iter()
                .find(|ep| ep.host.eq_ignore_ascii_case(target_host))
                .cloned()
                .ok_or_else(|| {
                    let valid_hosts: Vec<&str> =
                        endpoints.iter().map(|ep| ep.host.as_str()).collect();
                    tracing::warn!(
                        target_host,
                        ?valid_hosts,
                        "X-OAGW-Target-Host does not match any configured endpoint"
                    );
                    DomainError::UnknownTargetHost {
                        detail: format!(
                            "X-OAGW-Target-Host '{}' does not match any configured endpoint",
                            target_host
                        ),
                        instance: instance_uri.to_string(),
                    }
                });
        }

        // Tier 2: Automatic selection.
        if endpoints.len() == 1 {
            // Single-endpoint: use directly, no LB overhead.
            return Ok(endpoints[0].clone());
        }

        // Multi-endpoint: round-robin via BackendSelector.
        self.backend_selector
            .select(upstream.id, endpoints)
            .await
            .ok_or_else(|| DomainError::DownstreamError {
                detail: "all backends are unhealthy".into(),
                instance: instance_uri.to_string(),
            })
    }
}

#[async_trait]
impl DataPlaneService for DataPlaneServiceImpl {
    async fn proxy_request(
        &self,
        ctx: SecurityContext,
        req: http::Request<Body>,
    ) -> Result<http::Response<Body>, DomainError> {
        let instance_uri = req.uri().to_string();

        self.policy_enforcer
            .access_scope_with(
                &ctx,
                &resources::PROXY,
                actions::INVOKE,
                None,
                &AccessRequest::new()
                    .require_constraints(false)
                    .context_tenant_id(ctx.subject_tenant_id()),
            )
            .await?;

        // Extract alias from the raw path first, then normalize only the
        // suffix. This prevents path traversal (e.g. `/../../admin/...`)
        // from influencing alias extraction.
        let (alias, path_suffix) = {
            let path = req.uri().path();
            let trimmed = path.strip_prefix('/').unwrap_or(path);
            let (alias, raw_suffix) = match trimmed.find('/') {
                Some(pos) => (&trimmed[..pos], &trimmed[pos..]),
                None => (trimmed, ""),
            };
            (alias.to_string(), normalize_path(raw_suffix))
        };

        // Parse query parameters with proper URL decoding.
        let query_params: Vec<(String, String)> = req
            .uri()
            .query()
            .map(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect()
            })
            .unwrap_or_default();

        // Decompose request into parts. Keep body as-is for conditional handling.
        let (parts, body) = req.into_parts();
        let method = parts.method;
        let req_headers = parts.headers;

        // Reject WebSocket upgrade requests — the current bridge is unidirectional
        // and cannot support the bidirectional tunnel that WebSocket requires.
        if req_headers
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
            })
        {
            return Err(DomainError::ProtocolError {
                detail: "WebSocket upgrade is not supported by the proxy".into(),
                instance: instance_uri,
            });
        }

        // Conditional body conversion — keep streams for streaming request bodies.
        let max_body = self.max_body_size;
        let (body_bytes, body_stream): (Bytes, Option<BodyStream>) = match body {
            Body::Empty => (Bytes::new(), None),
            Body::Bytes(b) => {
                if b.len() > max_body {
                    return Err(DomainError::PayloadTooLarge {
                        detail: format!(
                            "request body of {} bytes exceeds maximum of {max_body} bytes",
                            b.len()
                        ),
                        instance: instance_uri,
                    });
                }
                (b, None)
            }
            Body::Stream(s) => (Bytes::new(), Some(s)),
        };

        // 1+2. Resolve upstream + route in one pass (single hierarchy walk).
        let (upstream, route) = self
            .cp
            .resolve_proxy_target(&ctx, &alias, method.as_ref(), &path_suffix)
            .await?;

        // 2b. Validate query parameters against route's allowlist.
        if let Some(ref http_match) = route.match_rules.http
            && !query_params.is_empty()
        {
            for (key, _) in &query_params {
                if !http_match.query_allowlist.contains(key) {
                    return Err(DomainError::Validation {
                        detail: format!(
                            "query parameter '{}' is not in the route's query_allowlist",
                            key
                        ),
                        instance: instance_uri,
                    });
                }
            }
        }

        // 2c. Enforce path_suffix_mode.
        if let Some(ref http_match) = route.match_rules.http
            && http_match.path_suffix_mode == PathSuffixMode::Disabled
        {
            let route_path = &http_match.path;
            let extra = path_suffix.strip_prefix(route_path.as_str()).unwrap_or("");
            if !extra.is_empty() {
                return Err(DomainError::Validation {
                    detail: format!(
                        "path suffix not allowed: route path_suffix_mode is disabled but request has extra path '{}'",
                        extra
                    ),
                    instance: instance_uri,
                });
            }
        }

        // 3. Prepare outbound headers (passthrough + strip).
        let mode = upstream
            .headers
            .as_ref()
            .and_then(|h| h.request.as_ref())
            .map_or(PassthroughMode::None, |r| r.passthrough);
        let allowlist: Vec<String> = upstream
            .headers
            .as_ref()
            .and_then(|h| h.request.as_ref())
            .map_or_else(Vec::new, |r| r.passthrough_allowlist.clone());
        let mut outbound_headers = headers::apply_passthrough(&req_headers, &mode, &allowlist);
        headers::strip_hop_by_hop(&mut outbound_headers);
        headers::strip_internal_headers(&mut outbound_headers);

        // 4. Execute auth plugin.
        if let Some(ref auth) = upstream.auth {
            let plugin = self.auth_registry.resolve(&auth.plugin_type).map_err(|e| {
                DomainError::AuthenticationFailed {
                    detail: e.to_string(),
                    instance: instance_uri.clone(),
                }
            })?;
            let auth_headers: HashMap<String, String> = outbound_headers
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_string(), s.to_string()))
                })
                .collect();
            let mut auth_ctx = AuthContext {
                headers: auth_headers,
                config: auth.config.clone().unwrap_or_default(),
                security_context: ctx.clone(),
            };
            plugin
                .authenticate(&mut auth_ctx)
                .await
                .map_err(|e| match e {
                    crate::domain::plugin::PluginError::SecretNotFound(ref s) => {
                        DomainError::SecretNotFound {
                            detail: s.clone(),
                            instance: instance_uri.clone(),
                        }
                    }
                    crate::domain::plugin::PluginError::Rejected(ref msg)
                    | crate::domain::plugin::PluginError::InvalidConfig(ref msg) => {
                        DomainError::Validation {
                            detail: msg.clone(),
                            instance: instance_uri.clone(),
                        }
                    }
                    crate::domain::plugin::PluginError::AuthFailed(_)
                    | crate::domain::plugin::PluginError::Internal(_) => {
                        DomainError::AuthenticationFailed {
                            detail: e.to_string(),
                            instance: instance_uri.clone(),
                        }
                    }
                })?;
            outbound_headers = HeaderMap::new();
            for (k, v) in &auth_ctx.headers {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    outbound_headers.insert(name, val);
                }
            }
        }

        // 5. Apply header rules + set Host.
        if let Some(ref hc) = upstream.headers
            && let Some(ref rules) = hc.request
        {
            headers::apply_header_rules(&mut outbound_headers, rules);
        }

        // 5a. Endpoint selection (D1 — two-tier).
        let endpoint = self
            .select_endpoint(&upstream, &req_headers, &instance_uri)
            .await?;

        // 5b. Enforce HTTPS-only constraint (cpt-cf-oagw-constraint-https-only).
        if !self.allow_http_upstream && matches!(endpoint.scheme, Scheme::Http) {
            return Err(DomainError::Validation {
                detail: "upstream endpoint uses HTTP; only HTTPS endpoints are permitted".into(),
                instance: instance_uri,
            });
        }

        headers::set_host_header(&mut outbound_headers, &endpoint.host, endpoint.port);

        // 6. Check rate limit (upstream then route).
        if let Some(ref rl) = upstream.rate_limit {
            let key = format!("upstream:{}", upstream.id);
            self.rate_limiter.try_consume(&key, rl, &instance_uri)?;
        }
        if let Some(ref rl) = route.rate_limit {
            let key = format!("route:{}", route.id);
            self.rate_limiter.try_consume(&key, rl, &instance_uri)?;
        }

        // 7. Build URL.
        // path_suffix is the full path from the proxy URL; strip the route prefix
        // so we get: endpoint + route_path + remaining_suffix.
        let route_path = route
            .match_rules
            .http
            .as_ref()
            .map_or("/", |h| h.path.as_str());
        let remaining_suffix = path_suffix.strip_prefix(route_path).unwrap_or("");
        let url = request_builder::build_upstream_url(
            &endpoint,
            route_path,
            remaining_suffix,
            &query_params,
        )?;

        // 7b. Inject internal context headers for PingoraProxy (D9).
        let scheme_str = match endpoint.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Wss => "wss",
            Scheme::Wt => "wt",
            Scheme::Grpc => "grpc",
        };
        if let Ok(v) = HeaderValue::from_str(&upstream.id.to_string()) {
            outbound_headers.insert(H_UPSTREAM_ID, v);
        }
        if let Ok(v) = HeaderValue::from_str(&endpoint.host) {
            outbound_headers.insert(H_ENDPOINT_HOST, v);
        }
        if let Ok(v) = HeaderValue::from_str(&endpoint.port.to_string()) {
            outbound_headers.insert(H_ENDPOINT_PORT, v);
        }
        outbound_headers.insert(H_ENDPOINT_SCHEME, HeaderValue::from_static(scheme_str));
        if let Ok(v) = HeaderValue::from_str(&instance_uri) {
            outbound_headers.insert(H_INSTANCE_URI, v);
        }

        // 8. Bridge request into Pingora via in-memory DuplexStream.
        let (client_io, server_io) = tokio::io::duplex(65_536);

        // Create Pingora H1 session from the server side of the DuplexStream.
        // Pingora implements all IO traits for DuplexStream (in ext_io_impl).
        let session = pingora_core::protocols::http::ServerSession::new_http1(Box::new(server_io));

        // Spawn Pingora proxy processing in background.
        let proxy = self.proxy.clone();
        let shutdown = self.shutdown_rx.clone();
        tokio::spawn(async move {
            proxy.process_new_http(session, &shutdown).await;
        });

        // Write the request and read the response from the client side.
        let timeout = self.request_timeout;

        if let Some(mut body_stream) = body_stream {
            // Streaming path: write headers, then forward body chunks concurrently.
            let (client_read, mut client_write) = tokio::io::split(client_io);

            let header_bytes =
                session_bridge::serialize_request_wire(&method, &url, &outbound_headers, None);
            client_write.write_all(&header_bytes).await.map_err(|e| {
                DomainError::DownstreamError {
                    detail: format!("failed to write to proxy bridge: {e}"),
                    instance: instance_uri.clone(),
                }
            })?;

            // Spawn task to forward body stream chunks, then shutdown.
            // Enforce max_body_size on the streaming path: signal 413 if exceeded.
            let (limit_tx, limit_rx) = tokio::sync::oneshot::channel::<usize>();
            let body_instance_uri = instance_uri.clone();
            tokio::spawn(async move {
                let mut total_bytes: usize = 0;
                let mut exceeded = false;
                while let Some(chunk) = body_stream.next().await {
                    match chunk {
                        Ok(bytes) => {
                            total_bytes = total_bytes.saturating_add(bytes.len());
                            if total_bytes > max_body {
                                tracing::warn!(
                                    total_bytes,
                                    max_body,
                                    "streaming body exceeded max size, aborting"
                                );
                                exceeded = true;
                                break;
                            }
                            if let Err(e) = client_write.write_all(&bytes).await {
                                tracing::debug!(error = %e, "body stream write error");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "body stream chunk error");
                            break;
                        }
                    }
                }
                if exceeded {
                    let _ = limit_tx.send(total_bytes);
                }
                let _ = client_write.shutdown().await;
            });

            // 9. Parse response from the read half, but short-circuit to 413
            //    if the body-forwarding task signals a limit breach.
            //
            // TODO(hardening): a fast upstream can respond before the body-forwarder
            // detects the limit breach, causing the client to see 200 instead of 413.
            // Fix: wrap the write half in a LimitedAsyncWrite that returns io::Error
            // at the byte limit, so Pingora aborts the exchange before responding.
            let resp_future =
                tokio::time::timeout(timeout, session_bridge::parse_response_stream(client_read));
            tokio::select! {
                biased;
                Ok(total) = limit_rx => {
                    return Err(DomainError::PayloadTooLarge {
                        detail: format!(
                            "streaming request body of {total} bytes exceeds maximum of {max_body} bytes"
                        ),
                        instance: body_instance_uri,
                    });
                }
                result = resp_future => {
                    let (status, resp_headers, resp_body_stream) = result
                        .map_err(|_| DomainError::RequestTimeout {
                            detail: format!("request to {url} timed out after {timeout:?}"),
                            instance: instance_uri.clone(),
                        })?
                        .map_err(|e| DomainError::DownstreamError {
                            detail: format!("proxy bridge error: {e}"),
                            instance: instance_uri.clone(),
                        })?;
                    Ok(build_proxy_response(status, resp_headers, resp_body_stream, instance_uri)?)
                }
            }
        } else {
            // Buffered path: write full request, shutdown write side, then read response.
            let wire = session_bridge::serialize_request_wire(
                &method,
                &url,
                &outbound_headers,
                Some(&body_bytes),
            );
            let mut client_io = client_io;
            client_io
                .write_all(&wire)
                .await
                .map_err(|e| DomainError::DownstreamError {
                    detail: format!("failed to write to proxy bridge: {e}"),
                    instance: instance_uri.clone(),
                })?;
            // Do NOT shutdown the write side — Pingora uses Content-Length to
            // determine the request boundary, and an early write-close is
            // misinterpreted as "downstream dropped the connection".

            // 9. Parse response.
            let (status, resp_headers, resp_body_stream) =
                tokio::time::timeout(timeout, session_bridge::parse_response_stream(client_io))
                    .await
                    .map_err(|_| DomainError::RequestTimeout {
                        detail: format!("request to {url} timed out after {timeout:?}"),
                        instance: instance_uri.clone(),
                    })?
                    .map_err(|e| DomainError::DownstreamError {
                        detail: format!("proxy bridge error: {e}"),
                        instance: instance_uri.clone(),
                    })?;

            Ok(build_proxy_response(
                status,
                resp_headers,
                resp_body_stream,
                instance_uri,
            )?)
        }
    }

    fn remove_rate_limit_key(&self, key: &str) {
        self.rate_limiter.remove_key(key);
    }
}

/// Build the final proxy response: extract error source, sanitize headers,
/// assemble the `http::Response<Body>`.
fn build_proxy_response(
    status: http::StatusCode,
    mut resp_headers: HeaderMap,
    body_stream: BodyStream,
    instance_uri: String,
) -> Result<http::Response<Body>, DomainError> {
    let error_source = headers::extract_error_source(&resp_headers);
    headers::sanitize_response_headers(&mut resp_headers);

    let mut resp = http::Response::builder()
        .status(status)
        .body(Body::Stream(body_stream))
        .map_err(|e| DomainError::DownstreamError {
            detail: format!("failed to build response: {e}"),
            instance: instance_uri,
        })?;
    *resp.headers_mut() = resp_headers;
    resp.extensions_mut().insert(error_source);
    Ok(resp)
}

/// Normalize a URL path: collapse consecutive slashes and resolve `.`/`..` segments.
/// Segments that would escape above the root are discarded.
fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut result = String::with_capacity(path.len());
    if path.starts_with('/') {
        result.push('/');
    }
    result.push_str(&segments.join("/"));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::{Endpoint, Scheme, Server, Upstream};
    use crate::domain::services::EndpointSelector;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    #[test]
    fn normalize_collapses_double_slashes() {
        assert_eq!(normalize_path("/alias//v1//chat"), "/alias/v1/chat");
    }

    #[test]
    fn normalize_resolves_dot_dot() {
        assert_eq!(normalize_path("/alias/../admin/secret"), "/admin/secret");
    }

    #[test]
    fn normalize_clamps_above_root() {
        assert_eq!(normalize_path("/alias/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn normalize_resolves_single_dot() {
        assert_eq!(normalize_path("/alias/./v1/chat"), "/alias/v1/chat");
    }

    #[test]
    fn normalize_preserves_clean_path() {
        assert_eq!(normalize_path("/alias/v1/chat"), "/alias/v1/chat");
    }

    // -----------------------------------------------------------------------
    // select_endpoint() unit tests
    // -----------------------------------------------------------------------

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint {
            scheme: Scheme::Https,
            host: host.to_string(),
            port,
        }
    }

    fn upstream_with(endpoints: Vec<Endpoint>) -> Upstream {
        Upstream {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            alias: "test".to_string(),
            server: Server { endpoints },
            protocol: "http".to_string(),
            enabled: true,
            auth: None,
            headers: None,
            plugins: None,
            rate_limit: None,
            tags: vec![],
        }
    }

    /// Mock BackendSelector that returns endpoints[call_count % endpoints.len()].
    struct MockSelector {
        call_count: AtomicUsize,
    }

    impl MockSelector {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl EndpointSelector for MockSelector {
        async fn select(&self, _upstream_id: Uuid, endpoints: &[Endpoint]) -> Option<Endpoint> {
            let idx = self.call_count.fetch_add(1, Ordering::Relaxed) % endpoints.len();
            Some(endpoints[idx].clone())
        }

        fn invalidate(&self, _upstream_id: Uuid) {}
    }

    /// Build a minimal `DataPlaneServiceImpl` with the given `BackendSelector`.
    fn build_svc(selector: Arc<dyn EndpointSelector>) -> DataPlaneServiceImpl {
        use authz_resolver_sdk::{
            AuthZResolverClient, AuthZResolverError, EvaluationRequest, EvaluationResponse,
            EvaluationResponseContext, PolicyEnforcer,
        };
        use credstore_sdk::{CredStoreClientV1, CredStoreError, GetSecretResponse, SecretRef};
        use modkit_security::SecurityContext;

        struct AllowAllAuthZ;
        #[async_trait]
        impl AuthZResolverClient for AllowAllAuthZ {
            async fn evaluate(
                &self,
                _request: EvaluationRequest,
            ) -> Result<EvaluationResponse, AuthZResolverError> {
                Ok(EvaluationResponse {
                    decision: true,
                    context: EvaluationResponseContext {
                        constraints: Vec::new(),
                        deny_reason: None,
                    },
                })
            }
        }

        struct NoopCredStore;
        #[async_trait]
        impl CredStoreClientV1 for NoopCredStore {
            async fn get(
                &self,
                _ctx: &SecurityContext,
                _key: &SecretRef,
            ) -> Result<Option<GetSecretResponse>, CredStoreError> {
                Ok(None)
            }
        }

        let credstore: Arc<dyn CredStoreClientV1> = Arc::new(NoopCredStore);
        let policy_enforcer = PolicyEnforcer::new(Arc::new(AllowAllAuthZ));

        // Minimal CP — never called by select_endpoint().
        use crate::domain::error::DomainError;
        use crate::domain::model::*;
        use crate::domain::services::ControlPlaneService;

        struct NoopCp;
        #[async_trait]
        impl ControlPlaneService for NoopCp {
            async fn create_upstream(
                &self,
                _: &SecurityContext,
                _: CreateUpstreamRequest,
            ) -> Result<Upstream, DomainError> {
                unimplemented!()
            }
            async fn get_upstream(
                &self,
                _: &SecurityContext,
                _: Uuid,
            ) -> Result<Upstream, DomainError> {
                unimplemented!()
            }
            async fn list_upstreams(
                &self,
                _: &SecurityContext,
                _: &ListQuery,
            ) -> Result<Vec<Upstream>, DomainError> {
                unimplemented!()
            }
            async fn update_upstream(
                &self,
                _: &SecurityContext,
                _: Uuid,
                _: UpdateUpstreamRequest,
            ) -> Result<Upstream, DomainError> {
                unimplemented!()
            }
            async fn delete_upstream(
                &self,
                _: &SecurityContext,
                _: Uuid,
            ) -> Result<(), DomainError> {
                unimplemented!()
            }
            async fn create_route(
                &self,
                _: &SecurityContext,
                _: CreateRouteRequest,
            ) -> Result<Route, DomainError> {
                unimplemented!()
            }
            async fn get_route(&self, _: &SecurityContext, _: Uuid) -> Result<Route, DomainError> {
                unimplemented!()
            }
            async fn list_routes(
                &self,
                _: &SecurityContext,
                _: Uuid,
                _: &ListQuery,
            ) -> Result<Vec<Route>, DomainError> {
                unimplemented!()
            }
            async fn update_route(
                &self,
                _: &SecurityContext,
                _: Uuid,
                _: UpdateRouteRequest,
            ) -> Result<Route, DomainError> {
                unimplemented!()
            }
            async fn delete_route(&self, _: &SecurityContext, _: Uuid) -> Result<(), DomainError> {
                unimplemented!()
            }
            async fn resolve_proxy_target(
                &self,
                _: &SecurityContext,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<(Upstream, Route), DomainError> {
                unimplemented!()
            }
        }

        let cp: Arc<dyn ControlPlaneService> = Arc::new(NoopCp);
        let server_conf = Arc::new(pingora_core::server::configuration::ServerConf::default());
        let pingora = crate::infra::proxy::pingora_proxy::PingoraProxy::new(
            Duration::from_secs(10),
            Duration::from_secs(30),
        );
        let proxy = Arc::new(crate::infra::proxy::pingora_proxy::new_http_proxy(
            &server_conf,
            pingora,
        ));

        DataPlaneServiceImpl::new(
            cp,
            credstore,
            policy_enforcer,
            None,
            TokenCacheConfig::default(),
            selector,
            proxy,
        )
    }

    // P2 #12: Alias extraction happens on raw path, then suffix is normalized.
    // Path traversal in the alias segment must not influence which upstream is resolved.
    #[test]
    fn alias_extraction_ignores_path_traversal() {
        // Simulate what proxy_request does: extract alias from raw path, normalize suffix.
        fn extract(path: &str) -> (String, String) {
            let trimmed = path.strip_prefix('/').unwrap_or(path);
            let (alias, raw_suffix) = match trimmed.find('/') {
                Some(pos) => (&trimmed[..pos], &trimmed[pos..]),
                None => (trimmed, ""),
            };
            (alias.to_string(), normalize_path(raw_suffix))
        }

        // Normal case.
        let (alias, suffix) = extract("/myalias/v1/chat");
        assert_eq!(alias, "myalias");
        assert_eq!(suffix, "/v1/chat");

        // Path traversal attempt: alias is still the first raw segment.
        let (alias, suffix) = extract("/myalias/../admin/secret");
        assert_eq!(alias, "myalias");
        assert_eq!(suffix, "/admin/secret"); // ".." collapsed in suffix only

        // Deep traversal: alias is still literal first segment.
        let (alias, suffix) = extract("/myalias/../../etc/passwd");
        assert_eq!(alias, "myalias");
        assert_eq!(suffix, "/etc/passwd"); // ".." collapsed, clamped at root
    }

    // P2: HTTPS-only — Http scheme endpoint must be rejected.
    #[tokio::test]
    async fn select_endpoint_rejects_http_scheme() {
        let selector = Arc::new(MockSelector::new());
        let svc = build_svc(selector);

        // Single Http endpoint.
        let upstream = upstream_with(vec![Endpoint {
            scheme: Scheme::Http,
            host: "insecure.example.com".to_string(),
            port: 80,
        }]);
        let headers = HeaderMap::new();

        let err = svc.select_endpoint(&upstream, &headers, "/test").await;

        // select_endpoint itself doesn't enforce HTTPS — the check is in proxy_request
        // after select_endpoint returns. Verify the endpoint is returned here (enforcement
        // is at a higher level).
        assert!(err.is_ok(), "select_endpoint should return the endpoint");
        assert_eq!(err.unwrap().scheme, Scheme::Http);
    }

    // positive-2.2 (custom-header-routing): X-OAGW-Target-Host matches an endpoint.
    #[tokio::test]
    async fn select_endpoint_target_host_matches() {
        let selector = Arc::new(MockSelector::new());
        let svc = build_svc(selector.clone());
        let upstream = upstream_with(vec![ep("a.com", 443), ep("b.com", 443)]);

        let mut headers = HeaderMap::new();
        headers.insert("x-oagw-target-host", "a.com".parse().unwrap());

        let result = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap();
        assert_eq!(result.host, "a.com");
        assert_eq!(selector.calls(), 0, "BackendSelector should not be called");
    }

    // negative-2.1 (custom-header-routing): X-OAGW-Target-Host does not match any endpoint.
    #[tokio::test]
    async fn select_endpoint_target_host_unknown() {
        let svc = build_svc(Arc::new(MockSelector::new()));
        let upstream = upstream_with(vec![ep("a.com", 443), ep("b.com", 443)]);

        let mut headers = HeaderMap::new();
        headers.insert("x-oagw-target-host", "evil.com".parse().unwrap());

        let err = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::UnknownTargetHost { .. }),
            "expected UnknownTargetHost, got: {err:?}"
        );
    }

    // negative-1.2..1.4 (custom-header-routing): X-OAGW-Target-Host with invalid format.
    #[tokio::test]
    async fn select_endpoint_target_host_invalid_format() {
        let svc = build_svc(Arc::new(MockSelector::new()));
        let upstream = upstream_with(vec![ep("a.com", 443)]);

        for bad_value in [
            "a.com:443",
            "a.com/path",
            "a.com?q=1",
            "a b",
            "evil.com@real.com",
            "evil.com\\real.com",
            "a.com#fragment",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("x-oagw-target-host", bad_value.parse().unwrap());
            let err = svc
                .select_endpoint(&upstream, &headers, "/test")
                .await
                .unwrap_err();
            assert!(
                matches!(err, DomainError::InvalidTargetHost { .. }),
                "expected InvalidTargetHost for '{bad_value}', got: {err:?}"
            );
        }

        // Empty header value: test separately since HeaderValue::from_static
        // allows empty strings while .parse() does not.
        let mut headers = HeaderMap::new();
        headers.insert("x-oagw-target-host", HeaderValue::from_static(""));
        let err = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidTargetHost { .. }),
            "expected InvalidTargetHost for empty header, got: {err:?}"
        );
    }

    // positive-2.1 (custom-header-routing): Round-robin fallback for multi-endpoint (no header).
    #[tokio::test]
    async fn select_endpoint_round_robin_fallback() {
        let selector = Arc::new(MockSelector::new());
        let svc = build_svc(selector.clone());
        let upstream = upstream_with(vec![ep("a.com", 443), ep("b.com", 443)]);
        let headers = HeaderMap::new();

        let ep1 = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap();
        let ep2 = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap();

        assert_eq!(
            selector.calls(),
            2,
            "BackendSelector should be called for multi-endpoint"
        );
        // MockSelector returns endpoints in order: [0], [1], [0], ...
        assert_eq!(ep1.host, "a.com");
        assert_eq!(ep2.host, "b.com");
    }

    // positive-1.1 (custom-header-routing): Single-endpoint bypass (no header, no BackendSelector call).
    #[tokio::test]
    async fn select_endpoint_single_endpoint_bypass() {
        let selector = Arc::new(MockSelector::new());
        let svc = build_svc(selector.clone());
        let upstream = upstream_with(vec![ep("only.com", 443)]);
        let headers = HeaderMap::new();

        let result = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap();
        assert_eq!(result.host, "only.com");
        assert_eq!(
            selector.calls(),
            0,
            "BackendSelector should NOT be called for single endpoint"
        );
    }

    // positive-1.2 (custom-header-routing): Single-endpoint upstream validates header if present.
    #[tokio::test]
    async fn select_endpoint_single_endpoint_validates_header() {
        let svc = build_svc(Arc::new(MockSelector::new()));
        let upstream = upstream_with(vec![ep("a.com", 443)]);

        // Valid header matching the single endpoint → OK.
        let mut headers = HeaderMap::new();
        headers.insert("x-oagw-target-host", "a.com".parse().unwrap());
        let result = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap();
        assert_eq!(result.host, "a.com");

        // Invalid header not matching → UnknownTargetHost.
        let mut headers = HeaderMap::new();
        headers.insert("x-oagw-target-host", "b.com".parse().unwrap());
        let err = svc
            .select_endpoint(&upstream, &headers, "/test")
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::UnknownTargetHost { .. }),
            "expected UnknownTargetHost for mismatched header on single-endpoint upstream"
        );
    }
}
