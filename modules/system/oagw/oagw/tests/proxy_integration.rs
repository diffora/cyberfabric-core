use http::{Method, StatusCode};
use oagw::test_support::{
    APIKEY_AUTH_PLUGIN_ID, AppHarness, MockBody, MockGuard, MockResponse, MockUpstream,
    OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID, parse_resource_gts,
};
use oagw_sdk::Body;
use oagw_sdk::api::ErrorSource;
use oagw_sdk::{
    BurstConfig, CreateRouteRequest, CreateUpstreamRequest, Endpoint, HttpMatch, HttpMethod,
    MatchRules, PathSuffixMode, RateLimitAlgorithm, RateLimitConfig, RateLimitScope,
    RateLimitStrategy, Scheme, Server, SharingMode, SustainedRate, Window,
};
use serde_json::json;

async fn setup_openai_mock() -> AppHarness {
    let h = AppHarness::builder()
        .with_credentials(vec![("cred://openai-key".into(), "sk-test123".into())])
        .build()
        .await;

    let resp = h
        .api_v1()
        .post_upstream()
        .with_body(serde_json::json!({
            "server": {
                "endpoints": [{"host": "127.0.0.1", "port": h.mock_port(), "scheme": "http"}]
            },
            "protocol": "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            "alias": "mock-upstream",
            "enabled": true,
            "tags": [],
            "auth": {
                "type": APIKEY_AUTH_PLUGIN_ID,
                "sharing": "private",
                "config": {
                    "header": "authorization",
                    "prefix": "Bearer ",
                    "secret_ref": "cred://openai-key"
                }
            }
        }))
        .expect_status(201)
        .await;
    let upstream_id = resp.json()["id"].as_str().unwrap().to_string();
    let (_, upstream_uuid) = parse_resource_gts(&upstream_id).unwrap();

    for (methods, path) in [
        (vec!["POST", "GET"], "/v1/chat/completions"),
        (vec!["GET"], "/error"),
    ] {
        h.api_v1()
            .post_route()
            .with_body(serde_json::json!({
                "upstream_id": upstream_uuid,
                "match": {
                    "http": {
                        "methods": methods,
                        "path": path
                    }
                },
                "enabled": true,
                "tags": [],
                "priority": 0
            }))
            .expect_status(201)
            .await;
    }

    h
}

// 6.13: Full pipeline — proxy POST /v1/chat/completions with JSON body.
#[tokio::test]
async fn proxy_chat_completion_round_trip() {
    let h = setup_openai_mock().await;

    let req = http::Request::builder()
        .method(Method::POST)
        .uri("/mock-upstream/v1/chat/completions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}"#,
        ))
        .unwrap();
    let response = h
        .facade()
        .proxy_request(h.security_context().clone(), req)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().into_bytes().await.unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(body_json.get("id").is_some());
    assert!(body_json.get("choices").is_some());
}

// 6.13 (auth): Verify the mock received the Authorization header.
#[tokio::test]
async fn proxy_injects_auth_header() {
    let mut guard = MockGuard::new();
    guard.mock(
        "POST",
        "/v1/chat/completions",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: MockBody::Json(json!({
                "id": "chatcmpl-auth-test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]
            })),
        },
    );

    let h = AppHarness::builder()
        .with_credentials(vec![("cred://openai-key".into(), "sk-test123".into())])
        .build()
        .await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("auth-hdr-test")
            .auth(oagw_sdk::AuthConfig {
                plugin_type: APIKEY_AUTH_PLUGIN_ID.into(),
                sharing: SharingMode::Private,
                config: Some(
                    [
                        ("header".into(), "authorization".into()),
                        ("prefix".into(), "Bearer ".into()),
                        ("secret_ref".into(), "cred://openai-key".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            })
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Post],
                        path: guard.path("/v1/chat/completions"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/auth-hdr-test{}",
            guard.path("/v1/chat/completions")
        ))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}"#,
        ))
        .unwrap();
    let response = h.facade().proxy_request(ctx, req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let recorded = guard.recorded_requests().await;
    assert_eq!(recorded.len(), 1);
    let auth_header = recorded[0]
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("authorization header missing");
    assert_eq!(auth_header, "Bearer sk-test123");
}

// 6.14: SSE streaming — proxy to dynamic SSE mock via MockGuard.
#[tokio::test]
async fn proxy_sse_streaming() {
    let mut guard = MockGuard::new();

    let chunks: Vec<String> = vec![
        json!({"id":"chatcmpl-mock-stream","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}).to_string(),
        json!({"id":"chatcmpl-mock-stream","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}).to_string(),
        "[DONE]".to_string(),
    ];
    guard.mock(
        "POST",
        "/v1/chat/completions/stream",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            body: MockBody::Sse(chunks),
        },
    );

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("sse-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Post],
                        path: guard.path("/v1/chat/completions/stream"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/sse-test{}",
            guard.path("/v1/chat/completions/stream")
        ))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"model":"gpt-4","stream":true}"#))
        .unwrap();
    let response = h.facade().proxy_request(ctx, req).await.unwrap();

    let ct = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/event-stream"), "got content-type: {ct}");

    let body_bytes = response.into_body().into_bytes().await.unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains("data: [DONE]"));
}

// 6.15: Upstream 500 error passthrough.
#[tokio::test]
async fn proxy_upstream_500_passthrough() {
    let h = setup_openai_mock().await;

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/mock-upstream/error/500")
        .body(Body::Empty)
        .unwrap();
    let response = h
        .facade()
        .proxy_request(h.security_context().clone(), req)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.extensions().get::<ErrorSource>().copied(),
        Some(ErrorSource::Upstream)
    );
}

// 6.17: Pipeline abort — nonexistent alias returns 404 without calling mock.
#[tokio::test]
async fn proxy_nonexistent_alias_returns_404() {
    let h = setup_openai_mock().await;

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/nonexistent/v1/test")
        .body(Body::Empty)
        .unwrap();
    match h
        .facade()
        .proxy_request(h.security_context().clone(), req)
        .await
    {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::NotFound { .. }
        )),
        Ok(_) => panic!("expected error"),
    }
}

// 6.17: Pipeline abort — disabled upstream returns 503.
#[tokio::test]
async fn proxy_disabled_upstream_returns_503() {
    let h = setup_openai_mock().await;
    let ctx = h.security_context().clone();

    let _upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: 9999,
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("disabled-upstream")
            .enabled(false)
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/disabled-upstream/test")
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::UpstreamDisabled { .. }
        )),
        Ok(_) => panic!("expected error"),
    }
}

// 6.17: Pipeline abort — rate limit exceeded returns 429.
#[tokio::test]
async fn proxy_rate_limit_exceeded_returns_429() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("rate-limited")
            .rate_limit(RateLimitConfig {
                sharing: SharingMode::Private,
                algorithm: RateLimitAlgorithm::TokenBucket,
                sustained: SustainedRate {
                    rate: 1,
                    window: Window::Minute,
                },
                burst: Some(BurstConfig { capacity: 1 }),
                scope: RateLimitScope::Tenant,
                strategy: RateLimitStrategy::Reject,
                cost: 1,
            })
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // First request should succeed.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/rate-limited/v1/models")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Second request should be rate limited.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/rate-limited/v1/models")
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::RateLimitExceeded { .. }
        )),
        Ok(_) => panic!("expected rate limit error"),
    }
}

// 6.16: Upstream timeout — proxy to gated mock that never responds, assert 504.
// Uses multi_thread runtime so the timer driver runs on a dedicated thread,
// preventing stalls when other test binaries compete for CPU.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_upstream_timeout_returns_504() {
    let mut guard = MockGuard::new();
    // Register a gated route that will never respond (sender kept alive but not signaled).
    let _gate = guard.mock_gated(
        "GET",
        "/timeout",
        MockResponse {
            status: 200,
            headers: vec![],
            body: MockBody::Json(json!({"ok": true})),
        },
    );

    let h = AppHarness::builder()
        .with_request_timeout(std::time::Duration::from_millis(500))
        .build()
        .await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("timeout-upstream")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: guard.path("/timeout"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri(format!("/timeout-upstream{}", guard.path("/timeout")))
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::RequestTimeout { .. }
        )),
        Ok(_) => panic!("expected timeout error"),
    }
}

// 8.9: Query allowlist enforcement.
#[tokio::test]
async fn proxy_query_allowlist_allowed_param_succeeds() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("ql-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec!["version".into()],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/ql-test/v1/models?version=2")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn proxy_query_allowlist_unknown_param_rejected() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("ql-reject")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec!["version".into()],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/ql-reject/v1/models?version=2&debug=true")
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::ValidationError { .. }
        )),
        Ok(_) => panic!("expected validation error"),
    }
}

// 13.5: Non-existent auth plugin ID returns error through proxy pipeline.
#[tokio::test]
async fn proxy_nonexistent_auth_plugin_returns_error() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("bad-auth")
            .auth(oagw_sdk::AuthConfig {
                plugin_type: "gts.x.core.oagw.auth.v1~nonexistent.plugin.v1".into(),
                sharing: SharingMode::Private,
                config: None,
            })
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/test".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/bad-auth/v1/test")
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::AuthenticationFailed { .. }
        )),
        Ok(_) => panic!("expected authentication error for non-existent plugin"),
    }
}

// 13.6: Assert on recorded_requests() URI and body content.
#[tokio::test]
async fn proxy_recorded_request_has_correct_uri_and_body() {
    let mut guard = MockGuard::new();
    guard.mock(
        "POST",
        "/v1/chat/completions",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: MockBody::Json(json!({
                "id": "chatcmpl-rec-test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]
            })),
        },
    );

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("rec-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Post],
                        path: guard.path("/v1/chat/completions"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let body_payload = r#"{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}"#;
    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!("/rec-test{}", guard.path("/v1/chat/completions")))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_payload))
        .unwrap();
    let response = h.facade().proxy_request(ctx, req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let recorded = guard.recorded_requests().await;
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].uri.ends_with("/v1/chat/completions"));
    assert_eq!(recorded[0].method, "POST");

    let body_str = String::from_utf8(recorded[0].body.clone()).unwrap();
    assert!(body_str.contains("gpt-4"));
    assert!(body_str.contains("Hello"));
}

// Response header sanitization: hop-by-hop and x-oagw-* headers stripped from upstream response.
#[tokio::test]
async fn proxy_response_headers_sanitized() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("resp-hdr-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/response-headers".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/resp-hdr-test/response-headers")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let resp_headers = response.headers();

    // Safe headers should be preserved.
    assert_eq!(
        resp_headers.get("x-custom-safe").unwrap(),
        "keep-me",
        "safe custom header should be forwarded"
    );
    assert!(
        resp_headers.get("content-type").is_some(),
        "content-type should be preserved"
    );

    // Hop-by-hop headers should be stripped.
    assert!(
        resp_headers.get("proxy-authenticate").is_none(),
        "proxy-authenticate should be stripped from response"
    );
    assert!(
        resp_headers.get("trailer").is_none(),
        "trailer should be stripped from response"
    );
    assert!(
        resp_headers.get("upgrade").is_none(),
        "upgrade should be stripped from response"
    );

    // Internal x-oagw-* headers should be stripped.
    assert!(
        resp_headers.get("x-oagw-debug").is_none(),
        "x-oagw-debug should be stripped from response"
    );
    assert!(
        resp_headers.get("x-oagw-trace-id").is_none(),
        "x-oagw-trace-id should be stripped from response"
    );
}

// 8.10: path_suffix_mode=disabled rejects suffix; append succeeds.
#[tokio::test]
async fn proxy_path_suffix_disabled_rejects_extra_path() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("psm-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // Exact path succeeds.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/psm-test/v1/models")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Extra suffix rejected with 400.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/psm-test/v1/models/gpt-4")
        .body(Body::Empty)
        .unwrap();
    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(matches!(
            err,
            oagw_sdk::error::ServiceGatewayError::ValidationError { .. }
        )),
        Ok(_) => panic!("expected validation error for disabled path_suffix_mode"),
    }
}

// ---------------------------------------------------------------------------
// Multi-endpoint load balancing integration tests
// ---------------------------------------------------------------------------

// positive-2.1 (custom-header-routing), positive-2.10 (upstreams): Round-robin distribution across 2 endpoints.
//
// Uses a single mock on 127.0.0.1 with two identical endpoint entries so the
// test works on all platforms (macOS only has 127.0.0.1 on loopback by default).
// Actual round-robin distribution across distinct backends is covered by unit
// tests in pingora_proxy.rs (`select_round_robin_distribution`) and service.rs
// (`select_endpoint_round_robin_fallback`).  This integration test verifies the
// full proxy pipeline succeeds with a multi-endpoint upstream configuration.
#[tokio::test]
async fn proxy_multi_endpoint_round_robin() {
    let mock = MockUpstream::start().await;
    let port = mock.addr().port();

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![
                        Endpoint {
                            scheme: Scheme::Http,
                            host: "127.0.0.1".into(),
                            port,
                        },
                        Endpoint {
                            scheme: Scheme::Http,
                            host: "127.0.0.1".into(),
                            port,
                        },
                    ],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("rr-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // Send 4 requests — all reach the single mock via the multi-endpoint pool.
    for _ in 0..4 {
        let req = http::Request::builder()
            .method(Method::GET)
            .uri("/rr-test/v1/models")
            .body(Body::Empty)
            .unwrap();
        let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    assert_eq!(
        mock.recorded_requests().await.len(),
        4,
        "mock should have received all 4 requests"
    );
}

// positive-2.2 (custom-header-routing): X-OAGW-Target-Host explicit selection.
//
// Uses a single mock on 127.0.0.1 with two identical endpoint entries so the
// test works on all platforms (macOS only has 127.0.0.1 on loopback by default).
// This test verifies the header is accepted without error; actual host-based
// routing is covered by the unit test `select_endpoint_target_host_matches` in
// service.rs.
#[tokio::test]
async fn proxy_target_host_header_selects_endpoint() {
    let mock = MockUpstream::start().await;
    let port = mock.addr().port();

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![
                        Endpoint {
                            scheme: Scheme::Http,
                            host: "127.0.0.1".into(),
                            port,
                        },
                        Endpoint {
                            scheme: Scheme::Http,
                            host: "127.0.0.1".into(),
                            port,
                        },
                    ],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("target-host-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // Send request with X-OAGW-Target-Host header selecting endpoint host.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/target-host-test/v1/models")
        .header("x-oagw-target-host", "127.0.0.1")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// negative-2.1 (custom-header-routing): X-OAGW-Target-Host validation — unknown host returns error.
#[tokio::test]
async fn proxy_target_host_unknown_returns_error() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("target-host-unknown")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/target-host-unknown/v1/models")
        .header("x-oagw-target-host", "unknown.com")
        .body(Body::Empty)
        .unwrap();

    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(
            matches!(
                err,
                oagw_sdk::error::ServiceGatewayError::UnknownTargetHost { .. }
            ),
            "expected UnknownTargetHost, got: {err:?}"
        ),
        Ok(_) => panic!("expected error for unknown target host"),
    }
}

// negative-2.10 (upstreams): All backends unreachable returns connection error (502).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_all_backends_unreachable() {
    let h = AppHarness::builder()
        .with_request_timeout(std::time::Duration::from_secs(5))
        .build()
        .await;
    let ctx = h.security_context().clone();

    // Ports 19991/19992 are unlikely to be listening.
    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: 19991,
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("unreachable-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/models".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/unreachable-test/v1/models")
        .body(Body::Empty)
        .unwrap();

    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(
            matches!(
                err,
                oagw_sdk::error::ServiceGatewayError::DownstreamError { .. }
            ),
            "expected DownstreamError for unreachable backend, got: {err:?}"
        ),
        Ok(resp) => {
            // Pingora may return a 502 response directly via fail_to_proxy.
            assert!(
                resp.status() == StatusCode::BAD_GATEWAY
                    || resp.status() == StatusCode::GATEWAY_TIMEOUT,
                "expected 502 or 504, got: {}",
                resp.status()
            );
        }
    }
}

// positive-2.13 (upstreams): CRUD invalidation — update upstream endpoints, verify new endpoint used.
#[tokio::test]
async fn proxy_crud_invalidation_after_update() {
    let mock_a = MockUpstream::start().await;
    let mock_b = MockUpstream::start().await;
    let port_a = mock_a.addr().port();
    let port_b = mock_b.addr().port();

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    // Create upstream pointing to mock_a only.
    let resp = h
        .api_v1()
        .post_upstream()
        .with_body(json!({
            "server": {
                "endpoints": [{"host": "127.0.0.1", "port": port_a, "scheme": "http"}]
            },
            "protocol": "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            "alias": "crud-invalidation",
            "enabled": true,
            "tags": []
        }))
        .expect_status(201)
        .await;
    let upstream_id = resp.json()["id"].as_str().unwrap().to_string();
    let (_, upstream_uuid) = parse_resource_gts(&upstream_id).unwrap();

    h.api_v1()
        .post_route()
        .with_body(json!({
            "upstream_id": upstream_uuid,
            "match": {
                "http": {
                    "methods": ["GET"],
                    "path": "/v1/models"
                }
            },
            "enabled": true,
            "tags": [],
            "priority": 0
        }))
        .expect_status(201)
        .await;

    // Proxy to mock_a.
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/crud-invalidation/v1/models")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        mock_a.recorded_requests().await.len(),
        1,
        "mock_a should have received 1 request"
    );
    assert_eq!(
        mock_b.recorded_requests().await.len(),
        0,
        "mock_b should have received 0 requests"
    );

    // Update upstream to point to mock_b via REST API (triggers invalidation).
    h.api_v1()
        .patch_upstream(&upstream_id)
        .with_body(json!({
            "server": {
                "endpoints": [{"host": "127.0.0.1", "port": port_b, "scheme": "http"}]
            }
        }))
        .expect_status(200)
        .await;

    // Proxy again — should now go to mock_b (cache was invalidated).
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/crud-invalidation/v1/models")
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !mock_b.recorded_requests().await.is_empty(),
        "mock_b should have received at least 1 request after update"
    );
}

// Demonstrate MockGuard pattern for custom per-test responses
#[tokio::test]
async fn proxy_with_mock_guard_custom_response() {
    // Create a MockGuard for test-isolated mock responses
    let mut guard = MockGuard::new();

    // Register a custom response at a unique path
    guard.mock(
        "POST",
        "/custom/endpoint",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: MockBody::Json(json!({
                "custom": "response",
                "test": "data"
            })),
        },
    );

    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    // Create upstream pointing to mock server
    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("guard-test")
            .build(),
        )
        .await
        .unwrap();

    // Create route using the guard's prefixed path
    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Post],
                        path: guard.path("/custom/endpoint"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // Make request to the prefixed path
    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!("/guard-test{}", guard.path("/custom/endpoint")))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"test":"input"}"#))
        .unwrap();

    let response = h.facade().proxy_request(ctx.clone(), req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().into_bytes().await.unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["custom"], "response");
    assert_eq!(body_json["test"], "data");

    // Verify request was recorded (filtered by guard prefix)
    let recorded = guard.recorded_requests().await;
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].uri.contains("/custom/endpoint"));
}

// P0 #3: WebSocket upgrade requests are rejected with ProtocolError.
#[tokio::test]
async fn proxy_websocket_upgrade_rejected() {
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("ws-reject-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/ws".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/ws-reject-test/v1/ws")
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .body(Body::Empty)
        .unwrap();

    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(
            matches!(
                err,
                oagw_sdk::error::ServiceGatewayError::ProtocolError { .. }
            ),
            "expected ProtocolError for WebSocket upgrade, got: {err:?}"
        ),
        Ok(_) => panic!("expected error for WebSocket upgrade request"),
    }
}

// P4 #18: Pingora fail_to_proxy produces valid RFC 9457 Problem body with correct GTS type.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_unreachable_backend_returns_rfc9457_problem_body() {
    let h = AppHarness::builder()
        .with_request_timeout(std::time::Duration::from_secs(5))
        .build()
        .await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: 19993,
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("rfc9457-body-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: "/v1/test".into(),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Append,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/rfc9457-body-test/v1/test")
        .body(Body::Empty)
        .unwrap();

    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => {
            // Went through DomainError path — already covered by other tests.
            // Still verify the variant is one of the two expected for an
            // unreachable backend (not e.g. ValidationError which would be a bug).
            assert!(
                matches!(
                    err,
                    oagw_sdk::error::ServiceGatewayError::DownstreamError { .. }
                        | oagw_sdk::error::ServiceGatewayError::ConnectionTimeout { .. }
                        | oagw_sdk::error::ServiceGatewayError::RequestTimeout { .. }
                ),
                "expected DownstreamError, ConnectionTimeout, or RequestTimeout for unreachable backend, got: {err:?}"
            );
        }
        Ok(resp) => {
            // Pingora wrote the response directly via fail_to_proxy.
            let status = resp.status();
            assert!(
                status == StatusCode::BAD_GATEWAY || status == StatusCode::GATEWAY_TIMEOUT,
                "expected 502 or 504, got: {status}"
            );

            let body_bytes = resp.into_body().into_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body_bytes)
                .expect("fail_to_proxy response body should be valid JSON");

            // Must have all RFC 9457 Problem fields.
            assert!(body.get("type").is_some(), "missing 'type' field");
            assert!(body.get("title").is_some(), "missing 'title' field");
            assert!(body.get("status").is_some(), "missing 'status' field");
            assert!(body.get("detail").is_some(), "missing 'detail' field");
            assert!(body.get("instance").is_some(), "missing 'instance' field");

            // GTS type must not be about:blank.
            let gts_type = body["type"].as_str().unwrap();
            assert!(
                gts_type.starts_with("gts."),
                "expected GTS error type, got: {gts_type}"
            );

            // Status field in body must match HTTP status.
            assert_eq!(
                body["status"].as_u64().unwrap(),
                status.as_u16() as u64,
                "body status must match HTTP status"
            );
        }
    }
}

// negative-8.1 (body-validation): Streaming body exceeding max_body_size returns 413 PayloadTooLarge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_streaming_body_exceeding_limit_returns_413() {
    // Gate the upstream response so it cannot reply before the body-forwarding
    // task detects the limit breach — eliminates the race between the upstream
    // response and the PayloadTooLarge signal.
    let mut guard = MockGuard::new();
    let _gate = guard.mock_gated(
        "POST",
        "/v1/upload",
        MockResponse {
            status: 200,
            headers: vec![],
            body: MockBody::Json(serde_json::json!({"ok": true})),
        },
    );

    let h = AppHarness::builder()
        .with_max_body_size(64) // tiny limit for testing
        .build()
        .await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("body-limit-test")
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Post],
                        path: guard.path("/v1/upload"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    // Build a streaming body that exceeds the 64-byte limit.
    let chunks: Vec<Result<bytes::Bytes, oagw_sdk::body::BoxError>> = vec![
        Ok(bytes::Bytes::from(vec![b'A'; 40])),
        Ok(bytes::Bytes::from(vec![b'B'; 40])), // total = 80 > 64
    ];
    let stream: oagw_sdk::body::BodyStream = Box::pin(futures_util::stream::iter(chunks));
    let body = Body::Stream(stream);

    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!("/body-limit-test{}/v1/upload", guard.prefix()))
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .unwrap();

    match h.facade().proxy_request(ctx.clone(), req).await {
        Err(err) => assert!(
            matches!(
                err,
                oagw_sdk::error::ServiceGatewayError::PayloadTooLarge { .. }
            ),
            "expected PayloadTooLarge, got: {err:?}"
        ),
        Ok(resp) => panic!(
            "expected PayloadTooLarge error, got response with status {}",
            resp.status()
        ),
    }
}

// ---------------------------------------------------------------------------
// OAuth2 Client Credentials integration tests
// ---------------------------------------------------------------------------

/// 9.5: OAuth2 CC happy path — token fetched from mock IdP, injected as Bearer.
#[tokio::test]
async fn proxy_oauth2_client_cred_injects_bearer_token() {
    let mut guard = MockGuard::new();

    // Mock token endpoint on the same shared mock server.
    guard.mock(
        "POST",
        "/oauth/token",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: MockBody::Json(
                json!({"access_token":"tok-oauth2-test","expires_in":3600,"token_type":"Bearer"}),
            ),
        },
    );

    // Mock upstream API endpoint.
    guard.mock(
        "GET",
        "/api/resource",
        MockResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: MockBody::Json(json!({"status":"ok"})),
        },
    );

    let h = AppHarness::builder()
        .with_credentials(vec![
            ("cred://oauth2-client-id".into(), "test-id".into()),
            ("cred://oauth2-client-secret".into(), "test-secret".into()),
        ])
        .build()
        .await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("oauth2-test")
            .auth(oagw_sdk::AuthConfig {
                plugin_type: OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID.into(),
                sharing: SharingMode::Private,
                config: Some(
                    [
                        (
                            "token_endpoint".into(),
                            format!(
                                "http://127.0.0.1:{}{}",
                                h.mock_port(),
                                guard.path("/oauth/token")
                            ),
                        ),
                        ("client_id_ref".into(), "cred://oauth2-client-id".into()),
                        (
                            "client_secret_ref".into(),
                            "cred://oauth2-client-secret".into(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            })
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: guard.path("/api/resource"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri(format!("/oauth2-test{}", guard.path("/api/resource")))
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx, req).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the upstream received the Bearer token from the OAuth2 flow.
    let recorded = guard.recorded_requests().await;
    let api_request = recorded
        .iter()
        .find(|r| r.uri.contains("/api/resource"))
        .expect("upstream API request not found");
    let auth_header = api_request
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("authorization header missing");
    assert_eq!(auth_header, "Bearer tok-oauth2-test");
}

/// 9.5: OAuth2 CC with missing credentials — credstore returns not found.
#[tokio::test]
async fn proxy_oauth2_missing_credentials_returns_error() {
    let mut guard = MockGuard::new();
    guard.mock(
        "GET",
        "/api/resource",
        MockResponse {
            status: 200,
            headers: vec![],
            body: MockBody::Json(json!({"status":"ok"})),
        },
    );

    // No credentials loaded for the OAuth2 refs.
    let h = AppHarness::builder().build().await;
    let ctx = h.security_context().clone();

    let upstream = h
        .facade()
        .create_upstream(
            ctx.clone(),
            CreateUpstreamRequest::builder(
                Server {
                    endpoints: vec![Endpoint {
                        scheme: Scheme::Http,
                        host: "127.0.0.1".into(),
                        port: h.mock_port(),
                    }],
                },
                "gts.x.core.oagw.protocol.v1~x.core.oagw.http.v1",
            )
            .alias("oauth2-missing-creds")
            .auth(oagw_sdk::AuthConfig {
                plugin_type: OAUTH2_CLIENT_CRED_AUTH_PLUGIN_ID.into(),
                sharing: SharingMode::Private,
                config: Some(
                    [
                        (
                            "token_endpoint".into(),
                            format!(
                                "http://127.0.0.1:{}{}",
                                h.mock_port(),
                                guard.path("/oauth/token")
                            ),
                        ),
                        ("client_id_ref".into(), "cred://missing-id".into()),
                        ("client_secret_ref".into(), "cred://missing-secret".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            })
            .build(),
        )
        .await
        .unwrap();

    h.facade()
        .create_route(
            ctx.clone(),
            CreateRouteRequest::builder(
                upstream.id,
                MatchRules {
                    http: Some(HttpMatch {
                        methods: vec![HttpMethod::Get],
                        path: guard.path("/api/resource"),
                        query_allowlist: vec![],
                        path_suffix_mode: PathSuffixMode::Disabled,
                    }),
                    grpc: None,
                },
            )
            .build(),
        )
        .await
        .unwrap();

    let req = http::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/oauth2-missing-creds{}",
            guard.path("/api/resource")
        ))
        .body(Body::Empty)
        .unwrap();
    let response = h.facade().proxy_request(ctx, req).await;

    // Should fail with a secret-not-found error.
    assert!(response.is_err());
}
