//! Axum handlers + `OperationBuilder` registration for
//! `/api/account-management/v1/tenants`.
//!
//! Each handler:
//!
//! 1. Extracts `Extension(ctx): Extension<SecurityContext>` BEFORE any
//!    service call (FR: `create-tenant-saga.actor-validation`).
//! 2. Converts the request DTO to a domain input (returning a Problem
//!    via `AmError` mapping on validation failure).
//! 3. Calls the matching `TenantService` method.
//! 4. Converts the domain result to a DTO and returns `ApiResult<...>`.
//!
//! The `am_error_to_problem` helper is the authoritative mapping between
//! the `AmError` taxonomy (DESIGN §3.8) and the RFC 9457 `Problem`
//! envelope. The helper is re-used inside `impl From<AmError> for
//! Problem`, which is what enables the `?` operator inside each
//! handler to return a well-formed problem response.
//!
//! The service is injected via `Extension<Arc<S>>` where `S =
//! TenantService<R>`. Production wiring uses the concrete
//! `TenantRepoImpl` together with the `Arc<dyn IdpTenantProvisioner>`
//! resolved from `ClientHub` (or the `NoopProvisioner` fallback); the
//! handler tests swap in the hermetic `FakeTenantRepo` +
//! `FakeIdpProvisioner` from `crate::domain::tenant::test_support`.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::http::{StatusCode, Uri};
use axum::{Json, Router};
use modkit::api::prelude::*;
use modkit::api::{OpenApiRegistry, OperationBuilder};
use modkit_security::SecurityContext;
use opentelemetry::trace::TraceContextExt;
use tracing::{error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::service::TenantService;

use super::models::{
    ChildListQuery, TenantCreateRequest, TenantDto, TenantPageDto, TenantUpdateRequest,
};

pub const API_TAG: &str = "Account Management - Tenants";
pub const BASE_PATH: &str = "/api/account-management/v1/tenants";

/// Extract the W3C trace-id from the current `OpenTelemetry` span
/// context. Returns `None` when no `OTel` span is active (e.g. tests
/// or background tasks started outside a traced request) — the
/// Problem envelope simply omits `trace_id` in that case rather than
/// fabricating an opaque tracing-span id that does not correlate
/// with Jaeger/Tempo. Mirrors `cf-mini-chat`'s `current_otel_trace_id`
/// helper so the platform converges on a single shape.
fn current_otel_trace_id() -> Option<String> {
    let ctx = tracing::Span::current().context();
    let tid = ctx.span().span_context().trace_id();
    (tid != opentelemetry::trace::TraceId::INVALID).then(|| tid.to_string())
}

/// Log a handler error at the level matched to its HTTP status: `error!`
/// for 5xx (server fault — alert-worthy) and `warn!` for 4xx (client
/// fault — useful but not paging-grade). Keeps the `am.rest` target and
/// the `code` field stable across all handlers so dashboards stay
/// uniform.
fn log_handler_error(op: &'static str, err: &AmError) {
    if err.http_status() >= 500 {
        error!(target: "am.rest", op, code = %err.code(), "{op} failed");
    } else {
        warn!(target: "am.rest", op, code = %err.code(), "{op} failed");
    }
}

/// Build a Problem envelope from an `AmError`.
///
/// The DESIGN §3.8 mapping is total over every `AmError` variant — this
/// helper delegates to the stable `http_status()` / `code()`
/// accessors and emits the fine-grained discriminator as the Problem
/// `code` field per the public `OpenAPI` contract. The broad
/// `RFC 9457` category is conveyed by `status` and does not need a
/// separate envelope field.
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-api-problem-envelope
pub fn am_error_to_problem(err: &AmError) -> Problem {
    let status = http::StatusCode::from_u16(err.http_status())
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let code = err.code();
    let detail = am_error_detail(err);

    let trace_id = current_otel_trace_id();

    let mut problem = Problem::new(status, title_for(err), detail)
        .with_type(format!("https://errors.hyperspot.com/am/{code}"))
        .with_code(code);
    if let Some(tid) = trace_id {
        problem = problem.with_trace_id(tid);
    }
    problem
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-api-problem-envelope

/// Allow `?` on `Result<T, AmError>` inside handlers.
impl From<AmError> for Problem {
    fn from(err: AmError) -> Self {
        am_error_to_problem(&err)
    }
}

/// Non-leaky human-readable `detail` per variant. The underlying
/// `Display` impl on `AmError` contains the Phase 1 diagnostic text
/// which is safe to propagate (no tokens, no secrets).
fn am_error_detail(err: &AmError) -> String {
    match err {
        AmError::Internal { .. } => {
            "An internal error occurred; see server logs with the trace id.".to_owned()
        }
        // All other variants already format safely via thiserror.
        _ => err.to_string(),
    }
}

/// Human-readable title for the Problem envelope.
fn title_for(err: &AmError) -> &'static str {
    use crate::domain::error::ErrorCategory;
    match err.category() {
        ErrorCategory::Validation => "Validation failed",
        ErrorCategory::NotFound => "Not found",
        ErrorCategory::Conflict => "Conflict",
        ErrorCategory::CrossTenantDenied => "Cross-tenant access denied",
        ErrorCategory::IdpUnavailable => "IdP unavailable",
        ErrorCategory::IdpUnsupportedOperation => "IdP unsupported operation",
        ErrorCategory::TooManyRequests => "Too many requests",
        ErrorCategory::ServiceUnavailable => "Service unavailable",
        ErrorCategory::Internal => "Internal error",
    }
}

// ======================================================================
// Handlers
// ======================================================================

type ServiceArc<R> = Arc<TenantService<R>>;

/// `POST /api/account-management/v1/tenants` - createTenant.
///
/// # Errors
///
/// Returns a [`Problem`] via `AmError` mapping when the service rejects
/// the payload (validation / conflict / `IdP` failure).
#[tracing::instrument(
    skip_all,
    fields(op = "create_tenant", parent_id = %req.parent_id)
)]
pub async fn create_tenant<R>(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<ServiceArc<R>>,
    uri: Uri,
    Json(req): Json<TenantCreateRequest>,
) -> ApiResult<impl IntoResponse>
where
    R: TenantRepo + 'static,
{
    // Use UUIDv7 (time-ordered) so newly minted tenant IDs sort by
    // creation time. The repo's `list_children` ordering is
    // `(created_at ASC, id ASC)` — UUIDv7 keeps the secondary ordering
    // stable and makes B-tree index inserts append-mostly under load.
    let child_id = Uuid::now_v7();
    let input = req.into_create_child_input(child_id)?;
    match svc.create_child(&ctx, input).await {
        Ok(created) => {
            info!(
                target: "am.rest",
                tenant_id = %created.id,
                parent_id = ?created.parent_id,
                "tenant created"
            );
            let new_id = created.id.to_string();
            let dto: TenantDto = created.into();
            Ok(created_json(dto, &uri, &new_id))
        }
        Err(err) => {
            log_handler_error("create_tenant", &err);
            Err(Problem::from(err))
        }
    }
}

/// `GET /api/account-management/v1/tenants/{tenant_id}` - getTenant.
///
/// # Errors
///
/// Returns a [`Problem`] via `AmError` mapping when the tenant is
/// missing or SDK-invisible.
pub async fn get_tenant<R>(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<ServiceArc<R>>,
    Path(tenant_id): Path<Uuid>,
) -> ApiResult<JsonBody<TenantDto>>
where
    R: TenantRepo,
{
    match svc.read_tenant(&ctx, tenant_id).await {
        Ok(t) => Ok(Json(t.into())),
        Err(err) => {
            log_handler_error("get_tenant", &err);
            Err(Problem::from(err))
        }
    }
}

/// `GET /api/account-management/v1/tenants/{tenant_id}/children` -
/// listChildren.
///
/// # Errors
///
/// Returns a [`Problem`] via `AmError` mapping when the parent is
/// missing or `$top` / `$skip` fall outside the accepted range.
pub async fn list_children<R>(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<ServiceArc<R>>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<ChildListQuery>,
) -> ApiResult<JsonBody<TenantPageDto>>
where
    R: TenantRepo,
{
    // Clamp $top to the operator-configured cap BEFORE the service
    // call. Honours `cfg.max_list_children_top` so tightening the cap
    // via config takes effect immediately; the handler used to
    // hardcode 200 which silently ignored that knob.
    let domain_query = query.into_domain_query(tenant_id, svc.max_list_children_top())?;
    match svc.list_children(&ctx, domain_query).await {
        Ok(page) => Ok(Json(page.into())),
        Err(err) => {
            log_handler_error("list_children", &err);
            Err(Problem::from(err))
        }
    }
}

/// `DELETE /api/account-management/v1/tenants/{tenant_id}` - `deleteTenant`.
///
/// Soft-delete entry-point. The cleanup sweep picks the row up after
/// the retention window elapses.
///
/// # Errors
///
/// Returns a [`Problem`] via `AmError` mapping when the tenant is root,
/// missing / SDK-invisible, still has children, or still owns resources.
#[tracing::instrument(
    skip_all,
    fields(op = "delete_tenant", tenant_id = %tenant_id)
)]
pub async fn delete_tenant<R>(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<ServiceArc<R>>,
    Path(tenant_id): Path<Uuid>,
) -> ApiResult<JsonBody<TenantDto>>
where
    R: TenantRepo,
{
    match svc.soft_delete(&ctx, tenant_id).await {
        Ok(t) => Ok(Json(t.into())),
        Err(err) => {
            log_handler_error("delete_tenant", &err);
            Err(Problem::from(err))
        }
    }
}

/// `PATCH /api/account-management/v1/tenants/{tenant_id}` - updateTenant.
///
/// # Errors
///
/// Returns a [`Problem`] via `AmError` mapping when the patch is empty,
/// the name is out of range, the status transition is unsupported, or
/// the tenant is missing / SDK-invisible.
pub async fn update_tenant<R>(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<ServiceArc<R>>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<TenantUpdateRequest>,
) -> ApiResult<JsonBody<TenantDto>>
where
    R: TenantRepo,
{
    let patch = req.into_domain_patch()?;
    match svc.update_tenant(&ctx, tenant_id, patch).await {
        Ok(updated) => Ok(Json(updated.into())),
        Err(err) => {
            log_handler_error("update_tenant", &err);
            Err(Problem::from(err))
        }
    }
}

// ======================================================================
// register_routes
// ======================================================================

/// Register the four `tenants` routes and attach the service extension.
pub fn register_routes<R>(
    mut router: Router,
    openapi: &dyn OpenApiRegistry,
    service: ServiceArc<R>,
) -> Router
where
    R: TenantRepo + 'static,
{
    // POST /tenants
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-route-surface
    router = OperationBuilder::post(BASE_PATH)
        .operation_id("createTenant")
        .summary("Create a child tenant")
        .description("Run the create-tenant saga: reserve `provisioning`, call the IdP provisioner, activate and write closure rows.")
        .tag(API_TAG)
        .authenticated()
        .required_scope("am.tenants.write")
        .json_request::<TenantCreateRequest>(openapi, "Tenant creation payload")
        .handler(create_tenant::<R>)
        .json_response_with_schema::<TenantDto>(openapi, StatusCode::CREATED, "Tenant created")
        .standard_errors(openapi)
        .register(router, openapi);
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-create-child-tenant:p1:inst-flow-create-route-surface

    // GET /tenants/{tenant_id}
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-read-tenant:p1:inst-flow-read-route-surface
    router = OperationBuilder::get(format!("{BASE_PATH}/{{tenant_id}}"))
        .operation_id("getTenant")
        .summary("Read tenant details")
        .description("Fetch an SDK-visible tenant by id. Provisioning rows are not surfaced.")
        .tag(API_TAG)
        .authenticated()
        .required_scope("am.tenants.read")
        .path_param("tenant_id", "Tenant UUID")
        .handler(get_tenant::<R>)
        .json_response_with_schema::<TenantDto>(openapi, StatusCode::OK, "Tenant details")
        .standard_errors(openapi)
        .register(router, openapi);
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-read-tenant:p1:inst-flow-read-route-surface

    // GET /tenants/{tenant_id}/children
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-list-children:p1:inst-flow-list-route-surface
    router = OperationBuilder::get(format!("{BASE_PATH}/{{tenant_id}}/children"))
        .operation_id("listChildren")
        .summary("List direct children of a tenant")
        .description("Paginated list of direct children, filterable by status. Matches OpenAPI $top/$skip semantics.")
        .tag(API_TAG)
        .authenticated()
        .required_scope("am.tenants.read")
        .path_param("tenant_id", "Parent tenant UUID")
        .query_param("$top", false, "Page size (1..=200, default 50)")
        .query_param("$skip", false, "Skip count (default 0)")
        .query_param("status", false, "Comma-separated status filter (active|suspended|deleted)")
        .handler(list_children::<R>)
        .json_response_with_schema::<TenantPageDto>(openapi, StatusCode::OK, "Page of direct children")
        .standard_errors(openapi)
        .register(router, openapi);
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-list-children:p1:inst-flow-list-route-surface

    // PATCH /tenants/{tenant_id}
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-update-tenant:p1:inst-flow-update-route-surface
    router = OperationBuilder::patch(format!("{BASE_PATH}/{{tenant_id}}"))
        .operation_id("updateTenant")
        .summary("Update mutable tenant fields")
        .description(
            "PATCH `name` and/or `status`. Empty patches and immutable fields are rejected.",
        )
        .tag(API_TAG)
        .authenticated()
        .required_scope("am.tenants.write")
        .path_param("tenant_id", "Tenant UUID")
        .json_request::<TenantUpdateRequest>(openapi, "Tenant update payload")
        .handler(update_tenant::<R>)
        .json_response_with_schema::<TenantDto>(openapi, StatusCode::OK, "Updated tenant")
        .standard_errors(openapi)
        .register(router, openapi);
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-update-tenant:p1:inst-flow-update-route-surface

    // DELETE /tenants/{tenant_id}
    // @cpt-begin:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-delete-route-surface
    router = OperationBuilder::delete(format!("{BASE_PATH}/{{tenant_id}}"))
        .operation_id("deleteTenant")
        .summary("Soft-delete a tenant")
        .description(
            "Mark the tenant as deleted and schedule hard-delete after the retention window. Rejects root / has-children / has-resources.",
        )
        .tag(API_TAG)
        .authenticated()
        .required_scope("am.tenants.write")
        .path_param("tenant_id", "Tenant UUID")
        .handler(delete_tenant::<R>)
        .json_response_with_schema::<TenantDto>(openapi, StatusCode::OK, "Soft-deleted tenant")
        .standard_errors(openapi)
        .register(router, openapi);
    // @cpt-end:cpt-cf-account-management-flow-tenant-hierarchy-management-soft-delete-tenant:p1:inst-flow-delete-route-surface

    // Attach service extension once after all routes are registered.
    router.layer(Extension(service))
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::domain::error::AmError;
    use crate::domain::tenant::model::TenantStatus;
    use crate::domain::tenant::test_support::{
        FakeOutcome, FakeService, FakeTenantRepo, make_service,
    };
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode as AxumStatus};
    use modkit::api::openapi_registry::{OpenApiInfo, OpenApiRegistryImpl};
    use modkit_security::SecurityContext;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn ctx() -> SecurityContext {
        // Default test ctx — caller is the platform admin (home tenant
        // id == the root id used by `FakeTenantRepo::with_root`).
        SecurityContext::builder()
            .subject_id(Uuid::from_u128(0xDEAD))
            .subject_tenant_id(Uuid::from_u128(0x100))
            .build()
            .expect("ctx")
    }

    fn ctx_for_tenant(tenant_id: Uuid) -> SecurityContext {
        SecurityContext::builder()
            .subject_id(Uuid::from_u128(0xDEAD))
            .subject_tenant_id(tenant_id)
            .build()
            .expect("ctx")
    }

    fn service(outcome: FakeOutcome) -> (Arc<FakeService>, Arc<FakeTenantRepo>, Uuid) {
        let root = Uuid::from_u128(0x100);
        let repo = Arc::new(FakeTenantRepo::with_root(root));
        let svc = make_service(repo.clone(), outcome);
        (svc, repo, root)
    }

    /// Build a router with the ctx extension pre-baked so tests don't
    /// have to inject it through middleware.
    fn test_router(svc: Arc<FakeService>) -> Router {
        let openapi = OpenApiRegistryImpl::new();
        let router = Router::new();
        let router = register_routes::<FakeTenantRepo>(router, &openapi, svc);
        router.layer(Extension(ctx()))
    }

    #[test]
    fn route_registration_matches_openapi_operation_ids_and_scopes() {
        let (svc, _repo, _root) = service(FakeOutcome::Ok);
        let openapi = OpenApiRegistryImpl::new();
        let router = Router::new();
        let _router = register_routes::<FakeTenantRepo>(router, &openapi, svc);

        #[allow(
            clippy::type_complexity,
            reason = "test-only assertion shape: keyed by (Method, path) with (operation_id, scopes) value; introducing a type alias for one local would just hide the assertion contract"
        )]
        let specs: HashMap<(Method, String), (String, Vec<String>)> = openapi
            .operation_specs
            .iter()
            .map(|entry| {
                let spec = entry.value();
                (
                    (spec.method.clone(), spec.path.clone()),
                    (
                        spec.operation_id.clone().expect("operation_id"),
                        spec.required_scopes.clone(),
                    ),
                )
            })
            .collect();

        let expected = [
            (
                Method::POST,
                BASE_PATH.to_owned(),
                "createTenant",
                vec!["am.tenants.write".to_owned()],
            ),
            (
                Method::GET,
                format!("{BASE_PATH}/{{tenant_id}}"),
                "getTenant",
                vec!["am.tenants.read".to_owned()],
            ),
            (
                Method::GET,
                format!("{BASE_PATH}/{{tenant_id}}/children"),
                "listChildren",
                vec!["am.tenants.read".to_owned()],
            ),
            (
                Method::PATCH,
                format!("{BASE_PATH}/{{tenant_id}}"),
                "updateTenant",
                vec!["am.tenants.write".to_owned()],
            ),
            (
                Method::DELETE,
                format!("{BASE_PATH}/{{tenant_id}}"),
                "deleteTenant",
                vec!["am.tenants.write".to_owned()],
            ),
        ];

        for (method, path, operation_id, scopes) in expected {
            let Some((actual_id, actual_scopes)) = specs.get(&(method.clone(), path.clone()))
            else {
                panic!("missing route spec for {method} {path}");
            };
            assert_eq!(actual_id, operation_id);
            assert_eq!(actual_scopes, &scopes);
        }
    }

    #[test]
    fn generated_openapi_security_scopes_match_route_contract() {
        let (svc, _repo, _root) = service(FakeOutcome::Ok);
        let openapi = OpenApiRegistryImpl::new();
        let router = Router::new();
        let _router = register_routes::<FakeTenantRepo>(router, &openapi, svc);
        let doc = openapi
            .build_openapi(&OpenApiInfo::default())
            .expect("openapi");
        let json = serde_json::to_value(doc).expect("json");

        let cases = [
            (
                "/api/account-management/v1/tenants",
                "post",
                "am.tenants.write",
            ),
            (
                "/api/account-management/v1/tenants/{tenant_id}",
                "get",
                "am.tenants.read",
            ),
            (
                "/api/account-management/v1/tenants/{tenant_id}/children",
                "get",
                "am.tenants.read",
            ),
            (
                "/api/account-management/v1/tenants/{tenant_id}",
                "patch",
                "am.tenants.write",
            ),
            (
                "/api/account-management/v1/tenants/{tenant_id}",
                "delete",
                "am.tenants.write",
            ),
        ];

        for (path, method, scope) in cases {
            let actual_scope = json
                .pointer(&format!(
                    "/paths/{}/{method}/security/0/bearerAuth/0",
                    path.replace('/', "~1")
                ))
                .and_then(serde_json::Value::as_str);
            assert_eq!(actual_scope, Some(scope), "{method} {path}");
        }
    }

    async fn read_body(body: Body) -> serde_json::Value {
        let bytes = to_bytes(body, 1024 * 64).await.expect("body bytes");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // ------------------- Handler happy + error paths -------------------

    #[tokio::test]
    async fn create_tenant_happy_path_returns_201_and_tenant_body() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let body = serde_json::json!({
            "name": "child",
            "parent_id": root.to_string(),
            "tenant_type": Uuid::from_u128(0xAA).to_string(),
        });
        let resp = router
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), AxumStatus::CREATED);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["parent_id"], root.to_string());
        assert_eq!(payload["status"], "active");
        assert_eq!(payload["name"], "child");
    }

    #[tokio::test]
    async fn get_tenant_happy_path_returns_200_and_tenant_body() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let resp = router
            .oneshot(
                Request::get(format!("/api/account-management/v1/tenants/{root}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), AxumStatus::OK);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["id"], root.to_string());
        assert_eq!(payload["status"], "active");
    }

    #[tokio::test]
    async fn list_children_happy_path_returns_200_and_page() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        // Create one child so the page is non-empty.
        let child_body = serde_json::json!({
            "name": "c",
            "parent_id": root.to_string(),
            "tenant_type": Uuid::from_u128(0xAA).to_string(),
        });
        let router = test_router(svc.clone());
        let create = router
            .clone()
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(child_body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("create");
        assert_eq!(create.status(), AxumStatus::CREATED);

        let resp = router
            .oneshot(
                Request::get(format!(
                    "/api/account-management/v1/tenants/{root}/children?$top=10"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .expect("list");
        assert_eq!(resp.status(), AxumStatus::OK);
        let payload = read_body(resp.into_body()).await;
        assert!(payload["items"].is_array());
        assert_eq!(payload["items"].as_array().unwrap().len(), 1);
        assert_eq!(payload["page_info"]["top"], 10);
    }

    #[tokio::test]
    async fn update_tenant_happy_path_returns_200_and_tenant_body() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let body = serde_json::json!({ "name": "renamed" });
        let resp = router
            .oneshot(
                Request::patch(format!("/api/account-management/v1/tenants/{root}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("patch");
        assert_eq!(resp.status(), AxumStatus::OK);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["name"], "renamed");
    }

    #[tokio::test]
    async fn create_tenant_maps_idp_unavailable_to_503_idp_unavailable() {
        let (svc, _repo, root) = service(FakeOutcome::CleanFailure);
        let router = test_router(svc);
        let body = serde_json::json!({
            "name": "child",
            "parent_id": root.to_string(),
            "tenant_type": Uuid::from_u128(0xAA).to_string(),
        });
        let resp = router
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("create");
        assert_eq!(resp.status(), AxumStatus::SERVICE_UNAVAILABLE);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "idp_unavailable");
    }

    #[test]
    fn problem_serializes_code_as_top_level_field() {
        let err = AmError::SerializationConflict {
            detail: "retry budget exhausted".into(),
        };
        let problem = am_error_to_problem(&err);
        let encoded = serde_json::to_value(&problem).expect("problem json");

        assert_eq!(encoded["code"], "serialization_conflict");
        assert!(
            encoded.get("context").is_none(),
            "code must not be nested under context: {encoded}"
        );
    }

    #[tokio::test]
    async fn create_tenant_maps_idp_unsupported_operation_to_501() {
        let (svc, _repo, root) = service(FakeOutcome::Unsupported);
        let router = test_router(svc);
        let body = serde_json::json!({
            "name": "child",
            "parent_id": root.to_string(),
            "tenant_type": Uuid::from_u128(0xAA).to_string(),
        });
        let resp = router
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("create");
        assert_eq!(resp.status(), AxumStatus::NOT_IMPLEMENTED);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "idp_unsupported_operation");
    }

    #[tokio::test]
    async fn update_tenant_maps_validation_to_422_validation() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        // Empty patch — DTO rejects.
        let body = serde_json::json!({});
        let resp = router
            .oneshot(
                Request::patch(format!("/api/account-management/v1/tenants/{root}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("patch");
        assert_eq!(resp.status(), AxumStatus::UNPROCESSABLE_ENTITY);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "validation");
    }

    #[tokio::test]
    async fn get_tenant_not_found_maps_to_404_not_found() {
        let (svc, _repo, _root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let missing = Uuid::from_u128(0xDEAD);
        let resp = router
            .oneshot(
                Request::get(format!("/api/account-management/v1/tenants/{missing}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("get");
        assert_eq!(resp.status(), AxumStatus::NOT_FOUND);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "not_found");
    }

    #[tokio::test]
    async fn create_tenant_maps_tenant_depth_exceeded_to_409() {
        // The Phase-1 service doesn't strict-reject on depth (advisory only).
        // To exercise the mapping we call am_error_to_problem directly.
        let err = AmError::TenantDepthExceeded {
            detail: "too deep".into(),
        };
        let problem = am_error_to_problem(&err);
        assert_eq!(problem.status, http::StatusCode::CONFLICT);
        assert_eq!(problem.code, "tenant_depth_exceeded");
    }

    /// AM does NOT own the 401 path — gateway middleware is responsible
    /// for authentication. At the handler level, what we CAN verify is
    /// that the `SecurityContext` is successfully extracted BEFORE the
    /// service is invoked (FR:
    /// `create-tenant-saga.actor-validation`). This test mirrors that
    /// contract: with the ctx extension absent, axum's
    /// `Extension<SecurityContext>` extractor short-circuits the
    /// request before the handler can reach the service. A missing-ctx
    /// case end-to-end (with proper 401 response shaping) is exercised
    /// by the axum gateway tests — reproducing it here would conflate
    /// concerns. The 401 response itself is gateway-owned, not handler-
    /// owned, so we only assert that the response is not a 2xx.
    #[tokio::test]
    async fn handler_does_not_invoke_service_without_ctx() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let openapi = OpenApiRegistryImpl::new();
        let router = Router::new();
        let router = register_routes::<FakeTenantRepo>(router, &openapi, svc);
        let resp = router
            .oneshot(
                Request::get(format!("/api/account-management/v1/tenants/{root}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        // Without the ctx extension, axum's Extension<SecurityContext>
        // extractor fails the request before the handler runs — the
        // exact status is implementation-defined by the extractor but
        // MUST NOT be 2xx. This is the best "forwards-only-with-ctx"
        // assertion we can make at the unit-test level. The proper 401
        // response shaping is owned by the gateway middleware, which is
        // why we do not assert any specific status code here.
        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn am_error_mapping_is_total_over_variants() {
        let cases: &[(AmError, http::StatusCode, &str)] = &[
            (
                AmError::Validation { detail: "x".into() },
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "validation",
            ),
            (
                AmError::InvalidTenantType { detail: "x".into() },
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_tenant_type",
            ),
            (
                AmError::RootTenantCannotDelete,
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "root_tenant_cannot_delete",
            ),
            (
                AmError::RootTenantCannotConvert,
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "root_tenant_cannot_convert",
            ),
            (
                AmError::NotFound { detail: "x".into() },
                http::StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                AmError::MetadataSchemaNotRegistered { detail: "x".into() },
                http::StatusCode::NOT_FOUND,
                "metadata_schema_not_registered",
            ),
            (
                AmError::MetadataEntryNotFound { detail: "x".into() },
                http::StatusCode::NOT_FOUND,
                "metadata_entry_not_found",
            ),
            (
                AmError::TypeNotAllowed { detail: "x".into() },
                http::StatusCode::CONFLICT,
                "type_not_allowed",
            ),
            (
                AmError::TenantDepthExceeded { detail: "x".into() },
                http::StatusCode::CONFLICT,
                "tenant_depth_exceeded",
            ),
            (
                AmError::TenantHasChildren,
                http::StatusCode::CONFLICT,
                "tenant_has_children",
            ),
            (
                AmError::TenantHasResources,
                http::StatusCode::CONFLICT,
                "tenant_has_resources",
            ),
            (
                AmError::PendingExists {
                    request_id: "r".into(),
                },
                http::StatusCode::CONFLICT,
                "pending_exists",
            ),
            (
                AmError::InvalidActorForTransition {
                    attempted_status: "a".into(),
                    caller_side: "b".into(),
                },
                http::StatusCode::CONFLICT,
                "invalid_actor_for_transition",
            ),
            (
                AmError::AlreadyResolved,
                http::StatusCode::CONFLICT,
                "already_resolved",
            ),
            (
                AmError::Conflict { detail: "x".into() },
                http::StatusCode::CONFLICT,
                "conflict",
            ),
            (
                AmError::CrossTenantDenied,
                http::StatusCode::FORBIDDEN,
                "cross_tenant_denied",
            ),
            (
                AmError::IdpUnavailable { detail: "x".into() },
                http::StatusCode::SERVICE_UNAVAILABLE,
                "idp_unavailable",
            ),
            (
                AmError::IdpUnsupportedOperation { detail: "x".into() },
                http::StatusCode::NOT_IMPLEMENTED,
                "idp_unsupported_operation",
            ),
            (
                AmError::ServiceUnavailable { detail: "x".into() },
                http::StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
            ),
            (
                AmError::Internal {
                    diagnostic: "x".into(),
                },
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
            ),
            (
                AmError::AuditAlreadyRunning {
                    scope: "whole".into(),
                },
                http::StatusCode::TOO_MANY_REQUESTS,
                "audit_already_running",
            ),
            (
                AmError::AuditAlreadyRunning {
                    scope: "subtree:00000000-0000-0000-0000-000000000001".into(),
                },
                http::StatusCode::TOO_MANY_REQUESTS,
                "audit_already_running",
            ),
        ];
        for (err, status, code) in cases {
            let p = am_error_to_problem(err);
            assert_eq!(p.status, *status, "variant {err:?}");
            assert_eq!(p.code, *code, "variant {err:?}");
            assert!(p.context.is_none(), "variant {err:?}");
        }
    }

    #[tokio::test]
    async fn internal_error_detail_is_non_leaky() {
        let err = AmError::Internal {
            diagnostic: "SECRET-DSN=postgres://user:pw@host/db".into(),
        };
        let problem = am_error_to_problem(&err);
        assert!(!problem.detail.contains("SECRET-DSN"));
        assert_eq!(problem.status, http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn create_tenant_invalid_tenant_type_uuid_is_422_validation() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let body = serde_json::json!({
            "name": "child",
            "parent_id": root.to_string(),
            "tenant_type": "not-a-uuid",
        });
        let resp = router
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("create");
        assert_eq!(resp.status(), AxumStatus::UNPROCESSABLE_ENTITY);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "validation");
    }

    // --------------- Phase 3 handler tests -----------------

    #[tokio::test]
    async fn delete_tenant_happy_path_returns_200() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        // Create a child first.
        let child_body = serde_json::json!({
            "name": "child",
            "parent_id": root.to_string(),
            "tenant_type": Uuid::from_u128(0xAA).to_string(),
        });
        let create = router
            .clone()
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(child_body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("create");
        assert_eq!(create.status(), AxumStatus::CREATED);
        let created_body = read_body(create.into_body()).await;
        let child_id = created_body["id"].as_str().expect("id").to_owned();

        let resp = router
            .oneshot(
                Request::delete(format!("/api/account-management/v1/tenants/{child_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("delete");
        assert_eq!(resp.status(), AxumStatus::OK);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["status"], "deleted");
        assert_eq!(payload["id"], child_id);
    }

    #[tokio::test]
    async fn delete_tenant_root_returns_422_root_tenant_cannot_delete() {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        let resp = router
            .oneshot(
                Request::delete(format!("/api/account-management/v1/tenants/{root}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("delete");
        assert_eq!(resp.status(), AxumStatus::UNPROCESSABLE_ENTITY);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "root_tenant_cannot_delete");
    }

    #[tokio::test]
    async fn update_tenant_status_active_after_suspended_returns_200() {
        // Suspend first, then unsuspend. Proves two round-trips survive
        // the status denorm invariant (the fake mirrors the repo). The
        // status discriminant uses the same `serde(rename_all =
        // "snake_case")` shape as `TenantStatus`, which is why the body
        // JSON literal mirrors the enum variant name.
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let router = test_router(svc);
        // Sanity: keep the `TenantStatus` import live by binding the
        // variant we are exercising via the JSON wire form below.
        let target = TenantStatus::Suspended;
        assert_eq!(target.as_smallint(), 2);

        let suspend = router
            .clone()
            .oneshot(
                Request::patch(format!("/api/account-management/v1/tenants/{root}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "status": "suspended" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("suspend");
        assert_eq!(suspend.status(), AxumStatus::OK);
        let suspended_body = read_body(suspend.into_body()).await;
        assert_eq!(suspended_body["status"], "suspended");
        assert_eq!(suspended_body["id"], root.to_string());

        let activate = router
            .oneshot(
                Request::patch(format!("/api/account-management/v1/tenants/{root}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "status": "active" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("activate");
        assert_eq!(activate.status(), AxumStatus::OK);
        let active_body = read_body(activate.into_body()).await;
        assert_eq!(active_body["status"], "active");
    }

    // ----------- Cross-tenant authorization (IDOR) tests -----------

    /// Build a router whose `Extension<SecurityContext>` is a
    /// non-admin caller (home tenant != root). Used by the cross-tenant
    /// denial tests to drive the service into the rejection branch.
    fn router_with_caller(svc: Arc<FakeService>, caller_tenant: Uuid) -> Router {
        let openapi = OpenApiRegistryImpl::new();
        let router = Router::new();
        let router = register_routes::<FakeTenantRepo>(router, &openapi, svc);
        router.layer(Extension(ctx_for_tenant(caller_tenant)))
    }

    /// Set up: root, `child_a` (under root), stranger (under root, sibling
    /// of `child_a`). Caller-B owns `stranger`; calls into `child_a` MUST
    /// be denied.
    async fn two_tenant_setup() -> (Uuid, Uuid, Uuid, Arc<FakeService>) {
        let (svc, _repo, root) = service(FakeOutcome::Ok);
        let admin_router = test_router(svc.clone());
        let mk = |id: Uuid, parent: Uuid| {
            serde_json::json!({
                "name": format!("t-{id}"),
                "parent_id": parent.to_string(),
                "tenant_type": Uuid::from_u128(0xAA).to_string(),
            })
            .to_string()
        };
        let child_a = Uuid::from_u128(0x200);
        let stranger = Uuid::from_u128(0x300);
        // Provision both tenants via the admin router so the closure
        // rows are written by the saga.
        let resp_a = admin_router
            .clone()
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(mk(child_a, root)))
                    .unwrap(),
            )
            .await
            .expect("create a");
        assert_eq!(resp_a.status(), AxumStatus::CREATED);
        // Read back the assigned id; the handler picks a fresh UUID.
        let body_a = read_body(resp_a.into_body()).await;
        let real_a: Uuid = body_a["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("uuid a");
        let resp_b = admin_router
            .oneshot(
                Request::post("/api/account-management/v1/tenants")
                    .header("content-type", "application/json")
                    .body(Body::from(mk(stranger, root)))
                    .unwrap(),
            )
            .await
            .expect("create b");
        assert_eq!(resp_b.status(), AxumStatus::CREATED);
        let body_b = read_body(resp_b.into_body()).await;
        let real_b: Uuid = body_b["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("uuid b");
        (root, real_a, real_b, svc)
    }

    #[tokio::test]
    async fn get_tenant_cross_tenant_returns_403_cross_tenant_denied() {
        let (_root, child_a, stranger, svc) = two_tenant_setup().await;
        let router = router_with_caller(svc, stranger);
        let resp = router
            .oneshot(
                Request::get(format!("/api/account-management/v1/tenants/{child_a}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("get");
        assert_eq!(resp.status(), AxumStatus::FORBIDDEN);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "cross_tenant_denied");
    }

    #[tokio::test]
    async fn delete_tenant_cross_tenant_returns_403_cross_tenant_denied() {
        let (_root, child_a, stranger, svc) = two_tenant_setup().await;
        let router = router_with_caller(svc, stranger);
        let resp = router
            .oneshot(
                Request::delete(format!("/api/account-management/v1/tenants/{child_a}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("delete");
        assert_eq!(resp.status(), AxumStatus::FORBIDDEN);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "cross_tenant_denied");
    }

    #[tokio::test]
    async fn update_tenant_cross_tenant_returns_403_cross_tenant_denied() {
        // Handler-level pin for the IDOR fix on PATCH. Domain tests
        // cover the same path, but the handler is the first safety
        // net at the request boundary — a regression here would let
        // a cross-tenant PATCH reach the service before the gate.
        let (_root, child_a, stranger, svc) = two_tenant_setup().await;
        let router = router_with_caller(svc, stranger);
        let body = serde_json::json!({ "name": "renamed" }).to_string();
        let resp = router
            .oneshot(
                Request::patch(format!("/api/account-management/v1/tenants/{child_a}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .expect("patch");
        assert_eq!(resp.status(), AxumStatus::FORBIDDEN);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "cross_tenant_denied");
    }

    #[tokio::test]
    async fn list_children_cross_tenant_returns_403_cross_tenant_denied() {
        // Handler-level pin for the IDOR fix on listChildren. A non-
        // admin caller asking for the children of a sibling tenant
        // must be rejected at the gate, not silently return the
        // sibling's child set.
        let (_root, child_a, stranger, svc) = two_tenant_setup().await;
        let router = router_with_caller(svc, stranger);
        let resp = router
            .oneshot(
                Request::get(format!(
                    "/api/account-management/v1/tenants/{child_a}/children"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .expect("list");
        assert_eq!(resp.status(), AxumStatus::FORBIDDEN);
        let payload = read_body(resp.into_body()).await;
        assert_eq!(payload["code"], "cross_tenant_denied");
    }
}
