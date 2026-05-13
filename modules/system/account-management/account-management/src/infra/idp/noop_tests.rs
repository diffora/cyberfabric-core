use super::*;
use account_management_sdk::{
    DeprovisionFailure, DeprovisionTenantRequest, DeprovisionUserRequest, ListUsersRequest,
    NewUser, ProvisionFailure, ProvisionTenantRequest, ProvisionUserRequest, TenantContext,
    UserOperationFailure, UserPagination,
};
use uuid::Uuid;

fn sample_tenant_context() -> TenantContext {
    TenantContext::new(
        Uuid::nil(),
        "t",
        gts::GtsSchemaId::new("gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~"),
        None,
    )
}

#[tokio::test]
async fn noop_provider_reports_unsupported_operation_on_provision_tenant() {
    let p = NoopIdpProvider;
    let req = ProvisionTenantRequest::for_root(
        Uuid::nil(),
        "t",
        gts::GtsSchemaId::new("gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~"),
    );
    let err = p.provision_tenant(&req).await.expect_err("noop must err");
    assert!(matches!(err, ProvisionFailure::UnsupportedOperation { .. }));
}

#[tokio::test]
async fn noop_provider_availability_reports_unreachable() {
    let p = NoopIdpProvider;
    let err = p
        .check_availability()
        .await
        .expect_err("noop must be unavailable");
    assert!(matches!(err, CheckAvailabilityFailure::Unreachable { .. }));
}

#[tokio::test]
async fn noop_provider_deprovision_tenant_reports_unsupported_operation() {
    let p = NoopIdpProvider;
    let req = DeprovisionTenantRequest::new(sample_tenant_context());
    let err = p.deprovision_tenant(&req).await.expect_err("noop must err");
    assert!(matches!(
        err,
        DeprovisionFailure::UnsupportedOperation { .. }
    ));
}

#[tokio::test]
async fn noop_provider_provision_user_reports_unsupported_operation() {
    let p = NoopIdpProvider;
    let req = ProvisionUserRequest::new(sample_tenant_context(), NewUser::new("alice"));
    let err = p.provision_user(&req).await.expect_err("noop must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
    ));
}

#[tokio::test]
async fn noop_provider_deprovision_user_reports_unsupported_operation() {
    let p = NoopIdpProvider;
    let req = DeprovisionUserRequest::new(sample_tenant_context(), Uuid::nil());
    let err = p.deprovision_user(&req).await.expect_err("noop must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
    ));
}

#[tokio::test]
async fn noop_provider_list_users_reports_unsupported_operation() {
    let p = NoopIdpProvider;
    let req = ListUsersRequest::new(sample_tenant_context(), UserPagination::default());
    let err = p.list_users(&req).await.expect_err("noop must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
    ));
}
