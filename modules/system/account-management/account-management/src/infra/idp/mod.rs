//! Infrastructure-layer glue for the optional
//! [`account_management_sdk::IdpTenantProvisionerClient`] and
//! [`account_management_sdk::IdpUserProvisionerClient`] plugins.
//!
//! AM can boot without an `IdP` adapter present — dev deployments and
//! tests do not need one. The services store the provisioner as
//! `Arc<dyn IdpTenantProvisionerClient>` /
//! `Arc<dyn IdpUserProvisionerClient>` directly; this module
//! contributes the [`NoopProvisioner`] and [`NoopUserProvisioner`]
//! fallbacks wired in when no plugin resolves from `ClientHub`.
//!
//! Each fallback returns the `UnsupportedOperation` / `Unreachable`
//! variants for every method so a deployment without an `IdP` plugin
//! keeps booting and surfaces a consistent error envelope at the call
//! site.

use account_management_sdk::{
    CheckAvailabilityFailure, CreateUserRequest, DeleteUserOutcome, DeleteUserRequest,
    DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient, IdpUserProvisionerClient,
    ListUsersRequest, ProvisionFailure, ProvisionRequest, ProvisionResult, UserOperationFailure,
    UserPage, UserProjection,
};
use async_trait::async_trait;

/// No-op provisioner: returns [`ProvisionFailure::UnsupportedOperation`]
/// for every request. Used when AM boots without an `IdP` plugin.
#[derive(Debug, Default, Clone)]
pub struct NoopProvisioner;

#[async_trait]
impl IdpTenantProvisionerClient for NoopProvisioner {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        Err(CheckAvailabilityFailure::Unreachable(
            "no IdP provisioner plugin is registered in this deployment".into(),
        ))
    }

    async fn provision_tenant(
        &self,
        _req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure> {
        Err(ProvisionFailure::UnsupportedOperation {
            detail: "no IdP provisioner plugin is registered in this deployment".into(),
        })
    }

    async fn deprovision_tenant(
        &self,
        _req: &DeprovisionRequest,
    ) -> Result<(), DeprovisionFailure> {
        Err(DeprovisionFailure::UnsupportedOperation {
            detail: "no IdP provisioner plugin is registered in this deployment".into(),
        })
    }
}

/// No-op user provisioner: returns
/// [`UserOperationFailure::UnsupportedOperation`] for every request.
/// Used when AM boots without an `IdP` user-operations plugin (dev /
/// test deployments) so downstream callers see a consistent error
/// envelope rather than a runtime panic on plugin lookup.
#[derive(Debug, Default, Clone)]
pub struct NoopUserProvisioner;

#[async_trait]
impl IdpUserProvisionerClient for NoopUserProvisioner {
    async fn create_user(
        &self,
        _req: &CreateUserRequest,
    ) -> Result<UserProjection, UserOperationFailure> {
        Err(UserOperationFailure::UnsupportedOperation {
            detail: "no IdP user-operations plugin is registered in this deployment".into(),
        })
    }

    async fn delete_user(
        &self,
        _req: &DeleteUserRequest,
    ) -> Result<DeleteUserOutcome, UserOperationFailure> {
        Err(UserOperationFailure::UnsupportedOperation {
            detail: "no IdP user-operations plugin is registered in this deployment".into(),
        })
    }

    async fn list_users(&self, _req: &ListUsersRequest) -> Result<UserPage, UserOperationFailure> {
        Err(UserOperationFailure::UnsupportedOperation {
            detail: "no IdP user-operations plugin is registered in this deployment".into(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use account_management_sdk::{NewUserPayload, TenantContext, UserPagination};
    use uuid::Uuid;

    #[tokio::test]
    async fn noop_provisioner_reports_unsupported_operation() {
        let p = NoopProvisioner;
        let req = ProvisionRequest {
            tenant_id: Uuid::nil(),
            parent_id: None,
            name: "t".into(),
            tenant_type: gts::GtsSchemaId::new(
                "gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~",
            ),
            metadata: None,
        };
        let err = p.provision_tenant(&req).await.expect_err("noop must err");
        assert!(matches!(err, ProvisionFailure::UnsupportedOperation { .. }));
    }

    #[tokio::test]
    async fn noop_provisioner_availability_reports_unreachable() {
        let p = NoopProvisioner;
        let err = p
            .check_availability()
            .await
            .expect_err("noop must be unavailable");
        assert!(matches!(err, CheckAvailabilityFailure::Unreachable(_)));
    }

    #[tokio::test]
    async fn noop_provisioner_deprovision_reports_unsupported_operation() {
        let p = NoopProvisioner;
        let req = DeprovisionRequest {
            tenant_id: Uuid::nil(),
        };
        let err = p.deprovision_tenant(&req).await.expect_err("noop must err");
        assert!(matches!(
            err,
            DeprovisionFailure::UnsupportedOperation { .. }
        ));
    }

    #[tokio::test]
    async fn noop_user_provisioner_create_reports_unsupported_operation() {
        let p = NoopUserProvisioner;
        let req = CreateUserRequest {
            tenant_id: Uuid::nil(),
            tenant_context: TenantContext::new(Uuid::nil(), "t"),
            payload: NewUserPayload {
                username: "alice".into(),
                email: None,
                display_name: None,
                avatar_url: None,
                attributes: None,
            },
        };
        let err = p.create_user(&req).await.expect_err("noop must err");
        assert!(matches!(
            err,
            UserOperationFailure::UnsupportedOperation { .. }
        ));
    }

    #[tokio::test]
    async fn noop_user_provisioner_delete_reports_unsupported_operation() {
        let p = NoopUserProvisioner;
        let req = DeleteUserRequest {
            tenant_id: Uuid::nil(),
            tenant_context: TenantContext::new(Uuid::nil(), "t"),
            user_id: Uuid::nil(),
        };
        let err = p.delete_user(&req).await.expect_err("noop must err");
        assert!(matches!(
            err,
            UserOperationFailure::UnsupportedOperation { .. }
        ));
    }

    #[tokio::test]
    async fn noop_user_provisioner_list_reports_unsupported_operation() {
        let p = NoopUserProvisioner;
        let req = ListUsersRequest {
            tenant_id: Uuid::nil(),
            tenant_context: TenantContext::new(Uuid::nil(), "t"),
            user_id_filter: None,
            pagination: UserPagination::default(),
        };
        let err = p.list_users(&req).await.expect_err("noop must err");
        assert!(matches!(
            err,
            UserOperationFailure::UnsupportedOperation { .. }
        ));
    }
}
