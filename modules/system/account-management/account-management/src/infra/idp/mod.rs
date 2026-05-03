//! Infrastructure-layer glue for the optional
//! [`account_management_sdk::IdpTenantProvisionerClient`] plugin.
//!
//! AM can boot without an `IdP` adapter present — dev deployments and
//! tests do not need one. The service stores the provisioner as
//! `Arc<dyn IdpTenantProvisionerClient>` directly; this module
//! contributes only the [`NoopProvisioner`] fallback that is wired in
//! when no plugin resolves from `ClientHub`.
//!
//! The SDK trait carries `check_availability`, `provision_tenant`, and
//! `deprovision_tenant`. The fallback returns the `UnsupportedOperation`
//! / `Unreachable` variants for each so a deployment without an `IdP`
//! plugin keeps booting and surfaces a consistent error envelope at
//! the call site.

use account_management_sdk::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient,
    ProvisionFailure, ProvisionRequest, ProvisionResult,
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn noop_provisioner_reports_unsupported_operation() {
        let p = NoopProvisioner;
        let req = ProvisionRequest {
            tenant_id: Uuid::nil(),
            parent_id: None,
            name: "t".into(),
            tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.customer.v1~".into(),
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
}
