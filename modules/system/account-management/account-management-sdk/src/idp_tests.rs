//! Tests for the SDK `IdP` provisioner contract -- trait default impl
//! and the metric-label constants on the failure enums.

use super::*;

use async_trait::async_trait;
use uuid::Uuid;

struct Stub;

#[async_trait]
impl IdpTenantProvisionerClient for Stub {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        Ok(())
    }

    async fn provision_tenant(
        &self,
        _req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure> {
        Ok(ProvisionResult::default())
    }
}

#[tokio::test]
async fn deprovision_default_impl_returns_unsupported_operation() {
    let s = Stub;
    let req = DeprovisionRequest {
        tenant_id: Uuid::nil(),
    };
    let err = s
        .deprovision_tenant(&req)
        .await
        .expect_err("default impl must err");
    assert!(matches!(
        err,
        DeprovisionFailure::UnsupportedOperation { .. }
    ));
}

#[test]
fn provision_failure_metric_labels_are_stable() {
    assert_eq!(
        ProvisionFailure::CleanFailure {
            detail: String::new()
        }
        .as_metric_label(),
        "clean_failure"
    );
    assert_eq!(
        ProvisionFailure::Ambiguous {
            detail: String::new()
        }
        .as_metric_label(),
        "ambiguous"
    );
    assert_eq!(
        ProvisionFailure::UnsupportedOperation {
            detail: String::new()
        }
        .as_metric_label(),
        "unsupported_operation"
    );
}

#[test]
fn deprovision_failure_metric_labels_are_stable() {
    assert_eq!(
        DeprovisionFailure::Terminal {
            detail: String::new()
        }
        .as_metric_label(),
        "terminal"
    );
    assert_eq!(
        DeprovisionFailure::Retryable {
            detail: String::new()
        }
        .as_metric_label(),
        "retryable"
    );
    assert_eq!(
        DeprovisionFailure::UnsupportedOperation {
            detail: String::new()
        }
        .as_metric_label(),
        "unsupported_operation"
    );
    assert_eq!(
        DeprovisionFailure::NotFound {
            detail: String::new()
        }
        .as_metric_label(),
        "already_absent"
    );
}

#[test]
fn check_availability_failure_detail_accessor() {
    assert_eq!(
        CheckAvailabilityFailure::Unreachable("nope".to_owned()).detail(),
        "nope"
    );
    assert_eq!(
        CheckAvailabilityFailure::TransientError("later".to_owned()).detail(),
        "later"
    );
}
