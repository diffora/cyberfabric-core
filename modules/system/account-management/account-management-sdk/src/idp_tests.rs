//! Tests for the SDK `IdP` provisioner contract -- trait default impl
//! and the metric-label constants on the failure enums.

use super::*;

use crate::{NewUserPayload, TenantContext, UserPagination};
use async_trait::async_trait;
use uuid::Uuid;

/// Minimal stub implementing only the required `check_availability`
/// method. Pins the `IdpPluginClient` defaults: every other
/// method MUST return its category-appropriate `UnsupportedOperation`.
struct Stub;

#[async_trait]
impl IdpPluginClient for Stub {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        Ok(())
    }
}

#[test]
fn provision_input_schema_id_defaults_to_none() {
    // Plugins that do not override `provision_input_schema_id` keep
    // the opaque (current) behaviour: AM forwards `metadata` to
    // `provision_tenant` without an input-side GTS pre-check. Adding
    // a default impl to a trait is not a SemVer break, and the
    // existing `Stub` here exercises that fall-through.
    let s = Stub;
    assert!(
        s.provision_input_schema_id().is_none(),
        "plugins inherit `None` so AM-side input validation is opt-in"
    );
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

#[tokio::test]
async fn provision_tenant_default_impl_returns_unsupported_operation() {
    let s = Stub;
    let req = ProvisionRequest {
        tenant_id: Uuid::nil(),
        target: crate::ProvisionTarget::Root,
        name: "t".into(),
        tenant_type: gts::GtsSchemaId::new("gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~"),
        metadata: None,
    };
    let err = s
        .provision_tenant(&req)
        .await
        .expect_err("default impl must err");
    assert!(matches!(err, ProvisionFailure::UnsupportedOperation { .. }));
}

#[tokio::test]
async fn provision_user_default_impl_returns_unsupported_operation() {
    let s = Stub;
    let req = ProvisionUserRequest {
        tenant_context: TenantContext::new(Uuid::nil(), "t", None),
        payload: NewUserPayload {
            username: "alice".into(),
            email: None,
            display_name: None,
            avatar_url: None,
            attributes: None,
        },
    };
    let err = s
        .provision_user(&req)
        .await
        .expect_err("default impl must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
    ));
}

#[tokio::test]
async fn deprovision_user_default_impl_returns_unsupported_operation() {
    let s = Stub;
    let req = DeprovisionUserRequest {
        tenant_context: TenantContext::new(Uuid::nil(), "t", None),
        user_id: Uuid::nil(),
    };
    let err = s
        .deprovision_user(&req)
        .await
        .expect_err("default impl must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
    ));
}

#[tokio::test]
async fn list_users_default_impl_returns_unsupported_operation() {
    let s = Stub;
    let req = ListUsersRequest {
        tenant_context: TenantContext::new(Uuid::nil(), "t", None),
        user_id_filter: None,
        pagination: UserPagination::default(),
    };
    let err = s.list_users(&req).await.expect_err("default impl must err");
    assert!(matches!(
        err,
        UserOperationFailure::UnsupportedOperation { .. }
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
        CheckAvailabilityFailure::Unreachable {
            detail: "nope".to_owned()
        }
        .detail(),
        "nope"
    );
    assert_eq!(
        CheckAvailabilityFailure::TransientError {
            detail: "later".to_owned()
        }
        .detail(),
        "later"
    );
}

#[test]
fn check_availability_failure_metric_labels_are_stable() {
    assert_eq!(
        CheckAvailabilityFailure::Unreachable {
            detail: "x".to_owned()
        }
        .as_metric_label(),
        "unreachable"
    );
    assert_eq!(
        CheckAvailabilityFailure::TransientError {
            detail: "x".to_owned()
        }
        .as_metric_label(),
        "transient_error"
    );
}

#[test]
fn provision_failure_detail_and_display() {
    // `detail()` returns the raw provider string verbatim across every
    // variant so audit / redaction consumers do not have to repeat the
    // match arms themselves.
    let f = ProvisionFailure::Ambiguous {
        detail: "vendor timeout".to_owned(),
    };
    assert_eq!(f.detail(), "vendor timeout");
    // `Display` is `"<metric_label>: <detail>"` so trace lines and
    // `Box<dyn Error>` propagation produce a stable, grep-able shape.
    assert_eq!(f.to_string(), "ambiguous: vendor timeout");
    let f2 = ProvisionFailure::CleanFailure {
        detail: "refused".to_owned(),
    };
    assert_eq!(f2.to_string(), "clean_failure: refused");
}

#[test]
fn deprovision_failure_detail_and_display() {
    let f = DeprovisionFailure::NotFound {
        detail: "gone".to_owned(),
    };
    assert_eq!(f.detail(), "gone");
    // `NotFound`'s metric label is `already_absent` (see
    // `DeprovisionFailure::as_metric_label`) — `Display` preserves the
    // operational label, not the variant name.
    assert_eq!(f.to_string(), "already_absent: gone");
}

#[test]
fn check_availability_failure_display() {
    let f = CheckAvailabilityFailure::Unreachable {
        detail: "dns".to_owned(),
    };
    assert_eq!(f.to_string(), "unreachable: dns");
}

#[test]
fn failure_enums_implement_std_error_trait() {
    // The four `IdP` failure enums must implement `core::error::Error`
    // so plugin authors can `?`-propagate them through `Box<dyn Error>`
    // / `thiserror::Error(#[from])` paths without writing manual
    // conversions. A `&dyn core::error::Error` coercion is the
    // compile-time witness.
    let provision: ProvisionFailure = ProvisionFailure::Ambiguous {
        detail: String::new(),
    };
    let deprovision: DeprovisionFailure = DeprovisionFailure::Terminal {
        detail: String::new(),
    };
    let check: CheckAvailabilityFailure = CheckAvailabilityFailure::Unreachable {
        detail: String::new(),
    };
    let _: &dyn core::error::Error = &provision;
    let _: &dyn core::error::Error = &deprovision;
    let _: &dyn core::error::Error = &check;
}
