use account_management_sdk::TenantUpdate;

use super::*;

#[test]
fn smallint_round_trip_is_total_over_known_values() {
    for s in [
        TenantStatus::Provisioning,
        TenantStatus::Active,
        TenantStatus::Suspended,
        TenantStatus::Deleted,
    ] {
        let v = s.as_smallint();
        assert_eq!(TenantStatus::from_smallint(v), Some(s));
    }
}

#[test]
fn from_smallint_rejects_unknown_values() {
    assert_eq!(TenantStatus::from_smallint(-1), None);
    assert_eq!(TenantStatus::from_smallint(4), None);
    assert_eq!(TenantStatus::from_smallint(42), None);
}

#[test]
fn is_sdk_visible_excludes_provisioning_only() {
    assert!(!TenantStatus::Provisioning.is_sdk_visible());
    assert!(TenantStatus::Active.is_sdk_visible());
    assert!(TenantStatus::Suspended.is_sdk_visible());
    assert!(TenantStatus::Deleted.is_sdk_visible());
}

#[test]
fn sdk_status_lifts_into_internal() {
    use account_management_sdk::TenantStatus as SdkStatus;
    assert_eq!(TenantStatus::from(SdkStatus::Active), TenantStatus::Active);
    assert_eq!(
        TenantStatus::from(SdkStatus::Suspended),
        TenantStatus::Suspended
    );
    assert_eq!(
        TenantStatus::from(SdkStatus::Deleted),
        TenantStatus::Deleted
    );
}

#[test]
fn internal_status_lowers_into_sdk_for_visible_variants() {
    use account_management_sdk::TenantStatus as SdkStatus;
    assert_eq!(SdkStatus::from(TenantStatus::Active), SdkStatus::Active);
    assert_eq!(
        SdkStatus::from(TenantStatus::Suspended),
        SdkStatus::Suspended
    );
    assert_eq!(SdkStatus::from(TenantStatus::Deleted), SdkStatus::Deleted);
}

#[test]
#[should_panic(expected = "Provisioning rows must be filtered")]
fn internal_status_lowering_provisioning_panics() {
    // Service-level filter must drop Provisioning before mapping; if a
    // bug ever lets it through, the unreachable arm should fire loudly.
    let _lowered = account_management_sdk::TenantStatus::from(TenantStatus::Provisioning);
}

#[test]
fn empty_update_is_empty() {
    assert!(TenantUpdate::default().is_empty());
    assert!(
        !TenantUpdate {
            name: Some("x".into()),
            ..Default::default()
        }
        .is_empty()
    );
    assert!(
        !TenantUpdate {
            status: Some(account_management_sdk::TenantStatus::Active),
            ..Default::default()
        }
        .is_empty()
    );
}

#[test]
fn status_transition_active_suspended_allowed() {
    validate_status_transition(TenantStatus::Active, TenantStatus::Suspended)
        .expect("active -> suspended ok");
    validate_status_transition(TenantStatus::Suspended, TenantStatus::Active)
        .expect("suspended -> active ok");
}

#[test]
fn status_transition_no_op_rejected() {
    // Strict contract: PATCH only permits the cross-flip; resending
    // the current status is a no-op that would still trigger a
    // wasted closure-rewrite, so it surfaces as `Conflict`.
    let active_active = validate_status_transition(TenantStatus::Active, TenantStatus::Active)
        .expect_err("A->A must reject");
    assert!(matches!(active_active, DomainError::Conflict { .. }));
    let suspended_suspended =
        validate_status_transition(TenantStatus::Suspended, TenantStatus::Suspended)
            .expect_err("S->S must reject");
    assert!(matches!(suspended_suspended, DomainError::Conflict { .. }));
}

#[test]
fn status_transition_to_deleted_rejected() {
    let err = validate_status_transition(TenantStatus::Active, TenantStatus::Deleted)
        .expect_err("reject");
    assert!(matches!(err, DomainError::Conflict { .. }));
}

#[test]
fn status_transition_from_provisioning_rejected() {
    let err = validate_status_transition(TenantStatus::Provisioning, TenantStatus::Active)
        .expect_err("reject");
    assert!(matches!(err, DomainError::Conflict { .. }));
}

#[test]
fn status_transition_from_deleted_rejected() {
    let err = validate_status_transition(TenantStatus::Deleted, TenantStatus::Active)
        .expect_err("reject");
    assert!(matches!(err, DomainError::Conflict { .. }));
}

#[test]
fn name_length_validation_rejects_empty_and_oversized() {
    assert!(validate_tenant_name("a").is_ok());
    assert!(validate_tenant_name(&"x".repeat(255)).is_ok());
    assert!(matches!(
        validate_tenant_name("").expect_err("empty rejected"),
        DomainError::Validation { .. }
    ));
    assert!(matches!(
        validate_tenant_name(&"x".repeat(256)).expect_err("too long rejected"),
        DomainError::Validation { .. }
    ));
}
