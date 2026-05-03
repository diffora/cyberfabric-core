//! Tests for the [`DomainError`] → [`CanonicalError`] boundary mapping.
//!
//! Validates the AIP-193 category, HTTP status code, and key context
//! fields (`resource_type`, `resource_name`, `retry_after_seconds`, `reason`)
//! produced by `From<DomainError> for CanonicalError`. Renaming any of
//! these mappings is a public-contract break — the tests below are the
//! regression line for that contract.
//!
//! Boundary mapping lives in [`crate::infra::canonical_mapping`]
//! (kept out of `domain/` so the DB-aware classification ladder can
//! reach `sea_orm`/`modkit_db` without violating Dylint
//! domain-layer rules). The tests still live alongside `domain/error`
//! because they pin the shape of the public contract.

use std::time::Duration;

use modkit_canonical_errors::CanonicalError;

use super::DomainError;

/// Convenience: convert a `DomainError` into a `CanonicalError` and
/// read its `status_code()`.
fn status_of(err: DomainError) -> u16 {
    CanonicalError::from(err).status_code()
}

// ---------------------------------------------------------------------------
// HTTP status codes — AIP-193 mapping
// ---------------------------------------------------------------------------

#[test]
fn invalid_argument_variants_map_to_400() {
    assert_eq!(
        status_of(DomainError::InvalidTenantType { detail: "x".into() }),
        400
    );
    assert_eq!(
        status_of(DomainError::Validation { detail: "x".into() }),
        400
    );
    assert_eq!(status_of(DomainError::RootTenantCannotDelete), 400);
    assert_eq!(status_of(DomainError::RootTenantCannotConvert), 400);
}

#[test]
fn not_found_variants_map_to_404() {
    assert_eq!(
        status_of(DomainError::NotFound {
            detail: "tenant x not found".into(),
            resource: "x".into(),
        }),
        404
    );
    assert_eq!(
        status_of(DomainError::MetadataSchemaNotRegistered {
            detail: "schema y missing".into(),
            schema: "y".into(),
        }),
        404
    );
    assert_eq!(
        status_of(DomainError::MetadataEntryNotFound {
            detail: "entry z missing".into(),
            entry: "z".into(),
        }),
        404
    );
}

#[test]
fn precondition_variants_map_to_400() {
    assert_eq!(
        status_of(DomainError::TypeNotAllowed { detail: "x".into() }),
        400
    );
    assert_eq!(
        status_of(DomainError::TenantDepthExceeded { detail: "x".into() }),
        400
    );
    assert_eq!(status_of(DomainError::TenantHasChildren), 400);
    assert_eq!(status_of(DomainError::TenantHasResources), 400);
    assert_eq!(
        status_of(DomainError::PendingExists {
            request_id: "r1".into()
        }),
        400
    );
    assert_eq!(
        status_of(DomainError::InvalidActorForTransition {
            attempted_status: "approved".into(),
            caller_side: "child".into(),
        }),
        400
    );
    assert_eq!(status_of(DomainError::AlreadyResolved), 400);
    assert_eq!(status_of(DomainError::Conflict { detail: "x".into() }), 400);
}

#[test]
fn already_exists_maps_to_409() {
    assert_eq!(
        status_of(DomainError::AlreadyExists {
            detail: "tenant exists".into()
        }),
        409
    );
}

#[test]
fn aborted_maps_to_409_with_reason() {
    let canonical: CanonicalError = DomainError::Aborted {
        reason: "SERIALIZATION_CONFLICT".into(),
        detail: "serialization conflict; retry budget exhausted".into(),
    }
    .into();
    assert_eq!(canonical.status_code(), 409);
    let CanonicalError::Aborted { ctx, .. } = canonical else {
        panic!("expected Aborted variant");
    };
    assert_eq!(ctx.reason, "SERIALIZATION_CONFLICT");
}

#[test]
fn cross_tenant_denied_maps_to_403() {
    assert_eq!(
        status_of(DomainError::CrossTenantDenied { cause: None }),
        403
    );
}

#[test]
fn service_unavailable_maps_to_503() {
    assert_eq!(status_of(DomainError::service_unavailable("idp down")), 503);
}

#[test]
fn unsupported_operation_maps_to_501() {
    assert_eq!(
        status_of(DomainError::UnsupportedOperation { detail: "x".into() }),
        501
    );
}

#[test]
fn audit_already_running_maps_to_429() {
    assert_eq!(
        status_of(DomainError::AuditAlreadyRunning {
            scope: "whole".into()
        }),
        429
    );
}

#[test]
fn internal_maps_to_500() {
    assert_eq!(status_of(DomainError::internal("unexpected")), 500);
}

// ---------------------------------------------------------------------------
// Context fields preserved across the boundary
// ---------------------------------------------------------------------------

#[test]
fn not_found_carries_resource_name_and_type() {
    let canonical: CanonicalError = DomainError::NotFound {
        detail: "tenant 7 not found".into(),
        resource: "7".into(),
    }
    .into();
    assert_eq!(canonical.resource_name(), Some("7"));
    assert_eq!(
        canonical.resource_type(),
        Some(account_management_sdk::gts::TENANT_RESOURCE_TYPE)
    );
}

#[test]
fn metadata_schema_not_registered_uses_metadata_resource_type() {
    let canonical: CanonicalError = DomainError::MetadataSchemaNotRegistered {
        detail: "schema billing.v1 missing".into(),
        schema: "billing.v1".into(),
    }
    .into();
    assert_eq!(canonical.resource_name(), Some("billing.v1"));
    assert_eq!(
        canonical.resource_type(),
        Some(account_management_sdk::gts::TENANT_METADATA_RESOURCE_TYPE)
    );
}

/// Pin the `#[resource_error]` macro literal strings against the SDK
/// constants — the macro takes a literal at expansion time and cannot
/// resolve consts, so the only mechanism preventing the impl-side
/// strings from drifting from the SDK source of truth is this test.
/// Covers all three resource types (`Tenant`, `TenantMetadata`,
/// `ConversionRequest`) — a fourth resource added without the
/// corresponding assertion would also drift undetected.
#[test]
fn resource_error_strings_match_sdk_constants() {
    let tenant_not_found: CanonicalError = DomainError::NotFound {
        detail: "any".into(),
        resource: "any".into(),
    }
    .into();
    assert_eq!(
        tenant_not_found.resource_type(),
        Some(account_management_sdk::gts::TENANT_RESOURCE_TYPE),
        "domain::error tenant resource_type drifted from SDK constant"
    );

    let metadata_not_found: CanonicalError = DomainError::MetadataSchemaNotRegistered {
        detail: "any".into(),
        schema: "any".into(),
    }
    .into();
    assert_eq!(
        metadata_not_found.resource_type(),
        Some(account_management_sdk::gts::TENANT_METADATA_RESOURCE_TYPE),
        "domain::error tenant_metadata resource_type drifted from SDK constant"
    );

    let conversion_already_resolved: CanonicalError = DomainError::AlreadyResolved.into();
    assert_eq!(
        conversion_already_resolved.resource_type(),
        Some(account_management_sdk::gts::CONVERSION_REQUEST_RESOURCE_TYPE),
        "domain::error conversion_request resource_type drifted from SDK constant"
    );
}

#[test]
fn service_unavailable_propagates_retry_after_seconds() {
    let canonical: CanonicalError = DomainError::ServiceUnavailable {
        detail: "idp warming up".into(),
        retry_after: Some(Duration::from_secs(15)),
        cause: None,
    }
    .into();
    let CanonicalError::ServiceUnavailable { ctx, .. } = canonical else {
        panic!("expected ServiceUnavailable variant");
    };
    assert_eq!(ctx.retry_after_seconds, Some(15));
}

#[test]
fn service_unavailable_without_hint_omits_retry_after() {
    let canonical: CanonicalError = DomainError::service_unavailable("db down").into();
    let CanonicalError::ServiceUnavailable { ctx, .. } = canonical else {
        panic!("expected ServiceUnavailable variant");
    };
    assert!(ctx.retry_after_seconds.is_none());
}

// ---------------------------------------------------------------------------
// Test-only accessors
// ---------------------------------------------------------------------------
//
// `code()` / `http_status()` are `#[cfg(test)]`-only convenience methods used
// by service-layer tests to pin the variant→code/status contract without
// going through `CanonicalError::from(...)` on every assertion. Production
// callers MUST go through [`crate::infra::canonical_mapping`]; this impl
// block lives in the companion test file (per dylint `DE1101`) so the
// production [`DomainError`] surface stays free of test-only items.

impl DomainError {
    /// AM-specific `snake_case` error tag. Mirrors the variant name in
    /// `snake_case`; the canonical wire code comes from
    /// [`crate::infra::canonical_mapping`] and may differ (e.g. several
    /// variants collapse to `failed_precondition` on the wire).
    #[must_use]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidTenantType { .. } => "invalid_tenant_type",
            Self::Validation { .. } => "validation",
            Self::RootTenantCannotDelete => "root_tenant_cannot_delete",
            Self::RootTenantCannotConvert => "root_tenant_cannot_convert",
            Self::NotFound { .. } => "not_found",
            Self::MetadataSchemaNotRegistered { .. } => "metadata_schema_not_registered",
            Self::MetadataEntryNotFound { .. } => "metadata_entry_not_found",
            Self::AlreadyExists { .. } => "already_exists",
            Self::Aborted { .. } => "aborted",
            Self::TypeNotAllowed { .. } => "type_not_allowed",
            Self::TenantDepthExceeded { .. } => "tenant_depth_exceeded",
            Self::TenantHasChildren => "tenant_has_children",
            Self::TenantHasResources => "tenant_has_resources",
            Self::PendingExists { .. } => "pending_exists",
            Self::InvalidActorForTransition { .. } => "invalid_actor_for_transition",
            Self::AlreadyResolved => "already_resolved",
            Self::Conflict { .. } => "conflict",
            Self::CrossTenantDenied { .. } => "cross_tenant_denied",
            Self::ServiceUnavailable { .. } => "service_unavailable",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::AuditAlreadyRunning { .. } => "audit_already_running",
            Self::Internal { .. } => "internal",
        }
    }

    /// HTTP status produced for this error by the canonical-mapping
    /// boundary. Computed locally so tests do not pay the per-call
    /// `CanonicalError::from(...)` allocation; pinned to the same
    /// status table the canonical mapping returns.
    ///
    /// `failed_precondition` variants land on **400** (per AIP-193 +
    /// the canonical mapping in [`crate::infra::canonical_mapping`]),
    /// not 409 — only `AlreadyExists` and `Aborted` carry 409 here.
    /// The `precondition_variants_map_to_400` /
    /// `already_exists_maps_to_409` tests in this file pin the
    /// authoritative mapping; this helper must agree with them.
    #[must_use]
    pub(crate) fn http_status(&self) -> u16 {
        match self {
            Self::InvalidTenantType { .. }
            | Self::Validation { .. }
            | Self::RootTenantCannotDelete
            | Self::RootTenantCannotConvert
            | Self::InvalidActorForTransition { .. }
            | Self::TypeNotAllowed { .. }
            | Self::TenantDepthExceeded { .. }
            | Self::TenantHasChildren
            | Self::TenantHasResources
            | Self::PendingExists { .. }
            | Self::AlreadyResolved
            | Self::Conflict { .. } => 400,
            Self::NotFound { .. }
            | Self::MetadataSchemaNotRegistered { .. }
            | Self::MetadataEntryNotFound { .. } => 404,
            Self::AlreadyExists { .. } | Self::Aborted { .. } => 409,
            Self::CrossTenantDenied { .. } => 403,
            Self::ServiceUnavailable { .. } => 503,
            Self::UnsupportedOperation { .. } => 501,
            Self::AuditAlreadyRunning { .. } => 429,
            Self::Internal { .. } => 500,
        }
    }
}
