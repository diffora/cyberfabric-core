//! Account Management SDK — public contract surface.
//!
//! This crate re-exports the canonical-errors public surface that AM
//! uses for inter-module Rust callers and for REST `Problem`
//! conversion. After the AIP-193 migration, AM no longer carries an
//! AM-specific public error enum; callers depend on
//! [`modkit_canonical_errors::CanonicalError`] directly, surfaced here
//! as [`AccountManagementError`] for backwards-readability with the
//! `resource-group-sdk` / `tenant-resolver-sdk` naming pattern.
//!
//! External consumers — plugin authors, dashboards, integration tests,
//! sibling modules calling AM via `ClientHub` — depend on **this**
//! crate, never on the impl crate (`cf-account-management`), so impl-side
//! churn (sea-orm migrations, axum wiring, tokio runtime) does not
//! propagate as a contract break.
//!
//! # Mapping summary (AIP-193)
//!
//! Every AM domain failure converts to a canonical category at the
//! impl-crate boundary (`cf-account-management::domain::error`). The
//! resulting HTTP status codes follow Google AIP-193 verbatim:
//!
//! | AM domain shape | Canonical category | HTTP |
//! |-----------------|-------------------|------|
//! | `Validation` / `InvalidTenantType` / `RootTenantCannotDelete` / `RootTenantCannotConvert` | `InvalidArgument` | 400 |
//! | `NotFound` / `MetadataSchemaNotRegistered` / `MetadataEntryNotFound` | `NotFound` | 404 |
//! | `TenantHasChildren` / `TenantHasResources` / `TypeNotAllowed` / `TenantDepthExceeded` / `PendingExists` / `InvalidActorForTransition` / `AlreadyResolved` / `Conflict` | `FailedPrecondition` | 400 |
//! | `CrossTenantDenied` | `PermissionDenied` | 403 |
//! | `ServiceUnavailable` (covers former `IdpUnavailable`) | `ServiceUnavailable` | 503 |
//! | `UnsupportedOperation` (former `IdpUnsupportedOperation`) | `Unimplemented` | 501 |
//! | `AuditAlreadyRunning` | `ResourceExhausted` | 429 |
//! | `Internal` + retry-exhausted serialization conflict (`Aborted`) + unique violation (`AlreadyExists`) + DB unavailability (`ServiceUnavailable`) | as listed | 500 / 409 / 409 / 503 |
//!
//! `ServiceUnavailable` carries `retry_after_seconds`; `Aborted` carries
//! `reason = "SERIALIZATION_CONFLICT"` for retry-exhausted serializable
//! conflicts; resource-scoped categories carry the GTS resource type
//! `gts.cf.core.am.{tenant|tenant_metadata|conversion_request}.v1~`
//! plus a `resource_name` set by the construction site. The strings
//! live in [`gts`] as `pub const` so consumers (audit pipeline,
//! sibling modules, integration tests) can match on them by typed
//! reference instead of stringly-typed comparison.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod gts;
pub mod idp;
pub mod tenant;

pub use gts::{
    CONVERSION_REQUEST_RESOURCE_TYPE, TENANT_METADATA_RESOURCE_TYPE, TENANT_RESOURCE_TYPE,
};
pub use idp::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
pub use modkit_canonical_errors::CanonicalError as AccountManagementError;
pub use modkit_canonical_errors::{self, CanonicalError, Problem};
pub use tenant::{
    CreateChildInput, ListChildrenQuery, ListChildrenQueryError, TenantId, TenantInfo, TenantPage,
    TenantStatus, TenantUpdate,
};
