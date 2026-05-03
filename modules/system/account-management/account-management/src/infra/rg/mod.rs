//! Infrastructure-layer wiring for the Resource Group SDK.
//!
//! Holds the [`RgResourceOwnershipChecker`] adapter that backs the
//! production resource-ownership probe consumed by
//! [`crate::domain::tenant::service::TenantService::soft_delete`].
//!
//! The `ClientHub` binding is wired in the AM module entry-point
//! ([`crate::module::AccountManagementModule`]): `resource-group` is
//! declared in `#[modkit::module(deps = [...])]`, so the runtime
//! guarantees its init runs first; the entry-point hard-resolves
//! `resource_group_sdk::ResourceGroupClient` and propagates a fatal
//! error from `init` if the client cannot be obtained — soft-delete
//! safety (DESIGN §3.5) is contract-load-bearing, so we fail closed
//! rather than admit-everything via an inert fallback.
//! [`crate::domain::tenant::resource_checker::InertResourceOwnershipChecker`]
//! is reserved for unit tests, which construct `TenantService`
//! directly and bypass this init path.

pub mod checker;

#[cfg(test)]
pub(crate) mod test_helpers;

// `RgResourceOwnershipChecker` is `pub use`d for the AM module
// entry-point's `ClientHub` wiring. It is **not** part of the AM
// module's external API surface — outside consumers go through
// `account-management-sdk`. Keep this re-export scoped to wiring
// usage; if the entry-point lands in a sibling crate, narrow this to
// `pub(crate)`.
pub use checker::RgResourceOwnershipChecker;
