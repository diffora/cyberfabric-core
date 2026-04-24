//! Infrastructure-layer wiring for the Resource Group SDK.
//!
//! Holds the [`RgResourceOwnershipChecker`] adapter that backs the
//! production resource-ownership probe consumed by
//! [`crate::domain::tenant::service::TenantService::soft_delete`]
//! when a `ResourceGroupClient` resolves from `ClientHub`. When no
//! client is registered, AM falls back to the inert checker
//! ([`crate::domain::tenant::resource_checker::InertResourceOwnershipChecker`]).

pub mod checker;

pub use checker::RgResourceOwnershipChecker;
