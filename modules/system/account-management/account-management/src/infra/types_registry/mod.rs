//! Infrastructure-layer wiring for the GTS Types Registry SDK.
//!
//! Holds the [`GtsTenantTypeChecker`] adapter that connects the AM
//! [`crate::domain::tenant_type::TenantTypeChecker`] domain trait to
//! `types_registry_sdk::TypesRegistryClient` resolved from `ClientHub`
//! (FEATURE 2.3 `tenant-type-enforcement`).
//!
//! The `ClientHub` binding is wired in the AM module entry-point
//! ([`crate::module::AccountManagementModule`]): if a
//! `types_registry_sdk::TypesRegistryClient` resolves, the entry-point
//! constructs `GtsTenantTypeChecker` and passes it to
//! `TenantService::new`; otherwise it logs a warning and falls back to
//! [`crate::domain::tenant_type::InertTenantTypeChecker`] (every
//! pairing admitted) so dev / test deployments without a registry keep
//! booting.

pub mod checker;

#[cfg(test)]
pub(crate) mod test_helpers;

// `GtsTenantTypeChecker` is `pub use`d for the AM module entry-point's
// `ClientHub` wiring. It is **not** part of the AM module's external
// API surface — outside consumers go through
// `account-management-sdk`. Keep this re-export scoped to wiring
// usage; if the entry-point lands in a sibling crate, narrow this to
// `pub(crate)`.
pub use checker::GtsTenantTypeChecker;
