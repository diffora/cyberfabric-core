//! Infrastructure-layer wiring for the GTS Types Registry SDK.
//!
//! Holds the [`GtsTenantTypeChecker`] adapter that connects the AM
//! [`crate::domain::tenant_type::TenantTypeChecker`] domain trait to
//! `types_registry_sdk::TypesRegistryClient` resolved from `ClientHub`
//! (FEATURE 2.3 `tenant-type-enforcement`).

pub mod checker;

pub use checker::GtsTenantTypeChecker;
