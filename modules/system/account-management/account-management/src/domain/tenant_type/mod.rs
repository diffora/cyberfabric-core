//! Tenant-type compatibility barrier (FEATURE 2.3 `tenant-type-enforcement`).
//!
//! Houses the [`TenantTypeChecker`] trait abstraction consumed by
//! [`crate::domain::tenant::service::TenantService::create_child`] at
//! saga step 3 (`inst-algo-saga-type-check`). Production wiring resolves
//! the trait via [`crate::infra::types_registry::checker::GtsTenantTypeChecker`];
//! dev / test wiring uses [`InertTenantTypeChecker`].

pub mod checker;

pub use checker::{InertTenantTypeChecker, TenantTypeChecker, inert_tenant_type_checker};
