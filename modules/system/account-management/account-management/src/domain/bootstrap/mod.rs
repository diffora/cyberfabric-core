//! Platform-bootstrap saga domain layer.
//!
//! Implements FEATURE `platform-bootstrap` (see
//! `modules/system/account-management/docs/features/feature-platform-bootstrap.md`).
//!
//! The bootstrap saga is invoked exactly once per platform start by
//! [`crate::module::AccountManagementModule::init`] and **MUST** complete
//! before the runtime invokes `serve` so that the retention + reaper
//! background loops never observe the platform without a root tenant.

pub mod config;
pub mod service;

pub use config::BootstrapConfig;
pub use service::BootstrapService;
