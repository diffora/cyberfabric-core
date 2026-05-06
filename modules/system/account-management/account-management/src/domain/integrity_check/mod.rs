//! Periodic hierarchy-integrity check job.
//!
//! Spawned once per platform start by
//! [`crate::module::AccountManagementModule::serve`] when
//! [`config::IntegrityCheckConfig::enabled`] is `true`. Each tick invokes
//! [`crate::domain::tenant::service::TenantService::check_hierarchy_integrity`],
//! tolerates the single-flight gate
//! ([`crate::domain::error::DomainError::IntegrityCheckInProgress`]) as a
//! `skipped` outcome, and emits per-tick `RUNS` / `DURATION` /
//! `LAST_SUCCESS` telemetry on top of the per-category
//! [`crate::domain::metrics::AM_HIERARCHY_INTEGRITY_VIOLATIONS`] gauge
//! the underlying service already produces.
//!
//! On-demand callers continue to use
//! `TenantService::check_hierarchy_integrity` directly; this job is
//! purely additive and opt-out via `enabled = false`.

pub mod config;
pub mod service;

pub use config::{IntegrityCheckConfig, IntegrityRepairConfig};
pub use service::{IntegrityChecker, run_integrity_check_loop};
