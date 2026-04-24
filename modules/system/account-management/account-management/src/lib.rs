//! Account Management Module — foundation crate.
//!
//! This crate owns Account Management's cross-cutting foundation surface:
//!
//! * the stable public error taxonomy (8 categories × DESIGN §3.8 sub-codes)
//! * AM observability metric families and fire-and-forget emitter
//! * the audit-emission helper honouring the `actor=system` allow-list
//!
//! Problem-envelope construction and the `SecurityContext` entry-point gate
//! are intentionally **not** in this crate — they are supplied by the
//! REST-wiring layer that consumes these primitives, matching the pattern
//! used by sibling modules (`resource-group`, `tenant-resolver`).
//!
//! Implements FEATURE `errors-observability`. See
//! `modules/system/account-management/docs/features/feature-errors-observability.md`.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod api;
pub mod config;
pub mod domain;
pub mod infra;
pub mod module;

pub use api::tenants::handlers::am_error_to_problem;
pub use config::AccountManagementConfig;
pub use domain::audit::{AuditActor, AuditEvent, AuditEventKind, emit_audit};
pub use domain::bootstrap::{BootstrapConfig, BootstrapService};
pub use domain::error::{AmError, ErrorCategory};
pub use domain::idp::{
    DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner, ProvisionFailure,
    ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
pub use domain::metrics::{
    AM_AUDIT_DROP, AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL,
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_METADATA_RESOLUTION, AM_RETENTION_INVALID_WINDOW, AM_TENANT_RETENTION, MetricKind,
    emit_metric,
};
pub use domain::tenant::{
    ClosureRow, CreateChildInput, HardDeleteOutcome, HardDeleteResult, HookError,
    InertResourceOwnershipChecker, IntegrityCategory, IntegrityReport, IntegrityScope,
    ListChildrenQuery, NewTenant, ReaperResult, ResourceOwnershipChecker, TenantHardDeleteHook,
    TenantModel, TenantPage, TenantProvisioningRow, TenantRepo, TenantRetentionRow, TenantService,
    TenantStatus, TenantUpdate, Violation,
};
pub use domain::tenant_type::{InertTenantTypeChecker, TenantTypeChecker};
// `bucket_by_category`, `build_activation_rows`,
// `classify_closure_shape_anomalies`, `classify_tree_shape_anomalies`,
// `is_due`, `order_batch_leaf_first`, and `compute_next_backoff` are
// not re-exported at the crate root: they are domain-internal helpers
// with no external consumers, reachable via
// `crate::domain::{tenant::{closure,integrity,retention},util::backoff}`
// for tests inside this crate.

// Keep SeaORM entities available inside the crate without exposing
// persistence internals as a public API surface.
#[allow(unused_imports, reason = "private compatibility re-export")]
pub(crate) use infra::storage::entity;

// Phase 2 public surface — module entry-point + infra helpers.
pub use infra::idp::NoopProvisioner;
pub use infra::rg::RgResourceOwnershipChecker;
#[allow(unused_imports, reason = "private compatibility re-export")]
pub(crate) use infra::storage::repo_impl::TenantRepoImpl;
pub use infra::types_registry::GtsTenantTypeChecker;
pub use module::AccountManagementModule;
