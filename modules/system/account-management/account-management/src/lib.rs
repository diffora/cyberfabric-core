//! Account Management — storage floor crate.
//!
//! This crate ships the persistence foundation for the AM module:
//! the stable domain shapes (error taxonomy, idp contract, tenant
//! model / repo trait, retention types) plus the SeaORM-backed
//! `TenantRepoImpl` and migration set.
//!
//! REST wiring, module lifecycle, audit classifiers, and domain
//! services arrive in subsequent PRs.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod domain;
pub mod infra;

pub use domain::error::{AmError, ErrorCategory};
pub use domain::idp::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
pub use domain::metrics::{
    AM_AUDIT_DROP, AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL,
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_METADATA_RESOLUTION, AM_RETENTION_INVALID_WINDOW, AM_TENANT_RETENTION, MetricKind,
    emit_metric,
};
pub use domain::tenant::{
    ChildCountFilter, ClosureRow, HardDeleteOutcome, HardDeleteResult, ListChildrenQuery,
    NewTenant, ReaperResult, TenantModel, TenantPage, TenantProvisioningRow, TenantRepo,
    TenantRetentionRow, TenantStatus, TenantUpdate,
};

pub use infra::storage::migrations::Migrator;
pub use infra::storage::repo_impl::{AmDbProvider, TenantRepoImpl};
