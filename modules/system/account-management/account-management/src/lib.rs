//! Account Management — storage floor crate.
//!
//! This crate ships the persistence foundation for the AM module:
//! the stable domain shapes (error taxonomy, idp contract, tenant
//! model / repo trait, retention types), the SeaORM-backed
//! `TenantRepoImpl` and migration set, the domain services
//! ([`crate::domain::tenant::service::TenantService`] with hooks,
//! retention + reaper pipelines), and the `ModKit` module entry-point
//! ([`AccountManagementModule`]) that wires everything together with
//! the `AuthZ` resolver, `IdP` provisioner, Resource Group and Types
//! Registry plugins resolved from `ClientHub`.
//!
//! REST wiring, the platform-bootstrap saga, and hierarchy-integrity
//! audit arrive in subsequent PRs.
//!
//! # Production readiness — pre-production gates
//!
//! The following items MUST land before this crate is fronted by an
//! externally-reachable REST surface in a production multi-tenant
//! deployment. They are tracked here so reviewers and operators see
//! them at the top of the crate doc, not buried in feature specs.
//!
//! * **`InTenantSubtree` predicate / SQL-level subtree clamp** —
//!   tracked in `cyberfabric-core#1813`. Today AM authorization is
//!   single-layer: the service-level PDP gate
//!   ([`crate::domain::tenant::service::TenantService`]) is the only
//!   enforcement layer. The `tenants` and `tenant_closure` entities
//!   are declared `no_tenant, no_resource, no_owner, no_type`, so
//!   `modkit-db secure` adds **no** automatic `WHERE` clause on
//!   reads; callers MUST pass [`modkit_security::AccessScope::allow_all`]
//!   (see [`crate::domain::tenant::TenantRepo`] trait contract). A
//!   future endpoint that forgets to call the PDP gate would have no
//!   DB-level backstop. After `InTenantSubtree` lands, the PDP
//!   returns `InTenantSubtree(root=subject.tenant_id)` constraints,
//!   the secure builder compiles them to a JOIN on `tenant_closure`,
//!   and the `require_constraints(false)` on the `authorize` helper
//!   flips to `true`.
//!
//! REST handlers MUST NOT be added on top of `TenantRepo` until
//! `cyberfabric-core#1813` is closed.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod config;
pub mod domain;
pub mod infra;
pub mod module;

pub use domain::error::DomainError;
pub use domain::metrics::{
    AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL, AM_DEPENDENCY_HEALTH,
    AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS, AM_METADATA_RESOLUTION,
    AM_RETENTION_INVALID_WINDOW, AM_TENANT_RETENTION, MetricKind, emit_metric,
};
pub use domain::tenant::{
    ChildCountFilter, ClosureRow, HardDeleteOutcome, HardDeleteResult, NewTenant, ReaperResult,
    TenantModel, TenantProvisioningRow, TenantRepo, TenantRetentionRow, TenantStatus,
};

pub use infra::storage::migrations::Migrator;
pub use infra::storage::repo_impl::{AmDbProvider, TenantRepoImpl};

pub use module::AccountManagementModule;
