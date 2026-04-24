//! Tenant hierarchy domain module.
//!
//! Owns the tenant entity's business rules (create-child saga, read,
//! list-children, update-mutable-fields) and the closure-table
//! maintenance invariants that back the `tenant_closure` publication
//! contract consumed by `tenant-resolver`.

pub mod closure;
pub mod hooks;
pub mod integrity;
pub mod model;
pub mod repo;
pub mod resource_checker;
pub mod retention;
pub mod service;

#[cfg(test)]
pub mod test_support;

pub use closure::{ClosureRow, build_activation_rows};
pub use hooks::{HookError, TenantHardDeleteHook};
pub use integrity::{
    IntegrityCategory, IntegrityReport, IntegrityScope, Violation, bucket_by_category,
    classify_closure_shape_anomalies, classify_tree_shape_anomalies,
};
pub use model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
pub use repo::TenantRepo;
pub use resource_checker::{InertResourceOwnershipChecker, ResourceOwnershipChecker};
pub use retention::{
    HardDeleteOutcome, HardDeleteResult, ReaperResult, TenantProvisioningRow, TenantRetentionRow,
    is_due, order_batch_leaf_first,
};
pub use service::{CreateChildInput, TenantService};
