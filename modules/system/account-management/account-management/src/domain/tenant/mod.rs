//! Tenant hierarchy domain module.
//!
//! Owns the tenant entity's core model, repository contract, closure-table
//! invariants, and retention pipeline types.
//!
//! Domain services, cascade hooks, integrity classifiers, and resource
//! checkers arrive in later PRs.

pub mod closure;
pub mod model;
pub mod repo;
pub mod retention;

pub use closure::{ClosureRow, build_activation_rows};
pub use model::{
    ChildCountFilter, ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus,
    TenantUpdate,
};
pub use repo::TenantRepo;
pub use retention::{
    HardDeleteOutcome, HardDeleteResult, ReaperResult, TenantProvisioningRow, TenantRetentionRow,
    is_due, order_batch_leaf_first,
};
