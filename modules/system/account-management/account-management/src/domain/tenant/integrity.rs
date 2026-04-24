//! Hierarchy-integrity types consumed by the SQL-side classifier.
//!
//! Phases 3-4 moved the actual classification work into the storage
//! adapter (Postgres + `SQLite`), where 10 fixed-shape SQL queries return
//! a flat `Vec<(IntegrityCategory, Violation)>` per scope. This module
//! retains only the type vocabulary used by:
//!
//! * the `TenantRepo::audit_integrity_for_scope` trait surface (Phase 2)
//! * the `TenantService::check_hierarchy_integrity` orchestrator
//!   (Phase 6), which buckets the flat pairs into a fixed-order
//!   [`IntegrityReport`] and emits one gauge sample per category.
//!
//! The previous in-memory classifier was removed in the SQL-side
//! refactor. Its categories are now produced by the SQL queries
//! directly; see `feature-tenant-hierarchy-management.md` "Removed
//! Surface" for the historical mapping of the deleted in-memory
//! helpers to the SQL queries that replaced them.

use modkit_macros::domain_model;
use uuid::Uuid;

/// Scope of an integrity run.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityScope {
    /// Scan every tenant + closure row in the module.
    Whole,
    /// Scan only the subtree rooted at the given tenant id (inclusive).
    /// The caller is responsible for pre-filtering rows so only the
    /// subtree membership is passed to the classifier.
    Subtree(Uuid),
}

/// One of the integrity categories emitted by the classifier.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityCategory {
    /// A tenant row has a `parent_id` that does not resolve to any known
    /// tenant (referential hole in the hierarchy).
    OrphanedChild,
    /// A tenant has a parent that exists but is itself in an invalid
    /// state (e.g. `Deleted`) for parenting a live descendant.
    BrokenParentReference,
    /// `tenant.depth` does not match the expected depth derived by
    /// walking the `parent_id` chain to the root.
    DepthMismatch,
    /// A parent walk exceeded the bounded step count, indicating a cycle
    /// in the tenant tree.
    Cycle,
    /// More than one tenant has `parent_id IS NULL` (root-count
    /// anomaly). `DESIGN` §3.1 requires exactly one root.
    RootCountAnomaly,
    /// An SDK-visible tenant lacks its `(id, id)` self-row in
    /// `tenant_closure`.
    MissingClosureSelfRow,
    /// An ancestor is present in the `parent_id` walk but missing from
    /// the closure as an `(ancestor, tenant)` row.
    ClosureCoverageGap,
    /// A closure row that should not be in `tenant_closure`: either it
    /// references a tenant (ancestor or descendant) that no longer
    /// exists, or both endpoints exist but the asserted ancestry is not
    /// present in the `parent_id` walk.
    StaleClosureRow,
    /// `tenant_closure.barrier` is inconsistent with the `self_managed`
    /// flag on the strict path (barrier-materialization invariant).
    BarrierColumnDivergence,
    /// `tenant_closure.descendant_status` diverges from the current
    /// `tenants.status` (status-denormalization invariant).
    DescendantStatusDivergence,
}

impl IntegrityCategory {
    /// Stable camel-case token used as the `category` label value in the
    /// `AM_HIERARCHY_INTEGRITY_VIOLATIONS` metric family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrphanedChild => "orphaned_child",
            Self::BrokenParentReference => "broken_parent_reference",
            Self::DepthMismatch => "depth_mismatch",
            Self::Cycle => "cycle_detected",
            Self::RootCountAnomaly => "root_count_anomaly",
            Self::MissingClosureSelfRow => "missing_closure_self_row",
            Self::ClosureCoverageGap => "closure_coverage_gap",
            Self::StaleClosureRow => "stale_closure_row",
            Self::BarrierColumnDivergence => "barrier_column_divergence",
            Self::DescendantStatusDivergence => "descendant_status_divergence",
        }
    }

    /// The categories in report order. Every [`IntegrityReport`]
    /// has exactly one entry per category in this order.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::OrphanedChild,
            Self::BrokenParentReference,
            Self::DepthMismatch,
            Self::Cycle,
            Self::RootCountAnomaly,
            Self::MissingClosureSelfRow,
            Self::ClosureCoverageGap,
            Self::StaleClosureRow,
            Self::BarrierColumnDivergence,
            Self::DescendantStatusDivergence,
        ]
    }
}

/// A single integrity violation record.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub category: IntegrityCategory,
    /// The most-relevant tenant id for this violation, if any. Used by
    /// the operator to jump straight to the row of interest.
    pub tenant_id: Option<Uuid>,
    /// Free-form human-readable context.
    pub details: String,
}

/// Result of a single integrity run.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    pub scope: IntegrityScope,
    /// Always one entry per [`IntegrityCategory::all`] in fixed
    /// order. An empty `Vec` for a category means "no violations".
    pub violations_by_category: Vec<(IntegrityCategory, Vec<Violation>)>,
}

impl IntegrityReport {
    /// Total number of violations across all categories.
    #[must_use]
    pub fn total(&self) -> usize {
        self.violations_by_category
            .iter()
            .map(|(_, v)| v.len())
            .sum()
    }
}
