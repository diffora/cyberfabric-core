//! Hierarchy-integrity types consumed by the Rust-side classifier.
//!
//! The classifier itself lives in
//! `crate::infra::storage::integrity::classifiers/`: 8 pure-Rust functions
//! run synchronously over an in-memory `(tenants, tenant_closure)`
//! snapshot loaded via `SecureSelect` inside a read-only
//! `REPEATABLE READ` transaction (see `integrity::run_integrity_check`).
//! The single-flight gate (`integrity_check_runs`) acquires and
//! releases in **separate** short committed transactions outside the
//! snapshot tx — see `integrity::lock` for the three-transaction
//! lifecycle. Together the 8 classifiers emit the 10 fixed-shape
//! categories enumerated by [`IntegrityCategory::all`].
//!
//! This module retains the type vocabulary shared by:
//!
//! * the `TenantRepo::run_integrity_check_for_scope` trait surface, which
//!   returns a flat `Vec<(IntegrityCategory, Violation)>` per scope.
//! * the `TenantService::check_hierarchy_integrity` orchestrator, which
//!   re-buckets the flat pairs into a fixed-order [`IntegrityReport`]
//!   and emits one gauge sample per category.

use modkit_macros::domain_model;
use uuid::Uuid;

/// Scope of an integrity run.
#[domain_model]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum IntegrityScope {
    /// Scan every tenant + closure row in the module.
    #[default]
    Whole,
    /// Scan only the subtree rooted at the given tenant id (inclusive).
    /// The repository's snapshot loader narrows the **closure**
    /// SELECT by `descendant_id ∈ subtree-membership` (computed from
    /// `tenants.parent_id`), so closure rows whose ancestor lives
    /// OUTSIDE the subtree are intentionally retained — those edges
    /// are needed for orphan / cycle / strict-ancestor detection at
    /// the subtree boundary. The classifier therefore expects
    /// descendant-only membership rather than "both endpoints in
    /// subtree".
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

    /// Whether any violation in a derivable category (one that
    /// `repair_hierarchy_integrity` can self-heal — see
    /// [`IntegrityCategory::is_derivable`]) is present. The periodic
    /// integrity-check loop uses this to decide whether to chain a
    /// repair tick after a successful check tick.
    #[must_use]
    pub fn has_derivable_violations(&self) -> bool {
        self.violations_by_category
            .iter()
            .any(|(cat, v)| cat.is_derivable() && !v.is_empty())
    }
}

impl IntegrityCategory {
    /// Whether the category's correct state is fully derivable from
    /// `tenants` + `parent_id` walk (i.e. closure is the
    /// denormalisation, `tenants` is authoritative). Repair touches
    /// only derivable categories; the remaining ones indicate
    /// corruption in `tenants` itself and require operator triage.
    ///
    /// Derivable (5):
    /// * [`IntegrityCategory::MissingClosureSelfRow`]
    /// * [`IntegrityCategory::ClosureCoverageGap`]
    /// * [`IntegrityCategory::StaleClosureRow`]
    /// * [`IntegrityCategory::BarrierColumnDivergence`]
    /// * [`IntegrityCategory::DescendantStatusDivergence`]
    ///
    /// Operator-triage only (5):
    /// * [`IntegrityCategory::OrphanedChild`]
    /// * [`IntegrityCategory::BrokenParentReference`]
    /// * [`IntegrityCategory::DepthMismatch`]
    /// * [`IntegrityCategory::Cycle`]
    /// * [`IntegrityCategory::RootCountAnomaly`]
    #[must_use]
    pub const fn is_derivable(self) -> bool {
        matches!(
            self,
            Self::MissingClosureSelfRow
                | Self::ClosureCoverageGap
                | Self::StaleClosureRow
                | Self::BarrierColumnDivergence
                | Self::DescendantStatusDivergence
        )
    }
}

/// Result of a single hierarchy-integrity repair run.
///
/// `repaired_per_category` and `deferred_per_category` are both in
/// [`IntegrityCategory::all`] order and **always** carry one entry
/// per derivable / non-derivable category respectively (zero count
/// for categories that did not appear in the snapshot). Callers can
/// rely on this fixed shape for dashboards and per-category metric
/// emission.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    /// Scope this report describes. `None` means "caller did not
    /// declare a scope" (e.g. a fresh `RepairReport::default()` used
    /// as a placeholder); production paths should always populate
    /// this via [`RepairReport::empty`] or `into_report` so the
    /// report cannot misreport its own scope.
    pub scope: Option<IntegrityScope>,
    /// Per-category count of closure rows touched (INSERT / UPDATE /
    /// DELETE). One entry per derivable
    /// [`IntegrityCategory`](IntegrityCategory::is_derivable) in
    /// fixed [`IntegrityCategory::all`] order.
    pub repaired_per_category: Vec<(IntegrityCategory, usize)>,
    /// Per-category count of violations the repair did not fix
    /// because the category is non-derivable (operator triage
    /// required). One entry per non-derivable category in fixed
    /// order.
    pub deferred_per_category: Vec<(IntegrityCategory, usize)>,
}

impl RepairReport {
    /// Build an empty report for the given `scope` whose per-category
    /// vectors honour the fixed-shape contract: one entry per
    /// derivable category in `repaired_per_category`, one entry per
    /// non-derivable category in `deferred_per_category`, all counts
    /// zero. Dashboards keyed on category labels stay aligned across
    /// "no run" / "clean run" / "non-zero run" states.
    ///
    /// Prefer this over `Default::default()` for any path with a
    /// known scope so a clean repair tick reports the actual scope
    /// rather than `None`.
    #[must_use]
    pub fn empty(scope: IntegrityScope) -> Self {
        let mut repaired_per_category: Vec<(IntegrityCategory, usize)> = Vec::new();
        let mut deferred_per_category: Vec<(IntegrityCategory, usize)> = Vec::new();
        for cat in IntegrityCategory::all() {
            if cat.is_derivable() {
                repaired_per_category.push((cat, 0));
            } else {
                deferred_per_category.push((cat, 0));
            }
        }
        Self {
            scope: Some(scope),
            repaired_per_category,
            deferred_per_category,
        }
    }

    /// Total number of closure rows touched.
    #[must_use]
    pub fn total_repaired(&self) -> usize {
        self.repaired_per_category.iter().map(|(_, c)| *c).sum()
    }

    /// Total number of deferred (non-derivable) violations.
    #[must_use]
    pub fn total_deferred(&self) -> usize {
        self.deferred_per_category.iter().map(|(_, c)| *c).sum()
    }
}

impl Default for RepairReport {
    /// Returns an empty, fixed-shape report with `scope: None`
    /// (scope-unspecified). Provided for ergonomics in test mocks
    /// and placeholder values; production paths SHOULD use
    /// [`RepairReport::empty`] with the actual scope so the report
    /// carries the scope it ran against rather than a neutral
    /// `None`.
    ///
    /// Delegates the per-category construction to
    /// [`RepairReport::empty`] so the fixed-shape contract (one
    /// entry per derivable / non-derivable category in
    /// [`IntegrityCategory::all`] order) lives in exactly one place
    /// and cannot drift between the two builders.
    fn default() -> Self {
        let mut report = Self::empty(IntegrityScope::default());
        report.scope = None;
        report
    }
}
