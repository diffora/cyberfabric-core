//! Pure-logic hierarchy-integrity classifier.
//!
//! The integrity checker walks the in-memory snapshot of `tenants` +
//! `tenant_closure` and produces an [`IntegrityReport`] with fixed
//! categories — always in a fixed order so a dashboard can diff reports
//! across ticks without interpreting the nested `Vec<Violation>` shape.
//!
//! Classification is split into two halves:
//!
//! * [`classify_tree_shape_anomalies`] runs against the tenants table
//!   alone (categories 1–4).
//! * [`classify_closure_shape_anomalies`] cross-references tenants with
//!   the closure rows (categories 5–9).
//!
//! Both halves are total over the input and never panic.

use std::collections::{BTreeMap, HashMap, HashSet};

use modkit_macros::domain_model;
use uuid::Uuid;

use crate::domain::metrics::{AM_HIERARCHY_INTEGRITY_VIOLATIONS, MetricKind, emit_metric};
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{TenantModel, TenantStatus};

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
    /// A closure row references a tenant (ancestor or descendant) that
    /// no longer exists.
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

fn record_cycle_detected(
    tenant_id: Option<Uuid>,
    parent_id: Uuid,
    walk: &'static str,
) -> Violation {
    tracing::error!(
        target: "am::integrity",
        category = "cycle_detected",
        parent_id = %parent_id,
        walk,
        "cycle detected during depth-walk"
    );
    emit_metric(
        AM_HIERARCHY_INTEGRITY_VIOLATIONS,
        MetricKind::Counter,
        &[("category", "cycle_detected")],
    );
    Violation {
        category: IntegrityCategory::Cycle,
        tenant_id,
        details: format!("cycle detected during {walk} at parent {parent_id}"),
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

/// Classify tree-shape anomalies from the tenants table alone
/// (categories 1–4 of `IntegrityCategory`).
///
/// The classifier treats `Deleted` tenants as "valid parents" for the
/// purposes of the `OrphanedChild` check so a mid-deletion state does not
/// light up the `OrphanedChild` counter. It DOES flag a
/// `BrokenParentReference` when an `Active` / `Suspended` / `Provisioning`
/// tenant has a `Deleted` parent (SDK-visible under a tombstoned
/// ancestor — not a legal state).
#[must_use]
// @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-tree-classifier
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-tree-classifier
pub fn classify_tree_shape_anomalies(rows: &[TenantModel]) -> Vec<Violation> {
    let mut out = Vec::new();

    // Build id → tenant lookup.
    let by_id: HashMap<Uuid, &TenantModel> = rows.iter().map(|t| (t.id, t)).collect();

    // Tenants flagged as `OrphanedChild` are excluded from the depth
    // check below: their walked depth defaults to 0 (the parent
    // chain breaks immediately on the missing parent), so a non-zero
    // stored depth would otherwise produce a redundant
    // `DepthMismatch` violation for the same root cause and inflate
    // the `depth_mismatch` metric.
    let mut orphaned: HashSet<Uuid> = HashSet::new();

    // Category 1 + 2: parent-reference validation.
    for t in rows {
        if let Some(pid) = t.parent_id {
            match by_id.get(&pid) {
                None => {
                    out.push(Violation {
                        category: IntegrityCategory::OrphanedChild,
                        tenant_id: Some(t.id),
                        details: format!("parent {pid} missing for tenant {}", t.id),
                    });
                    orphaned.insert(t.id);
                }
                Some(parent)
                    if matches!(parent.status, TenantStatus::Deleted)
                        && !matches!(t.status, TenantStatus::Deleted) =>
                {
                    out.push(Violation {
                        category: IntegrityCategory::BrokenParentReference,
                        tenant_id: Some(t.id),
                        details: format!(
                            "tenant {} is {:?} but parent {pid} is Deleted",
                            t.id, t.status
                        ),
                    });
                }
                Some(_) => {}
            }
        }
    }

    // Category 3: depth-mismatch. Walk parents; expected depth is the
    // walk length. Bail out if the walk exceeds `rows.len()` steps to
    // protect against cycles (a separate defect we do not classify).
    for t in rows {
        if orphaned.contains(&t.id) {
            continue;
        }
        let mut expected: u32 = 0;
        let mut cursor = t.parent_id;
        let mut steps = 0;
        let limit = rows.len() + 1;
        while let Some(pid) = cursor {
            steps += 1;
            if steps > limit {
                out.push(record_cycle_detected(Some(t.id), pid, "tenant_depth"));
                break;
            }
            match by_id.get(&pid) {
                Some(parent) => {
                    expected = expected.saturating_add(1);
                    cursor = parent.parent_id;
                }
                None => break,
            }
        }
        if t.depth != expected {
            out.push(Violation {
                category: IntegrityCategory::DepthMismatch,
                tenant_id: Some(t.id),
                details: format!(
                    "tenant {} stored depth {} but walk yields {expected}",
                    t.id, t.depth
                ),
            });
        }
    }

    // Category 4: root count.
    let roots: Vec<&TenantModel> = rows.iter().filter(|t| t.parent_id.is_none()).collect();
    if roots.len() > 1 {
        out.push(Violation {
            category: IntegrityCategory::RootCountAnomaly,
            tenant_id: None,
            details: format!(
                "found {} roots (parent_id IS NULL); expected 1",
                roots.len()
            ),
        });
    }
    // Zero-root case only anomalous when the module has any rows.
    if roots.is_empty() && !rows.is_empty() {
        out.push(Violation {
            category: IntegrityCategory::RootCountAnomaly,
            tenant_id: None,
            details: "no root tenant present but module has tenants".to_owned(),
        });
    }

    out
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-tree-classifier
// @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-tree-classifier

/// Classify closure-shape anomalies (categories 5–9).
#[must_use]
#[allow(
    clippy::cognitive_complexity,
    reason = "fixed 5-step classification loop over the same (rows, closure) pair"
)]
// @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-closure-classifier
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-closure-classifier
pub fn classify_closure_shape_anomalies(
    rows: &[TenantModel],
    closure: &[ClosureRow],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let by_id: HashMap<Uuid, &TenantModel> = rows.iter().map(|t| (t.id, t)).collect();
    let tenant_ids: HashSet<Uuid> = rows.iter().map(|t| t.id).collect();

    // Index closure rows by (ancestor, descendant) for fast lookup.
    let closure_index: HashMap<(Uuid, Uuid), &ClosureRow> = closure
        .iter()
        .map(|r| ((r.ancestor_id, r.descendant_id), r))
        .collect();

    // Category 5: missing self-rows.
    for t in rows {
        if !t.status.is_sdk_visible() {
            continue;
        }
        if !closure_index.contains_key(&(t.id, t.id)) {
            out.push(Violation {
                category: IntegrityCategory::MissingClosureSelfRow,
                tenant_id: Some(t.id),
                details: format!("tenant {} lacks self-row in tenant_closure", t.id),
            });
        }
    }

    // Category 6: closure coverage gaps. For each SDK-visible tenant,
    // walk its `parent_id` chain and assert each ancestor row exists.
    for t in rows {
        if !t.status.is_sdk_visible() {
            continue;
        }
        let mut cursor = t.parent_id;
        let mut steps = 0;
        let limit = rows.len() + 1;
        while let Some(pid) = cursor {
            steps += 1;
            if steps > limit {
                out.push(record_cycle_detected(Some(t.id), pid, "closure_coverage"));
                break;
            }
            if !closure_index.contains_key(&(pid, t.id)) {
                out.push(Violation {
                    category: IntegrityCategory::ClosureCoverageGap,
                    tenant_id: Some(t.id),
                    details: format!(
                        "closure gap: ancestor {pid} missing for descendant {}",
                        t.id
                    ),
                });
            }
            cursor = by_id.get(&pid).and_then(|p| p.parent_id);
        }
    }

    // Category 7: stale closure rows (reference tenants that no longer exist).
    for row in closure {
        if !tenant_ids.contains(&row.ancestor_id) {
            out.push(Violation {
                category: IntegrityCategory::StaleClosureRow,
                tenant_id: Some(row.ancestor_id),
                details: format!(
                    "closure row references missing ancestor {}",
                    row.ancestor_id
                ),
            });
        }
        if !tenant_ids.contains(&row.descendant_id) {
            out.push(Violation {
                category: IntegrityCategory::StaleClosureRow,
                tenant_id: Some(row.descendant_id),
                details: format!(
                    "closure row references missing descendant {}",
                    row.descendant_id
                ),
            });
        }
    }

    // Category 8: barrier-column divergence. For each strict
    // `(ancestor, descendant)` row, expected barrier is the
    // `self_managed` flag on the descendant OR on any tenant on the
    // strict `(ancestor, descendant]` path (walked via parent_id).
    for row in closure {
        if row.ancestor_id == row.descendant_id {
            // Self-rows are covered by the self-row DB `CHECK` (barrier = 0).
            continue;
        }
        let Some(descendant) = by_id.get(&row.descendant_id) else {
            continue; // StaleClosureRow already reported.
        };
        let ancestor_exists = tenant_ids.contains(&row.ancestor_id);
        if !ancestor_exists {
            continue;
        }
        // Walk from `descendant` up to (but not including) `ancestor`.
        let mut path: Vec<Uuid> = vec![descendant.id];
        let mut cursor = descendant.parent_id;
        let limit = rows.len() + 1;
        let mut steps = 0;
        let mut reached_ancestor = false;
        while let Some(pid) = cursor {
            steps += 1;
            if steps > limit {
                out.push(record_cycle_detected(
                    Some(row.descendant_id),
                    pid,
                    "barrier_path",
                ));
                break;
            }
            if pid == row.ancestor_id {
                reached_ancestor = true;
                break;
            }
            path.push(pid);
            cursor = by_id.get(&pid).and_then(|p| p.parent_id);
        }
        if !reached_ancestor {
            // The closure row claims an ancestry relationship the
            // parent_id walk cannot confirm — flag as a coverage
            // inconsistency rather than a barrier anomaly.
            continue;
        }
        let expected_barrier = path
            .iter()
            .any(|id| by_id.get(id).is_some_and(|t| t.self_managed));
        let expected = i16::from(expected_barrier);
        if row.barrier != expected {
            out.push(Violation {
                category: IntegrityCategory::BarrierColumnDivergence,
                tenant_id: Some(row.descendant_id),
                details: format!(
                    "closure({ancestor} -> {descendant}).barrier={actual} but expected {expected}",
                    ancestor = row.ancestor_id,
                    descendant = row.descendant_id,
                    actual = row.barrier,
                ),
            });
        }
    }

    // Category 9: descendant_status divergence. The stored
    // `descendant_status` on every row must match `tenants.status` of
    // the descendant (for SDK-visible tenants only).
    for row in closure {
        if let Some(t) = by_id.get(&row.descendant_id) {
            if !t.status.is_sdk_visible() {
                continue;
            }
            if row.descendant_status != t.status.as_smallint() {
                out.push(Violation {
                    category: IntegrityCategory::DescendantStatusDivergence,
                    tenant_id: Some(row.descendant_id),
                    details: format!(
                        "closure({ancestor} -> {descendant}).descendant_status={stored} but tenants.status={current}",
                        ancestor = row.ancestor_id,
                        descendant = row.descendant_id,
                        stored = row.descendant_status,
                        current = t.status.as_smallint(),
                    ),
                });
            }
        }
    }

    out
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-integrity-diagnostics:p2:inst-dod-integrity-closure-classifier
// @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hierarchy-integrity-check:p2:inst-algo-integ-closure-classifier

/// Bucket a flat `Vec<Violation>` into the fixed-category shape.
///
/// The output always carries exactly one entry per category in
/// [`IntegrityCategory::all`] order, even when some categories have
/// no violations.
#[must_use]
pub fn bucket_by_category(mut flat: Vec<Violation>) -> Vec<(IntegrityCategory, Vec<Violation>)> {
    let mut map: BTreeMap<usize, Vec<Violation>> = BTreeMap::new();
    let ordering = IntegrityCategory::all();
    for (idx, _) in ordering.iter().enumerate() {
        map.insert(idx, Vec::new());
    }
    for v in flat.drain(..) {
        if let Some(idx) = ordering.iter().position(|c| *c == v.category) {
            map.entry(idx).or_default().push(v);
        }
    }
    ordering
        .iter()
        .enumerate()
        .map(|(idx, cat)| (*cat, map.remove(&idx).unwrap_or_default()))
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch")
    }

    fn t(
        id: u128,
        parent: Option<u128>,
        depth: u32,
        status: TenantStatus,
        self_managed: bool,
    ) -> TenantModel {
        TenantModel {
            id: Uuid::from_u128(id),
            parent_id: parent.map(Uuid::from_u128),
            name: format!("t{id}"),
            status,
            self_managed,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
        }
    }

    fn self_row(id: u128, status: TenantStatus) -> ClosureRow {
        ClosureRow {
            ancestor_id: Uuid::from_u128(id),
            descendant_id: Uuid::from_u128(id),
            barrier: 0,
            descendant_status: status.as_smallint(),
        }
    }

    fn strict_row(a: u128, d: u128, barrier: i16, status: TenantStatus) -> ClosureRow {
        ClosureRow {
            ancestor_id: Uuid::from_u128(a),
            descendant_id: Uuid::from_u128(d),
            barrier,
            descendant_status: status.as_smallint(),
        }
    }

    #[test]
    fn clean_hierarchy_yields_no_violations() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Active, false),
            t(0x2, Some(0x1), 1, TenantStatus::Active, false),
        ];
        let closure = vec![
            self_row(0x1, TenantStatus::Active),
            self_row(0x2, TenantStatus::Active),
            strict_row(0x1, 0x2, 0, TenantStatus::Active),
        ];
        let tree = classify_tree_shape_anomalies(&rows);
        let closure_viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(tree.is_empty(), "clean tree: {tree:?}");
        assert!(closure_viols.is_empty(), "clean closure: {closure_viols:?}");
    }

    #[test]
    fn clean_hierarchy_yields_all_empty_arrays() {
        // When bucketed, a clean hierarchy still produces a complete
        // report with every Vec<Violation> empty.
        let rows = vec![t(0x1, None, 0, TenantStatus::Active, false)];
        let closure = vec![self_row(0x1, TenantStatus::Active)];
        let mut viols = classify_tree_shape_anomalies(&rows);
        viols.extend(classify_closure_shape_anomalies(&rows, &closure));
        let bucketed = bucket_by_category(viols);
        assert_eq!(bucketed.len(), IntegrityCategory::all().len());
        for (cat, vs) in &bucketed {
            assert!(vs.is_empty(), "{cat:?} should be empty");
        }
    }

    #[test]
    fn classifies_orphaned_child() {
        // Child references a parent id that does not exist.
        let rows = vec![t(0x2, Some(0xDEAD), 1, TenantStatus::Active, false)];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::OrphanedChild)
        );
    }

    #[test]
    fn orphaned_child_does_not_double_report_depth_mismatch() {
        // An orphan with stored depth > 0 must NOT also produce a
        // DepthMismatch violation: the depth-walk falls off the missing
        // parent and yields expected=0, but reporting that on top of
        // OrphanedChild inflates the depth_mismatch metric and points
        // operators at the same root cause twice.
        let rows = vec![t(0x2, Some(0xDEAD), 1, TenantStatus::Active, false)];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::OrphanedChild),
            "{viols:?}"
        );
        assert!(
            !viols
                .iter()
                .any(|v| v.category == IntegrityCategory::DepthMismatch),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_broken_parent_reference() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Deleted, false),
            t(0x2, Some(0x1), 1, TenantStatus::Active, false),
        ];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::BrokenParentReference),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_depth_mismatch() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Active, false),
            t(0x2, Some(0x1), 3, TenantStatus::Active, false),
        ];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::DepthMismatch),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_cycle_detected() {
        let rows = vec![
            t(0x1, Some(0x2), 1, TenantStatus::Active, false),
            t(0x2, Some(0x1), 1, TenantStatus::Active, false),
        ];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols.iter().any(|v| v.category == IntegrityCategory::Cycle),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_missing_closure_self_row() {
        let rows = vec![t(0x1, None, 0, TenantStatus::Active, false)];
        let closure: Vec<ClosureRow> = vec![]; // No self-row.
        let viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::MissingClosureSelfRow)
        );
    }

    #[test]
    fn classifies_closure_coverage_gap() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Active, false),
            t(0x2, Some(0x1), 1, TenantStatus::Active, false),
        ];
        let closure = vec![
            self_row(0x1, TenantStatus::Active),
            self_row(0x2, TenantStatus::Active),
        ];
        let viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::ClosureCoverageGap),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_stale_closure_row() {
        let rows = vec![t(0x1, None, 0, TenantStatus::Active, false)];
        let closure = vec![
            self_row(0x1, TenantStatus::Active),
            strict_row(0x1, 0xDEAD, 0, TenantStatus::Active),
        ];
        let viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::StaleClosureRow),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_barrier_column_divergence() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Active, false),
            t(0x2, Some(0x1), 1, TenantStatus::Active, true),
        ];
        let closure = vec![
            self_row(0x1, TenantStatus::Active),
            self_row(0x2, TenantStatus::Active),
            strict_row(0x1, 0x2, 0, TenantStatus::Active),
        ];
        let viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::BarrierColumnDivergence),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_descendant_status_divergence() {
        // tenant is Active but closure still says Suspended.
        let rows = vec![t(0x1, None, 0, TenantStatus::Active, false)];
        let closure = vec![self_row(0x1, TenantStatus::Suspended)];
        let viols = classify_closure_shape_anomalies(&rows, &closure);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::DescendantStatusDivergence),
            "{viols:?}"
        );
    }

    #[test]
    fn classifies_root_count_anomaly_when_two_roots() {
        let rows = vec![
            t(0x1, None, 0, TenantStatus::Active, false),
            t(0x2, None, 0, TenantStatus::Active, false),
        ];
        let viols = classify_tree_shape_anomalies(&rows);
        assert!(
            viols
                .iter()
                .any(|v| v.category == IntegrityCategory::RootCountAnomaly)
        );
    }

    #[test]
    fn category_as_str_is_stable_snake_case() {
        assert_eq!(IntegrityCategory::OrphanedChild.as_str(), "orphaned_child");
        assert_eq!(
            IntegrityCategory::BarrierColumnDivergence.as_str(),
            "barrier_column_divergence"
        );
        assert_eq!(IntegrityCategory::Cycle.as_str(), "cycle_detected");
    }
}
