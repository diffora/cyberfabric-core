//! Pure-Rust repair planner for derivable closure violations.
//!
//! Mirrors the classifier subsystem in `infra/storage/integrity/classifiers/`:
//! a synchronous, DB-free function over a [`Snapshot`] that produces the
//! INSERT / UPDATE / DELETE operations needed to bring `tenant_closure`
//! into agreement with the authoritative `tenants` + parent-walk view.
//!
//! Closure is a denormalisation of `tenants` + `parent_id`; for every
//! healthy tenant the planner re-derives the expected self-row +
//! strict-ancestor edges and diffs the result against the snapshot's
//! actual closure rows. Five derivable categories are emitted as
//! repair ops; the other five are emitted as deferred counts for
//! operator triage.
//!
//! "Healthy" means: tenant is in the snapshot, in scope, NOT a member
//! of any `parent_id` cycle, AND its parent-walk reaches a root
//! without hitting an absent ancestor (orphan-affected). Cycle and
//! orphan-affected tenants are skipped because the parent-walk that
//! defines their expected closure does not converge — operator triage
//! is required before repair can produce a meaningful target state.
//!
//! The planner does NOT touch the `tenants` table. `DepthMismatch` and
//! `RootCountAnomaly` are flagged in the deferred bucket but the row
//! is otherwise eligible for closure repair (closure shape is derived
//! by re-walking `parent_id`, not by reading stored `depth`).

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::domain::tenant::integrity::{IntegrityCategory, IntegrityScope, RepairReport};
use crate::domain::tenant::model::TenantStatus;

use super::snapshot::Snapshot;

/// One closure row to insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureInsert {
    pub ancestor_id: Uuid,
    pub descendant_id: Uuid,
    pub barrier: i16,
    pub descendant_status: TenantStatus,
}

/// One barrier-column update on an existing closure row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierUpdate {
    pub ancestor_id: Uuid,
    pub descendant_id: Uuid,
    pub new_barrier: i16,
}

/// Bulk descendant-status update — every closure row with the given
/// `descendant_id` is rewritten to `new_status`. One entry per tenant
/// whose closure rows diverged from `tenants.status`; the executor
/// issues a single `UPDATE ... WHERE descendant_id = X` per entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusUpdate {
    pub descendant_id: Uuid,
    pub new_status: TenantStatus,
}

/// Diff between authoritative (`tenants` + parent-walk) and observed
/// (`tenant_closure`) closure shape, plus per-category counts for the
/// final [`RepairReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairPlan {
    pub inserts: Vec<ClosureInsert>,
    pub deletes: Vec<(Uuid, Uuid)>,
    pub barrier_updates: Vec<BarrierUpdate>,
    pub status_updates: Vec<StatusUpdate>,
    pub repaired_per_category: Vec<(IntegrityCategory, usize)>,
    pub deferred_per_category: Vec<(IntegrityCategory, usize)>,
}

impl RepairPlan {
    /// Total number of logical write operations in this plan.
    ///
    /// Note: `status_updates` is counted per descendant, not per
    /// `tenant_closure` row rewritten by the executor. A single
    /// `StatusUpdate` resolves to one bulk `UPDATE ... WHERE
    /// descendant_id = X` statement that may rewrite multiple rows.
    /// Use this as the planner-side activity count (matches the
    /// per-category emitter in [`RepairReport`]); the executor-side
    /// "rows touched" count is owned by the storage layer instead.
    #[must_use]
    pub fn total_ops(&self) -> usize {
        self.inserts.len()
            + self.deletes.len()
            + self.barrier_updates.len()
            + self.status_updates.len()
    }

    /// Lift this plan into a [`RepairReport`] for the given scope.
    /// Both `repaired_per_category` and `deferred_per_category` are
    /// emitted in fixed [`IntegrityCategory::all`] order; absent
    /// categories carry zero counts so dashboards see a consistent
    /// per-category gauge surface across runs.
    #[must_use]
    pub fn into_report(self, scope: IntegrityScope) -> RepairReport {
        RepairReport {
            scope: Some(scope),
            repaired_per_category: self.repaired_per_category,
            deferred_per_category: self.deferred_per_category,
        }
    }
}

/// Compute the repair plan for the given `(tenants, tenant_closure)`
/// snapshot. `scope_root` follows the same convention as
/// `classifiers::run`: `None` for whole-tree, `Some(root)` for subtree
/// (membership = `root` itself OR `(root, t)` present in the
/// snapshot's closure).
///
/// The plan is deterministic: inserts / deletes / updates are emitted
/// in tenant-id (and ancestor-id) sort order so two runs over the
/// same snapshot produce identical plans (matters for property tests
/// asserting idempotency).
#[must_use]
pub fn compute_repair_plan(snap: &Snapshot, scope_root: Option<Uuid>) -> RepairPlan {
    // Index `parent_id` adjacency once so every walk in this planner
    // is O(depth) rather than O(N) lookups per step.
    let mut parent_of: HashMap<Uuid, Option<Uuid>> = HashMap::with_capacity(snap.tenants().len());
    for t in snap.tenants() {
        parent_of.insert(t.id, t.parent_id);
    }

    // Pre-classify the corruption sites that disqualify a tenant from
    // automated closure repair (cycle / orphan-affected). Both share
    // the bounded-walk shape used by `classifiers::cycle` and
    // `classifiers::strict_ancestor`; we redo the walks here so the
    // planner is self-contained and doesn't pay the cost of running
    // the full classifier set first.
    let cycle_members = identify_cycle_members(snap, &parent_of);
    let orphan_affected = identify_orphan_affected(snap, &parent_of);

    let cap = snap.tenants().len();

    // === Pass 1: derive expected closure for every healthy in-scope tenant. ===
    //
    // For each tenant T in scope, walk T's parent chain to the root
    // (terminating on cycle / orphan / depth-cap to be safe even
    // though both are filtered above). At each step record:
    //   * (T, T) self-row with barrier=0, descendant_status=T.status
    //   * (A, T) strict-ancestor row with barrier derived from the
    //     `(A, T]` strict path's self_managed flags
    //
    // `expected_rows[(a, d)] = (barrier, descendant_status)`.
    let mut expected_rows: HashMap<(Uuid, Uuid), (i16, TenantStatus)> = HashMap::new();
    let mut healthy_in_scope: HashSet<Uuid> = HashSet::new();

    for t in snap.tenants() {
        if !snap.is_in_scope(scope_root, t.id) {
            continue;
        }
        if cycle_members.contains(&t.id) || orphan_affected.contains(&t.id) {
            continue;
        }
        healthy_in_scope.insert(t.id);

        // Self-row.
        expected_rows.insert((t.id, t.id), (0, t.status));

        // Walk strict ancestors. Track `has_self_managed` over the
        // strict `(A, D]` path — i.e. include nodes on the path
        // walked-to-far excluding the current ancestor we're about to
        // step to. This matches `classifiers::barrier` semantics.
        let mut cursor = t.parent_id;
        let mut has_self_managed = t.self_managed; // descendant itself counted
        let mut visited: HashSet<Uuid> = HashSet::new();
        visited.insert(t.id);
        let mut steps = 0usize;
        while let Some(anc) = cursor {
            if !visited.insert(anc) || steps > cap {
                break; // belt-and-suspenders: cycle/orphan guards above
            }
            steps += 1;
            let Some(anc_t) = snap.tenant(anc) else {
                break; // orphan parent — guarded by orphan_affected pass
            };
            let barrier = i16::from(has_self_managed);
            expected_rows.insert((anc, t.id), (barrier, t.status));
            // Update `has_self_managed` AFTER recording the row so
            // the ancestor's own `self_managed` only flips the
            // barrier for ancestors *above* it.
            if anc_t.self_managed {
                has_self_managed = true;
            }
            cursor = parent_of.get(&anc).copied().flatten();
        }
    }

    // === Pass 2: diff actual closure vs expected. ===
    //
    // For every actual closure row whose descendant is in scope:
    //   * if descendant is unhealthy (cycle / orphan-affected /
    //     missing from tenants entirely) → DELETE (StaleClosureRow).
    //   * else if (a, d) not in expected → DELETE (StaleClosureRow).
    //   * else if barrier mismatches → UPDATE (BarrierColumnDivergence).
    //   * descendant_status mismatch is handled per-tenant after the
    //     row pass so a single `UPDATE ... WHERE descendant_id = X`
    //     replaces N per-row updates.
    //
    // Self-rows (a == d) cannot host a barrier mismatch (the schema
    // CHECK pins them at 0); barrier checks below skip self-rows.
    let mut deletes: Vec<(Uuid, Uuid)> = Vec::new();
    let mut barrier_updates: Vec<BarrierUpdate> = Vec::new();
    let mut actual_keyed: HashSet<(Uuid, Uuid)> = HashSet::new();
    let mut status_divergent_tenants: HashMap<Uuid, TenantStatus> = HashMap::new();

    for c in snap.closure() {
        // Subtree-scope filter mirrors the classifiers: we operate
        // only on rows whose descendant is in scope. Whole-scope
        // (`scope_root == None`) sees every row.
        if !snap.is_in_scope(scope_root, c.descendant_id) {
            continue;
        }

        let key = (c.ancestor_id, c.descendant_id);
        actual_keyed.insert(key);

        let descendant_healthy = healthy_in_scope.contains(&c.descendant_id);
        let ancestor_present = snap.has_tenant(c.ancestor_id);

        if !descendant_healthy || !ancestor_present {
            // Descendant unhealthy (cycle/orphan/missing) OR ancestor
            // missing → row cannot be derived, classify as stale.
            // Cycle / orphan members of the descendant role are
            // explicitly EXCLUDED from delete list because operator
            // triage is required for cycle/orphan; only truly absent
            // descendants (cleaned up by hard_delete after this row
            // existed) get DELETE'd.
            if !snap.has_tenant(c.descendant_id) || !ancestor_present {
                deletes.push(key);
            }
            continue;
        }

        match expected_rows.get(&key) {
            None => deletes.push(key),
            Some((expected_barrier, expected_status)) => {
                if c.ancestor_id != c.descendant_id && c.barrier != *expected_barrier {
                    barrier_updates.push(BarrierUpdate {
                        ancestor_id: c.ancestor_id,
                        descendant_id: c.descendant_id,
                        new_barrier: *expected_barrier,
                    });
                }
                if c.descendant_status != *expected_status {
                    // Aggregate at descendant level — every row for
                    // this descendant takes the same target status.
                    status_divergent_tenants.insert(c.descendant_id, *expected_status);
                }
            }
        }
    }

    // === Pass 3: missing INSERTs (rows in expected but not in actual). ===
    let mut inserts: Vec<ClosureInsert> = Vec::new();
    for (&(ancestor_id, descendant_id), &(barrier, descendant_status)) in &expected_rows {
        if actual_keyed.contains(&(ancestor_id, descendant_id)) {
            continue;
        }
        inserts.push(ClosureInsert {
            ancestor_id,
            descendant_id,
            barrier,
            descendant_status,
        });
    }

    // Stable order — INSERTs by (descendant, ancestor), DELETEs by
    // (ancestor, descendant), UPDATEs by their key. Idempotency
    // tests assert the planner is deterministic across runs.
    inserts.sort_by(|a, b| {
        a.descendant_id
            .cmp(&b.descendant_id)
            .then_with(|| a.ancestor_id.cmp(&b.ancestor_id))
    });
    deletes.sort();
    barrier_updates.sort_by(|a, b| {
        a.descendant_id
            .cmp(&b.descendant_id)
            .then_with(|| a.ancestor_id.cmp(&b.ancestor_id))
    });
    let mut status_updates: Vec<StatusUpdate> = status_divergent_tenants
        .into_iter()
        .map(|(descendant_id, new_status)| StatusUpdate {
            descendant_id,
            new_status,
        })
        .collect();
    status_updates.sort_by_key(|u| u.descendant_id);

    // === Pass 4: per-category counts for the report. ===
    //
    // Inserts split by self-row vs strict edge → MissingClosureSelfRow
    // / ClosureCoverageGap. Deletes always count as StaleClosureRow.
    // Barrier updates always count as BarrierColumnDivergence. Status
    // updates always count as DescendantStatusDivergence (one per
    // affected tenant — matches operator-visible "tenants needing
    // status realignment" rather than "rows touched").
    let mut missing_self_row = 0usize;
    let mut closure_coverage_gap = 0usize;
    for ins in &inserts {
        if ins.ancestor_id == ins.descendant_id {
            missing_self_row += 1;
        } else {
            closure_coverage_gap += 1;
        }
    }

    let repaired_per_category = vec![
        (IntegrityCategory::MissingClosureSelfRow, missing_self_row),
        (IntegrityCategory::ClosureCoverageGap, closure_coverage_gap),
        (IntegrityCategory::StaleClosureRow, deletes.len()),
        (
            IntegrityCategory::BarrierColumnDivergence,
            barrier_updates.len(),
        ),
        (
            IntegrityCategory::DescendantStatusDivergence,
            status_updates.len(),
        ),
    ];

    // Deferred counts come from the four non-derivable classifiers
    // (five categories: `orphan` emits both `OrphanedChild` and
    // `BrokenParentReference`). Running the derivable classifiers
    // here would duplicate the repair pass we just computed.
    let deferred_per_category = compute_deferred_counts(snap, scope_root);

    RepairPlan {
        inserts,
        deletes,
        barrier_updates,
        status_updates,
        repaired_per_category,
        deferred_per_category,
    }
}

/// Tenants whose `parent_id` walk re-enters its own path. These rows
/// are skipped by the planner because the parent-walk that defines
/// the expected closure does not converge.
fn identify_cycle_members(
    snap: &Snapshot,
    parent_of: &HashMap<Uuid, Option<Uuid>>,
) -> HashSet<Uuid> {
    let mut visited: HashSet<Uuid> = HashSet::new();
    let mut on_cycle: HashSet<Uuid> = HashSet::new();

    for t in snap.tenants() {
        if visited.contains(&t.id) {
            continue;
        }
        let mut path: Vec<Uuid> = Vec::new();
        let mut path_set: HashSet<Uuid> = HashSet::new();
        let mut cursor: Option<Uuid> = Some(t.id);
        while let Some(node) = cursor {
            if visited.contains(&node) {
                break;
            }
            if path_set.contains(&node)
                && let Some(idx) = path.iter().position(|p| *p == node)
            {
                for n in &path[idx..] {
                    on_cycle.insert(*n);
                }
                break;
            }
            path.push(node);
            path_set.insert(node);
            cursor = parent_of.get(&node).copied().flatten();
        }
        for n in &path {
            visited.insert(*n);
        }
    }

    on_cycle
}

/// Tenants whose parent-walk hits an ancestor that is missing from
/// the snapshot (orphaned chain) **or** enters a cycle. These rows
/// are skipped by the planner because the expected closure target
/// is undefined until the operator resolves the upstream corruption
/// (orphan repair → re-link or hard-delete; cycle repair → break a
/// `parent_id` edge). Auto-committing closure rows for cycle-tail
/// tenants while a cycle persists would commit closure under a
/// `parent_id` state that is by construction in flux.
///
/// Walks are amortised across tenants: once a node has been
/// classified as `Affected` (orphan-affected or cycle-tail) or
/// `Clean`, every tenant passing through it inherits the result
/// without re-walking. This matches the pattern in
/// `identify_cycle_members` and turns the otherwise-quadratic worst
/// case (a deep subtree under a missing ancestor) into linear work
/// in the snapshot size.
fn identify_orphan_affected(
    snap: &Snapshot,
    parent_of: &HashMap<Uuid, Option<Uuid>>,
) -> HashSet<Uuid> {
    enum Verdict {
        Affected,
        Clean,
    }

    let mut decided: HashMap<Uuid, Verdict> = HashMap::with_capacity(snap.tenants().len());
    let mut affected: HashSet<Uuid> = HashSet::new();
    let cap = snap.tenants().len();

    for t in snap.tenants() {
        if decided.contains_key(&t.id) {
            continue;
        }
        // Walk and record the path. Stop when we reach a decided
        // node (inherit its verdict), a missing ancestor (orphan-
        // affected), a cycle (cycle-tail — also affected because
        // the closure target is undefined), or the root (clean).
        let mut path: Vec<Uuid> = vec![t.id];
        let mut path_set: HashSet<Uuid> = HashSet::from([t.id]);
        let mut cursor = t.parent_id;
        let mut steps = 0usize;
        let verdict = loop {
            let Some(anc) = cursor else {
                break Verdict::Clean; // walked to a root; no missing ancestor on the path
            };
            if path_set.contains(&anc) || steps > cap {
                // Cycle reached. The cycle members themselves are
                // surfaced by the cycle classifier; tail-tenants
                // upstream of the cycle (this branch) are
                // additionally treated as affected so the planner
                // does not commit closure rows under a corrupted
                // `parent_id` chain. The closure under the cycle is
                // structurally undefined: any choice the operator
                // makes when breaking the cycle (NULLing one edge,
                // re-linking elsewhere) changes the canonical
                // `parent_id` walk for these descendants, so
                // pre-committing closure rows would just need to be
                // re-validated and possibly rewritten anyway.
                break Verdict::Affected;
            }
            if let Some(prev) = decided.get(&anc) {
                break match prev {
                    Verdict::Affected => Verdict::Affected,
                    Verdict::Clean => Verdict::Clean,
                };
            }
            if !snap.has_tenant(anc) {
                break Verdict::Affected;
            }
            path.push(anc);
            path_set.insert(anc);
            steps += 1;
            cursor = parent_of.get(&anc).copied().flatten();
        };

        let is_affected = matches!(verdict, Verdict::Affected);
        for node in path {
            decided.insert(
                node,
                if is_affected {
                    Verdict::Affected
                } else {
                    Verdict::Clean
                },
            );
            if is_affected {
                affected.insert(node);
            }
        }
    }

    affected
}

/// Run the four non-derivable classifiers (orphan + cycle + depth +
/// root, emitting five categories) and return per-category violation
/// counts in fixed [`IntegrityCategory::all`] order.
fn compute_deferred_counts(
    snap: &Snapshot,
    scope_root: Option<Uuid>,
) -> Vec<(IntegrityCategory, usize)> {
    use super::classifiers;
    let report = classifiers::run_non_derivable(snap, scope_root);
    let mut by_cat: HashMap<IntegrityCategory, usize> = HashMap::new();
    for v in &report {
        *by_cat.entry(v.category).or_insert(0) += 1;
    }
    [
        IntegrityCategory::OrphanedChild,
        IntegrityCategory::BrokenParentReference,
        IntegrityCategory::DepthMismatch,
        IntegrityCategory::Cycle,
        IntegrityCategory::RootCountAnomaly,
    ]
    .into_iter()
    .map(|c| (c, by_cat.get(&c).copied().unwrap_or(0)))
    .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "repair_tests.rs"]
mod repair_tests;
