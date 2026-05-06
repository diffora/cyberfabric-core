//! Pure-Rust integrity classifiers operating over an in-memory
//! [`Snapshot`](super::snapshot::Snapshot).
//!
//! Each submodule implements one classifier as a synchronous,
//! DB-free function over `&Snapshot`. The 8-file layout matches the
//! 8 canonical classifier names from phase-01 spec; the ten
//! [`IntegrityCategory`](crate::domain::tenant::integrity::IntegrityCategory)
//! variants are produced by these eight files (some classifiers emit
//! more than one category — see `orphan.rs` and `barrier.rs` for the
//! grouped cases).
//!
//! The single entry point used by the rest of the audit pipeline is
//! [`run`], which dispatches to each classifier in fixed order and
//! returns the concatenated `Vec<Violation>`. The aggregation into the
//! per-category [`IntegrityReport`](crate::domain::tenant::integrity::IntegrityReport)
//! lives in `audit::run_classifiers`.

mod barrier;
mod cycle;
mod depth;
mod extra_edge;
mod orphan;
mod root;
mod self_row;
mod strict_ancestor;

use uuid::Uuid;

use crate::domain::tenant::integrity::Violation;

use super::snapshot::Snapshot;

/// Run every classifier in order and return the concatenated violations.
pub(super) fn run(snap: &Snapshot, scope_root: Option<Uuid>) -> Vec<Violation> {
    let mut all = Vec::new();
    all.extend(orphan::classify(snap, scope_root));
    all.extend(cycle::classify(snap, scope_root));
    all.extend(depth::classify(snap, scope_root));
    all.extend(self_row::classify(snap, scope_root));
    all.extend(strict_ancestor::classify(snap, scope_root));
    all.extend(extra_edge::classify(snap, scope_root));
    all.extend(root::classify(snap, scope_root));
    all.extend(barrier::classify(snap, scope_root));
    all
}

/// Run only the **non-derivable** (operator-triage) classifiers and
/// return the concatenated violations.
///
/// Four classifiers, five categories:
/// `orphan` (`OrphanedChild`, `BrokenParentReference`), `cycle`,
/// `depth`, `root`. The other four classifiers (`self_row`,
/// `strict_ancestor`, `extra_edge`, `barrier`) emit derivable
/// categories that auto-repair handles, so the repair planner
/// counts only the deferred ones via this entry.
pub(super) fn run_non_derivable(snap: &Snapshot, scope_root: Option<Uuid>) -> Vec<Violation> {
    let mut all = Vec::new();
    all.extend(orphan::classify(snap, scope_root));
    all.extend(cycle::classify(snap, scope_root));
    all.extend(depth::classify(snap, scope_root));
    all.extend(root::classify(snap, scope_root));
    all
}
