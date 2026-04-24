//! Pure-logic retention primitives for the hard-delete pipeline.
//!
//! This module owns no I/O. The service layer (`service.rs`) drives the
//! pipeline; the repository layer (`infra/storage/repo_impl.rs`) owns the
//! SQL. What lives here is the set of algebraic helpers that both layers
//! reuse:
//!
//! * [`is_due`] — half-closed retention-window inclusion test.
//! * [`order_batch_leaf_first`] — stable leaf-first batch ordering
//!   (`depth DESC, id ASC`).
//! * [`HardDeleteOutcome`] / [`HardDeleteResult`] / [`ReaperResult`] —
//!   outcome enums + aggregate summaries emitted by the service.
//!
//! Per-tenant exponential backoff lives in
//! [`crate::domain::util::backoff::compute_next_backoff`] (shared with
//! the bootstrap saga).

use std::time::Duration;

use modkit_macros::domain_model;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::metrics::{AM_RETENTION_INVALID_WINDOW, MetricKind, emit_metric};

/// A single tenant row selected by the retention scan.
///
/// `claimed_by` is the worker UUID stamped on the row during the
/// claim UPDATE inside `scan_retention_due`. The hard-delete pipeline
/// passes this token back into [`crate::domain::tenant::repo::TenantRepo::clear_retention_claim`]
/// so the clear only succeeds when the row is still owned by this
/// worker — a stale-claim takeover by a peer must NOT be reverted by
/// the original worker resuming after a TTL window.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRetentionRow {
    pub id: Uuid,
    pub depth: u32,
    pub deletion_scheduled_at: OffsetDateTime,
    pub retention_window: Duration,
    pub claimed_by: Uuid,
}

/// A single tenant row selected by the provisioning-reaper scan.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProvisioningRow {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
}

/// True iff `scheduled_at + retention <= now`. Comparison is inclusive —
/// a row whose effective reclaim timestamp equals `now` IS due.
#[must_use]
pub fn is_due(now: OffsetDateTime, scheduled_at: OffsetDateTime, retention: Duration) -> bool {
    if time::Duration::try_from(retention).is_err() {
        emit_metric(AM_RETENTION_INVALID_WINDOW, MetricKind::Counter, &[]);
        return false;
    }

    let age = now - scheduled_at;
    let Ok(elapsed) = Duration::try_from(age) else {
        return false;
    };
    elapsed >= retention
}

/// Leaf-first stable ordering for the hard-delete batch:
/// `depth DESC` (deepest first) then `id ASC` (tie-breaker).
///
/// Sorting the batch leaf-first is what lets `hard_delete_one` succeed
/// under the `ON DELETE RESTRICT` parent-FK from Phase 1: children are
/// reclaimed before their parents, so the parent's in-tx child-existence
/// guard always finds the table empty when its turn arrives.
#[must_use]
pub fn order_batch_leaf_first(mut rows: Vec<TenantRetentionRow>) -> Vec<TenantRetentionRow> {
    rows.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.id.cmp(&b.id)));
    rows
}

/// Per-row outcome of the hard-delete pipeline for a single tenant.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardDeleteOutcome {
    /// Fully reclaimed — closure and tenant rows gone.
    Cleaned,
    /// A child still exists under this tenant. Defer to a later tick;
    /// children will be cleaned first thanks to leaf-first ordering.
    DeferredChildPresent,
    /// Row failed the structural eligibility guard at hard-delete time:
    /// either `status != Deleted` or `deletion_scheduled_at IS NULL`.
    /// Temporal eligibility (`scheduled_at + retention <= now`) is
    /// established at candidate-selection time by
    /// [`crate::domain::tenant::repo::TenantRepo::scan_retention_due`]
    /// and is not re-checked here, so this variant indicates a stale
    /// candidate set or a data-integrity anomaly rather than a
    /// retention-window extension.
    NotEligible,
    /// A cascade hook returned [`crate::domain::tenant::hooks::HookError::Retryable`].
    /// Defer to next tick.
    CascadeRetryable,
    /// A cascade hook returned terminal failure. Skip this tenant; an
    /// operator must intervene.
    CascadeTerminal,
    /// `IdP` deprovision returned retryable failure. Defer.
    IdpRetryable,
    /// `IdP` deprovision returned terminal failure. Skip.
    IdpTerminal,
    /// `IdP` deprovision returned `UnsupportedOperation`. Treated as
    /// "nothing to do on the `IdP` side" — the pipeline continues
    /// with the DB teardown as if the deprovision succeeded.
    IdpUnsupported,
    /// The DB-teardown step itself failed (storage-layer error — pool
    /// exhausted, network blip, SERIALIZABLE retry budget exhausted).
    /// Distinct from `CascadeTerminal` so the metric label and the
    /// operator's mental model don't conflate cascade-hook failures
    /// with infra failures.
    StorageError,
}

impl HardDeleteOutcome {
    /// Whether the row was reclaimed from the DB in this tick.
    #[must_use]
    pub const fn is_cleaned(&self) -> bool {
        matches!(self, Self::Cleaned)
    }

    /// Whether the outcome should be counted as "deferred" (retry on
    /// a later tick with the same row still present).
    #[must_use]
    pub const fn is_deferred(&self) -> bool {
        matches!(
            self,
            Self::DeferredChildPresent | Self::CascadeRetryable | Self::IdpRetryable
        )
    }

    /// Whether the outcome should be counted as "failed" (terminal
    /// failure, tenant left in place until operator action).
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::CascadeTerminal | Self::IdpTerminal | Self::StorageError
        )
    }

    /// Stable, snake-case metric-label form of this variant. Used as
    /// the `outcome` label on `AM_TENANT_RETENTION` counter samples;
    /// kept here so the producer (service layer) does not duplicate
    /// the variant → string mapping in match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::Cleaned => "cleaned",
            Self::DeferredChildPresent => "deferred_child_present",
            Self::NotEligible => "not_eligible",
            Self::CascadeRetryable => "cascade_retryable",
            Self::CascadeTerminal => "cascade_terminal",
            Self::IdpRetryable => "idp_retryable",
            Self::IdpTerminal => "idp_terminal",
            Self::IdpUnsupported => "idp_unsupported",
            Self::StorageError => "storage_error",
        }
    }
}

/// Aggregate summary for a single hard-delete batch tick.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HardDeleteResult {
    pub processed: u64,
    pub cleaned: u64,
    pub deferred: u64,
    pub failed: u64,
}

impl HardDeleteResult {
    /// Fold a single row outcome into the running counters.
    pub fn tally(&mut self, outcome: &HardDeleteOutcome) {
        self.processed += 1;
        if outcome.is_cleaned() {
            self.cleaned += 1;
        } else if outcome.is_deferred() {
            self.deferred += 1;
        } else if outcome.is_failed() {
            self.failed += 1;
        } else {
            // `NotEligible` / `IdpUnsupported` without follow-up DB work
            // are counted under `processed` only; they are neither
            // cleaned (nothing happened) nor deferred (no need to retry).
        }
    }
}

/// Aggregate summary for a single reaper tick.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReaperResult {
    pub scanned: u64,
    pub compensated: u64,
    pub deferred: u64,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).expect("valid epoch")
    }

    #[test]
    fn is_due_crosses_boundary_inclusive() {
        let scheduled = ts(1_000_000);
        let win = Duration::from_secs(60);
        // Before boundary — not due.
        assert!(!is_due(ts(1_000_000 + 59), scheduled, win));
        // On boundary — due (inclusive).
        assert!(is_due(ts(1_000_000 + 60), scheduled, win));
        // Past boundary — due.
        assert!(is_due(ts(1_000_000 + 61), scheduled, win));
    }

    #[test]
    fn is_due_rejects_invalid_retention_window() {
        let scheduled = ts(1_000_000);
        assert!(!is_due(ts(1_000_001), scheduled, Duration::MAX));
    }

    #[test]
    fn order_batch_leaf_first_sorts_depth_desc() {
        let a = TenantRetentionRow {
            id: Uuid::from_u128(0x1),
            depth: 1,
            deletion_scheduled_at: ts(100),
            retention_window: Duration::from_secs(60),
            claimed_by: Uuid::nil(),
        };
        let b = TenantRetentionRow {
            id: Uuid::from_u128(0x2),
            depth: 3,
            deletion_scheduled_at: ts(100),
            retention_window: Duration::from_secs(60),
            claimed_by: Uuid::nil(),
        };
        let c = TenantRetentionRow {
            id: Uuid::from_u128(0x3),
            depth: 2,
            deletion_scheduled_at: ts(100),
            retention_window: Duration::from_secs(60),
            claimed_by: Uuid::nil(),
        };
        let d = TenantRetentionRow {
            id: Uuid::from_u128(0x4),
            // tie with `c` on depth=2; id order decides
            depth: 2,
            deletion_scheduled_at: ts(100),
            retention_window: Duration::from_secs(60),
            claimed_by: Uuid::nil(),
        };
        let ordered = order_batch_leaf_first(vec![a.clone(), b.clone(), c.clone(), d.clone()]);
        assert_eq!(
            ordered.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![b.id, c.id, d.id, a.id]
        );
    }

    #[test]
    fn hard_delete_result_tally_counts_correctly() {
        let mut r = HardDeleteResult::default();
        r.tally(&HardDeleteOutcome::Cleaned);
        r.tally(&HardDeleteOutcome::DeferredChildPresent);
        r.tally(&HardDeleteOutcome::CascadeTerminal);
        r.tally(&HardDeleteOutcome::NotEligible);
        assert_eq!(r.processed, 4);
        assert_eq!(r.cleaned, 1);
        assert_eq!(r.deferred, 1);
        assert_eq!(r.failed, 1);
    }
}
