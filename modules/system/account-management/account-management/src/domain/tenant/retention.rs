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
//! Per-tenant exponential backoff is computed by a shared helper that
//! lands together with the bootstrap saga in a later PR.

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
/// `(depth DESC, deletion_scheduled_at ASC, id ASC)`.
///
/// `depth DESC` is what lets `hard_delete_one` succeed under the
/// `ON DELETE RESTRICT` parent-FK from Phase 1: children are reclaimed
/// before their parents, so the parent's in-tx child-existence guard
/// always finds the table empty when its turn arrives.
///
/// `deletion_scheduled_at ASC` is the second key — it mirrors the
/// scanner contract (`scan_retention_due` returns rows in
/// `(depth DESC, deletion_scheduled_at ASC, id ASC)` order to prevent
/// starvation: among siblings at the same depth, the tenant scheduled
/// earliest goes first). Dropping it as a tiebreaker would make the
/// hard-delete batch order siblings by `id` only — a tenant scheduled
/// last could randomly beat one scheduled first if its UUID sorted
/// earlier. `id ASC` is the final deterministic tiebreaker for rows
/// scheduled at the exact same instant.
#[must_use]
pub fn order_batch_leaf_first(mut rows: Vec<TenantRetentionRow>) -> Vec<TenantRetentionRow> {
    rows.sort_by(|a, b| {
        b.depth
            .cmp(&a.depth)
            .then_with(|| a.deletion_scheduled_at.cmp(&b.deletion_scheduled_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    rows
}

/// Per-row outcome of the hard-delete pipeline for a single tenant.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A cascade hook returned a retryable failure. Defer to next tick.
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
    /// with the DB teardown as if the deprovision succeeded, so this
    /// outcome is reported only after a successful teardown and counts
    /// toward [`HardDeleteOutcome::is_cleaned`]. The dedicated metric
    /// label (`idp_unsupported`) lets observability distinguish
    /// "cleaned via `IdP` no-op" from "cleaned via `IdP` success".
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
    /// `IdpUnsupported` counts as cleaned because the variant docstring
    /// guarantees the DB teardown ran successfully — the `IdP` no-op
    /// is reflected in the metric label, not the cleanup count.
    #[must_use]
    pub const fn is_cleaned(&self) -> bool {
        matches!(self, Self::Cleaned | Self::IdpUnsupported)
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
            // `NotEligible` is counted under `processed` only —
            // nothing happened (stale candidate set or data-integrity
            // anomaly) so it's neither cleaned nor deferred.
            // `IdpUnsupported` folds into `cleaned` via `is_cleaned()`
            // and is therefore not handled here.
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
#[path = "retention_tests.rs"]
mod tests;
