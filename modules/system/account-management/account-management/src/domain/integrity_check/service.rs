//! Periodic hierarchy-integrity check loop.
//!
//! The loop is driven by [`run_integrity_check_loop`], invoked from
//! [`crate::module::AccountManagementModule::serve`] alongside the
//! retention + reaper interval loops. The dispatched work is hidden
//! behind the [`IntegrityChecker`] trait so the lifecycle wiring can
//! reach the production
//! [`crate::domain::tenant::service::TenantService::check_hierarchy_integrity`]
//! while tests inject a counting fake without standing up a full
//! `TenantService`.
//!
//! Per-tick error policy:
//!
//! * Success → emit `RUNS{outcome=completed}` + `DURATION` +
//!   `LAST_SUCCESS`; the underlying service has already emitted the
//!   per-category violation gauge.
//! * [`crate::domain::error::DomainError::IntegrityCheckInProgress`] →
//!   another worker (peer replica or operator on-demand call) holds the
//!   single-flight gate; emit
//!   `RUNS{outcome=skipped_in_progress}` + warn log; the loop
//!   intentionally **does not** retry inside the tick because a
//!   competing run is already producing fresh telemetry.
//! * Any other error → emit `RUNS{outcome=failed}` + warn log; the loop
//!   continues so a transient DB blip does not silently disable the
//!   periodic audit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use modkit_macros::domain_model;
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::domain::error::DomainError;
use crate::domain::integrity_check::config::IntegrityCheckConfig;
use crate::domain::metrics::{
    AM_HIERARCHY_INTEGRITY_DURATION, AM_HIERARCHY_INTEGRITY_LAST_FAILURE,
    AM_HIERARCHY_INTEGRITY_LAST_SUCCESS, AM_HIERARCHY_INTEGRITY_REPAIR_RUNS,
    AM_HIERARCHY_INTEGRITY_RUNS, MetricKind, emit_gauge_value, emit_histogram_value, emit_metric,
};
use crate::domain::tenant::integrity::{IntegrityReport, RepairReport};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::service::TenantService;

/// Abstraction over the production
/// [`TenantService::check_hierarchy_integrity`] +
/// [`TenantService::repair_hierarchy_integrity`] used by the periodic
/// loop.
#[async_trait]
pub trait IntegrityChecker: Send + Sync {
    /// Execute one whole-tree integrity check tick and return the
    /// report. Errors propagate verbatim so the loop can classify
    /// gate-conflict vs. transient failure.
    async fn run_whole_integrity_check(&self) -> Result<IntegrityReport, DomainError>;

    /// Execute one whole-tree repair tick and return the per-category
    /// repair report. Invoked by the periodic loop only when
    /// [`IntegrityRepairConfig::auto_after_check`] is `true` AND the
    /// preceding check tick observed at least one derivable
    /// violation.
    async fn run_whole_integrity_repair(&self) -> Result<RepairReport, DomainError>;
}

#[async_trait]
impl<R: TenantRepo + 'static> IntegrityChecker for TenantService<R> {
    async fn run_whole_integrity_check(&self) -> Result<IntegrityReport, DomainError> {
        self.check_hierarchy_integrity().await
    }

    async fn run_whole_integrity_repair(&self) -> Result<RepairReport, DomainError> {
        self.repair_hierarchy_integrity().await
    }
}

/// Lifecycle entry point invoked from [`crate::module::AccountManagementModule::serve`].
///
/// Returns when `cancel` fires. When `cfg.enabled == false`, the loop
/// is not entered at all — the function still awaits cancellation so
/// the calling `select!` arm in `serve` keeps a uniform shape across
/// enabled/disabled configurations and never observes a prematurely
/// completed `JoinHandle`.
pub async fn run_integrity_check_loop(
    checker: Arc<dyn IntegrityChecker>,
    cfg: IntegrityCheckConfig,
    cancel: CancellationToken,
) {
    if !cfg.enabled {
        cancel.cancelled().await;
        return;
    }

    // Initial delay — cancellable so a fast shutdown after start does
    // not block on the configured warmup sleep.
    tokio::select! {
        biased;
        () = cancel.cancelled() => return,
        () = tokio::time::sleep(cfg.initial_delay()) => {}
    }

    let mut jitter_rng = JitterRng::seeded_from_clock();
    let auto_repair = cfg.repair.enabled && cfg.repair.auto_after_check;

    loop {
        run_one_tick(checker.as_ref(), auto_repair).await;

        let next_sleep = jittered_interval(cfg.interval(), cfg.jitter, &mut jitter_rng);
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(next_sleep) => {}
        }
    }
}

async fn run_one_tick(checker: &dyn IntegrityChecker, auto_repair: bool) {
    let started = Instant::now();
    match checker.run_whole_integrity_check().await {
        Ok(report) => {
            emit_metric(
                AM_HIERARCHY_INTEGRITY_RUNS,
                MetricKind::Counter,
                &[("outcome", "completed")],
            );
            // Histogram value in milliseconds — stable unit across
            // backends. Truncate u128 → f64; integrity ticks complete
            // in seconds-to-minutes range, so f64 mantissa is plenty.
            #[allow(
                clippy::cast_precision_loss,
                reason = "millisecond duration <= a few minutes fits f64 mantissa exactly"
            )]
            let elapsed_ms = started.elapsed().as_millis() as f64;
            emit_histogram_value(
                AM_HIERARCHY_INTEGRITY_DURATION,
                elapsed_ms,
                &[("phase", "check")],
            );
            emit_gauge_value(
                AM_HIERARCHY_INTEGRITY_LAST_SUCCESS,
                OffsetDateTime::now_utc().unix_timestamp(),
                &[],
            );

            // Auto-repair: chain a repair tick after a clean check
            // tick that observed at least one derivable violation.
            // Skipped when the operator did not enable
            // `auto_after_check`, when the report is clean, or when
            // only deferred (operator-triage) violations are
            // present.
            if auto_repair && report.has_derivable_violations() {
                trigger_auto_repair(checker).await;
            }
        }
        Err(DomainError::IntegrityCheckInProgress) => {
            warn!(
                target: "am.integrity",
                "integrity check tick skipped: another worker holds the single-flight gate"
            );
            emit_metric(
                AM_HIERARCHY_INTEGRITY_RUNS,
                MetricKind::Counter,
                &[("outcome", "skipped_in_progress")],
            );
            emit_last_failure_gauge("skipped_in_progress");
        }
        Err(err) => {
            warn!(
                target: "am.integrity",
                error = %err,
                "integrity check tick failed"
            );
            emit_metric(
                AM_HIERARCHY_INTEGRITY_RUNS,
                MetricKind::Counter,
                &[("outcome", "failed")],
            );
            emit_last_failure_gauge("failed");
        }
    }
}

/// Emit `AM_HIERARCHY_INTEGRITY_LAST_FAILURE` with the wall-clock
/// timestamp of this failed (or skipped) tick. The `outcome` label
/// matches the outcome label used on `AM_HIERARCHY_INTEGRITY_RUNS`
/// so dashboards can correlate the gauge sample with the run-counter
/// increment that produced it. Companion to the success-side gauge
/// emitted on `Ok(_)` ticks.
fn emit_last_failure_gauge(outcome: &'static str) {
    emit_gauge_value(
        AM_HIERARCHY_INTEGRITY_LAST_FAILURE,
        OffsetDateTime::now_utc().unix_timestamp(),
        &[("outcome", outcome)],
    );
}

/// Run the auto-repair tick that follows a check observing
/// derivable violations. The repair-side metrics
/// ([`crate::domain::metrics::AM_HIERARCHY_INTEGRITY_REPAIRED`]) are
/// emitted by the service method; here we only translate the result
/// into a check-loop-shaped log line + skip / failure counter so
/// dashboards can correlate auto-repair invocations with the
/// preceding check tick.
#[allow(
    clippy::cognitive_complexity,
    reason = "three-arm match over typed error variants — collapsing the arms would obscure the per-error policy each branch documents"
)]
async fn trigger_auto_repair(checker: &dyn IntegrityChecker) {
    let started = Instant::now();
    match checker.run_whole_integrity_repair().await {
        Ok(report) => {
            emit_metric(
                AM_HIERARCHY_INTEGRITY_REPAIR_RUNS,
                MetricKind::Counter,
                &[("outcome", "completed")],
            );
            // Emit the repair duration with `phase=repair` so
            // dashboards can disaggregate the auto-repair phase from
            // the preceding check phase (which uses `phase=check`).
            // Without this an operator looking at
            // `am.hierarchy_integrity_duration` cannot tell whether
            // a long tick was a slow check or a slow check + repair.
            #[allow(
                clippy::cast_precision_loss,
                reason = "millisecond duration <= a few minutes fits f64 mantissa exactly"
            )]
            let elapsed_ms = started.elapsed().as_millis() as f64;
            emit_histogram_value(
                AM_HIERARCHY_INTEGRITY_DURATION,
                elapsed_ms,
                &[("phase", "repair")],
            );
            tracing::info!(
                target: "am.integrity",
                repaired_total = report.total_repaired(),
                deferred_total = report.total_deferred(),
                "integrity repair tick completed (auto_after_check)"
            );
        }
        Err(DomainError::IntegrityCheckInProgress) => {
            emit_metric(
                AM_HIERARCHY_INTEGRITY_REPAIR_RUNS,
                MetricKind::Counter,
                &[("outcome", "skipped_in_progress")],
            );
            warn!(
                target: "am.integrity",
                "integrity repair tick skipped: another worker holds the single-flight gate"
            );
        }
        Err(err) => {
            emit_metric(
                AM_HIERARCHY_INTEGRITY_REPAIR_RUNS,
                MetricKind::Counter,
                &[("outcome", "failed")],
            );
            warn!(
                target: "am.integrity",
                error = %err,
                "integrity repair tick failed"
            );
        }
    }
}

fn jittered_interval(interval: Duration, jitter: f64, rng: &mut JitterRng) -> Duration {
    if jitter <= 0.0 {
        return interval;
    }
    // `next_neg_one_to_one` returns a value in [-1.0, 1.0); multiplying
    // by `jitter` (already validated to ∈ [0.0, 0.5]) keeps the offset
    // in [-jitter, +jitter), and `(1.0 + offset).max(0.0)` defends
    // against a future jitter bound > 1.0 producing a negative factor.
    let offset = rng.next_neg_one_to_one() * jitter;
    let factor = (1.0 + offset).max(0.0);
    Duration::from_secs_f64(interval.as_secs_f64() * factor)
}

/// Tiny self-contained PRNG for jitter. Uses splitmix64 stepping
/// (single multiply + xorshift mix per call) which is more than
/// sufficient for spread-the-load purposes; pulling in `rand` for one
/// use site would add a transitive dependency to the AM crate without
/// any cryptographic requirement to justify it.
#[domain_model]
struct JitterRng {
    state: u64,
}

impl JitterRng {
    fn seeded_from_clock() -> Self {
        // System time, not `tokio::time::Instant`, so each replica
        // seeds independently regardless of paused-test virtual
        // clocks. Wall-clock nanos are unique enough to spread two
        // replicas starting in the same second; the state OR'd with 1
        // forbids the all-zero degenerate case the splitmix step
        // tolerates.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0xDEAD_BEEF_CAFE_F00D, |d| {
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "wrapping nanos into u64 is the seeding intent"
                )]
                let lo = d.as_nanos() as u64;
                lo
            });
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        // splitmix64 — stateless mixer, advances by a known constant.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value uniformly distributed in `[-1.0, 1.0)`.
    fn next_neg_one_to_one(&mut self) -> f64 {
        // Take the top 53 bits → exact f64 mantissa precision.
        #[allow(
            clippy::cast_precision_loss,
            reason = "53-bit value casts exactly to f64"
        )]
        let unit = (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
        unit.mul_add(2.0, -1.0)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "service_tests.rs"]
mod service_tests;
