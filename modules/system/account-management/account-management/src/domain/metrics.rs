//! AM observability metric catalog.
//!
//! Declares the AM metric families from PRD §5.9 / FEATURE §5 "Metric
//! Catalog". Metric constants and [`MetricKind`] were previously carried
//! by the SDK's `metric_names` module; they are defined here so the
//! runtime crate is self-contained and peer SDKs do not expose metric
//! constants (see `resource-group-sdk`, `tenant-resolver-sdk`).
//!
//! Emission helpers ([`emit_metric`], [`emit_gauge_value`],
//! [`emit_histogram_value`]) are fire-and-forget no-ops in this
//! storage-floor phase; the observability port is wired in a later PR.

use modkit_macros::domain_model;

// @cpt-begin:cpt-cf-account-management-dod-errors-observability-metric-catalog:p1:inst-dod-metric-catalog-constants
/// Dependency-call health: `IdP` / Resource Group / GTS / `AuthZ` outbound calls.
pub const AM_DEPENDENCY_HEALTH: &str = "am.dependency_health";

/// Tenant-metadata resolution operations and inheritance policy outcomes.
pub const AM_METADATA_RESOLUTION: &str = "am.metadata_resolution";

/// Root-tenant bootstrap lifecycle (phase transitions, IdP-wait timeouts).
pub const AM_BOOTSTRAP_LIFECYCLE: &str = "am.bootstrap_lifecycle";

/// Provisioning reaper / hard-delete / deprovision background job telemetry.
pub const AM_TENANT_RETENTION: &str = "am.tenant_retention";

/// Invalid retention-window configuration encountered while evaluating due-ness.
pub const AM_RETENTION_INVALID_WINDOW: &str = "am.retention.invalid_window";

/// Mode-conversion request transitions and outcomes.
pub const AM_CONVERSION_LIFECYCLE: &str = "am.conversion_lifecycle";

/// Hierarchy-depth threshold exceedance (warning-band + hard-limit rejects).
pub const AM_HIERARCHY_DEPTH_EXCEEDANCE: &str = "am.hierarchy_depth_exceedance";

/// Cross-tenant denial counter (security-alert candidate family).
pub const AM_CROSS_TENANT_DENIAL: &str = "am.cross_tenant_denial";

/// Hierarchy-integrity violation telemetry (one per integrity category).
pub const AM_HIERARCHY_INTEGRITY_VIOLATIONS: &str = "am.hierarchy_integrity_violations";

/// Periodic integrity-check job tick outcome (`outcome` ∈ `completed` |
/// `skipped_in_progress` | `failed`). Distinguishes "no violations
/// because the check ran cleanly" from "no violations because the job
/// hasn't run successfully" — the latter is invisible from
/// [`AM_HIERARCHY_INTEGRITY_VIOLATIONS`] alone (which would just keep
/// reporting stale-zero gauges).
///
/// **Outcome label set is fixed**: dashboards keyed on this counter
/// rely on the three values above. Auto-repair tick outcomes live on
/// [`AM_HIERARCHY_INTEGRITY_REPAIR_RUNS`] instead so this counter's
/// label set stays stable across releases.
pub const AM_HIERARCHY_INTEGRITY_RUNS: &str = "am.hierarchy_integrity_runs";

/// Periodic auto-repair tick outcome (`outcome` ∈ `completed` |
/// `skipped_in_progress` | `failed`). Sister metric to
/// [`AM_HIERARCHY_INTEGRITY_RUNS`] kept on its own family so the
/// check-loop counter's documented label set is not silently widened
/// when auto-repair lands. Dashboards filter by family rather than
/// `outcome` prefix to avoid label-name collisions.
pub const AM_HIERARCHY_INTEGRITY_REPAIR_RUNS: &str = "am.hierarchy_integrity_repair_runs";

/// Periodic integrity-check tick wall-clock duration in milliseconds.
/// The `phase` label disaggregates the check phase (`phase = "check"`)
/// from the chained auto-repair phase (`phase = "repair"`) so
/// dashboards can tell a slow check from a slow check + repair.
/// Drives capacity-planning alerts ("p95 > 60s"), distinct from
/// [`AM_HIERARCHY_INTEGRITY_RUNS`] which is a tick-outcome counter.
pub const AM_HIERARCHY_INTEGRITY_DURATION: &str = "am.hierarchy_integrity_duration";

/// Unix-epoch seconds of the last successful integrity-check tick.
/// Used for a freshness watchdog (alert when `last_success` is older
/// than twice the configured interval) that the violation gauge
/// cannot satisfy on its own — a stuck job and a perfectly-clean tree
/// look identical at the violation-gauge level until this gauge stops
/// advancing.
pub const AM_HIERARCHY_INTEGRITY_LAST_SUCCESS: &str = "am.hierarchy_integrity_last_success";

/// Unix-epoch seconds of the last integrity-check tick that did NOT
/// complete successfully (gate-conflict or generic error). Sister
/// gauge to [`AM_HIERARCHY_INTEGRITY_LAST_SUCCESS`]: an alert wired
/// to "`LAST_SUCCESS` older than threshold" alone cannot tell
/// "sustained-failure-since-Y" from "never-ran" because the success
/// gauge keeps the last good timestamp indefinitely. Emitting both
/// gauges from the loop's failure arms lets operators triage which
/// kind of staleness they're looking at.
pub const AM_HIERARCHY_INTEGRITY_LAST_FAILURE: &str = "am.hierarchy_integrity_last_failure";

/// Lock-lifecycle event counter for `integrity_check_runs`. Emitted
/// from [`crate::infra::storage::integrity::lock::release`] when the
/// release DELETE affects zero rows — the row this worker inserted
/// was reclaimed by a contender's stale-lock sweep, which means the
/// check or repair exceeded
/// [`crate::infra::storage::integrity::lock::MAX_LOCK_AGE`] AND a
/// peer raced in. Distinct from
/// [`AM_HIERARCHY_INTEGRITY_RUNS`] (which documents a fixed
/// scheduler-tick outcome set) so dashboards keyed on
/// `RUNS{outcome=*}` stay stable; this counter exists for
/// lock-health alerting.
pub const AM_INTEGRITY_LOCK_EVENTS: &str = "am.integrity_lock_events";

/// Hierarchy-integrity repair telemetry. Emits one gauge sample per
/// run with `category` ∈ all 10
/// [`IntegrityCategory`](crate::domain::tenant::integrity::IntegrityCategory)
/// values and `bucket` ∈ {`repaired`, `deferred`} so dashboards see a
/// stable shape across runs (zero-valued samples for categories that
/// did not appear). The five derivable categories carry counts only
/// in `bucket = repaired`; the five operator-triage categories carry
/// counts only in `bucket = deferred`.
pub const AM_HIERARCHY_INTEGRITY_REPAIRED: &str = "am.hierarchy_integrity_repaired";

/// SERIALIZABLE-isolation retry telemetry for the AM repo's
/// `with_serializable_retry` helper.
pub const AM_SERIALIZABLE_RETRY: &str = "am.serializable_retry";
// @cpt-end:cpt-cf-account-management-dod-errors-observability-metric-catalog:p1:inst-dod-metric-catalog-constants

/// Kinds of metric samples the emitter supports.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl MetricKind {
    /// Stable string tag used in emitted samples.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Emit a metric sample (fire-and-forget, currently a no-op).
///
/// The observability port is wired in a later PR; call sites are stable.
#[inline]
#[allow(unused_variables)]
pub fn emit_metric(family: &'static str, kind: MetricKind, labels: &[(&'static str, &str)]) {}

/// Emit a value-carrying gauge sample (fire-and-forget, currently a no-op).
#[inline]
#[allow(unused_variables)]
pub fn emit_gauge_value(family: &'static str, value: i64, labels: &[(&'static str, &str)]) {}

/// Emit a value-carrying histogram sample (fire-and-forget, currently a no-op).
#[inline]
#[allow(unused_variables)]
pub fn emit_histogram_value(family: &'static str, value: f64, labels: &[(&'static str, &str)]) {}
