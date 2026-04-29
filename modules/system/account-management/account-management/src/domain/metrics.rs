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

/// Audit-emission drop counter.
pub const AM_AUDIT_DROP: &str = "am.audit_drop";

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
