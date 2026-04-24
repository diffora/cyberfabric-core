//! Account Management observability metric-name catalog.
//!
//! Carries the canonical `AM_*` family-name constants and the
//! [`MetricKind`] enum from PRD §5.9 / FEATURE §5 "Metric Catalog".
//! These names are part of AM's public observability contract:
//! dashboards, alert rules, and external scrapers may reference them
//! literally, so renaming requires a contract-version bump.
//!
//! Emission helpers (`emit_metric` + the family allow-list table) are
//! intentionally **not** in this SDK — they belong with the impl
//! crate's runtime sink.

use modkit_macros::domain_model;

/// Dependency-call health: `IdP` / Resource Group / GTS / `AuthZ` outbound calls.
/// Counters record call outcomes; gauges record boot-time dependency binding
/// state such as an inert Resource Group checker fallback.
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-metric-catalog:p1:inst-dod-metric-catalog-constants
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

/// Hierarchy-integrity violation telemetry (one per integrity category). Emitted
/// by the hierarchy-integrity checker introduced in the deletion-pipeline
/// phase. The categories are the members of
/// `IntegrityCategory`. Gauge emission is always zero-valued for clean
/// categories so the dashboard can distinguish "no violations" from
/// "checker never ran"; cycle detection additionally emits a counter
/// sample at the detection boundary.
pub const AM_HIERARCHY_INTEGRITY_VIOLATIONS: &str = "am.hierarchy_integrity_violations";

/// Audit-emission drop counter. Increments every time `emit_audit` rejects
/// an event because an `actor=system` record carried a kind that is not on
/// the system-actor allow-list. A non-zero count indicates a misconfigured
/// caller (audit records are silently lost on this path) and should be
/// alertable. Label `kind` records the rejected audit kind so the
/// offending call site can be located.
pub const AM_AUDIT_DROP: &str = "am.audit_drop";

/// SERIALIZABLE-isolation retry telemetry for the AM repo's
/// `with_serializable_retry` helper. Counter only; `outcome` is
/// `recovered` (transaction committed after one or more retries) or
/// `exhausted` (retry budget exhausted, surfaced to the caller as
/// `AmError::SerializationConflict` mapped to `conflict` / HTTP 409 per
/// `feature-tenant-hierarchy-management §6` AC line 711). `attempts`
/// reports the final attempt count; bounded by `MAX_SERIALIZABLE_ATTEMPTS`
/// so cardinality stays small. Sustained `outcome=exhausted` indicates DB
/// contention; `recovered` rate informs retry-budget tuning.
pub const AM_SERIALIZABLE_RETRY: &str = "am.serializable_retry";
// @cpt-end:cpt-cf-account-management-dod-errors-observability-metric-catalog:p1:inst-dod-metric-catalog-constants

/// Kinds of metric samples the emitter supports.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
