//! AM observability metric catalog.
//!
//! Declares the AM metric families from PRD §5.9 / FEATURE §5 "Metric
//! Catalog" as canonical `pub const` names plus a single [`emit_metric`]
//! helper that enforces the label-whitelist + cardinality guard contract
//! from `algo-metric-emission`.
//!
//! Emission is fire-and-forget: [`emit_metric`] returns `()` and never
//! fails. Violations of the label contract degrade to a `tracing::warn!`
//! diagnostic — they never propagate as a domain error.

// TODO(errors-observability): wire to an OTel meter provider handle on
// `ModuleCtx` once ModKit surfaces one; until then the structured
// `tracing::info!` sink is scraped by the platform log-to-metric pipeline.

use modkit_macros::domain_model;
use tracing::{Level, enabled, info, warn};

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
/// [`crate::domain::tenant::integrity::IntegrityCategory`]. Gauge emission is
/// always zero-valued for clean categories so the dashboard can distinguish
/// "no violations" from "checker never ran"; cycle detection additionally
/// emits a counter sample at the detection boundary.
pub const AM_HIERARCHY_INTEGRITY_VIOLATIONS: &str = "am.hierarchy_integrity_violations";

/// Audit-emission drop counter. Increments every time `emit_audit` rejects
/// an event because an `actor=system` record carried a kind that is not on
/// the system-actor allow-list. A non-zero count indicates a misconfigured
/// caller (audit records are silently lost on this path) and should be
/// alertable. Label `kind` records the rejected audit kind so the
/// offending call site can be located.
pub const AM_AUDIT_DROP: &str = "am.audit_drop";

/// SERIALIZABLE-isolation retry telemetry for the
/// [`with_serializable_retry`](crate::infra::storage) helper. Counter only;
/// `outcome` is `recovered` (transaction committed after one or more
/// retries) or `exhausted` (retry budget exhausted, surfaced to the caller
/// as `AmError::SerializationConflict` mapped to `conflict` / HTTP 409 per
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
    const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Static family descriptor: canonical name + allow-listed label keys +
/// allowed [`MetricKind`]s. Declared as a compile-time table so the
/// emission path validates against it without allocating.
#[domain_model]
struct FamilyDescriptor {
    name: &'static str,
    allowed_labels: &'static [&'static str],
    allowed_kinds: &'static [MetricKind],
}

// Family table — must stay in sync with FEATURE §5 "Observability Metric
// Catalog". Label keys that carry tenant / user UUIDs are deliberately absent:
// the allow-list is the cardinality guard.
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-ops-metrics-treatment:p2:inst-dod-ops-metrics-family-table
const FAMILIES: &[FamilyDescriptor] = &[
    FamilyDescriptor {
        name: AM_DEPENDENCY_HEALTH,
        allowed_labels: &["target", "op", "outcome"],
        allowed_kinds: &[
            MetricKind::Counter,
            MetricKind::Gauge,
            MetricKind::Histogram,
        ],
    },
    FamilyDescriptor {
        name: AM_METADATA_RESOLUTION,
        allowed_labels: &["operation", "outcome", "inheritance_policy"],
        allowed_kinds: &[MetricKind::Counter, MetricKind::Histogram],
    },
    FamilyDescriptor {
        name: AM_BOOTSTRAP_LIFECYCLE,
        allowed_labels: &["phase", "classification", "outcome"],
        allowed_kinds: &[MetricKind::Counter, MetricKind::Histogram],
    },
    FamilyDescriptor {
        name: AM_TENANT_RETENTION,
        allowed_labels: &["job", "outcome", "failure_class"],
        allowed_kinds: &[
            MetricKind::Counter,
            MetricKind::Gauge,
            MetricKind::Histogram,
        ],
    },
    FamilyDescriptor {
        name: AM_RETENTION_INVALID_WINDOW,
        allowed_labels: &[],
        allowed_kinds: &[MetricKind::Counter],
    },
    FamilyDescriptor {
        name: AM_CONVERSION_LIFECYCLE,
        allowed_labels: &["transition", "initiator_side", "outcome"],
        allowed_kinds: &[MetricKind::Counter, MetricKind::Histogram],
    },
    FamilyDescriptor {
        name: AM_HIERARCHY_DEPTH_EXCEEDANCE,
        allowed_labels: &["mode", "threshold", "outcome"],
        allowed_kinds: &[MetricKind::Counter, MetricKind::Gauge],
    },
    FamilyDescriptor {
        name: AM_CROSS_TENANT_DENIAL,
        allowed_labels: &["operation", "barrier_mode", "reason"],
        allowed_kinds: &[MetricKind::Counter],
    },
    FamilyDescriptor {
        name: AM_HIERARCHY_INTEGRITY_VIOLATIONS,
        allowed_labels: &["category"],
        allowed_kinds: &[MetricKind::Counter, MetricKind::Gauge],
    },
    FamilyDescriptor {
        name: AM_AUDIT_DROP,
        allowed_labels: &["kind"],
        allowed_kinds: &[MetricKind::Counter],
    },
    FamilyDescriptor {
        name: AM_SERIALIZABLE_RETRY,
        allowed_labels: &["outcome", "attempts"],
        allowed_kinds: &[MetricKind::Counter],
    },
];
// @cpt-end:cpt-cf-account-management-dod-errors-observability-ops-metrics-treatment:p2:inst-dod-ops-metrics-family-table

fn lookup(family: &str) -> Option<&'static FamilyDescriptor> {
    FAMILIES.iter().find(|f| f.name == family)
}

/// Emit a metric sample against one of the seven AM families.
///
/// Contract (fire-and-forget, see `algo-metric-emission`):
///
/// * `family` **MUST** be one of the `AM_*` canonical constants declared in
///   this module; an unknown name is dropped with a `warn!` diagnostic.
/// * every `(key, _)` in `labels` **MUST** appear in the family's
///   allow-list; unexpected keys are dropped per-label with a `warn!` and
///   the remaining labels still emit.
/// * `kind` **MUST** be one of the family's allowed metric kinds.
/// * the catalog's `allowed_labels` list is the cardinality guardrail —
///   callers **MUST NOT** pass raw tenant / user UUIDs as label values;
///   emit points are expected to bucket or hash before calling.
///
/// The caller receives `()` regardless of validation outcome.
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-metric-emission:p1:inst-algo-metric-emit-validate
#[allow(clippy::cognitive_complexity)] // branchy warn! paths; no logic
pub fn emit_metric(family: &'static str, kind: MetricKind, labels: &[(&'static str, &str)]) {
    let Some(desc) = lookup(family) else {
        warn!(
            target: "metrics.am",
            family,
            "unknown AM metric family; dropping sample"
        );
        return;
    };

    if !desc.allowed_kinds.contains(&kind) {
        warn!(
            target: "metrics.am",
            family = desc.name,
            kind = kind.as_str(),
            "metric kind not allowed for family; dropping sample"
        );
        return;
    }

    emit_sample(desc, kind, labels);
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-metric-emission:p1:inst-algo-metric-emit-validate

fn emit_sample(desc: &'static FamilyDescriptor, kind: MetricKind, labels: &[(&'static str, &str)]) {
    #[cfg(test)]
    capture_metric_sample(desc.name, kind, labels);

    // Fast path: if nothing is listening on `metrics.am` at INFO, skip
    // serialization entirely. Label allow-list violations still surface
    // because they `warn!` on their own target.
    let render = enabled!(target: "metrics.am", Level::INFO);
    let rendered = render_labels(desc, labels, render);
    if render {
        info!(
            target: "metrics.am",
            family = desc.name,
            kind = kind.as_str(),
            labels = %rendered,
            "am metric sample"
        );
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedMetricSample {
    pub family: &'static str,
    pub kind: MetricKind,
    pub labels: Vec<(&'static str, String)>,
}

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    static CAPTURED_METRIC_SAMPLES: RefCell<Vec<CapturedMetricSample>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn capture_metric_sample(family: &'static str, kind: MetricKind, labels: &[(&'static str, &str)]) {
    let sample = CapturedMetricSample {
        family,
        kind,
        labels: labels
            .iter()
            .map(|(key, value)| (*key, (*value).to_owned()))
            .collect(),
    };
    CAPTURED_METRIC_SAMPLES.with(|samples| samples.borrow_mut().push(sample));
}

#[cfg(test)]
pub(crate) fn clear_captured_metric_samples() {
    CAPTURED_METRIC_SAMPLES.with(|samples| samples.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn take_captured_metric_samples() -> Vec<CapturedMetricSample> {
    CAPTURED_METRIC_SAMPLES.with(|samples| std::mem::take(&mut *samples.borrow_mut()))
}

fn render_labels(
    desc: &'static FamilyDescriptor,
    labels: &[(&'static str, &str)],
    render: bool,
) -> String {
    let mut out = if render {
        String::with_capacity(labels.len() * 16)
    } else {
        String::new()
    };
    let mut first = true;
    for (k, v) in labels {
        if !desc.allowed_labels.contains(k) {
            warn!(
                target: "metrics.am",
                family = desc.name,
                label = k,
                "metric label not in allow-list; dropping label"
            );
            continue;
        }
        if render {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn all_families_are_looked_up() {
        for f in [
            AM_DEPENDENCY_HEALTH,
            AM_METADATA_RESOLUTION,
            AM_BOOTSTRAP_LIFECYCLE,
            AM_TENANT_RETENTION,
            AM_RETENTION_INVALID_WINDOW,
            AM_CONVERSION_LIFECYCLE,
            AM_HIERARCHY_DEPTH_EXCEEDANCE,
            AM_CROSS_TENANT_DENIAL,
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            AM_AUDIT_DROP,
            AM_SERIALIZABLE_RETRY,
        ] {
            assert!(lookup(f).is_some(), "family {f} not in catalog");
        }
    }

    #[test]
    fn serializable_retry_accepts_outcome_and_attempts_as_counter() {
        emit_metric(
            AM_SERIALIZABLE_RETRY,
            MetricKind::Counter,
            &[("outcome", "exhausted"), ("attempts", "4")],
        );
        emit_metric(
            AM_SERIALIZABLE_RETRY,
            MetricKind::Counter,
            &[("outcome", "recovered"), ("attempts", "2")],
        );
    }

    #[test]
    fn dependency_health_accepts_bound_inert_gauge() {
        emit_metric(
            AM_DEPENDENCY_HEALTH,
            MetricKind::Gauge,
            &[("target", "rg"), ("op", "bound"), ("outcome", "inert")],
        );
    }

    #[test]
    fn integrity_violations_accepts_category_label_as_gauge() {
        // Happy-path: category label + Gauge kind are in the allow-list.
        emit_metric(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            MetricKind::Gauge,
            &[("category", "orphaned_child")],
        );
    }

    #[test]
    fn integrity_violations_accepts_category_label_as_counter() {
        emit_metric(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            MetricKind::Counter,
            &[("category", "cycle_detected")],
        );
    }

    #[test]
    fn retention_invalid_window_accepts_counter_without_labels() {
        emit_metric(AM_RETENTION_INVALID_WINDOW, MetricKind::Counter, &[]);
    }

    #[test]
    fn emit_does_not_panic_for_unknown_family_or_label() {
        emit_metric("am.nonexistent", MetricKind::Counter, &[]);
        emit_metric(
            AM_CROSS_TENANT_DENIAL,
            MetricKind::Counter,
            &[("totally_made_up_label", "x")],
        );
    }

    #[test]
    fn valid_sample_emits_cleanly() {
        emit_metric(
            AM_CROSS_TENANT_DENIAL,
            MetricKind::Counter,
            &[
                ("operation", "create_child"),
                ("barrier_mode", "strict"),
                ("reason", "non_platform_admin"),
            ],
        );
    }
}
