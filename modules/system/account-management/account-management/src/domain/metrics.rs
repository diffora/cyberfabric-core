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

use std::borrow::Cow;

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

/// Emit a metric sample against one of the AM metric families declared
/// in this module's `FAMILIES` catalog.
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
    let render = enabled!(target: "metrics.am", Level::INFO);

    // Cold production path: nothing listens on `metrics.am` at INFO and
    // there is no test capture buffer to populate, so don't allocate the
    // normalized `Vec` or escape values — but still walk `labels` once to
    // surface allow-list violations on the `warn!` target.
    #[cfg(not(test))]
    if !render {
        warn_invalid_labels(desc, labels);
        return;
    }

    // Hot/test path: build the normalized labels (used by capture in test
    // builds) and, when INFO is enabled, the rendered `k=v,k=v` string.
    // Capture and `info!` must agree with the production-visible label
    // set — allow-list-filtered and value-escaped.
    let (normalized, rendered) = render_labels(desc, labels, render);

    #[cfg(test)]
    capture_metric_sample(desc.name, kind, &normalized);
    #[cfg(not(test))]
    let _ = &normalized;

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

/// No-allocation cold-path validator: walks `labels` once and emits a
/// `warn!` for each entry whose key is not in the family's allow-list
/// or duplicates a previous accepted key, matching `render_labels`'
/// diagnostics verbatim so the cold and hot paths produce identical
/// warnings. Used by [`emit_sample`] in non-test builds when nothing is
/// listening at `metrics.am=INFO`; in test builds the cold path is
/// short-circuited so this helper is unreachable.
#[cfg(not(test))]
fn warn_invalid_labels(desc: &'static FamilyDescriptor, labels: &[(&'static str, &str)]) {
    // Bounded by `desc.allowed_labels.len()` (≤3 for live families); a
    // tiny stack-resident slice is cheaper than a hash set here.
    let mut seen: [&'static str; 8] = [""; 8];
    let mut seen_len: usize = 0;
    for (k, _) in labels {
        if !desc.allowed_labels.contains(k) {
            warn!(
                target: "metrics.am",
                family = desc.name,
                label = k,
                "metric label not in allow-list; dropping label"
            );
            continue;
        }
        if seen[..seen_len].iter().any(|s| s == k) {
            warn!(
                target: "metrics.am",
                family = desc.name,
                label = k,
                "duplicate metric label; dropping duplicate"
            );
            continue;
        }
        if seen_len < seen.len() {
            seen[seen_len] = *k;
            seen_len += 1;
        }
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
fn capture_metric_sample(
    family: &'static str,
    kind: MetricKind,
    labels: &[(&'static str, Cow<'_, str>)],
) {
    let sample = CapturedMetricSample {
        family,
        kind,
        labels: labels
            .iter()
            .map(|(key, value)| (*key, value.as_ref().to_owned()))
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

/// Filter `labels` against `desc.allowed_labels`, escape each accepted
/// value, and (when `render` is `true`) format the accepted pairs into the
/// `k=v,k=v` rendering used by `info!`.
///
/// The structured `Vec` return value is the **single source of truth** for
/// the production-visible label set: both `capture_metric_sample` (in test
/// builds) and the `info!` emission below are driven from it, so they
/// cannot disagree about which labels were dropped or how their values
/// were escaped.
fn render_labels<'a>(
    desc: &'static FamilyDescriptor,
    labels: &'a [(&'static str, &'a str)],
    render: bool,
) -> (Vec<(&'static str, Cow<'a, str>)>, String) {
    let mut normalized: Vec<(&'static str, Cow<'a, str>)> = Vec::with_capacity(labels.len());
    // Track seen keys via linear scan over `normalized` itself: catalog
    // families allow at most a handful of labels (the largest live entry
    // has 3), so a hash set would dominate the cost of the work it saves.
    // First-occurrence wins; later duplicates are warned-and-dropped so
    // the rendered `k=v,k=v` cannot contain `kind=a,kind=b`-style ambiguity.
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
        if normalized.iter().any(|(seen, _)| seen == k) {
            warn!(
                target: "metrics.am",
                family = desc.name,
                label = k,
                "duplicate metric label; dropping duplicate"
            );
            continue;
        }
        normalized.push((*k, escape_label_value(v)));
    }

    let out = if render {
        let mut out = String::with_capacity(normalized.len() * 16);
        let mut first = true;
        for (k, v) in &normalized {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    } else {
        String::new()
    };
    (normalized, out)
}

/// Percent-encode characters that would corrupt the `k=v,k=v` rendering
/// or forge log lines (`\n`, `\r`). `%` is encoded first so the output is
/// reversible. Returns `Cow::Borrowed` when no escaping is required, so the
/// common (well-behaved) path stays allocation-free on the hot emit path.
fn escape_label_value(value: &str) -> Cow<'_, str> {
    if !value
        .bytes()
        .any(|b| matches!(b, b'%' | b',' | b'=' | b'\n' | b'\r'))
    {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 4);
    for c in value.chars() {
        match c {
            '%' => out.push_str("%25"),
            ',' => out.push_str("%2C"),
            '=' => out.push_str("%3D"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            other => out.push(other),
        }
    }
    Cow::Owned(out)
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
        clear_captured_metric_samples();
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
        let samples = take_captured_metric_samples();
        assert_eq!(
            samples.len(),
            2,
            "both emits must be recorded; got: {samples:?}"
        );
        assert_eq!(samples[0].family, AM_SERIALIZABLE_RETRY);
        assert_eq!(samples[0].kind, MetricKind::Counter);
        assert_eq!(
            samples[0].labels,
            vec![
                ("outcome", "exhausted".to_owned()),
                ("attempts", "4".to_owned()),
            ]
        );
        assert_eq!(samples[1].family, AM_SERIALIZABLE_RETRY);
        assert_eq!(samples[1].kind, MetricKind::Counter);
        assert_eq!(
            samples[1].labels,
            vec![
                ("outcome", "recovered".to_owned()),
                ("attempts", "2".to_owned()),
            ]
        );
    }

    #[test]
    fn dependency_health_accepts_bound_inert_gauge() {
        clear_captured_metric_samples();
        emit_metric(
            AM_DEPENDENCY_HEALTH,
            MetricKind::Gauge,
            &[("target", "rg"), ("op", "bound"), ("outcome", "inert")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_DEPENDENCY_HEALTH);
        assert_eq!(samples[0].kind, MetricKind::Gauge);
        assert_eq!(
            samples[0].labels,
            vec![
                ("target", "rg".to_owned()),
                ("op", "bound".to_owned()),
                ("outcome", "inert".to_owned()),
            ]
        );
    }

    #[test]
    fn integrity_violations_accepts_category_label_as_gauge() {
        // Happy-path: category label + Gauge kind are in the allow-list.
        clear_captured_metric_samples();
        emit_metric(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            MetricKind::Gauge,
            &[("category", "orphaned_child")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_HIERARCHY_INTEGRITY_VIOLATIONS);
        assert_eq!(samples[0].kind, MetricKind::Gauge);
        assert_eq!(
            samples[0].labels,
            vec![("category", "orphaned_child".to_owned())]
        );
    }

    #[test]
    fn integrity_violations_accepts_category_label_as_counter() {
        clear_captured_metric_samples();
        emit_metric(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            MetricKind::Counter,
            &[("category", "cycle_detected")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_HIERARCHY_INTEGRITY_VIOLATIONS);
        assert_eq!(samples[0].kind, MetricKind::Counter);
        assert_eq!(
            samples[0].labels,
            vec![("category", "cycle_detected".to_owned())]
        );
    }

    #[test]
    fn retention_invalid_window_accepts_counter_without_labels() {
        clear_captured_metric_samples();
        emit_metric(AM_RETENTION_INVALID_WINDOW, MetricKind::Counter, &[]);
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_RETENTION_INVALID_WINDOW);
        assert_eq!(samples[0].kind, MetricKind::Counter);
        assert!(
            samples[0].labels.is_empty(),
            "no labels expected; got: {:?}",
            samples[0].labels
        );
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
    fn render_labels_escapes_delimiter_and_newline_chars() {
        // The k=v,k=v rendering must not be corruptible by a label value that
        // happens to contain `,`, `=`, `\n`, `\r`, or `%` itself.
        let desc = lookup(AM_AUDIT_DROP).expect("AM_AUDIT_DROP descriptor");
        let (normalized, rendered) = render_labels(desc, &[("kind", "a,b=c\nd\re%f")], true);
        assert_eq!(rendered, "kind=a%2Cb%3Dc%0Ad%0De%25f");
        // The normalized view that feeds the test capture must carry the
        // same escaped value the info! emission renders.
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].0, "kind");
        assert_eq!(normalized[0].1.as_ref(), "a%2Cb%3Dc%0Ad%0De%25f");
    }

    #[test]
    fn capture_omits_labels_dropped_by_allow_list() {
        // Regression: tests must not see labels that production would
        // never emit. emit_sample now drives capture from the same
        // filtered/escaped list it hands to info!, so a non-allow-listed
        // label is dropped from both paths.
        clear_captured_metric_samples();
        emit_metric(
            AM_CROSS_TENANT_DENIAL,
            MetricKind::Counter,
            &[
                ("operation", "create_child"),
                ("totally_made_up_label", "x"),
                ("barrier_mode", "strict"),
                ("reason", "non_platform_admin"),
            ],
        );
        let samples = take_captured_metric_samples();
        let leaked = samples
            .iter()
            .flat_map(|s| s.labels.iter().map(|(k, _)| *k))
            .any(|k| k == "totally_made_up_label");
        assert!(
            !leaked,
            "non-allow-listed label leaked into capture: {samples:?}"
        );
        let kept_keys: Vec<&'static str> = samples
            .iter()
            .flat_map(|s| s.labels.iter().map(|(k, _)| *k))
            .collect();
        assert!(kept_keys.contains(&"operation"));
        assert!(kept_keys.contains(&"barrier_mode"));
        assert!(kept_keys.contains(&"reason"));
    }

    #[test]
    fn render_labels_drops_duplicate_keys_first_wins() {
        // Pin the first-occurrence-wins rule for duplicate keys at the
        // render_labels level: a caller passing two `("kind", _)` entries
        // must not produce the ambiguous `kind=a,kind=b` rendering — the
        // second entry is dropped (with a `warn!`) so both the captured
        // sample and the rendered string carry exactly one `kind` pair.
        let desc = lookup(AM_AUDIT_DROP).expect("AM_AUDIT_DROP descriptor");
        let (normalized, rendered) =
            render_labels(desc, &[("kind", "first"), ("kind", "second")], true);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].0, "kind");
        assert_eq!(normalized[0].1.as_ref(), "first");
        assert_eq!(rendered, "kind=first");
    }

    #[test]
    fn capture_drops_duplicate_label_keys() {
        // End-to-end: emit_metric with a duplicate label key records a
        // single, unambiguous sample — duplicates are filtered before
        // hitting capture, just like they are before info!.
        clear_captured_metric_samples();
        emit_metric(
            AM_AUDIT_DROP,
            MetricKind::Counter,
            &[("kind", "first"), ("kind", "second")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(
            samples[0].labels,
            vec![("kind", "first".to_owned())],
            "duplicate `kind` must be dropped, first wins; got: {:?}",
            samples[0].labels
        );
    }

    #[test]
    fn capture_records_escaped_label_values() {
        // The capture path stores the same escaped values the info!
        // emission renders, so a test asserting on captured values
        // matches what production logs would carry.
        clear_captured_metric_samples();
        emit_metric(
            AM_AUDIT_DROP,
            MetricKind::Counter,
            &[("kind", "a,b=c\nd\re%f")],
        );
        let samples = take_captured_metric_samples();
        let kind_value: Option<String> = samples
            .iter()
            .flat_map(|s| s.labels.iter().cloned())
            .find_map(|(k, v)| (k == "kind").then_some(v));
        assert_eq!(
            kind_value.as_deref(),
            Some("a%2Cb%3Dc%0Ad%0De%25f"),
            "captured value must be escaped: {samples:?}"
        );
    }

    #[test]
    fn render_labels_does_not_allocate_for_clean_values() {
        // Sanity: the no-special-char path returns a borrow (no extra alloc
        // beyond the outer `out` buffer).
        let cleaned = super::escape_label_value("orphaned_child");
        assert!(matches!(cleaned, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn valid_sample_emits_cleanly() {
        clear_captured_metric_samples();
        emit_metric(
            AM_CROSS_TENANT_DENIAL,
            MetricKind::Counter,
            &[
                ("operation", "create_child"),
                ("barrier_mode", "strict"),
                ("reason", "non_platform_admin"),
            ],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_CROSS_TENANT_DENIAL);
        assert_eq!(samples[0].kind, MetricKind::Counter);
        assert_eq!(
            samples[0].labels,
            vec![
                ("operation", "create_child".to_owned()),
                ("barrier_mode", "strict".to_owned()),
                ("reason", "non_platform_admin".to_owned()),
            ]
        );
    }
}
