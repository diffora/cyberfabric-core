//! AM observability metric catalog.
//!
//! Declares the AM metric families from PRD §5.9 / FEATURE §5 "Metric
//! Catalog" plus a small emit surface ([`emit_metric`],
//! [`emit_gauge_value`], [`emit_histogram_value`]) that dispatches into
//! the typed [`AmMetricsPort`] installed at module init.
//!
//! The metric **names** ([`AM_*`] constants) and the [`MetricKind`] enum
//! live in `account-management-sdk`'s [`metric_names`] module — they are
//! part of the public observability contract so renaming requires a
//! contract-version bump. They are re-exported below verbatim so internal
//! `use crate::domain::metrics::AM_*` paths stay stable. The emission
//! sink (this file's emit helpers) is impl-side and may evolve without
//! contract impact.
//!
//! Emission is fire-and-forget: the helpers return `()` and never fail.
//! Unknown family names or kinds disallowed by the typed `AmMetricsPort`
//! (i.e. families without a matching instrument) are silently dropped.
//!
//! [`metric_names`]: account_management_sdk::metric_names
//! [`AmMetricsPort`]: crate::infra::observability::AmMetricsPort

pub use account_management_sdk::metric_names::{
    AM_AUDIT_DROP, AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL,
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_METADATA_RESOLUTION, AM_RETENTION_INVALID_WINDOW, AM_SERIALIZABLE_RETRY,
    AM_TENANT_RETENTION, MetricKind,
};

/// Convert the `&[(&'static str, &str)]` label slice that emit-side call
/// sites pass into the `Vec<KeyValue>` shape that [`AmMetricsPort`] expects.
///
/// Allocates a `String` per label value because `KeyValue::new` requires an
/// owned [`opentelemetry::Value`]; the cost is bounded by the small
/// (≤ a few entries) label sets every AM family declares.
///
/// [`AmMetricsPort`]: crate::infra::observability::AmMetricsPort
fn to_keyvalues(labels: &[(&'static str, &str)]) -> Vec<opentelemetry::KeyValue> {
    labels
        .iter()
        .map(|(k, v)| opentelemetry::KeyValue::new(*k, (*v).to_owned()))
        .collect()
}

/// Emit a metric sample against one of the AM metric families declared
/// in `account_management_sdk::metric_names`.
///
/// Contract (fire-and-forget):
///
/// * `family` **MUST** be one of the `AM_*` canonical constants re-exported
///   from this module; an unknown name is dropped silently by the
///   underlying [`AmMetricsPort`] dispatch.
/// * `kind` **MUST** be one of the family's allowed metric kinds; kinds
///   that no instrument supports for the family are dropped silently.
/// * `labels` carry callsite-controlled tags. Cardinality is the caller's
///   responsibility — emit points must bucket / hash high-cardinality
///   identifiers (tenant IDs, user IDs) before calling.
///
/// The caller receives `()` regardless of validation outcome.
///
/// For value-carrying gauge / histogram emissions, use
/// [`emit_gauge_value`] / [`emit_histogram_value`]. `emit_metric` records
/// a fixed `1` for [`MetricKind::Counter`] and `0` for
/// [`MetricKind::Gauge`] / [`MetricKind::Histogram`] — it remains the
/// no-payload baseline-ack surface.
///
/// [`AmMetricsPort`]: crate::infra::observability::AmMetricsPort
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-metric-emission:p1:inst-algo-metric-emit-validate
#[allow(clippy::cognitive_complexity)] // branchy by design
pub fn emit_metric(family: &'static str, kind: MetricKind, labels: &[(&'static str, &str)]) {
    let port = crate::infra::observability::metrics();
    let kvs = to_keyvalues(labels);
    match kind {
        MetricKind::Counter => port.record_counter(family, 1, &kvs),
        MetricKind::Gauge => port.record_gauge(family, 0, &kvs),
        MetricKind::Histogram => port.record_histogram(family, 0.0, &kvs),
    }
    // Test capture buffer (preserved): so existing unit tests don't churn.
    #[cfg(test)]
    capture_metric_sample(family, kind, labels);
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-metric-emission:p1:inst-algo-metric-emit-validate

/// Emit a value-carrying gauge sample against an AM gauge family.
///
/// Sibling to [`emit_metric`] for gauges that need to report a numeric
/// reading rather than a baseline-ack `0`. The integrity-violations gauge
/// (`AM_HIERARCHY_INTEGRITY_VIOLATIONS`) is the canonical caller — it
/// emits one sample per `IntegrityCategory` carrying the category's
/// violation count.
///
/// Same fire-and-forget contract as [`emit_metric`]: unknown family or
/// kind not allowed for the family is dropped silently by the typed
/// [`AmMetricsPort`] dispatch.
///
/// [`AmMetricsPort`]: crate::infra::observability::AmMetricsPort
pub fn emit_gauge_value(family: &'static str, value: i64, labels: &[(&'static str, &str)]) {
    let port = crate::infra::observability::metrics();
    let kvs = to_keyvalues(labels);
    port.record_gauge(family, value, &kvs);
    #[cfg(test)]
    capture_metric_sample(family, MetricKind::Gauge, labels);
}

/// Emit a value-carrying histogram sample against an AM histogram family.
///
/// Sibling to [`emit_metric`] for histograms that need to report a
/// numeric observation (e.g. latency in ms) rather than a baseline-ack
/// `0.0`.
///
/// Same fire-and-forget contract as [`emit_metric`].
pub fn emit_histogram_value(family: &'static str, value: f64, labels: &[(&'static str, &str)]) {
    let port = crate::infra::observability::metrics();
    let kvs = to_keyvalues(labels);
    port.record_histogram(family, value, &kvs);
    #[cfg(test)]
    capture_metric_sample(family, MetricKind::Histogram, labels);
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
    labels: &[(&'static str, &str)],
) {
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

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
        // Happy-path: category label + Gauge kind dispatch through
        // emit_metric without panic, recording a baseline-ack sample.
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
        // Unknown family: the typed port drops silently; capture still
        // records the call so tests can observe it.
        emit_metric("am.nonexistent", MetricKind::Counter, &[]);
        emit_metric(
            AM_CROSS_TENANT_DENIAL,
            MetricKind::Counter,
            &[("totally_made_up_label", "x")],
        );
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

    #[test]
    fn emit_gauge_value_records_value_and_labels_through_capture() {
        // Sibling helper: value-carrying gauge emission. Capture stores
        // the labels (the numeric value is observable only through the
        // typed port; the test capture asserts the kind + label set).
        clear_captured_metric_samples();
        emit_gauge_value(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            7,
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
    fn emit_gauge_value_zero_count_still_records_sample() {
        // Zero-valued gauge emissions matter: they distinguish "no
        // violations" from "checker never ran" on the dashboard.
        clear_captured_metric_samples();
        emit_gauge_value(
            AM_HIERARCHY_INTEGRITY_VIOLATIONS,
            0,
            &[("category", "depth_exceeded")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "zero-valued emit must still record");
        assert_eq!(samples[0].kind, MetricKind::Gauge);
        assert_eq!(
            samples[0].labels,
            vec![("category", "depth_exceeded".to_owned())]
        );
    }

    #[test]
    fn emit_histogram_value_records_kind_and_labels_through_capture() {
        clear_captured_metric_samples();
        emit_histogram_value(
            AM_DEPENDENCY_HEALTH,
            12.5,
            &[("target", "rg"), ("op", "bound"), ("outcome", "ok")],
        );
        let samples = take_captured_metric_samples();
        assert_eq!(samples.len(), 1, "emit must be recorded; got: {samples:?}");
        assert_eq!(samples[0].family, AM_DEPENDENCY_HEALTH);
        assert_eq!(samples[0].kind, MetricKind::Histogram);
        assert_eq!(
            samples[0].labels,
            vec![
                ("target", "rg".to_owned()),
                ("op", "bound".to_owned()),
                ("outcome", "ok".to_owned()),
            ]
        );
    }

    #[test]
    fn emit_helpers_are_silent_for_unknown_family() {
        // Unknown family: the typed port drops silently. Capture still
        // records the call; the assertion is no-panic.
        emit_gauge_value("am.nonexistent", 5, &[("category", "x")]);
        emit_histogram_value("am.nonexistent", 1.5, &[("op", "x")]);
    }

    #[test]
    fn capture_records_label_values_verbatim() {
        // Post-swap: label values are no longer escaped or filtered by an
        // allow-list — they are passed through verbatim to the typed
        // OTel instrument and (in test builds) into the capture buffer.
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
            Some("a,b=c\nd\re%f"),
            "captured value must be verbatim post-swap: {samples:?}"
        );
    }

    #[test]
    fn metric_kind_reexports_match_sdk() {
        // Pin the re-export: emit_metric / emit_gauge_value /
        // emit_histogram_value all dispatch on MetricKind values; the
        // SDK type is the contract source of truth.
        let counter: MetricKind = MetricKind::Counter;
        let gauge: MetricKind = MetricKind::Gauge;
        let histogram: MetricKind = MetricKind::Histogram;
        assert_ne!(counter, gauge);
        assert_ne!(gauge, histogram);
        assert_ne!(counter, histogram);
    }
}
