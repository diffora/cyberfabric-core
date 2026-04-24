//! Typed `OTel` instruments for the AM metric-family catalog.
//!
//! Mirrors `MiniChatMetricsMeter` from `mini-chat`:
//! [`AmMetricsMeter`] holds one typed instrument per `(family, kind)` pair
//! the AM metric catalog permits (see `account_management_sdk::metric_names`
//! plus the per-family kind set documented in PRD §5.9). Production wires
//! `AmMetricsMeter` behind the [`AmMetricsPort`] trait; tests can substitute
//! [`NoopMetricsPort`] (or a capture mock) without touching the global
//! `OTel` meter provider.
//!
//! ## Why a port trait?
//!
//! Module init (phase 2) parks an `Arc<dyn AmMetricsPort>` in a `OnceLock`
//! that `domain/metrics.rs::emit_metric` (phase 3) reads on every emission.
//! The trait keeps the impl crate compilable in test contexts where no
//! `MeterProvider` has been installed and gives integration tests a
//! purpose-built capture seam.
//!
//! ## Naming
//!
//! Each instrument is constructed with the `AM_*` family constant
//! verbatim as the metric name (e.g. `meter.u64_counter("am.dependency_health")`).
//! Multi-kind families (`AM_DEPENDENCY_HEALTH` allows Counter + Gauge +
//! Histogram) get one field per kind; `OTel` distinguishes the instruments
//! internally by `(name, kind)` tuple.

use account_management_sdk::metric_names::{
    AM_AUDIT_DROP, AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL,
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_METADATA_RESOLUTION, AM_RETENTION_INVALID_WINDOW, AM_SERIALIZABLE_RETRY,
    AM_TENANT_RETENTION,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};

/// Typed metric instruments for the AM family catalog.
///
/// Mirrors `MiniChatMetricsMeter` — one field per `(family, kind)` pair
/// the AM catalog permits (PRD §5.9). The constructor calls
/// `meter.u64_counter(...)`, `meter.f64_histogram(...)`, `meter.i64_gauge(...)`
/// with the `AM_*` family constant verbatim as the instrument name.
/// Histogram fields carry a `_latency_ms` suffix in the Rust struct to make
/// their unit obvious at the call site; the underlying `OTel` metric name
/// is still the family constant.
#[derive(Debug)]
pub struct AmMetricsMeter {
    // ── AM_DEPENDENCY_HEALTH (Counter | Gauge | Histogram) ─────────────
    pub dependency_health_counter: Counter<u64>,
    pub dependency_health_gauge: Gauge<i64>,
    pub dependency_health_latency_ms: Histogram<f64>,

    // ── AM_METADATA_RESOLUTION (Counter | Histogram) ───────────────────
    pub metadata_resolution_counter: Counter<u64>,
    pub metadata_resolution_latency_ms: Histogram<f64>,

    // ── AM_BOOTSTRAP_LIFECYCLE (Counter | Histogram) ───────────────────
    pub bootstrap_lifecycle_counter: Counter<u64>,
    pub bootstrap_lifecycle_latency_ms: Histogram<f64>,

    // ── AM_TENANT_RETENTION (Counter | Gauge | Histogram) ──────────────
    pub tenant_retention_counter: Counter<u64>,
    pub tenant_retention_gauge: Gauge<i64>,
    pub tenant_retention_latency_ms: Histogram<f64>,

    // ── AM_RETENTION_INVALID_WINDOW (Counter) ──────────────────────────
    pub retention_invalid_window_counter: Counter<u64>,

    // ── AM_CONVERSION_LIFECYCLE (Counter | Histogram) ──────────────────
    pub conversion_lifecycle_counter: Counter<u64>,
    pub conversion_lifecycle_latency_ms: Histogram<f64>,

    // ── AM_HIERARCHY_DEPTH_EXCEEDANCE (Counter | Gauge) ────────────────
    pub hierarchy_depth_exceedance_counter: Counter<u64>,
    pub hierarchy_depth_exceedance_gauge: Gauge<i64>,

    // ── AM_CROSS_TENANT_DENIAL (Counter) ───────────────────────────────
    pub cross_tenant_denial_counter: Counter<u64>,

    // ── AM_HIERARCHY_INTEGRITY_VIOLATIONS (Counter | Gauge) ────────────
    pub hierarchy_integrity_violations_counter: Counter<u64>,
    pub hierarchy_integrity_violations_gauge: Gauge<i64>,

    // ── AM_AUDIT_DROP (Counter) ────────────────────────────────────────
    pub audit_drop_counter: Counter<u64>,

    // ── AM_SERIALIZABLE_RETRY (Counter) ────────────────────────────────
    pub serializable_retry_counter: Counter<u64>,
}

impl AmMetricsMeter {
    /// Construct every typed instrument by calling the matching builder on
    /// `meter`. Each instrument is registered under its `AM_*` family
    /// constant verbatim (no namespace prefix); `domain/metrics.rs` emits
    /// against those exact strings. If per-deployment namespacing is
    /// needed in the future, re-introduce a `prefix` parameter at that
    /// time — keeping it as an unused reservation just confused
    /// callsites.
    #[must_use]
    //
    // Each instrument carries a UCUM `unit` literal so dashboards and
    // OTLP receivers can render axes correctly without guessing from
    // the description. Latency histograms use `"ms"` (UCUM
    // millisecond); counters / gauges that count discrete domain
    // events use `"{event}"`, `"{outcome}"`, `"{transition}"`,
    // `"{call}"`, `"{tenant}"`, `"{level}"`, or `"{violation}"`
    // (UCUM curly-brace dimensionless tokens) — these annotate the
    // semantic kind without changing the dimensional analysis. Bind
    // state is `"{state}"`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            // ── AM_DEPENDENCY_HEALTH ───────────────────────────────────
            dependency_health_counter: meter
                .u64_counter(AM_DEPENDENCY_HEALTH)
                .with_description("AM dependency-call health (counter)")
                .with_unit("{call}")
                .build(),
            dependency_health_gauge: meter
                .i64_gauge(AM_DEPENDENCY_HEALTH)
                .with_description("AM dependency-call health (gauge: bind state)")
                .with_unit("{state}")
                .build(),
            dependency_health_latency_ms: meter
                .f64_histogram(AM_DEPENDENCY_HEALTH)
                .with_description("AM dependency-call latency (ms)")
                .with_unit("ms")
                .build(),

            // ── AM_METADATA_RESOLUTION ────────────────────────────────
            metadata_resolution_counter: meter
                .u64_counter(AM_METADATA_RESOLUTION)
                .with_description("AM tenant-metadata resolution operations")
                .with_unit("{op}")
                .build(),
            metadata_resolution_latency_ms: meter
                .f64_histogram(AM_METADATA_RESOLUTION)
                .with_description("AM tenant-metadata resolution latency (ms)")
                .with_unit("ms")
                .build(),

            // ── AM_BOOTSTRAP_LIFECYCLE ────────────────────────────────
            bootstrap_lifecycle_counter: meter
                .u64_counter(AM_BOOTSTRAP_LIFECYCLE)
                .with_description("AM root-tenant bootstrap lifecycle transitions")
                .with_unit("{transition}")
                .build(),
            bootstrap_lifecycle_latency_ms: meter
                .f64_histogram(AM_BOOTSTRAP_LIFECYCLE)
                .with_description("AM root-tenant bootstrap phase latency (ms)")
                .with_unit("ms")
                .build(),

            // ── AM_TENANT_RETENTION ───────────────────────────────────
            tenant_retention_counter: meter
                .u64_counter(AM_TENANT_RETENTION)
                .with_description("AM provisioning reaper / hard-delete job outcomes")
                .with_unit("{outcome}")
                .build(),
            tenant_retention_gauge: meter
                .i64_gauge(AM_TENANT_RETENTION)
                .with_description("AM tenant retention backlog (gauge)")
                .with_unit("{tenant}")
                .build(),
            tenant_retention_latency_ms: meter
                .f64_histogram(AM_TENANT_RETENTION)
                .with_description("AM tenant retention job latency (ms)")
                .with_unit("ms")
                .build(),

            // ── AM_RETENTION_INVALID_WINDOW ───────────────────────────
            retention_invalid_window_counter: meter
                .u64_counter(AM_RETENTION_INVALID_WINDOW)
                .with_description("AM invalid retention-window configurations encountered")
                .with_unit("{event}")
                .build(),

            // ── AM_CONVERSION_LIFECYCLE ───────────────────────────────
            conversion_lifecycle_counter: meter
                .u64_counter(AM_CONVERSION_LIFECYCLE)
                .with_description("AM mode-conversion request transitions")
                .with_unit("{transition}")
                .build(),
            conversion_lifecycle_latency_ms: meter
                .f64_histogram(AM_CONVERSION_LIFECYCLE)
                .with_description("AM mode-conversion request latency (ms)")
                .with_unit("ms")
                .build(),

            // ── AM_HIERARCHY_DEPTH_EXCEEDANCE ─────────────────────────
            hierarchy_depth_exceedance_counter: meter
                .u64_counter(AM_HIERARCHY_DEPTH_EXCEEDANCE)
                .with_description("AM hierarchy-depth threshold exceedance events")
                .with_unit("{event}")
                .build(),
            hierarchy_depth_exceedance_gauge: meter
                .i64_gauge(AM_HIERARCHY_DEPTH_EXCEEDANCE)
                .with_description("AM hierarchy depth (gauge)")
                .with_unit("{level}")
                .build(),

            // ── AM_CROSS_TENANT_DENIAL ────────────────────────────────
            cross_tenant_denial_counter: meter
                .u64_counter(AM_CROSS_TENANT_DENIAL)
                .with_description("AM cross-tenant denial events")
                .with_unit("{event}")
                .build(),

            // ── AM_HIERARCHY_INTEGRITY_VIOLATIONS ─────────────────────
            hierarchy_integrity_violations_counter: meter
                .u64_counter(AM_HIERARCHY_INTEGRITY_VIOLATIONS)
                .with_description("AM hierarchy-integrity violations (counter)")
                .with_unit("{violation}")
                .build(),
            hierarchy_integrity_violations_gauge: meter
                .i64_gauge(AM_HIERARCHY_INTEGRITY_VIOLATIONS)
                .with_description("AM hierarchy-integrity violations (gauge per category)")
                .with_unit("{violation}")
                .build(),

            // ── AM_AUDIT_DROP ─────────────────────────────────────────
            audit_drop_counter: meter
                .u64_counter(AM_AUDIT_DROP)
                .with_description("AM audit emission drops (allow-list reject)")
                .with_unit("{event}")
                .build(),

            // ── AM_SERIALIZABLE_RETRY ─────────────────────────────────
            serializable_retry_counter: meter
                .u64_counter(AM_SERIALIZABLE_RETRY)
                .with_description("AM SERIALIZABLE-isolation retry outcomes")
                .with_unit("{outcome}")
                .build(),
        }
    }
}

/// Port trait for DI.
///
/// Production wires [`AmMetricsMeter`]; tests wire [`NoopMetricsPort`] or
/// a capture mock. `domain/metrics.rs::emit_metric` (phase 3) holds an
/// `Arc<dyn AmMetricsPort>` and dispatches on the validated `(family, kind)`
/// tuple.
///
/// All methods are fire-and-forget: an unknown `family` MUST be dropped
/// silently (no panic) so that the port's defensive contract matches the
/// AM family-catalog semantics in `domain/metrics.rs`.
pub trait AmMetricsPort: Send + Sync {
    /// Record a counter increment of `value` against the named family.
    fn record_counter(&self, family: &str, value: u64, labels: &[KeyValue]);

    /// Record a histogram observation of `value` against the named family.
    fn record_histogram(&self, family: &str, value: f64, labels: &[KeyValue]);

    /// Record a gauge observation of `value` against the named family.
    fn record_gauge(&self, family: &str, value: i64, labels: &[KeyValue]);
}

impl AmMetricsPort for AmMetricsMeter {
    fn record_counter(&self, family: &str, value: u64, labels: &[KeyValue]) {
        match family {
            AM_DEPENDENCY_HEALTH => self.dependency_health_counter.add(value, labels),
            AM_METADATA_RESOLUTION => self.metadata_resolution_counter.add(value, labels),
            AM_BOOTSTRAP_LIFECYCLE => self.bootstrap_lifecycle_counter.add(value, labels),
            AM_TENANT_RETENTION => self.tenant_retention_counter.add(value, labels),
            AM_RETENTION_INVALID_WINDOW => {
                self.retention_invalid_window_counter.add(value, labels);
            }
            AM_CONVERSION_LIFECYCLE => self.conversion_lifecycle_counter.add(value, labels),
            AM_HIERARCHY_DEPTH_EXCEEDANCE => {
                self.hierarchy_depth_exceedance_counter.add(value, labels);
            }
            AM_CROSS_TENANT_DENIAL => self.cross_tenant_denial_counter.add(value, labels),
            AM_HIERARCHY_INTEGRITY_VIOLATIONS => {
                self.hierarchy_integrity_violations_counter.add(value, labels);
            }
            AM_AUDIT_DROP => self.audit_drop_counter.add(value, labels),
            AM_SERIALIZABLE_RETRY => self.serializable_retry_counter.add(value, labels),
            // Defensive: unknown family — drop silently (matches AM family catalog).
            _ => {}
        }
    }

    fn record_histogram(&self, family: &str, value: f64, labels: &[KeyValue]) {
        match family {
            AM_DEPENDENCY_HEALTH => self.dependency_health_latency_ms.record(value, labels),
            AM_METADATA_RESOLUTION => self.metadata_resolution_latency_ms.record(value, labels),
            AM_BOOTSTRAP_LIFECYCLE => self.bootstrap_lifecycle_latency_ms.record(value, labels),
            AM_TENANT_RETENTION => self.tenant_retention_latency_ms.record(value, labels),
            AM_CONVERSION_LIFECYCLE => self.conversion_lifecycle_latency_ms.record(value, labels),
            // Families without a Histogram kind in the AM catalog are
            // intentionally not dispatched here — drop silently.
            _ => {}
        }
    }

    fn record_gauge(&self, family: &str, value: i64, labels: &[KeyValue]) {
        match family {
            AM_DEPENDENCY_HEALTH => self.dependency_health_gauge.record(value, labels),
            AM_TENANT_RETENTION => self.tenant_retention_gauge.record(value, labels),
            AM_HIERARCHY_DEPTH_EXCEEDANCE => {
                self.hierarchy_depth_exceedance_gauge.record(value, labels);
            }
            AM_HIERARCHY_INTEGRITY_VIOLATIONS => {
                self.hierarchy_integrity_violations_gauge
                    .record(value, labels);
            }
            // Families without a Gauge kind in the AM catalog are
            // intentionally not dispatched here — drop silently.
            _ => {}
        }
    }
}

/// No-op [`AmMetricsPort`] — used as the default until module init runs.
///
/// Module init (phase 2) seeds the global `OnceLock` with a `NoopMetricsPort`
/// before the real `AmMetricsMeter` is wired, so call sites that emit
/// metrics during very early bootstrap (before the `MeterProvider` is
/// installed) do not need to defend against an absent port.
#[derive(Debug, Default)]
pub struct NoopMetricsPort;

impl AmMetricsPort for NoopMetricsPort {
    fn record_counter(&self, _family: &str, _value: u64, _labels: &[KeyValue]) {}
    fn record_histogram(&self, _family: &str, _value: f64, _labels: &[KeyValue]) {}
    fn record_gauge(&self, _family: &str, _value: i64, _labels: &[KeyValue]) {}
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use opentelemetry::global;

    #[test]
    fn noop_port_record_methods_are_silent() {
        let port = NoopMetricsPort;
        // No panics, no observable effects.
        port.record_counter(AM_AUDIT_DROP, 1, &[]);
        port.record_histogram(AM_DEPENDENCY_HEALTH, 1.5, &[]);
        port.record_gauge(AM_HIERARCHY_INTEGRITY_VIOLATIONS, 0, &[]);
    }

    #[test]
    fn meter_constructor_builds_every_field() {
        // The default global `MeterProvider` is a no-op until module init
        // wires a real `SdkMeterProvider`, so this constructor call exercises
        // the field-builder code without requiring a real exporter.
        let meter = global::meter("am.test");
        let m = AmMetricsMeter::new(&meter);

        // Each typed field must dispatch without panicking on its allowed
        // (family, kind) tuple. Unknown family must drop silently.
        m.record_counter(AM_DEPENDENCY_HEALTH, 1, &[]);
        m.record_gauge(AM_DEPENDENCY_HEALTH, 0, &[]);
        m.record_histogram(AM_DEPENDENCY_HEALTH, 1.0, &[]);
        m.record_counter(AM_METADATA_RESOLUTION, 1, &[]);
        m.record_histogram(AM_METADATA_RESOLUTION, 1.0, &[]);
        m.record_counter(AM_BOOTSTRAP_LIFECYCLE, 1, &[]);
        m.record_histogram(AM_BOOTSTRAP_LIFECYCLE, 1.0, &[]);
        m.record_counter(AM_TENANT_RETENTION, 1, &[]);
        m.record_gauge(AM_TENANT_RETENTION, 0, &[]);
        m.record_histogram(AM_TENANT_RETENTION, 1.0, &[]);
        m.record_counter(AM_RETENTION_INVALID_WINDOW, 1, &[]);
        m.record_counter(AM_CONVERSION_LIFECYCLE, 1, &[]);
        m.record_histogram(AM_CONVERSION_LIFECYCLE, 1.0, &[]);
        m.record_counter(AM_HIERARCHY_DEPTH_EXCEEDANCE, 1, &[]);
        m.record_gauge(AM_HIERARCHY_DEPTH_EXCEEDANCE, 0, &[]);
        m.record_counter(AM_CROSS_TENANT_DENIAL, 1, &[]);
        m.record_counter(AM_HIERARCHY_INTEGRITY_VIOLATIONS, 1, &[]);
        m.record_gauge(AM_HIERARCHY_INTEGRITY_VIOLATIONS, 0, &[]);
        m.record_counter(AM_AUDIT_DROP, 1, &[]);
        m.record_counter(AM_SERIALIZABLE_RETRY, 1, &[]);
    }

    #[test]
    fn dispatch_drops_unknown_family_without_panic() {
        let meter = global::meter("am.test.unknown");
        let m = AmMetricsMeter::new(&meter);
        m.record_counter("am.totally_made_up", 1, &[]);
        m.record_histogram("am.totally_made_up", 1.0, &[]);
        m.record_gauge("am.totally_made_up", 0, &[]);
    }

    #[test]
    fn dispatch_drops_kind_mismatch_without_panic() {
        // `AM_AUDIT_DROP` is Counter-only; gauge/histogram calls must drop.
        let meter = global::meter("am.test.kind_mismatch");
        let m = AmMetricsMeter::new(&meter);
        m.record_gauge(AM_AUDIT_DROP, 0, &[]);
        m.record_histogram(AM_AUDIT_DROP, 1.0, &[]);
    }
}
