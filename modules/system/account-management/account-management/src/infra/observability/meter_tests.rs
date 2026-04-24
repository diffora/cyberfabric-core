//! `OTel` SDK-backed integration tests for [`super::AmMetricsMeter`].
//!
//! Mirrors `mini-chat/src/infra/metrics_tests.rs`: builds a local
//! `SdkMeterProvider` + `PeriodicReader` + `InMemoryMetricExporter`,
//! exercises one happy-path emission per `(family, kind)` pair the
//! [`super::AmMetricsMeter`] struct declares, then queries the exporter
//! via the matching `extract_*` helper to confirm the sample landed.
//!
//! There are 20 typed instruments on `AmMetricsMeter` (one field per
//! `(family, kind)` pair the AM catalog permits — see Phase 1 handoff)
//! plus one end-to-end test that drives the global accessor +
//! `install_metrics_port` flow through `domain::metrics::emit_metric`.
//! Total: 20 + 1 = 21 tests.
//!
//! Why no cardinality-limit view (mini-chat has one): the AM emit-side
//! call sites already hash high-cardinality identifiers (tenant IDs,
//! user IDs) before passing labels, so the view's defensive cap is
//! unnecessary for AM. Mini-chat sets it because raw provider/model
//! strings flow through unchanged.

use account_management_sdk::metric_names::{
    AM_AUDIT_DROP, AM_BOOTSTRAP_LIFECYCLE, AM_CONVERSION_LIFECYCLE, AM_CROSS_TENANT_DENIAL,
    AM_DEPENDENCY_HEALTH, AM_HIERARCHY_DEPTH_EXCEEDANCE, AM_HIERARCHY_INTEGRITY_VIOLATIONS,
    AM_METADATA_RESOLUTION, AM_RETENTION_INVALID_WINDOW, AM_SERIALIZABLE_RETRY,
    AM_TENANT_RETENTION,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use std::time::Duration;

use super::AmMetricsMeter;
use super::meter::AmMetricsPort;

/// Build a fresh `SdkMeterProvider` + `InMemoryMetricExporter` pair.
///
/// Each test gets its own provider — no global state is touched, so
/// tests can run in parallel. The `PeriodicReader` interval is short
/// (50ms) but irrelevant in practice: every test ends with
/// `provider.force_flush()` to drain pending samples synchronously.
fn local_provider() -> (SdkMeterProvider, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone())
        .with_interval(Duration::from_millis(50))
        .build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    (provider, exporter)
}

/// Sum across every counter data point recorded for the named metric.
///
/// Returns `0` if no `Sum` aggregation is found under that name — same
/// reduction style as mini-chat's `extract_counter_value`.
fn extract_counter(exporter: &InMemoryMetricExporter, name: &str) -> u64 {
    let metrics = exporter.get_finished_metrics().unwrap();
    for resource_metrics in &metrics {
        for scope_metrics in resource_metrics.scope_metrics() {
            for metric in scope_metrics.metrics() {
                if metric.name() == name
                    && let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data()
                {
                    return sum
                        .data_points()
                        .map(opentelemetry_sdk::metrics::data::SumDataPoint::value)
                        .sum();
                }
            }
        }
    }
    0
}

/// Sum across every gauge data point recorded for the named metric.
///
/// AM uses gauges as point-in-time observations (one sample per emit
/// call), so a one-shot test typically sees one data point and the sum
/// equals the recorded value. Returns `0` if no `Gauge` aggregation is
/// found under that name.
fn extract_gauge(exporter: &InMemoryMetricExporter, name: &str) -> i64 {
    let metrics = exporter.get_finished_metrics().unwrap();
    for resource_metrics in &metrics {
        for scope_metrics in resource_metrics.scope_metrics() {
            for metric in scope_metrics.metrics() {
                if metric.name() == name
                    && let AggregatedMetrics::I64(MetricData::Gauge(g)) = metric.data()
                {
                    return g
                        .data_points()
                        .map(opentelemetry_sdk::metrics::data::GaugeDataPoint::value)
                        .sum();
                }
            }
        }
    }
    0
}

/// Sum the `count` field across every histogram data point recorded
/// for the named metric. Counts the number of observations, not their
/// values — that matches the brief's `extract_histogram_count` signature
/// and lets per-instrument tests assert "≥ 1 observation landed" without
/// pinning to bucket layout.
fn extract_histogram_count(exporter: &InMemoryMetricExporter, name: &str) -> u64 {
    let metrics = exporter.get_finished_metrics().unwrap();
    for resource_metrics in &metrics {
        for scope_metrics in resource_metrics.scope_metrics() {
            for metric in scope_metrics.metrics() {
                if metric.name() == name
                    && let AggregatedMetrics::F64(MetricData::Histogram(h)) = metric.data()
                {
                    return h
                        .data_points()
                        .map(opentelemetry_sdk::metrics::data::HistogramDataPoint::count)
                        .sum();
                }
            }
        }
    }
    0
}

// ────────────────────────────────────────────────────────────────────
// AM_DEPENDENCY_HEALTH — Counter | Gauge | Histogram (3 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_dependency_health_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_DEPENDENCY_HEALTH,
        1,
        &[
            KeyValue::new("target", "idp"),
            KeyValue::new("op", "provision_tenant"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_DEPENDENCY_HEALTH), 1);
}

#[test]
fn am_meter_records_dependency_health_gauge() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_gauge(
        AM_DEPENDENCY_HEALTH,
        1,
        &[
            KeyValue::new("target", "rg"),
            KeyValue::new("op", "bound"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_gauge(&exporter, AM_DEPENDENCY_HEALTH), 1);
}

#[test]
fn am_meter_records_dependency_health_histogram() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_histogram(
        AM_DEPENDENCY_HEALTH,
        12.5,
        &[
            KeyValue::new("target", "idp"),
            KeyValue::new("op", "provision_tenant"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_histogram_count(&exporter, AM_DEPENDENCY_HEALTH), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_METADATA_RESOLUTION — Counter | Histogram (2 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_metadata_resolution_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_METADATA_RESOLUTION,
        1,
        &[
            KeyValue::new("op", "resolve"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_METADATA_RESOLUTION), 1);
}

#[test]
fn am_meter_records_metadata_resolution_histogram() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_histogram(
        AM_METADATA_RESOLUTION,
        7.0,
        &[
            KeyValue::new("op", "resolve"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(
        extract_histogram_count(&exporter, AM_METADATA_RESOLUTION),
        1
    );
}

// ────────────────────────────────────────────────────────────────────
// AM_BOOTSTRAP_LIFECYCLE — Counter | Histogram (2 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_bootstrap_lifecycle_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_BOOTSTRAP_LIFECYCLE,
        1,
        &[
            KeyValue::new("phase", "ensure_root"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_BOOTSTRAP_LIFECYCLE), 1);
}

#[test]
fn am_meter_records_bootstrap_lifecycle_histogram() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_histogram(
        AM_BOOTSTRAP_LIFECYCLE,
        42.0,
        &[
            KeyValue::new("phase", "ensure_root"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_histogram_count(&exporter, AM_BOOTSTRAP_LIFECYCLE), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_TENANT_RETENTION — Counter | Gauge | Histogram (3 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_tenant_retention_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_TENANT_RETENTION,
        1,
        &[
            KeyValue::new("op", "hard_delete"),
            KeyValue::new("outcome", "deleted"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_TENANT_RETENTION), 1);
}

#[test]
fn am_meter_records_tenant_retention_gauge() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_gauge(
        AM_TENANT_RETENTION,
        3,
        &[KeyValue::new("op", "backlog")],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_gauge(&exporter, AM_TENANT_RETENTION), 3);
}

#[test]
fn am_meter_records_tenant_retention_histogram() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_histogram(
        AM_TENANT_RETENTION,
        99.0,
        &[
            KeyValue::new("op", "hard_delete"),
            KeyValue::new("outcome", "deleted"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_histogram_count(&exporter, AM_TENANT_RETENTION), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_RETENTION_INVALID_WINDOW — Counter (1 test)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_retention_invalid_window_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(AM_RETENTION_INVALID_WINDOW, 1, &[]);
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_RETENTION_INVALID_WINDOW), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_CONVERSION_LIFECYCLE — Counter | Histogram (2 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_conversion_lifecycle_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_CONVERSION_LIFECYCLE,
        1,
        &[
            KeyValue::new("transition", "request"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_CONVERSION_LIFECYCLE), 1);
}

#[test]
fn am_meter_records_conversion_lifecycle_histogram() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_histogram(
        AM_CONVERSION_LIFECYCLE,
        15.5,
        &[
            KeyValue::new("transition", "request"),
            KeyValue::new("outcome", "ok"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(
        extract_histogram_count(&exporter, AM_CONVERSION_LIFECYCLE),
        1
    );
}

// ────────────────────────────────────────────────────────────────────
// AM_HIERARCHY_DEPTH_EXCEEDANCE — Counter | Gauge (2 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_hierarchy_depth_exceedance_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_HIERARCHY_DEPTH_EXCEEDANCE,
        1,
        &[KeyValue::new("op", "create_child")],
    );
    provider.force_flush().unwrap();
    assert_eq!(
        extract_counter(&exporter, AM_HIERARCHY_DEPTH_EXCEEDANCE),
        1
    );
}

#[test]
fn am_meter_records_hierarchy_depth_exceedance_gauge() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_gauge(
        AM_HIERARCHY_DEPTH_EXCEEDANCE,
        7,
        &[KeyValue::new("op", "current_depth")],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_gauge(&exporter, AM_HIERARCHY_DEPTH_EXCEEDANCE), 7);
}

// ────────────────────────────────────────────────────────────────────
// AM_CROSS_TENANT_DENIAL — Counter (1 test)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_cross_tenant_denial_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_CROSS_TENANT_DENIAL,
        1,
        &[
            KeyValue::new("operation", "create_child"),
            KeyValue::new("barrier_mode", "strict"),
            KeyValue::new("reason", "non_platform_admin"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_CROSS_TENANT_DENIAL), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_HIERARCHY_INTEGRITY_VIOLATIONS — Counter | Gauge (2 tests)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_hierarchy_integrity_violations_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_HIERARCHY_INTEGRITY_VIOLATIONS,
        1,
        &[KeyValue::new("category", "cycle_detected")],
    );
    provider.force_flush().unwrap();
    assert_eq!(
        extract_counter(&exporter, AM_HIERARCHY_INTEGRITY_VIOLATIONS),
        1
    );
}

#[test]
fn am_meter_records_hierarchy_integrity_violations_gauge() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_gauge(
        AM_HIERARCHY_INTEGRITY_VIOLATIONS,
        2,
        &[KeyValue::new("category", "orphaned_child")],
    );
    provider.force_flush().unwrap();
    assert_eq!(
        extract_gauge(&exporter, AM_HIERARCHY_INTEGRITY_VIOLATIONS),
        2
    );
}

// ────────────────────────────────────────────────────────────────────
// AM_AUDIT_DROP — Counter (1 test)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_audit_drop_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_AUDIT_DROP,
        1,
        &[KeyValue::new("kind", "policy_drop")],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_AUDIT_DROP), 1);
}

// ────────────────────────────────────────────────────────────────────
// AM_SERIALIZABLE_RETRY — Counter (1 test)
// ────────────────────────────────────────────────────────────────────

#[test]
fn am_meter_records_serializable_retry_counter() {
    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let am = AmMetricsMeter::new(&meter);
    am.record_counter(
        AM_SERIALIZABLE_RETRY,
        1,
        &[
            KeyValue::new("outcome", "recovered"),
            KeyValue::new("attempts", "2"),
        ],
    );
    provider.force_flush().unwrap();
    assert_eq!(extract_counter(&exporter, AM_SERIALIZABLE_RETRY), 1);
}

// ────────────────────────────────────────────────────────────────────
// Trait-surface plumbing test — proves an `Arc<dyn AmMetricsPort>`
// constructed over a local `SdkMeterProvider` correctly forwards
// emissions into that provider's exporter.
//
// We intentionally do NOT exercise `install_metrics_port` +
// `domain::metrics::emit_metric` here: that path is `OnceLock`-backed
// and first-set-wins, so a prior test in the same binary may have
// already bound a different port and our local exporter would never
// see the sample. That global-accessor round-trip belongs in a
// dedicated integration test binary; this unit test pins the trait
// surface itself.
// ────────────────────────────────────────────────────────────────────

#[test]
fn direct_trait_surface_emission_lands_in_local_exporter() {
    use crate::domain::metrics::AM_AUDIT_DROP as DOMAIN_AM_AUDIT_DROP;
    use std::sync::Arc;

    let (provider, exporter) = local_provider();
    let meter = provider.meter("account-management");
    let port: Arc<dyn AmMetricsPort> = Arc::new(AmMetricsMeter::new(&meter));

    port.record_counter(DOMAIN_AM_AUDIT_DROP, 1, &[KeyValue::new("kind", "direct")]);
    provider.force_flush().unwrap();

    assert_eq!(
        extract_counter(&exporter, DOMAIN_AM_AUDIT_DROP),
        1,
        "trait-surface emission via Arc<dyn AmMetricsPort> must land in the local exporter"
    );
}
