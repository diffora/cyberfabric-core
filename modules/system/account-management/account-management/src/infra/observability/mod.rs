//! Observability infra for Account Management.
//!
//! Holds the typed `OTel` instrument struct ([`AmMetricsMeter`]) and the
//! port trait ([`AmMetricsPort`]) the domain layer reads from in
//! `domain/metrics.rs::emit_metric`. Module init (phase 2) wires a real
//! `AmMetricsMeter` via a global `OnceLock<Arc<dyn AmMetricsPort>>`; the
//! default is [`NoopMetricsPort`] so call sites do not need to defend
//! against an absent port during early bootstrap.

use std::sync::{Arc, OnceLock};

pub mod meter;

#[cfg(test)]
mod meter_tests;

pub use meter::{AmMetricsMeter, AmMetricsPort, NoopMetricsPort};

static METRICS_PORT: OnceLock<Arc<dyn AmMetricsPort>> = OnceLock::new();

/// Install the production meter at module init. Idempotent: subsequent
/// calls are silently ignored (the `OnceLock` owns the first port set).
///
/// Phase 2 wires this from `module.rs::init` after dependency
/// resolution and before service construction so saga emit calls land
/// somewhere observable. Tests that need a non-default port either
/// install one as the very first action of the test binary or rely on
/// the `#[cfg(test)]` capture buffer in `domain/metrics.rs`.
pub fn install_metrics_port(port: Arc<dyn AmMetricsPort>) {
    // OnceLock::set returns Err if a port was already installed; ignore by
    // assignment (mini-chat parity: first-set-wins, idempotent installer).
    _ = METRICS_PORT.set(port);
}

/// Resolve the active port. Returns a reference to the installed port,
/// or a static [`NoopMetricsPort`] if init has not run (production:
/// between binary start and module init; tests: when no test setup ran
/// `install_metrics_port`). Always returns a `&'static dyn
/// AmMetricsPort`, so emit-side call sites never have to defend against
/// `Option::None`.
#[must_use]
pub fn metrics() -> &'static dyn AmMetricsPort {
    static NOOP: NoopMetricsPort = NoopMetricsPort;
    METRICS_PORT
        .get()
        .map_or(&NOOP as &dyn AmMetricsPort, |p| p.as_ref())
}

// Note on test reset semantics: `OnceLock` has no public clear, so tests
// that need a non-default port either run in a fresh process or accept
// first-set-wins. The integration tests in `meter_tests.rs` build a
// per-test `SdkMeterProvider` and exercise the trait surface directly,
// which is exporter-agnostic and unaffected by the global port choice.
