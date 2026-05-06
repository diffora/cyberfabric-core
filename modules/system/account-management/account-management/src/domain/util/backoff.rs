//! Pure exponential-backoff helpers shared across AM domain features.
//!
//! Used by both the bootstrap saga (`domain/bootstrap/service.rs` IdP-wait
//! loop) and the provisioning reaper (`domain/tenant/service.rs`
//! per-tenant reaper backoff). The retry helper in
//! `infra/storage/repo_impl.rs` keeps its own ms-resolution ramp because
//! it operates on a different unit (milliseconds vs. seconds-scale
//! durations) and a different shape (1ms × 2^attempt vs. doubling a
//! running delay).

use std::time::Duration;

/// `(prev * 2).min(cap)` — pure exponential backoff with a hard cap.
/// Saturating multiplication on the [`Duration`] domain.
///
/// # Panics
///
/// Debug-asserts that `prev > Duration::ZERO`. Doubling zero stays
/// at zero, so a caller seeded with `0` would spin without ever
/// backing off. All in-tree callers seed with at least one second
/// (e.g. `idp_retry_backoff_initial_secs.max(1)`), so this is a
/// programmer-error precondition rather than a runtime path. Release
/// builds bump a zero seed to 1ms before doubling so the loop never
/// busy-spins even if the assertion is stripped.
#[must_use]
pub fn compute_next_backoff(prev: Duration, cap: Duration) -> Duration {
    debug_assert!(
        !prev.is_zero(),
        "compute_next_backoff requires prev > Duration::ZERO; doubling zero starves the caller's retry loop"
    );
    let prev = if prev.is_zero() {
        Duration::from_millis(1)
    } else {
        prev
    };
    let doubled = prev.checked_mul(2).unwrap_or(Duration::MAX);
    doubled.min(cap)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::duration_suboptimal_units, reason = "test helpers")]
mod tests {
    use super::*;

    #[test]
    fn doubles_until_cap() {
        let cap = Duration::from_secs(600);
        assert_eq!(
            compute_next_backoff(Duration::from_secs(30), cap),
            Duration::from_secs(60)
        );
        assert_eq!(
            compute_next_backoff(Duration::from_secs(60), cap),
            Duration::from_secs(120)
        );
        assert_eq!(compute_next_backoff(Duration::from_secs(400), cap), cap);
        assert_eq!(compute_next_backoff(cap, cap), cap);
    }

    #[test]
    fn saturates_on_overflow() {
        let cap = Duration::MAX;
        assert_eq!(compute_next_backoff(Duration::MAX, cap), Duration::MAX);
    }
}
