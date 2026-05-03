//! Configuration for the Account Management module.
//!
//! Knobs consumed by [`crate::domain::tenant::service::TenantService`].
//! Bootstrap saga, RG probe, and Types Registry probe knobs land
//! together with their consumers in subsequent PRs.

use serde::Deserialize;

/// Module configuration for `cf-account-management`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountManagementConfig {
    /// Hard cap on `$top` for `listChildren` — clamped at the REST layer
    /// before the service call. Matches `OpenAPI` `Top.maximum` = 200.
    pub max_list_children_top: u32,

    /// Strict-mode reject switch for hierarchy depth. When `true`,
    /// attempts to create a child tenant at `depth > depth_threshold`
    /// are rejected with `tenant_depth_exceeded`. When `false`, the
    /// service emits an advisory log + metric at the same boundary and
    /// proceeds. Both branches fire at the same threshold per
    /// `algo-depth-threshold-evaluation`.
    pub depth_strict_mode: bool,

    /// Hierarchy depth threshold. Defaults to `10` (DESIGN §3.1 / PRD).
    pub depth_threshold: u32,

    /// Retention-pipeline tick period in seconds.
    pub retention_tick_secs: u64,

    /// Provisioning-reaper tick period in seconds.
    pub reaper_tick_secs: u64,

    /// Provisioning-row staleness threshold in seconds — rows older
    /// than this are eligible for reaper compensation.
    pub provisioning_timeout_secs: u64,

    /// Default retention window applied at soft-delete time when the
    /// caller does not specify one. `0` disables retention (immediate
    /// hard-delete eligibility).
    pub default_retention_secs: u64,

    /// Maximum tenants processed per retention tick.
    pub hard_delete_batch_size: usize,

    /// Maximum provisioning rows processed per reaper tick.
    pub reaper_batch_size: usize,

    /// Max parallel hard-delete tasks within one retention tick.
    /// Default `4`. `0` is **rejected by [`Self::validate`]** at module
    /// init so a misconfigured deployment fails loud rather than
    /// silently single-flighting; the call site in
    /// `domain::tenant::service::retention` additionally clamps
    /// `.max(1)` as defense-in-depth for tests that bypass `validate`.
    pub hard_delete_concurrency: usize,

    /// When `true`, module init fails closed if no
    /// `IdpTenantProvisionerClient` is registered in `ClientHub`.
    /// When `false` (default), AM falls back to the no-op
    /// `NoopProvisioner`, in which case `create_child` returns
    /// [`crate::domain::error::DomainError::UnsupportedOperation`] at
    /// runtime if the saga reaches the `IdP` step. Production
    /// deployments that need `IdP` integration MUST set this to `true`
    /// so the missing-plugin condition surfaces as a clean init
    /// failure instead of a runtime error on every create. The
    /// default is `false` so dev / test deployments without an `IdP`
    /// plugin keep booting without changing existing config.
    pub idp_required: bool,
}

impl Default for AccountManagementConfig {
    fn default() -> Self {
        Self {
            max_list_children_top: 200,
            depth_strict_mode: false,
            depth_threshold: 10,
            retention_tick_secs: 60,
            reaper_tick_secs: 30,
            provisioning_timeout_secs: 300,
            // 90 days in seconds.
            default_retention_secs: 90 * 86_400,
            hard_delete_batch_size: 64,
            reaper_batch_size: 64,
            hard_delete_concurrency: 4,
            idp_required: false,
        }
    }
}

impl AccountManagementConfig {
    /// Upper bound on `depth_threshold` so that the
    /// `algo-depth-threshold-evaluation` `parent.depth + 1` arithmetic
    /// in `create_child` cannot land on `u32::MAX` and either silently
    /// saturate (via `saturating_add`) or overflow if the
    /// implementation ever switches to checked arithmetic. The 1 M cap
    /// is far past any realistic hierarchy (the design default is 10).
    pub(crate) const MAX_DEPTH_THRESHOLD: u32 = 1_000_000;

    /// Reject configurations that would panic the lifecycle tasks or
    /// produce undefined runtime behavior. Called by the module's
    /// `init` lifecycle hook before `serve` spawns the retention +
    /// reaper background tasks.
    ///
    /// Specifically, [`tokio::time::interval`] panics on a
    /// zero-duration period; passing
    /// `Duration::from_secs(retention_tick_secs.unwrap_or(0))` to it
    /// would crash the lifecycle task on its first tick. Validating
    /// at startup surfaces the misconfig as a clean `init` failure
    /// instead of a runtime panic that the host runtime sees as a
    /// task abort.
    ///
    /// Beyond the hard panic gates this method also rejects values
    /// that would deadlock the pipelines or silently no-op user-
    /// visible operations:
    ///
    /// * `hard_delete_batch_size == 0` / `reaper_batch_size == 0` —
    ///   the SQL `LIMIT` clamp evaluates to zero and the pipeline
    ///   ticks scan zero rows forever.
    /// * `hard_delete_concurrency == 0` — would degrade to single-
    ///   flight processing of every batch with no observable error.
    ///   Although the retention call site clamps with `.max(1)`, the
    ///   misconfig is still rejected here so it surfaces as an `init`
    ///   failure instead of a silent rewrite.
    /// * `max_list_children_top == 0` — every `listChildren` call
    ///   returns an empty page regardless of the requested `$top`.
    /// * `depth_threshold > MAX_DEPTH_THRESHOLD` — guards the saga's
    ///   `parent.depth + 1` arithmetic against silent saturation.
    ///
    /// # Errors
    ///
    /// Returns a human-readable string naming each invalid field.
    /// Callers map this into [`crate::domain::error::DomainError::Internal`]
    /// (a fatal `init` failure).
    pub fn validate(&self) -> Result<(), String> {
        let mut bad: Vec<&'static str> = Vec::new();
        if self.retention_tick_secs == 0 {
            bad.push("retention_tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.reaper_tick_secs == 0 {
            bad.push("reaper_tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.hard_delete_batch_size == 0 {
            bad.push("hard_delete_batch_size (must be > 0; zero would scan no rows forever)");
        }
        if self.reaper_batch_size == 0 {
            bad.push("reaper_batch_size (must be > 0; zero would scan no rows forever)");
        }
        if self.hard_delete_concurrency == 0 {
            bad.push("hard_delete_concurrency (must be > 0; zero is normalised to 1 at the call site but rejected here so the misconfig is observable)");
        }
        if self.max_list_children_top == 0 {
            bad.push(
                "max_list_children_top (must be > 0; zero would empty every listChildren response)",
            );
        }
        if self.depth_threshold > Self::MAX_DEPTH_THRESHOLD {
            bad.push(
                "depth_threshold (must be <= MAX_DEPTH_THRESHOLD; protects saga depth arithmetic)",
            );
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "account-management configuration is invalid: {}",
                bad.join(", ")
            ))
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "config_tests.rs"]
mod tests;
