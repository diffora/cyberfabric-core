//! Configuration for the Account Management module.
//!
//! Phase 2 shipped the `max_list_children_top` knob that caps the `$top`
//! page-size accepted by `listChildren`. Phase 3 extends the surface
//! with depth-policy + retention / reaper scheduling knobs plus the
//! provisioning-reaper age threshold.
//!
//! All Phase 3 defaults match PRD §5.4 / FEATURE §5 operational contracts.

use serde::Deserialize;

use crate::domain::bootstrap::config::BootstrapConfig;

/// Module configuration for `cf-account-management`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountManagementConfig {
    /// Hard cap on `$top` for `listChildren` — clamped at the REST layer
    /// before the service call. Matches `OpenAPI` `Top.maximum` = 200.
    pub max_list_children_top: u32,

    // ---- Phase 3 additions ----
    /// Strict-mode reject switch for hierarchy depth. When `true`,
    /// attempts to create a child tenant at `depth > depth_threshold`
    /// are rejected with `tenant_depth_exceeded`. When `false`, the
    /// service emits an advisory log + metric at the same boundary and
    /// proceeds. Both branches fire at the same threshold per
    /// `algo-depth-threshold-evaluation`
    /// (`feature-tenant-hierarchy-management.md` §3 lines 301-308).
    pub depth_strict_mode: bool,

    /// Hierarchy depth threshold. Defaults to `10` (DESIGN §3.1 / PRD
    /// §5). Advisory and strict-mode rejection both fire at
    /// `depth > depth_threshold` per the algorithm spec.
    pub depth_threshold: u32,

    /// Tick interval (seconds) for the hard-delete retention sweep.
    pub retention_tick_secs: u64,

    /// Tick interval (seconds) for the provisioning reaper sweep.
    pub reaper_tick_secs: u64,

    /// How long a `provisioning` row may linger before the reaper
    /// attempts to compensate it (seconds).
    pub provisioning_timeout_secs: u64,

    /// Default retention window applied at soft-delete time when the
    /// caller does not supply an explicit override (seconds).
    pub default_retention_secs: u64,

    /// Maximum number of retention-due rows processed in a single
    /// hard-delete batch tick.
    pub hard_delete_batch_size: usize,

    /// Maximum number of stuck-`Provisioning` rows the reaper scans
    /// per tick. Bounds the SQL `LIMIT` on `scan_stuck_provisioning`
    /// so a large backlog does not load every row into memory in one
    /// query. Default `64`, matching `hard_delete_batch_size`.
    pub reaper_batch_size: usize,

    /// Maximum concurrent in-flight hard-delete pipelines per depth
    /// bucket. Sibling tenants at the same depth have no FK ordering
    /// constraint and can be reclaimed concurrently; the buckets
    /// themselves are still processed leaf-first (deepest depth first).
    /// Default `4`. `0` is normalised to `1` at the call site so the
    /// service always makes forward progress.
    pub hard_delete_concurrency: usize,

    /// Fail closed for production dependency barriers that can only prove
    /// dependency reachability but cannot yet enforce the full semantic
    /// check. Defaults to `false` for backward compatibility while SDK
    /// lookup gaps are closed; production deployments should enable it.
    pub strict_barriers: bool,

    /// Per-call deadline for Resource Group ownership probes, in
    /// milliseconds. Defaults to `2000` so a dependency stall cannot
    /// hold tenant soft-delete indefinitely.
    pub rg_probe_timeout_ms: u64,

    /// Per-call deadline for Types Registry tenant-type probes, in
    /// milliseconds. Defaults to `2000` so the pre-write tenant-type
    /// barrier fails closed instead of waiting on an unbounded SDK call.
    pub types_registry_probe_timeout_ms: u64,

    /// Optional platform-bootstrap configuration. When `Some`, the
    /// module's `init` lifecycle hook drives the
    /// [`crate::domain::bootstrap::BootstrapService`] saga to
    /// completion **before** `serve` starts the retention + reaper
    /// loops (FR `fr-bootstrap-ordering`). When `None`, bootstrap is
    /// skipped — useful for dev / multi-region deployments where the
    /// root tenant is bootstrapped out of band.
    pub bootstrap: Option<BootstrapConfig>,
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
            strict_barriers: false,
            rg_probe_timeout_ms: 2_000,
            types_registry_probe_timeout_ms: 2_000,
            bootstrap: None,
        }
    }
}

impl AccountManagementConfig {
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
    /// # Errors
    ///
    /// Returns a human-readable string naming each invalid field.
    /// Callers map this into [`crate::domain::error::AmError::Internal`]
    /// (a fatal `init` failure).
    pub fn validate(&self) -> Result<(), String> {
        let mut bad: Vec<&'static str> = Vec::new();
        if self.retention_tick_secs == 0 {
            bad.push("retention_tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.reaper_tick_secs == 0 {
            bad.push("reaper_tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.rg_probe_timeout_ms == 0 {
            bad.push("rg_probe_timeout_ms (must be > 0; dependency probe timeout cannot be zero)");
        }
        if self.types_registry_probe_timeout_ms == 0 {
            bad.push(
                "types_registry_probe_timeout_ms (must be > 0; dependency probe timeout cannot be zero)",
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
mod tests {
    use super::*;

    #[test]
    fn default_max_list_children_top_is_200() {
        assert_eq!(
            AccountManagementConfig::default().max_list_children_top,
            200
        );
    }

    #[test]
    fn default_config_passes_validate() {
        AccountManagementConfig::default()
            .validate()
            .expect("default config must validate cleanly");
    }

    #[test]
    fn validate_rejects_zero_retention_tick() {
        let cfg = AccountManagementConfig {
            retention_tick_secs: 0,
            ..AccountManagementConfig::default()
        };
        let err = cfg.validate().expect_err("zero tick must reject");
        assert!(err.contains("retention_tick_secs"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_reaper_tick() {
        let cfg = AccountManagementConfig {
            reaper_tick_secs: 0,
            ..AccountManagementConfig::default()
        };
        let err = cfg.validate().expect_err("zero tick must reject");
        assert!(err.contains("reaper_tick_secs"), "got: {err}");
    }

    #[test]
    fn validate_reports_all_invalid_fields_at_once() {
        let cfg = AccountManagementConfig {
            retention_tick_secs: 0,
            reaper_tick_secs: 0,
            rg_probe_timeout_ms: 0,
            types_registry_probe_timeout_ms: 0,
            ..AccountManagementConfig::default()
        };
        let err = cfg.validate().expect_err("multi-field reject");
        assert!(err.contains("retention_tick_secs"), "got: {err}");
        assert!(err.contains("reaper_tick_secs"), "got: {err}");
        assert!(err.contains("rg_probe_timeout_ms"), "got: {err}");
        assert!(
            err.contains("types_registry_probe_timeout_ms"),
            "got: {err}"
        );
    }

    #[test]
    fn deserializes_empty_object_as_default() {
        let cfg: AccountManagementConfig = serde_json::from_str("{}").expect("ok");
        assert_eq!(cfg.max_list_children_top, 200);
        assert_eq!(cfg.depth_threshold, 10);
        assert!(!cfg.depth_strict_mode);
        assert_eq!(cfg.retention_tick_secs, 60);
        assert_eq!(cfg.reaper_tick_secs, 30);
        assert_eq!(cfg.provisioning_timeout_secs, 300);
        assert_eq!(cfg.default_retention_secs, 90 * 86_400);
        assert_eq!(cfg.hard_delete_batch_size, 64);
        assert_eq!(cfg.reaper_batch_size, 64);
        assert_eq!(cfg.hard_delete_concurrency, 4);
        assert!(!cfg.strict_barriers);
        assert_eq!(cfg.rg_probe_timeout_ms, 2_000);
        assert_eq!(cfg.types_registry_probe_timeout_ms, 2_000);
        assert!(cfg.bootstrap.is_none());
    }

    #[test]
    fn deserializes_custom_value() {
        let cfg: AccountManagementConfig =
            serde_json::from_str(r#"{"max_list_children_top": 50}"#).expect("ok");
        assert_eq!(cfg.max_list_children_top, 50);
    }
}
