//! Configuration for the Account Management module.
//!
//! Operator-facing knobs consumed by
//! [`crate::domain::tenant::service::TenantService`]. The schema is
//! grouped into sub-sections (matching the YAML layout in
//! `docs/config-example.yaml`) so related knobs travel together and
//! future additions land in the right namespace without renaming.
//!
//! Each section uses `#[serde(default, deny_unknown_fields)]`: any
//! omitted field falls back to its [`Default`] value, and any
//! unknown key surfaces as a loud `init` failure instead of silently
//! ignored configuration.

use serde::Deserialize;

/// Module configuration for `cf-account-management`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountManagementConfig {
    /// Pagination clamps for collection endpoints (currently
    /// `listChildren` only).
    pub listing: ListingConfig,

    /// Tenant-hierarchy depth gating
    /// (DESIGN §3.1 / `algo-depth-threshold-evaluation`).
    pub hierarchy: HierarchyConfig,

    /// Soft-delete + hard-delete pipeline knobs.
    pub retention: RetentionConfig,

    /// Provisioning-row reaper pipeline knobs.
    pub reaper: ReaperConfig,

    /// External `IdP` integration policy.
    pub idp: IdpConfig,

    /// In-process Tenant Resolver plugin registration knobs.
    pub tr_plugin: TrPluginConfig,
}

/// Pagination knobs for collection endpoints.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListingConfig {
    /// Hard cap on `$top` for `listChildren` — clamped at the REST
    /// layer before the service call. Matches `OpenAPI`
    /// `Top.maximum` = 200. `validate()` rejects `0` (would empty every
    /// page).
    pub max_top: u32,
}

impl Default for ListingConfig {
    fn default() -> Self {
        Self { max_top: 200 }
    }
}

/// Tenant-hierarchy depth gating.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HierarchyConfig {
    /// Strict-mode reject switch. When `true`, attempts to create a
    /// child tenant at `depth > depth_threshold` are rejected with
    /// `tenant_depth_exceeded`. When `false`, the service emits an
    /// advisory log + metric at the same boundary and proceeds. Both
    /// branches fire at the same threshold per
    /// `algo-depth-threshold-evaluation`.
    pub depth_strict_mode: bool,

    /// Hierarchy depth threshold. Defaults to `10` (DESIGN §3.1 /
    /// PRD). Hard upper bound
    /// [`AccountManagementConfig::MAX_DEPTH_THRESHOLD`] guards the
    /// saga's `parent.depth + 1` arithmetic against silent saturation.
    pub depth_threshold: u32,
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        Self {
            depth_strict_mode: false,
            depth_threshold: 10,
        }
    }
}

/// Retention + hard-delete pipeline knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Retention-pipeline tick period in seconds. Must be `> 0`
    /// ([`tokio::time::interval`] panics on zero).
    pub tick_secs: u64,

    /// Default retention window applied at soft-delete time when the
    /// caller does not specify one. `0` disables retention (immediate
    /// hard-delete eligibility).
    pub default_window_secs: u64,

    /// Maximum tenants processed per retention tick. Must be `> 0`
    /// (`LIMIT 0` would scan zero rows forever).
    pub hard_delete_batch_size: usize,

    /// Max parallel hard-delete tasks within one retention tick.
    /// Default `4`. `0` is **rejected by
    /// [`AccountManagementConfig::validate`]** at module init so a
    /// misconfigured deployment fails loud rather than silently
    /// single-flighting; the call site in
    /// `domain::tenant::service::retention` additionally clamps
    /// `.max(1)` as defense-in-depth for tests that bypass `validate`.
    pub hard_delete_concurrency: usize,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            tick_secs: 60,
            // 90 days in seconds.
            default_window_secs: 90 * 86_400,
            hard_delete_batch_size: 64,
            hard_delete_concurrency: 4,
        }
    }
}

/// Provisioning-row reaper pipeline knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReaperConfig {
    /// Reaper tick period in seconds. Must be `> 0`
    /// ([`tokio::time::interval`] panics on zero).
    pub tick_secs: u64,

    /// Provisioning-row staleness threshold in seconds — rows older
    /// than this are eligible for reaper compensation. Must be `> 0`
    /// (zero would make every fresh `Provisioning` row instantly
    /// reaper-eligible and trigger premature compensation).
    pub provisioning_timeout_secs: u64,

    /// Maximum provisioning rows processed per reaper tick. Must be
    /// `> 0` (`LIMIT 0` would scan zero rows forever).
    pub batch_size: usize,

    /// Per-tick concurrency for the `IdP` `deprovision_tenant`
    /// classification fan-out. Must be `> 0`. The reaper `IdP` call is
    /// the dominant per-row cost (full provider round-trip,
    /// hundreds of ms typical, multi-second on degraded providers);
    /// fan-out keeps one tick's wall-clock to roughly
    /// `(batch_size / deprovision_concurrency) × IdP_RTT` instead of
    /// `batch_size × IdP_RTT`. The DB-side actions
    /// (`compensate_provisioning_row` / `mark_terminal_provisioning_row` /
    /// `release_claim`) still run sequentially after the classify
    /// fan-out, since they share write paths and serializing them
    /// avoids per-row contention with no meaningful latency cost
    /// (DB writes are 10–100× faster than the `IdP` RTT they
    /// replace).
    pub deprovision_concurrency: usize,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            tick_secs: 30,
            provisioning_timeout_secs: 300,
            batch_size: 64,
            deprovision_concurrency: 8,
        }
    }
}

/// In-process Tenant Resolver plugin registration knobs.
///
/// AM can register its co-located `tr_plugin` as a
/// `BaseModkitPluginV1<TenantResolverPluginSpecV1>` instance in
/// types-registry. While the AM plugin is still in build-out,
/// registration is **opt-in**: a deploy that incidentally pulls AM
/// into its binary MUST NOT have AM start serving tenant-resolver
/// traffic without an explicit operator decision. The `priority`
/// knob is a secondary defense (see below) but is not sufficient
/// on its own — in an AM-only binary AM would be the sole
/// candidate for the configured vendor and `choose_plugin_instance`
/// would pick it regardless of priority value.
///
/// When the plugin is feature-complete a single switch-over commit
/// flips the `enabled` default to `true` (and lowers `priority`);
/// until then operators opt in by setting `enabled = true`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrPluginConfig {
    /// Master switch for the AM-co-located TR plugin. `false` (the
    /// default) skips both the types-registry instance registration
    /// and the `ClientHub` bind, so the gateway never sees AM as a
    /// candidate plugin. Operators flip this to `true` to opt the
    /// deploy into the AM-served tenant-resolver path.
    pub enabled: bool,

    /// Plugin vendor — registered alongside the GTS instance and
    /// used by the TR gateway's `choose_plugin_instance` to filter
    /// candidates. **Must match `tenant-resolver.vendor`** in the
    /// same deploy or AM's instance is registered but never
    /// selectable. Defaults to `"cyberfabric"` to align with
    /// `TenantResolverConfig::default()`; deploys that override
    /// `tenant-resolver.vendor` MUST override this knob to the
    /// same value.
    pub vendor: String,

    /// Plugin selection priority — only consulted when `enabled =
    /// true`. Lower wins. Signed `i16` mirrors the wire format of
    /// `BaseModkitPluginV1.priority`. The wide range
    /// (−32 768 … 32 767) is deliberate: deploys that need to
    /// guarantee AM wins regardless of any future plugin can pin
    /// `priority = i16::MIN`, and the "I want AM to lose" knob is
    /// `priority = i16::MAX`. The default sits well above the
    /// in-tree alternatives (`rg-tr-plugin` = 50,
    /// `static-tr-plugin` = 100) so an AM-included deploy that
    /// flips `enabled = true` without picking a priority still
    /// loses to those plugins when they coexist.
    pub priority: i16,
}

impl Default for TrPluginConfig {
    fn default() -> Self {
        Self {
            // Opt-in: registration is skipped entirely until the
            // operator flips this to `true`.
            enabled: false,
            // Matches `TenantResolverConfig::default().vendor`.
            // Deploys that override the resolver vendor MUST
            // override this knob to the same value.
            vendor: "cyberfabric".to_owned(),
            // 1000 — well above the 50 / 100 of in-tree
            // alternatives, leaves headroom for future plugins,
            // fits in `i16`.
            priority: 1000,
        }
    }
}

/// External `IdP` integration policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdpConfig {
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
    pub required: bool,
}

impl AccountManagementConfig {
    /// Upper bound on `hierarchy.depth_threshold` so that the
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
    /// Hard panic gates:
    ///
    /// * `retention.tick_secs == 0` / `reaper.tick_secs == 0` —
    ///   [`tokio::time::interval`] panics on zero.
    /// * `reaper.provisioning_timeout_secs == 0` — would make every
    ///   fresh `Provisioning` row instantly reaper-eligible.
    /// * `retention.hard_delete_batch_size == 0` /
    ///   `reaper.batch_size == 0` — the SQL `LIMIT` clamp evaluates to
    ///   zero and the pipeline ticks scan zero rows forever.
    /// * `retention.hard_delete_concurrency == 0` — would degrade to
    ///   single-flight processing of every batch with no observable
    ///   error. Although the retention call site clamps with
    ///   `.max(1)`, the misconfig is still rejected here so it
    ///   surfaces as an `init` failure instead of a silent rewrite.
    /// * `listing.max_top == 0` — every `listChildren` call returns
    ///   an empty page regardless of the requested `$top`.
    /// * `hierarchy.depth_threshold > MAX_DEPTH_THRESHOLD` — guards
    ///   the saga's `parent.depth + 1` arithmetic against silent
    ///   saturation.
    ///
    /// # Errors
    ///
    /// Returns a human-readable string naming each invalid field.
    /// Callers map this into [`crate::domain::error::DomainError::Internal`]
    /// (a fatal `init` failure).
    pub fn validate(&self) -> Result<(), String> {
        let mut bad: Vec<&'static str> = Vec::new();
        if self.retention.tick_secs == 0 {
            bad.push("retention.tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.reaper.tick_secs == 0 {
            bad.push("reaper.tick_secs (must be > 0; tokio::time::interval panics on zero)");
        }
        if self.reaper.provisioning_timeout_secs == 0 {
            bad.push(
                "reaper.provisioning_timeout_secs (must be > 0; zero would make every fresh provisioning row instantly reaper-eligible and trigger premature compensation)",
            );
        }
        if self.retention.hard_delete_batch_size == 0 {
            bad.push(
                "retention.hard_delete_batch_size (must be > 0; zero would scan no rows forever)",
            );
        }
        if self.reaper.batch_size == 0 {
            bad.push("reaper.batch_size (must be > 0; zero would scan no rows forever)");
        }
        if self.retention.hard_delete_concurrency == 0 {
            bad.push("retention.hard_delete_concurrency (must be > 0; zero is normalised to 1 at the call site but rejected here so the misconfig is observable)");
        }
        if self.reaper.deprovision_concurrency == 0 {
            bad.push("reaper.deprovision_concurrency (must be > 0; zero is normalised to 1 at the call site but rejected here so the misconfig is observable)");
        }
        if self.listing.max_top == 0 {
            bad.push("listing.max_top (must be > 0; zero would empty every listChildren response)");
        }
        if self.hierarchy.depth_threshold > Self::MAX_DEPTH_THRESHOLD {
            bad.push(
                "hierarchy.depth_threshold (must be <= MAX_DEPTH_THRESHOLD; protects saga depth arithmetic)",
            );
        }
        if self.tr_plugin.vendor.is_empty() {
            bad.push(
                "tr_plugin.vendor (must be non-empty; an empty string would register an instance the TR gateway can never select)",
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
