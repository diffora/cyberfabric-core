//! Configuration for the [`crate::domain::bootstrap::service::BootstrapService`].
//!
//! The platform-bootstrap FEATURE (see
//! `modules/system/account-management/docs/features/feature-platform-bootstrap.md`)
//! requires the operator to declare the root-tenant identity AND the
//! IdP-wait backoff envelope at deployment time. Defaults match
//! FEATURE §3 `algo-platform-bootstrap-idp-wait-with-backoff`:
//! `idp_retry_backoff_initial = 2s`, `idp_retry_backoff_max = 30s`,
//! `idp_retry_timeout = 5min`. The non-mutating availability probe
//! defaults to 5 attempts with a 250ms fixed backoff, and the bootstrap
//!
//! `BootstrapConfig` is deliberately separate from
//! [`crate::config::AccountManagementConfig`] so deployments that bootstrap
//! externally (multi-region splash-page / CI smoke tests / unit tests)
//! can leave the slot `None` without polluting the rest of the module
//! configuration with optional fields.

use modkit_macros::domain_model;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// Bootstrap-feature configuration.
///
/// All numeric fields are in **seconds**. UUIDs are deployment-stable —
/// changing `root_id` between platform restarts breaks the
/// `fr-bootstrap-idempotency` contract.
#[domain_model]
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Deterministic UUID for the platform root tenant. The bootstrap
    /// service reads this id back via
    /// [`crate::domain::tenant::repo::TenantRepo::find_by_id`] on every
    /// platform start to classify the bootstrap state — picking a
    /// fresh UUID per restart silently breaks idempotency.
    pub root_id: Uuid,

    /// Human-readable display name for the root tenant. Forwarded into
    /// the `tenants.name` column verbatim.
    pub root_name: String,

    /// SeaORM-side `tenant_type_uuid` foreign-key value — corresponds to
    /// the registered tenant-type row in GTS. AM stores this as the
    /// `tenants.tenant_type_uuid` column.
    pub root_tenant_type_uuid: Uuid,

    /// Chained GTS tenant-type identifier (e.g.
    /// `gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~`) forwarded
    /// to the `IdP` plugin in
    /// [`crate::domain::idp::provisioner::ProvisionRequest::tenant_type`].
    pub root_tenant_type: String,

    /// Opaque deployment-supplied metadata forwarded to the `IdP` plugin
    /// without interpretation. AM does **not** validate the shape of
    /// this blob — that contract is owned by the `IdP` plugin.
    pub root_tenant_metadata: Option<Value>,

    /// Number of non-mutating `IdP` availability probes before the saga
    /// starts. Defaults to 5.
    pub idp_check_availability_attempts: u32,

    /// Fixed sleep between availability probes in milliseconds. Defaults
    /// to 250ms.
    pub idp_check_availability_backoff_ms: u64,

    /// Total time the bootstrap saga is allowed to spend waiting for
    /// `IdP` availability (FEATURE §3 `idp_retry_timeout`, default 300s).
    pub idp_wait_timeout_secs: u64,

    /// Initial sleep between `IdP`-availability retries (FEATURE §3
    /// `idp_retry_backoff_initial`, default 2s).
    pub idp_retry_backoff_initial_secs: u64,

    /// Cap on the doubled backoff (FEATURE §3 `idp_retry_backoff_max`,
    /// default 30s).
    pub idp_retry_backoff_max_secs: u64,

    /// Strict-mode flag. When `true`, a bootstrap failure aborts module
    /// `init` (lifecycle-fatal). When `false`, the failure is logged
    /// and the module proceeds — useful for dev / multi-region splits
    /// where the root tenant is bootstrapped out of band.
    pub strict: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            // Deterministic placeholder root id; deployments **MUST**
            // override this with their canonical platform-root UUID.
            // The default exists only so `serde(default)` round-trips
            // an empty TOML table without panicking — the production
            // wiring path requires an explicit value.
            root_id: Uuid::nil(),
            root_name: "platform-root".to_owned(),
            root_tenant_type_uuid: Uuid::nil(),
            root_tenant_type: String::new(),
            root_tenant_metadata: None,
            idp_check_availability_attempts: 5,
            idp_check_availability_backoff_ms: 250,
            idp_wait_timeout_secs: 300,
            idp_retry_backoff_initial_secs: 2,
            idp_retry_backoff_max_secs: 30,
            strict: false,
        }
    }
}

impl BootstrapConfig {
    /// Reject deployments whose required identifiers were never set.
    ///
    /// `serde(default)` lets the operator omit any field, so an empty
    /// `[bootstrap]` TOML table deserialises to a config with
    /// `root_id = Uuid::nil()`, `root_tenant_type_uuid = Uuid::nil()`,
    /// and `root_tenant_type = ""`. With `strict = true` the saga
    /// would then insert a nil-id root, breaking the
    /// `fr-bootstrap-idempotency` contract on the next platform start
    /// (see `feature-platform-bootstrap.md` lines 23-25 — UUIDs are
    /// "deployment-stable; changing it between platform restarts
    /// breaks the `fr-bootstrap-idempotency` contract"). This
    /// validator is invoked by the module-level wiring before
    /// constructing `BootstrapService` so the failure surfaces during
    /// `init` rather than at the first DB write.
    ///
    /// # Errors
    ///
    /// Returns a human-readable string naming each missing /
    /// nil-valued field. Callers map this into
    /// [`crate::domain::error::AmError::Internal`] (strict-mode
    /// init failure).
    pub fn validate(&self) -> Result<(), String> {
        let mut missing: Vec<&'static str> = Vec::new();
        if self.root_id.is_nil() {
            missing.push("root_id");
        }
        if self.root_tenant_type_uuid.is_nil() {
            missing.push("root_tenant_type_uuid");
        }
        if self.root_tenant_type.trim().is_empty() {
            missing.push("root_tenant_type");
        }
        if self.root_name.trim().is_empty() {
            missing.push("root_name");
        }
        if self.idp_check_availability_attempts == 0 {
            missing.push("idp_check_availability_attempts (must be > 0)");
        }
        if self.idp_check_availability_backoff_ms == 0 {
            missing.push("idp_check_availability_backoff_ms (must be > 0)");
        }
        if self.idp_wait_timeout_secs == 0 {
            missing.push("idp_wait_timeout_secs (must be > 0)");
        }
        if self.idp_retry_backoff_initial_secs == 0 {
            missing.push("idp_retry_backoff_initial_secs (must be > 0)");
        }
        if self.idp_retry_backoff_max_secs < self.idp_retry_backoff_initial_secs {
            missing.push("idp_retry_backoff_max_secs (must be >= initial)");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "bootstrap configuration is missing or invalid: {}",
                missing.join(", ")
            ))
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn deserialize_empty_table_yields_defaults() {
        let cfg: BootstrapConfig = serde_json::from_str("{}").expect("ok");
        assert_eq!(cfg.idp_wait_timeout_secs, 300);
        assert_eq!(cfg.idp_retry_backoff_initial_secs, 2);
        assert_eq!(cfg.idp_retry_backoff_max_secs, 30);
        assert_eq!(cfg.idp_check_availability_attempts, 5);
        assert_eq!(cfg.idp_check_availability_backoff_ms, 250);
        assert!(!cfg.strict);
    }

    #[test]
    fn deserialize_overrides() {
        let cfg: BootstrapConfig = serde_json::from_str(
            r#"{"root_id":"00000000-0000-0000-0000-0000000000aa","strict":true}"#,
        )
        .expect("ok");
        assert!(cfg.strict);
        assert_eq!(cfg.root_id, Uuid::from_u128(0xAA));
    }

    #[test]
    fn validate_default_rejects_nil_identifiers() {
        // An empty TOML table deserialises to `Default::default()`,
        // which carries nil UUIDs and an empty `root_tenant_type`.
        // The validator MUST reject this so `strict = true`
        // deployments cannot insert a nil-id root and break
        // idempotency on the next restart.
        let cfg = BootstrapConfig::default();
        let err = cfg.validate().expect_err("nil ids must reject");
        assert!(err.contains("root_id"), "got: {err}");
        assert!(err.contains("root_tenant_type_uuid"), "got: {err}");
        assert!(err.contains("root_tenant_type"), "got: {err}");
    }

    #[test]
    fn validate_accepts_fully_specified_config() {
        let cfg = BootstrapConfig {
            root_id: Uuid::from_u128(0xAA),
            root_name: "platform-root".into(),
            root_tenant_type_uuid: Uuid::from_u128(0xBB),
            root_tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".into(),
            root_tenant_metadata: None,
            idp_check_availability_attempts: 5,
            idp_check_availability_backoff_ms: 250,
            idp_wait_timeout_secs: 300,
            idp_retry_backoff_initial_secs: 2,
            idp_retry_backoff_max_secs: 30,
            strict: true,
        };
        cfg.validate().expect("fully-specified config is valid");
    }

    #[test]
    fn validate_rejects_inverted_backoff_envelope() {
        let cfg = BootstrapConfig {
            root_id: Uuid::from_u128(0xAA),
            root_name: "platform-root".into(),
            root_tenant_type_uuid: Uuid::from_u128(0xBB),
            root_tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".into(),
            root_tenant_metadata: None,
            idp_check_availability_attempts: 5,
            idp_check_availability_backoff_ms: 250,
            idp_wait_timeout_secs: 300,
            idp_retry_backoff_initial_secs: 60,
            idp_retry_backoff_max_secs: 30,
            strict: true,
        };
        let err = cfg.validate().expect_err("max < initial must reject");
        assert!(err.contains("idp_retry_backoff_max_secs"), "got: {err}");
    }
}
