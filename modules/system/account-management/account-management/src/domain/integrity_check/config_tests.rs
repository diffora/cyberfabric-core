//! Unit tests for [`IntegrityCheckConfig`] +
//! [`IntegrityRepairConfig`]: serde defaults / overrides / validation
//! matrix. Pure-Rust, no DB.

use super::*;

#[test]
fn default_is_enabled_with_one_hour_interval() {
    let cfg = IntegrityCheckConfig::default();
    assert!(cfg.enabled);
    assert_eq!(cfg.interval_secs, 3600);
    assert_eq!(cfg.initial_delay_secs, 300);
    assert!((cfg.jitter - 0.1).abs() < f64::EPSILON);
}

#[test]
fn deserialize_empty_table_yields_defaults() {
    let cfg: IntegrityCheckConfig = serde_json::from_str("{}").expect("empty deserialises");
    assert!(cfg.enabled);
    assert_eq!(cfg.interval_secs, 3600);
    assert_eq!(cfg.initial_delay_secs, 300);
}

#[test]
fn deserialize_overrides() {
    let cfg: IntegrityCheckConfig = serde_json::from_str(
        r#"{"enabled":false,"interval_secs":7200,"initial_delay_secs":120,"jitter":0.25}"#,
    )
    .expect("ok");
    assert!(!cfg.enabled);
    assert_eq!(cfg.interval_secs, 7200);
    assert_eq!(cfg.initial_delay_secs, 120);
    assert!((cfg.jitter - 0.25).abs() < f64::EPSILON);
}

#[test]
fn validate_accepts_default_config() {
    IntegrityCheckConfig::default()
        .validate()
        .expect("default is valid");
}

#[test]
fn validate_rejects_interval_below_floor() {
    let cfg = IntegrityCheckConfig {
        interval_secs: 30,
        initial_delay_secs: 30,
        ..IntegrityCheckConfig::default()
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("interval_secs"), "got: {err}");
    assert!(err.contains(">= 60"), "got: {err}");
}

#[test]
fn validate_rejects_interval_above_ceiling() {
    let cfg = IntegrityCheckConfig {
        interval_secs: 7 * 86_400,
        ..IntegrityCheckConfig::default()
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("interval_secs"), "got: {err}");
    assert!(err.contains("<= 86400"), "got: {err}");
}

#[test]
fn validate_rejects_negative_jitter() {
    let cfg = IntegrityCheckConfig {
        jitter: -0.01,
        ..IntegrityCheckConfig::default()
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("jitter"), "got: {err}");
}

#[test]
fn validate_rejects_jitter_above_half() {
    let cfg = IntegrityCheckConfig {
        jitter: 0.6,
        ..IntegrityCheckConfig::default()
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("jitter"), "got: {err}");
    assert!(err.contains("0.5"), "got: {err}");
}

#[test]
fn validate_rejects_initial_delay_exceeding_interval() {
    let cfg = IntegrityCheckConfig {
        interval_secs: 600,
        initial_delay_secs: 1200,
        ..IntegrityCheckConfig::default()
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("initial_delay_secs"), "got: {err}");
}

#[test]
fn repair_default_is_disabled() {
    let cfg = IntegrityRepairConfig::default();
    assert!(!cfg.enabled);
    assert!(!cfg.auto_after_check);
}

#[test]
fn repair_validate_rejects_auto_without_enabled() {
    let cfg = IntegrityRepairConfig {
        enabled: false,
        auto_after_check: true,
    };
    let err = cfg.validate().expect_err("must reject");
    assert!(err.contains("auto_after_check"), "got: {err}");
}

#[test]
fn repair_validate_accepts_enabled_without_auto() {
    let cfg = IntegrityRepairConfig {
        enabled: true,
        auto_after_check: false,
    };
    cfg.validate()
        .expect("staged-rollout shape (enabled, no auto) is valid");
}

#[test]
fn repair_validate_accepts_full_on() {
    let cfg = IntegrityRepairConfig {
        enabled: true,
        auto_after_check: true,
    };
    cfg.validate().expect("full self-heal mode is valid");
}

#[test]
fn deserialize_with_repair_section() {
    let cfg: IntegrityCheckConfig =
        serde_json::from_str(r#"{"repair":{"enabled":true,"auto_after_check":true}}"#).expect("ok");
    assert!(cfg.repair.enabled);
    assert!(cfg.repair.auto_after_check);
}
