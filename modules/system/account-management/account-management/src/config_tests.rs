use super::*;

#[test]
fn default_validates_clean() {
    AccountManagementConfig::default()
        .validate()
        .expect("default config must always validate; it is the production fallback");
}

#[test]
fn idp_required_defaults_to_false() {
    // Pinned: deployments inheriting the default keep the existing
    // NoopProvisioner-fallback behaviour. Production deployments
    // that want fail-closed init must opt in explicitly.
    let cfg = AccountManagementConfig::default();
    assert!(
        !cfg.idp_required,
        "idp_required must default to false; production deployments opt in explicitly"
    );
}

#[test]
fn rejects_zero_retention_tick() {
    let cfg = AccountManagementConfig {
        retention_tick_secs: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("retention_tick_secs"), "{err}");
}

#[test]
fn rejects_zero_reaper_tick() {
    let cfg = AccountManagementConfig {
        reaper_tick_secs: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("reaper_tick_secs"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_batch_size() {
    let cfg = AccountManagementConfig {
        hard_delete_batch_size: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("hard_delete_batch_size"), "{err}");
}

#[test]
fn rejects_zero_reaper_batch_size() {
    let cfg = AccountManagementConfig {
        reaper_batch_size: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("reaper_batch_size"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_concurrency() {
    let cfg = AccountManagementConfig {
        hard_delete_concurrency: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero concurrency must reject");
    assert!(err.contains("hard_delete_concurrency"), "{err}");
}

#[test]
fn rejects_zero_max_list_children_top() {
    let cfg = AccountManagementConfig {
        max_list_children_top: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero top must reject");
    assert!(err.contains("max_list_children_top"), "{err}");
}

#[test]
fn rejects_excessive_depth_threshold() {
    let cfg = AccountManagementConfig {
        depth_threshold: AccountManagementConfig::MAX_DEPTH_THRESHOLD + 1,
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("depth_threshold > MAX must reject");
    assert!(err.contains("depth_threshold"), "{err}");
}

#[test]
fn aggregates_multiple_failures_in_one_message() {
    let cfg = AccountManagementConfig {
        retention_tick_secs: 0,
        reaper_tick_secs: 0,
        hard_delete_batch_size: 0,
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("triple-bad must reject");
    assert!(err.contains("retention_tick_secs"), "{err}");
    assert!(err.contains("reaper_tick_secs"), "{err}");
    assert!(err.contains("hard_delete_batch_size"), "{err}");
}
