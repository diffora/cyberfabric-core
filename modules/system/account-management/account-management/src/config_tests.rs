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
    // NoopIdpProvider-fallback behaviour. Production deployments
    // that want fail-closed init must opt in explicitly.
    let cfg = AccountManagementConfig::default();
    assert!(
        !cfg.idp.required,
        "idp.required must default to false; production deployments opt in explicitly"
    );
}

#[test]
fn rejects_zero_retention_tick() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            tick_secs: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("retention.tick_secs"), "{err}");
}

#[test]
fn rejects_zero_reaper_tick() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            tick_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("reaper.tick_secs"), "{err}");
}

#[test]
fn rejects_zero_provisioning_timeout() {
    // Zero staleness threshold would make every fresh `Provisioning`
    // row instantly reaper-eligible — the reaper would compensate
    // creates that haven't even reached the IdP step yet.
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            provisioning_timeout_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("zero provisioning timeout must reject");
    assert!(err.contains("reaper.provisioning_timeout_secs"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_batch_size() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            hard_delete_batch_size: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("retention.hard_delete_batch_size"), "{err}");
}

#[test]
fn rejects_zero_reaper_batch_size() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            batch_size: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("reaper.batch_size"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_concurrency() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            hard_delete_concurrency: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero concurrency must reject");
    assert!(err.contains("retention.hard_delete_concurrency"), "{err}");
}

#[test]
fn rejects_zero_deprovision_concurrency() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            deprovision_concurrency: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero concurrency must reject");
    assert!(err.contains("reaper.deprovision_concurrency"), "{err}");
}

#[test]
fn rejects_zero_max_top() {
    let cfg = AccountManagementConfig {
        listing: ListingConfig { max_top: 0 },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero top must reject");
    assert!(err.contains("listing.max_top"), "{err}");
}

#[test]
fn rejects_excessive_depth_threshold() {
    let cfg = AccountManagementConfig {
        hierarchy: HierarchyConfig {
            depth_threshold: AccountManagementConfig::MAX_DEPTH_THRESHOLD + 1,
            ..HierarchyConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("depth_threshold > MAX must reject");
    assert!(err.contains("hierarchy.depth_threshold"), "{err}");
}

// ---- ConversionConfig validation paths ----------------------------
//
// Pin every `ConversionConfig::validate()` rejection path: TTL /
// retention / cleanup / batch out-of-range, plus the cross-check
// `resolved_retention_secs <= retention.default_window_secs`. The
// happy-path defaults are already covered by `default_validates_clean`.

#[test]
fn rejects_conversion_approval_ttl_below_floor() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            approval_ttl_secs: ConversionConfig::MIN_APPROVAL_TTL_SECS - 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("TTL below floor must reject");
    assert!(err.contains("conversion.approval_ttl_secs"), "{err}");
}

#[test]
fn rejects_conversion_approval_ttl_above_ceiling() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            approval_ttl_secs: ConversionConfig::MAX_APPROVAL_TTL_SECS + 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("TTL above ceiling must reject");
    assert!(err.contains("conversion.approval_ttl_secs"), "{err}");
}

#[test]
fn rejects_conversion_resolved_retention_below_floor() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            resolved_retention_secs: ConversionConfig::MIN_RESOLVED_RETENTION_SECS - 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("retention below floor must reject");
    assert!(err.contains("conversion.resolved_retention_secs"), "{err}");
}

#[test]
fn rejects_conversion_resolved_retention_above_ceiling() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            resolved_retention_secs: ConversionConfig::MAX_RESOLVED_RETENTION_SECS + 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("retention above MAX_RESOLVED_RETENTION_SECS must reject");
    assert!(err.contains("conversion.resolved_retention_secs"), "{err}");
}

#[test]
fn rejects_conversion_cleanup_interval_below_floor() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            cleanup_interval_secs: ConversionConfig::MIN_CLEANUP_INTERVAL_SECS - 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("cleanup_interval below floor must reject");
    assert!(err.contains("conversion.cleanup_interval_secs"), "{err}");
}

#[test]
fn rejects_conversion_cleanup_interval_above_ceiling() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            cleanup_interval_secs: ConversionConfig::MAX_CLEANUP_INTERVAL_SECS + 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("cleanup_interval above ceiling must reject");
    assert!(err.contains("conversion.cleanup_interval_secs"), "{err}");
}

#[test]
fn rejects_conversion_zero_expire_batch_size() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            expire_batch_size: 0,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("conversion.expire_batch_size"), "{err}");
}

#[test]
fn rejects_conversion_expire_batch_size_above_ceiling() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            expire_batch_size: ConversionConfig::MAX_BATCH_SIZE + 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("expire batch above MAX_BATCH_SIZE must reject");
    assert!(err.contains("conversion.expire_batch_size"), "{err}");
}

#[test]
fn rejects_conversion_oversized_retention_batch() {
    let cfg = AccountManagementConfig {
        conversion: ConversionConfig {
            retention_batch_size: ConversionConfig::MAX_BATCH_SIZE + 1,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("batch above MAX_BATCH_SIZE must reject (PG IN(...) ceiling)");
    assert!(err.contains("conversion.retention_batch_size"), "{err}");
}

#[test]
fn rejects_resolved_retention_exceeding_tenant_default_window() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            default_window_secs: 24 * 60 * 60, // 1 day
            ..RetentionConfig::default()
        },
        conversion: ConversionConfig {
            // Default 30d > deliberately-shortened 1-day tenant
            // retention. Cross-check MUST fire because resolved
            // conversion history would outlive the tenant cascade.
            resolved_retention_secs: 30 * 24 * 60 * 60,
            ..ConversionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("resolved_retention > tenant default_window must reject");
    assert!(err.contains("conversion.resolved_retention_secs"), "{err}");
    assert!(
        err.contains("retention.default_window_secs"),
        "diagnostic must name the cross-checked field; got: {err}"
    );
}

#[test]
fn allows_default_resolved_retention_when_tenant_retention_disabled() {
    // `retention.default_window_secs = 0` means "tenants are
    // immediately hard-delete-eligible", and the FK
    // `conversion_requests.tenant_id REFERENCES tenants(id) ON DELETE
    // CASCADE` reclaims the resolved-conversion rows alongside the
    // tenant. The cross-check therefore only fires when tenant
    // retention is positive — disabled tenant retention does not
    // require disabling conversion retention as well.
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            default_window_secs: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    cfg.validate()
        .expect("default conversion config must validate when tenant retention is disabled");
}

#[test]
fn aggregates_multiple_failures_in_one_message() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            tick_secs: 0,
            hard_delete_batch_size: 0,
            ..RetentionConfig::default()
        },
        reaper: ReaperConfig {
            tick_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("triple-bad must reject");
    assert!(err.contains("retention.tick_secs"), "{err}");
    assert!(err.contains("reaper.tick_secs"), "{err}");
    assert!(err.contains("retention.hard_delete_batch_size"), "{err}");
}
