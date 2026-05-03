//! Module-level lifecycle tests. These are deliberately narrow —
//! the full DB wiring is exercised via integration tests; here we
//! verify the cooperative cancellation contract.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::config::AccountManagementConfig;
use crate::domain::tenant::resource_checker::InertResourceOwnershipChecker;
use crate::domain::tenant::service::TenantService;
use crate::domain::tenant::test_support::{
    FakeIdpProvisioner, FakeOutcome, FakeTenantRepo, mock_enforcer,
};

#[tokio::test]
async fn stateful_task_shuts_down_on_cancel() {
    // Run the equivalent of `serve` (retention + reaper as two
    // independent `tokio::spawn` tasks under child tokens) and
    // prove that cancelling the root token shuts down both
    // children promptly.
    let root = uuid::Uuid::from_u128(0x100);
    let repo = Arc::new(FakeTenantRepo::with_root(root));
    let svc = Arc::new(TenantService::new(
        repo,
        Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok)),
        Arc::new(InertResourceOwnershipChecker),
        crate::domain::tenant_type::inert_tenant_type_checker(),
        mock_enforcer(),
        AccountManagementConfig {
            retention_tick_secs: 1,
            reaper_tick_secs: 1,
            ..AccountManagementConfig::default()
        },
    ));

    let cancel = CancellationToken::new();
    let retention_cancel = cancel.child_token();
    let reaper_cancel = cancel.child_token();
    let retention_svc = svc.clone();
    let reaper_svc = svc;

    let retention_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = retention_cancel.cancelled() => break,
                _tick = interval.tick() => {
                    let _ = retention_svc.hard_delete_batch(8).await;
                }
            }
        }
    });
    let reaper_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = reaper_cancel.cancelled() => break,
                _tick = interval.tick() => {
                    let _ = reaper_svc
                        .reap_stuck_provisioning(std::time::Duration::from_secs(1))
                        .await;
                }
            }
        }
    });

    // Let the children run a couple of ticks.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    cancel.cancel();
    // Both child tasks must exit within the timeout window AND
    // return `Ok(())` from their `JoinHandle`. A `tokio::time::timeout`
    // alone only proves they finished; if either task had panicked,
    // the join would still resolve (with `Err(JoinError)`), and an
    // `is_ok()` check on the outer timeout result would silently
    // pass over the panic.
    let join = tokio::time::timeout(std::time::Duration::from_millis(200), async move {
        tokio::join!(retention_handle, reaper_handle)
    })
    .await
    .expect("retention + reaper tasks must both exit within 200ms of cancel");
    let (retention_res, reaper_res) = join;
    retention_res.expect("retention task must exit without panic on cooperative cancel");
    reaper_res.expect("reaper task must exit without panic on cooperative cancel");
}
