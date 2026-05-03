//! Provisioning-reaper tick on `TenantService` —
//! `reap_stuck_provisioning`. Cleanup is routed through
//! `schedule_deletion(retention = 0)` so every row removal flows
//! through the unified hard-delete pipeline.
//!
//! Each tick claims a batch of stuck `Provisioning` rows via the
//! same `tenants.claimed_by` / `claimed_at` lease that backs the
//! retention pipeline, so two replicas cannot stamp duplicate
//! `IdpTenantProvisionerClient::deprovision_tenant` calls onto the
//! same row inside one `RETENTION_CLAIM_TTL` window. Defense-in-depth
//! against the
//! [`account_management_sdk::DeprovisionFailure::NotFound`]-
//! as-success-equivalent error mapping (which handles edge cases —
//! crash recovery, stale claim takeover).
//!
//! Retry / backoff / circuit-breaker policy is owned by the
//! [`account_management_sdk::IdpTenantProvisionerClient`]
//! implementation — a `Retryable` return signals that the plugin
//! has exhausted its own retry budget for that call, and AM simply
//! defers the row to the next reaper tick (default 30 s).

use std::time::Duration;

use modkit_macros::domain_model;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use tracing::warn;

use account_management_sdk::{DeprovisionFailure, DeprovisionRequest};

use crate::domain::metrics::{AM_TENANT_RETENTION, MetricKind, emit_metric};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::ReaperResult;

use super::TenantService;

/// Compensation-arm classification for a single reaper row. Lets
/// the per-row body in `reap_stuck_provisioning` decide whether to
/// proceed with the local DB teardown without re-matching the full
/// `DeprovisionFailure` shape twice.
#[domain_model]
enum ReaperOutcome {
    /// Plugin acknowledged the deprovision (or there was nothing
    /// `IdP`-side to do); proceed to DB teardown. The label is the
    /// metric `outcome=` value emitted on success.
    Compensable(&'static str),
    /// `IdP` plugin classified the deprovision as non-recoverable
    /// (`DeprovisionFailure::Terminal`). Stamp `terminal_failure_at`
    /// on the row so `scan_stuck_provisioning` filters it out of the
    /// retry loop until an operator intervenes. Distinct from
    /// [`Self::Defer`]: a deferred row goes back on the next tick;
    /// a terminal row stays stamped until manually cleared.
    Terminal,
    /// Defer the row to the next tick; metric label + log detail
    /// already emitted by the caller. The claim is released on the
    /// way out so a peer worker may pick the row up.
    Defer,
}

impl<R: TenantRepo> TenantService<R> {
    /// Implements FEATURE `Provisioning Reaper`.
    ///
    /// Deviation from `inst-algo-reap-delete-tx`: routes cleanup
    /// through `schedule_deletion(retention = 0)` so every row removal
    /// (user-initiated, retention-driven, stuck-`Provisioning`) flows
    /// through one pipeline (hooks + `IdP` deprovision + closure-row
    /// removal). Worst-case stuck → row-gone latency is
    /// `reaper_tick_secs + retention_tick_secs`. See FEATURE §3
    /// `algo-tenant-hierarchy-management-provisioning-reaper-compensation`.
    #[allow(
        clippy::cognitive_complexity,
        reason = "single linear pipeline: scan -> per-row classification + claim release"
    )]
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-provisioning-reaper-compensation:p1:inst-algo-reap-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provisioning-failure-reaper
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-reaper
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-reaper
    pub async fn reap_stuck_provisioning(&self, threshold: Duration) -> ReaperResult {
        let now = OffsetDateTime::now_utc();
        let older_than = match time::Duration::try_from(threshold) {
            Ok(d) => now - d,
            Err(err) => {
                // `time::Duration::try_from(std::time::Duration)` only
                // refuses values past `i64::MAX` seconds (~292 yrs); any
                // realistic misconfig of `provisioning_timeout_secs`
                // lands here and would otherwise look like a clean
                // empty tick. Surface it loudly so a bad config does
                // not masquerade as "nothing stuck."
                warn!(
                    target: "am.retention",
                    threshold_secs = threshold.as_secs(),
                    error = %err,
                    "reap_stuck_provisioning: threshold exceeds time::Duration range; skipping tick"
                );
                return ReaperResult::default();
            }
        };
        let system_scope = AccessScope::allow_all();
        let rows = match self
            .repo
            .scan_stuck_provisioning(&system_scope, now, older_than, self.cfg.reaper_batch_size)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    target: "am.retention",
                    error = %err,
                    "reap_stuck_provisioning: scan failed; skipping tick"
                );
                return ReaperResult::default();
            }
        };

        let mut result = ReaperResult {
            scanned: u64::try_from(rows.len()).unwrap_or(u64::MAX),
            ..ReaperResult::default()
        };

        let now = OffsetDateTime::now_utc();
        for row in rows {
            let claimed_by = row.claimed_by;
            let outcome = self.classify_deprovision(row.id).await;
            match outcome {
                ReaperOutcome::Compensable(label) => {
                    self.compensate_provisioning_row(
                        &system_scope,
                        row.id,
                        claimed_by,
                        label,
                        &mut result,
                    )
                    .await;
                }
                ReaperOutcome::Terminal => {
                    self.mark_terminal_provisioning_row(
                        &system_scope,
                        row.id,
                        claimed_by,
                        now,
                        &mut result,
                    )
                    .await;
                }
                ReaperOutcome::Defer => {
                    result.deferred += 1;
                    self.release_claim(&system_scope, row.id, claimed_by).await;
                }
            }
        }

        result
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-remediation:p2:inst-dod-data-remediation-reaper
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-reaper
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-provisioning-failure:p1:inst-dod-idp-provisioning-failure-reaper
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-provisioning-reaper-compensation:p1:inst-algo-reap-service

    /// Call the `IdP` and translate the response into a
    /// [`ReaperOutcome`]. Side effects (`warn!` + `emit_metric` for
    /// non-success branches) are performed here so the caller body
    /// stays linear.
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat dispatch over five Deprovision outcomes; splitting hides the per-branch label/log"
    )]
    #[allow(
        unreachable_patterns,
        reason = "DeprovisionFailure is #[non_exhaustive]; the wildcard guards against future SDK variants"
    )]
    async fn classify_deprovision(&self, tenant_id: uuid::Uuid) -> ReaperOutcome {
        match self
            .idp
            .deprovision_tenant(&DeprovisionRequest { tenant_id })
            .await
        {
            Ok(()) | Err(DeprovisionFailure::UnsupportedOperation { .. }) => {
                ReaperOutcome::Compensable("compensated")
            }
            Err(DeprovisionFailure::NotFound { .. }) => {
                // Vendor reports the tenant is already gone (typical
                // 404 / 410 from the SDK). Per the IdP trait
                // contract this is success-equivalent: continue with
                // local DB teardown, but emit a distinct metric
                // label so dashboards can spot the difference
                // between "we deleted it" and "it was already gone"
                // — the latter often signals a lost claim or
                // cross-system inconsistency.
                ReaperOutcome::Compensable("already_absent")
            }
            Err(DeprovisionFailure::Retryable { detail }) => {
                // Vendor SDK detail strings may carry hostnames,
                // endpoint paths, or token-bearing fragments — same
                // class of secrets the `am.idp` mapping in
                // `domain/idp` redacts. The reaper logs into a
                // longer-retention target (`am.retention`), so the
                // raw text MUST be redacted here too. Operators
                // correlate via the FNV-1a digest plus character
                // length, identical to the provision-side redaction
                // contract.
                let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                warn!(
                    target: "am.retention",
                    tenant_id = %tenant_id,
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "reaper: retryable IdP failure; deferring to next tick (raw detail redacted; correlate via digest)"
                );
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[("job", "provisioning_reaper"), ("outcome", "retryable")],
                );
                ReaperOutcome::Defer
            }
            Err(DeprovisionFailure::Terminal { detail }) => {
                // Per the SDK contract, `Terminal` means the vendor
                // refused to deprovision and operator intervention is
                // required. The reaper used to map this to `Defer`,
                // which released the claim and let
                // `scan_stuck_provisioning` re-pick the row on the
                // next tick — producing an indefinite reissue loop
                // without any new operator-visible signal. We now
                // stamp `terminal_failure_at` (in
                // `compensate_terminal_provisioning_row`) so the
                // scan filter excludes the row until an operator
                // clears the column or hard-deletes the row.
                let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                warn!(
                    target: "am.retention",
                    tenant_id = %tenant_id,
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "reaper: terminal IdP failure; marking row terminal_failure_at and parking out of the retry loop (operator action required; raw detail redacted, correlate via digest)"
                );
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[("job", "provisioning_reaper"), ("outcome", "terminal")],
                );
                ReaperOutcome::Terminal
            }
            // `DeprovisionFailure` is `#[non_exhaustive]`; the
            // wildcard guards against a future SDK variant landing
            // without a service-side classification update.
            Err(_) => {
                warn!(
                    target: "am.retention",
                    tenant_id = %tenant_id,
                    "reaper: unknown DeprovisionFailure variant; deferring as retryable"
                );
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[("job", "provisioning_reaper"), ("outcome", "unknown")],
                );
                ReaperOutcome::Defer
            }
        }
    }

    /// Physically remove the `Provisioning` row via
    /// `TenantRepo::compensate_provisioning` and emit the audit
    /// event for a row whose `IdP`-side cleanup is classified as
    /// success-equivalent. Provisioning rows never become
    /// SDK-visible, so reconciling them through the soft-delete +
    /// retention pipeline (the previous `schedule_deletion`
    /// approach) would leak tombstones — operators would see
    /// `Deleted` rows in the DB long after the `IdP` teardown finished
    /// and the retention pipeline would have to re-claim and
    /// re-process the same row on a later tick. Deleting directly
    /// here keeps the outcome local to one reaper tick.
    ///
    /// Releases the claim regardless of outcome (the row is gone on
    /// success; on infra failure a peer should retry next tick).
    async fn compensate_provisioning_row(
        &self,
        scope: &AccessScope,
        tenant_id: uuid::Uuid,
        claimed_by: uuid::Uuid,
        outcome_label: &'static str,
        result: &mut ReaperResult,
    ) {
        if let Err(err) = self.repo.compensate_provisioning(scope, tenant_id).await {
            // A storage fault on the compensation delete is an infra
            // blip (pool exhausted, SERIALIZABLE retry budget gone,
            // etc.) OR a legitimate "no longer Provisioning" Conflict
            // raised by the repo's status-fence. Either way, defer
            // the row, release the claim so a peer can retry, emit a
            // dedicated `compensate_failed` metric so the infra fault
            // stays observable distinct from IdP-side failures.
            warn!(
                target: "am.retention",
                tenant_id = %tenant_id,
                error = %err,
                "reaper: compensate_provisioning failed"
            );
            result.deferred += 1;
            emit_metric(
                AM_TENANT_RETENTION,
                MetricKind::Counter,
                &[
                    ("job", "provisioning_reaper"),
                    ("outcome", "compensate_failed"),
                ],
            );
            self.release_claim(scope, tenant_id, claimed_by).await;
            return;
        }
        // Match on the outcome label so the operator-visible counter
        // reflects whether we actively cleaned the row or merely
        // observed it was already absent on the vendor side. Both
        // increment via the metric label too — the dashboard split
        // and the result-struct split are in lockstep.
        match outcome_label {
            "already_absent" => result.already_absent += 1,
            _ => result.compensated += 1,
        }
        emit_metric(
            AM_TENANT_RETENTION,
            MetricKind::Counter,
            &[("job", "provisioning_reaper"), ("outcome", outcome_label)],
        );
        // TODO(events): emit AM event when platform event-bus lands.
        tracing::info!(
            target: "am.events",
            kind = "provisioningReaperCompensated",
            actor = "system",
            tenant_id = %tenant_id,
            outcome = outcome_label,
            "am tenant state changed"
        );
        // Release the claim now: schedule_deletion flipped the row
        // to `Deleted`, so the retention pipeline owns it from
        // here. Without an explicit release the retention scan
        // would have to wait out the full RETENTION_CLAIM_TTL
        // window before picking the row up.
        self.release_claim(scope, tenant_id, claimed_by).await;
    }

    /// Stamp `terminal_failure_at` on the row via
    /// [`TenantRepo::mark_provisioning_terminal_failure`] and bump
    /// `result.terminal`. The marker keeps the row out of the
    /// `scan_stuck_provisioning` retry loop until an operator
    /// clears it; the reaper releases the claim afterwards (whether
    /// the mark landed or not) so the row's columns remain tidy
    /// regardless of whether a peer reaper would have eventually
    /// observed the same Terminal outcome.
    ///
    /// On infra failure of the mark UPDATE itself (storage fault),
    /// the row falls through to `result.deferred` instead — the
    /// scan filter will not exclude it on the next tick, and a peer
    /// (or this worker on a later tick) will retry the
    /// classification + mark sequence.
    async fn mark_terminal_provisioning_row(
        &self,
        scope: &AccessScope,
        tenant_id: uuid::Uuid,
        claimed_by: uuid::Uuid,
        now: OffsetDateTime,
        result: &mut ReaperResult,
    ) {
        match self
            .repo
            .mark_provisioning_terminal_failure(scope, tenant_id, claimed_by, now)
            .await
        {
            Ok(true) => {
                result.terminal += 1;
            }
            Ok(false) => {
                // Either the row left `Provisioning` between the
                // IdP round-trip and our mark write (treated as
                // success-equivalent for idempotency — the row is
                // no longer the reaper's concern) or this worker
                // lost its claim. Counted as `deferred` because no
                // terminal stamp was actually persisted; the
                // scan-filter still applies on the next tick if
                // some other party already stamped the row, or the
                // row is gone entirely.
                result.deferred += 1;
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[
                        ("job", "provisioning_reaper"),
                        ("outcome", "terminal_lost_claim"),
                    ],
                );
            }
            Err(err) => {
                warn!(
                    target: "am.retention",
                    tenant_id = %tenant_id,
                    error = %err,
                    "reaper: mark_provisioning_terminal_failure failed; deferring"
                );
                result.deferred += 1;
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[
                        ("job", "provisioning_reaper"),
                        ("outcome", "terminal_mark_failed"),
                    ],
                );
            }
        }
        self.release_claim(scope, tenant_id, claimed_by).await;
    }

    /// Release the per-row claim, swallowing storage errors so a
    /// transient fault never leaks past the reaper tick. The
    /// `RETENTION_CLAIM_TTL` window in
    /// [`crate::infra::storage::repo_impl::retention`] is the
    /// fallback if this call doesn't land.
    async fn release_claim(
        &self,
        scope: &AccessScope,
        tenant_id: uuid::Uuid,
        claimed_by: uuid::Uuid,
    ) {
        if let Err(err) = self
            .repo
            .clear_retention_claim(scope, tenant_id, claimed_by)
            .await
        {
            warn!(
                target: "am.retention",
                tenant_id = %tenant_id,
                error = %err,
                "reaper: failed to clear claim; will be released by RETENTION_CLAIM_TTL"
            );
        }
    }

    // `check_hierarchy_integrity` (the FEATURE "Hierarchy Integrity
    // Audit" admin diagnostic API) lands together with the classifier
    // set, snapshot loader, and `running_audits` single-flight gate in
    // a subsequent PR. Storing it here pre-emptively would require
    // committing the `IntegrityCategory` / `IntegrityReport` shapes to
    // the public surface before the classifiers that produce them are
    // ready, so the method ships in one bundle with its dependencies.
}
