//! [`BootstrapService`] — orchestrates the platform-bootstrap saga.
//!
//! Implements FEATURE `platform-bootstrap` (see
//! `modules/system/account-management/docs/features/feature-platform-bootstrap.md`).
//!
//! The saga has three observable phases (FEATURE §3):
//!
//! 1. **Idempotency classification** — `find_by_id(root_id)` drives the
//!    branch decision. Active root → no-op skip; Provisioning root →
//!    defer to the provisioning reaper without re-running `IdP`;
//!    Suspended/Deleted root → fail-fast `Internal` (illegal
//!    pre-existing state — operator intervention required); no row →
//!    fresh insert.
//! 2. **`IdP` wait with backoff** — implemented via non-mutating
//!    `check_availability` probes before saga state is written. A
//!    `ProvisionFailure::CleanFailure` during the actual provision call
//!    while the deadline still has budget reschedules the saga after
//!    compensating; the bootstrap deadline (`idp_wait_timeout_secs`) is
//!    the wall-clock cap. Backoff doubles from
//!    `idp_retry_backoff_initial_secs` up to
//!    `idp_retry_backoff_max_secs` per FEATURE §3.
//! 3. **Finalization** — single short transaction that flips the root
//!    row from `Provisioning` to `Active` and writes the self-row in
//!    `tenant_closure` via `TenantRepo::activate_tenant` (closure
//!    helpers in [`crate::domain::tenant::closure`]).
//!
//! Compensation rules per FEATURE §3 `algo-platform-bootstrap-finalization-saga`:
//!
//! * `ProvisionFailure::CleanFailure` → delete the provisioning row and
//!   surface `idp_unavailable` (retry-safe).
//! * `ProvisionFailure::Ambiguous` → leave the provisioning row in
//!   place for the reaper; surface `Internal` (NOT retry-safe).
//! * `ProvisionFailure::UnsupportedOperation` → delete the provisioning
//!   row and surface `idp_unsupported_operation`.

use std::sync::Arc;
use std::time::Duration;

use modkit_macros::domain_model;
use modkit_security::AccessScope;
use serde_json::json;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::domain::audit::{AuditEvent, AuditEventKind, emit_audit};
use crate::domain::bootstrap::config::BootstrapConfig;
use crate::domain::error::AmError;
use crate::domain::idp::provisioner::{
    CheckAvailabilityFailure, IdpTenantProvisioner, ProvisionFailure, ProvisionMetadataEntry,
    ProvisionRequest,
};
use crate::domain::metrics::{AM_BOOTSTRAP_LIFECYCLE, MetricKind, emit_metric};
use crate::domain::tenant::closure::build_activation_rows;
use crate::domain::tenant::model::{NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::util::backoff::compute_next_backoff;
use types_registry_sdk::TypesRegistryClient;

/// Internal classification produced by `BootstrapService::classify`.
///
/// `TenantModel` is ~120 bytes; the previous `Box<TenantModel>` arms
/// existed solely to placate `clippy::large_enum_variant`. Bootstrap
/// runs at most once per process, so the per-call heap traffic is not
/// worth the indirection — allow the lint instead.
#[allow(clippy::large_enum_variant)]
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapClassification {
    /// No root row exists — proceed with the fresh-insert + saga path.
    NoRoot,
    /// Active root already present — skip (idempotent re-run).
    ActiveRootExists(TenantModel),
    /// Root row in `Provisioning` from a prior crashed attempt —
    /// re-run only the `IdP` + activate steps.
    ProvisioningRootResume(TenantModel),
    /// Root row in `Suspended` or `Deleted` — illegal pre-existing
    /// state. Fail-fast.
    InvariantViolation { observed_status: TenantStatus },
}

/// Platform-bootstrap saga.
///
/// Owns the root-tenant lifecycle from `absent` (or
/// `stuck-provisioning`) to `active`. Holds no async state across calls
/// — every invocation re-reads the current root row from the repo.
#[domain_model]
pub struct BootstrapService<R: TenantRepo> {
    repo: Arc<R>,
    idp: Arc<dyn IdpTenantProvisioner + Send + Sync>,
    types_registry: Option<Arc<dyn TypesRegistryClient + Send + Sync>>,
    cfg: BootstrapConfig,
}

impl<R: TenantRepo> BootstrapService<R> {
    /// Construct a fully-wired bootstrap service.
    #[must_use]
    pub fn new(
        repo: Arc<R>,
        idp: Arc<dyn IdpTenantProvisioner + Send + Sync>,
        cfg: BootstrapConfig,
    ) -> Self {
        Self {
            repo,
            idp,
            types_registry: None,
            cfg,
        }
    }

    /// Attach the GTS Types Registry client used for root-tenant-type
    /// preflight. Tests that exercise non-GTS paths may omit this; module
    /// wiring supplies it when `ClientHub` resolves the registry client.
    #[must_use]
    pub fn with_types_registry(
        mut self,
        types_registry: Arc<dyn TypesRegistryClient + Send + Sync>,
    ) -> Self {
        self.types_registry = Some(types_registry);
        self
    }

    /// Run the bootstrap saga to terminal state. Either returns the
    /// active root tenant or surfaces a domain error per FEATURE §5.
    ///
    /// # Errors
    ///
    /// * [`AmError::IdpUnavailable`] when the `IdP` wait exhausts the
    ///   configured timeout or every retry returned `CleanFailure`.
    /// * [`AmError::IdpUnsupportedOperation`] when the `IdP` plugin signals
    ///   it cannot perform root provisioning at all (compensated).
    /// * [`AmError::Internal`] for ambiguous `IdP` outcomes (provisioning
    ///   row left for reaper) and for invariant-violation root states.
    #[tracing::instrument(skip_all, fields(root_id = %self.cfg.root_id))]
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-wait-before-saga
    pub async fn run(&self) -> Result<TenantModel, AmError> {
        self.wait_for_idp_availability().await?;

        let deadline = Instant::now() + Duration::from_secs(self.cfg.idp_wait_timeout_secs);
        let mut backoff = Duration::from_secs(self.cfg.idp_retry_backoff_initial_secs.max(1));
        let cap = Duration::from_secs(self.cfg.idp_retry_backoff_max_secs.max(1));

        loop {
            match self.try_bootstrap_once().await {
                Ok(root) => return Ok(root),
                Err(err) if matches!(err, AmError::IdpUnavailable { .. }) => {
                    if Instant::now() >= deadline {
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[("phase", "idp_waiting"), ("outcome", "timeout")],
                        );
                        warn!(
                            target: "am.bootstrap",
                            "bootstrap idp wait exhausted; surfacing idp_unavailable"
                        );
                        return Err(err);
                    }
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[("phase", "idp_waiting"), ("outcome", "retry")],
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = compute_next_backoff(backoff, cap);
                }
                Err(err) => return Err(err),
            }
        }
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-wait-before-saga

    /// Single attempt: classify → fresh / resume / skip → `IdP` →
    /// finalize. Surfacing a `CleanFailure` here lets the outer loop
    /// retry within the `IdP`-wait deadline.
    // @cpt-begin:cpt-cf-account-management-flow-platform-bootstrap-saga:p1:inst-flow-bootstrap-attempt
    async fn try_bootstrap_once(&self) -> Result<TenantModel, AmError> {
        self.try_bootstrap_once_locked().await
    }
    // @cpt-end:cpt-cf-account-management-flow-platform-bootstrap-saga:p1:inst-flow-bootstrap-attempt

    // @cpt-begin:cpt-cf-account-management-flow-platform-bootstrap-saga:p1:inst-flow-bootstrap-classify-branch
    async fn try_bootstrap_once_locked(&self) -> Result<TenantModel, AmError> {
        let scope = AccessScope::allow_all();

        match self.classify(&scope).await? {
            BootstrapClassification::ActiveRootExists(root) => Ok(handle_skip(root)),
            BootstrapClassification::InvariantViolation { observed_status } => {
                Err(handle_invariant_violation(observed_status))
            }
            BootstrapClassification::ProvisioningRootResume(existing) => {
                Ok(handle_deferred_to_reaper(existing))
            }
            BootstrapClassification::NoRoot => {
                self.preflight_root_tenant_type().await?;
                let inserted = self.insert_root_provisioning(&scope).await?;
                self.finalize(&scope, inserted).await
            }
        }
    }
    // @cpt-end:cpt-cf-account-management-flow-platform-bootstrap-saga:p1:inst-flow-bootstrap-classify-branch

    // @cpt-begin:cpt-cf-account-management-algo-platform-bootstrap-idp-wait-with-backoff:p1:inst-algo-wait-check-availability
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-idp-probe
    async fn wait_for_idp_availability(&self) -> Result<(), AmError> {
        let attempts = self.cfg.idp_check_availability_attempts.max(1);
        let backoff = Duration::from_millis(self.cfg.idp_check_availability_backoff_ms.max(1));
        let mut last_failure: Option<CheckAvailabilityFailure> = None;

        for attempt in 1..=attempts {
            match self.idp.check_availability().await {
                Ok(()) => {
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[("phase", "idp_waiting"), ("outcome", "available")],
                    );
                    return Ok(());
                }
                Err(failure) => {
                    last_failure = Some(failure);
                    if attempt < attempts {
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[("phase", "idp_waiting"), ("outcome", "retry")],
                        );
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "idp_waiting"), ("outcome", "timeout")],
        );
        let detail = last_failure
            .as_ref()
            .map_or("availability probe failed".to_owned(), |f| {
                f.detail().to_owned()
            });
        Err(AmError::IdpUnavailable { detail })
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-idp-probe
    // @cpt-end:cpt-cf-account-management-algo-platform-bootstrap-idp-wait-with-backoff:p1:inst-algo-wait-check-availability

    async fn preflight_root_tenant_type(&self) -> Result<(), AmError> {
        let Some(registry) = &self.types_registry else {
            emit_metric(
                AM_BOOTSTRAP_LIFECYCLE,
                MetricKind::Counter,
                &[
                    ("phase", "gts_preflight"),
                    ("classification", "service_unavailable"),
                    ("outcome", "failure"),
                ],
            );
            return Err(AmError::ServiceUnavailable {
                detail: "types-registry client not attached".to_owned(),
            });
        };

        let entity = registry
            .get(&self.cfg.root_tenant_type)
            .await
            .map_err(|err| {
                if err.is_not_found() {
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[
                            ("phase", "gts_preflight"),
                            ("classification", "invalid_tenant_type"),
                            ("outcome", "failure"),
                        ],
                    );
                    AmError::InvalidTenantType {
                        detail: self.cfg.root_tenant_type.clone(),
                    }
                } else {
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[
                            ("phase", "gts_preflight"),
                            ("classification", "service_unavailable"),
                            ("outcome", "failure"),
                        ],
                    );
                    AmError::ServiceUnavailable {
                        detail: format!("types-registry: {err}"),
                    }
                }
            })?;

        if !entity.is_schema || !entity.gts_id.starts_with("gts.x.core.am.tenant_type.v1~") {
            emit_metric(
                AM_BOOTSTRAP_LIFECYCLE,
                MetricKind::Counter,
                &[
                    ("phase", "gts_preflight"),
                    ("classification", "invalid_tenant_type"),
                    ("outcome", "failure"),
                ],
            );
            return Err(AmError::InvalidTenantType {
                detail: format!("{} is not an AM tenant type", entity.gts_id),
            });
        }

        let allowed = extract_allowed_parent_types(&entity.content)?;
        if !allowed.is_empty() {
            emit_metric(
                AM_BOOTSTRAP_LIFECYCLE,
                MetricKind::Counter,
                &[
                    ("phase", "gts_preflight"),
                    ("classification", "type_not_allowed"),
                    ("outcome", "failure"),
                ],
            );
            return Err(AmError::TypeNotAllowed {
                detail: format!(
                    "root tenant type {} has allowed_parent_types={allowed:?}",
                    self.cfg.root_tenant_type
                ),
            });
        }

        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "gts_preflight"), ("outcome", "success")],
        );
        Ok(())
    }

    /// Read the configured root id and classify the bootstrap state.
    // @cpt-begin:cpt-cf-account-management-algo-platform-bootstrap-idempotency-detection:p1:inst-algo-idem-classify-root
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-idempotency-classify
    async fn classify(&self, scope: &AccessScope) -> Result<BootstrapClassification, AmError> {
        let existing = self.repo.find_by_id(scope, self.cfg.root_id).await?;
        Ok(match existing {
            None => BootstrapClassification::NoRoot,
            Some(t) => match t.status {
                TenantStatus::Active => BootstrapClassification::ActiveRootExists(t),
                TenantStatus::Provisioning => BootstrapClassification::ProvisioningRootResume(t),
                other => BootstrapClassification::InvariantViolation {
                    observed_status: other,
                },
            },
        })
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-idempotency-classify
    // @cpt-end:cpt-cf-account-management-algo-platform-bootstrap-idempotency-detection:p1:inst-algo-idem-classify-root

    /// Saga step 1 — insert the root row in `provisioning` status.
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-insert
    async fn insert_root_provisioning(&self, scope: &AccessScope) -> Result<TenantModel, AmError> {
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "root_creating"), ("outcome", "success")],
        );
        // The repo enforces the per-id uniqueness invariant; we accept
        // its `Conflict` mapping if a concurrent replica beat us to it.
        // Root tenants are the unique row with `parent_id = None` per
        // the migration's `ck_tenants_root_depth` constraint
        // (`parent_id IS NULL AND depth = 0`) and the
        // `ux_tenants_single_root` partial unique index.
        let new_root = NewTenant {
            id: self.cfg.root_id,
            parent_id: None,
            name: self.cfg.root_name.clone(),
            self_managed: false,
            tenant_type_uuid: self.cfg.root_tenant_type_uuid,
            depth: 0,
        };
        self.repo.insert_provisioning(scope, &new_root).await
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-insert

    /// Saga steps 2 + 3 — `IdP` provision + activate-with-closure-self-row.
    // @cpt-begin:cpt-cf-account-management-algo-platform-bootstrap-finalization-saga:p1:inst-algo-bootstrap-finalization
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-finalize
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idp-linking:p1:inst-dod-bootstrap-idp-link
    async fn finalize(
        &self,
        scope: &AccessScope,
        provisioning_root: TenantModel,
    ) -> Result<TenantModel, AmError> {
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "idp_provisioning"), ("outcome", "success")],
        );

        let req = ProvisionRequest {
            tenant_id: provisioning_root.id,
            // Root tenants have no `parent_id` per
            // `dod-platform-bootstrap-root-creation`. The IdP contract
            // accepts an `Option<Uuid>` for exactly this reason.
            parent_id: None,
            name: self.cfg.root_name.clone(),
            tenant_type: self.cfg.root_tenant_type.clone(),
            metadata: self.cfg.root_tenant_metadata.clone(),
        };
        match self.idp.provision_tenant(&req).await {
            Ok(result) => {
                self.handle_provision_success(scope, provisioning_root.id, &result.metadata_entries)
                    .await
            }
            Err(failure) => Err(self
                .handle_provision_failure(scope, provisioning_root.id, failure)
                .await),
        }
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idp-linking:p1:inst-dod-bootstrap-idp-link
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-finalize
    // @cpt-end:cpt-cf-account-management-algo-platform-bootstrap-finalization-saga:p1:inst-algo-bootstrap-finalization

    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-activate
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-success-telemetry
    async fn handle_provision_success(
        &self,
        scope: &AccessScope,
        root_id: uuid::Uuid,
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, AmError> {
        // Root tenant has no strict ancestors; closure rows
        // collapse to the self-row.
        let closure_rows = build_activation_rows(root_id, TenantStatus::Active, false, &[]);
        let activated = self
            .repo
            .activate_tenant(scope, root_id, &closure_rows, metadata_entries)
            .await?;
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[
                ("phase", "completed"),
                ("classification", "fresh"),
                ("outcome", "success"),
            ],
        );
        if let Some(event) = AuditEvent::system(
            AuditEventKind::BootstrapCompleted,
            activated.id,
            json!({ "classification": "fresh" }),
        ) {
            emit_audit(&event);
        }
        info!(
            target: "am.bootstrap",
            root_id = %activated.id,
            "platform-bootstrap saga completed"
        );
        Ok(activated)
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-success-telemetry
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-root-creation:p1:inst-dod-bootstrap-root-activate

    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-failure-telemetry
    async fn handle_provision_failure(
        &self,
        scope: &AccessScope,
        root_id: uuid::Uuid,
        failure: ProvisionFailure,
    ) -> AmError {
        // Emit the same `phase=failed` metric for every terminal arm so
        // dashboards count failures symmetrically. The `classification`
        // label is the typed `ProvisionFailure::as_metric_label()` token
        // (avoids hand-rolled strings drifting between this site and
        // the saga's failure path in `tenant::service`).
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[
                ("phase", "failed"),
                ("classification", failure.as_metric_label()),
                ("outcome", "failure"),
            ],
        );
        match failure {
            ProvisionFailure::CleanFailure { detail } => {
                self.compensate(scope, root_id, "clean-failure").await;
                AmError::IdpUnavailable { detail }
            }
            ProvisionFailure::Ambiguous { detail } => {
                // Leave the provisioning row in place — the reaper
                // compensates per FEATURE §3 step 8.2.
                AmError::Internal {
                    diagnostic: format!("idp provision ambiguous outcome: {detail}"),
                }
            }
            ProvisionFailure::UnsupportedOperation { detail } => {
                self.compensate(scope, root_id, "unsupported").await;
                AmError::IdpUnsupportedOperation { detail }
            }
        }
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-failure-telemetry

    /// Best-effort compensation for the bootstrap saga. Compensation
    /// failure is intentionally swallowed (logged at warn-level, no
    /// error returned): the provisioning reaper
    /// (`algo-provisioning-reaper-compensation`) sweeps any row left
    /// behind on its next tick, so propagating the comp failure here
    /// would only surface a duplicate `Internal` to the caller without
    /// changing the eventual end state.
    async fn compensate(&self, scope: &AccessScope, root_id: uuid::Uuid, label: &str) {
        if let Err(comp_err) = self.repo.compensate_provisioning(scope, root_id).await {
            warn!(
                target: "am.bootstrap",
                error = %comp_err,
                label,
                "bootstrap compensation failed; deferring to reaper"
            );
        }
    }
}

/// Idempotent skip path — emit the `BootstrapCompleted` audit event
/// + completed-skipped metric, then return the existing active root.
// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-skip-existing
// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-skip-telemetry
fn handle_skip(root: TenantModel) -> TenantModel {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", "completed"),
            ("classification", "skipped"),
            ("outcome", "success"),
        ],
    );
    if let Some(event) = AuditEvent::system(
        AuditEventKind::BootstrapCompleted,
        root.id,
        json!({ "classification": "skipped" }),
    ) {
        emit_audit(&event);
    }
    root
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-skip-telemetry
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-skip-existing

// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-defer-reaper
// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-defer-telemetry
fn handle_deferred_to_reaper(root: TenantModel) -> TenantModel {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", "completed"),
            ("classification", "deferred_to_reaper"),
            ("outcome", "success"),
        ],
    );
    if let Some(event) = AuditEvent::system(
        AuditEventKind::BootstrapDeferredToReaper,
        root.id,
        json!({ "classification": "deferred_to_reaper" }),
    ) {
        emit_audit(&event);
    }
    warn!(
        target: "am.bootstrap",
        root_id = %root.id,
        "platform-bootstrap found provisioning root; deferring to provisioning reaper"
    );
    root
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-defer-telemetry
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-defer-reaper

// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-invariant-telemetry
fn handle_invariant_violation(observed_status: TenantStatus) -> AmError {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", "failed"),
            ("classification", "invariant_violation"),
            ("outcome", "failure"),
        ],
    );
    AmError::Internal {
        diagnostic: format!(
            "bootstrap invariant violation: root tenant in unexpected state {observed_status:?}"
        ),
    }
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-invariant-telemetry

fn extract_allowed_parent_types(content: &serde_json::Value) -> Result<Vec<String>, AmError> {
    let Some(value) = find_allowed_parent_types(content) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(AmError::InvalidTenantType {
            detail: "allowed_parent_types trait must be an array".to_owned(),
        });
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| AmError::InvalidTenantType {
                    detail: "allowed_parent_types trait must contain only strings".to_owned(),
                })
        })
        .collect()
}

fn find_allowed_parent_types(content: &serde_json::Value) -> Option<&serde_json::Value> {
    content
        .get("x-gts-traits")
        .and_then(|traits| traits.get("allowed_parent_types"))
        .or_else(|| {
            content
                .get("allOf")
                .and_then(|all_of| all_of.as_array())
                .and_then(|items| {
                    items.iter().find_map(|item| {
                        item.get("x-gts-traits")
                            .and_then(|traits| traits.get("allowed_parent_types"))
                    })
                })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]
mod tests {
    use super::*;
    use crate::domain::tenant::test_support::{FakeIdpProvisioner, FakeOutcome, FakeTenantRepo};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use types_registry_sdk::{GtsEntity, ListQuery, RegisterResult, TypesRegistryError};
    use uuid::Uuid;

    enum RegistryOutcome {
        RootEligible,
        NonRoot,
    }

    struct FakeTypesRegistry {
        outcome: Mutex<RegistryOutcome>,
    }

    impl FakeTypesRegistry {
        fn root_eligible() -> Self {
            Self {
                outcome: Mutex::new(RegistryOutcome::RootEligible),
            }
        }

        fn non_root() -> Self {
            Self {
                outcome: Mutex::new(RegistryOutcome::NonRoot),
            }
        }
    }

    fn tenant_type_entity(allowed_parent_types: Vec<&str>) -> GtsEntity {
        GtsEntity {
            id: Uuid::from_u128(0xAA),
            gts_id: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".to_owned(),
            segments: Vec::new(),
            is_schema: true,
            content: json!({
                "allOf": [
                    { "$ref": "gts://gts.x.core.am.tenant_type.v1~" },
                    { "x-gts-traits": { "allowed_parent_types": allowed_parent_types } }
                ]
            }),
            description: None,
        }
    }

    #[async_trait]
    impl TypesRegistryClient for FakeTypesRegistry {
        async fn register(
            &self,
            _entities: Vec<serde_json::Value>,
        ) -> Result<Vec<RegisterResult>, TypesRegistryError> {
            unreachable!("not used by bootstrap")
        }

        async fn list(&self, _query: ListQuery) -> Result<Vec<GtsEntity>, TypesRegistryError> {
            unreachable!("not used by bootstrap")
        }

        async fn get(&self, _gts_id: &str) -> Result<GtsEntity, TypesRegistryError> {
            match &*self.outcome.lock().expect("lock") {
                RegistryOutcome::RootEligible => Ok(tenant_type_entity(Vec::new())),
                RegistryOutcome::NonRoot => Ok(tenant_type_entity(vec![
                    "gts.x.core.am.tenant_type.v1~x.core.am.provider.v1~",
                ])),
            }
        }
    }

    fn config_for(root_id: Uuid) -> BootstrapConfig {
        BootstrapConfig {
            root_id,
            root_name: "platform-root".into(),
            root_tenant_type_uuid: Uuid::from_u128(0xAA),
            root_tenant_type: "gts.x.core.am.tenant_type.v1~x.core.am.platform.v1~".into(),
            root_tenant_metadata: None,
            idp_check_availability_attempts: 3,
            idp_check_availability_backoff_ms: 1,
            // Aggressive timing so the retry test does not block CI.
            idp_wait_timeout_secs: 1,
            idp_retry_backoff_initial_secs: 1,
            idp_retry_backoff_max_secs: 1,
            strict: false,
        }
    }

    /// Test bench: fresh repo + `IdP` fake with `outcome` + service over
    /// `config_for(root_id)`. Returns the four pieces every bootstrap
    /// test needs so call sites stay tight.
    fn make_bootstrap(
        outcome: FakeOutcome,
    ) -> (
        Uuid,
        Arc<FakeTenantRepo>,
        Arc<FakeIdpProvisioner>,
        BootstrapService<FakeTenantRepo>,
    ) {
        let root_id = Uuid::new_v4();
        let repo = Arc::new(FakeTenantRepo::new());
        let idp = Arc::new(FakeIdpProvisioner::new(outcome));
        let svc = BootstrapService::new(repo.clone(), idp.clone(), config_for(root_id))
            .with_types_registry(Arc::new(FakeTypesRegistry::root_eligible()));
        (root_id, repo, idp, svc)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_fresh_creates_root_and_emits_audit() {
        let (root_id, repo, idp, svc) = make_bootstrap(FakeOutcome::Ok);

        let activated = svc.run().await.expect("fresh bootstrap succeeds");
        assert_eq!(activated.id, root_id);
        assert_eq!(activated.status, TenantStatus::Active);

        // The IdP plugin must have been invoked exactly once.
        assert_eq!(idp.calls.lock().expect("lock").len(), 1);

        // The repo must hold an active root with a self-row in closure.
        let state = repo.state.lock().expect("lock");
        let stored = state.tenants.get(&root_id).expect("root row");
        assert_eq!(stored.status, TenantStatus::Active);
        // Root tenants store parent_id = NULL — required by the
        // migration's `ck_tenants_root_depth` constraint
        // (`parent_id IS NULL AND depth = 0`) and the
        // `ux_tenants_single_root` partial unique index. A
        // self-referential `parent_id == id` would violate both, so
        // assert the None invariant here.
        assert!(
            stored.parent_id.is_none(),
            "root tenant must store parent_id = None (got {:?})",
            stored.parent_id
        );
        assert_eq!(stored.depth, 0, "root tenant has depth 0");
        assert!(
            state
                .closure
                .iter()
                .any(|r| r.ancestor_id == root_id && r.descendant_id == root_id),
            "self-row missing from tenant_closure"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_persists_provider_metadata_on_activation() {
        let (root_id, repo, idp, svc) = make_bootstrap(FakeOutcome::Ok);
        idp.set_metadata_entries(vec![ProvisionMetadataEntry {
            schema_id: "gts.x.core.am.tenant_metadata.v1~x.core.am.idp_binding.v1~".into(),
            value: json!({ "realm": "platform" }),
        }]);

        svc.run().await.expect("fresh bootstrap succeeds");

        let state = repo.state.lock().expect("lock");
        assert_eq!(state.metadata.len(), 1);
        assert_eq!(state.metadata[0].0, root_id);
        assert_eq!(
            state.metadata[0].1.schema_id,
            "gts.x.core.am.tenant_metadata.v1~x.core.am.idp_binding.v1~"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_gts_preflight_rejects_non_root_type_before_persistence() {
        let root_id = Uuid::new_v4();
        let repo = Arc::new(FakeTenantRepo::new());
        let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
        let svc = BootstrapService::new(repo.clone(), idp.clone(), config_for(root_id))
            .with_types_registry(Arc::new(FakeTypesRegistry::non_root()));

        let err = svc.run().await.expect_err("non-root type rejects");
        assert!(matches!(err, AmError::TypeNotAllowed { .. }));
        assert!(repo.state.lock().expect("lock").tenants.is_empty());
        assert!(idp.calls.lock().expect("lock").is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_check_availability_runs_before_saga_and_can_fail() {
        let (root_id, repo, idp, svc) = {
            let root_id = Uuid::new_v4();
            let repo = Arc::new(FakeTenantRepo::new());
            let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
            let mut cfg = config_for(root_id);
            cfg.idp_check_availability_attempts = 2;
            let svc = BootstrapService::new(repo.clone(), idp.clone(), cfg)
                .with_types_registry(Arc::new(FakeTypesRegistry::root_eligible()));
            (root_id, repo, idp, svc)
        };
        idp.fail_availability_times(2);

        let err = svc.run().await.expect_err("availability should fail");
        assert!(matches!(err, AmError::IdpUnavailable { .. }));
        assert_eq!(*idp.availability_calls.lock().expect("lock"), 2);
        assert!(idp.calls.lock().expect("lock").is_empty());
        assert!(repo.state.lock().expect("lock").tenants.is_empty());
        assert!(!root_id.is_nil());

        let (root_id, _repo, idp, svc2) = make_bootstrap(FakeOutcome::Ok);
        svc2.run().await.expect("availability happy path");
        assert_eq!(*idp.availability_calls.lock().expect("lock"), 1);
        assert!(!root_id.is_nil());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_idempotent_when_root_already_exists_returns_existing() {
        // This test pre-seeds the root row, so build the repo with a
        // root + matching service from scratch (the `make_bootstrap`
        // helper assumes an empty repo).
        let root_id = Uuid::from_u128(0x200);
        let repo = Arc::new(FakeTenantRepo::with_root(root_id));
        let idp = Arc::new(FakeIdpProvisioner::new(FakeOutcome::Ok));
        let svc = BootstrapService::new(repo.clone(), idp.clone(), config_for(root_id));

        let result = svc.run().await.expect("idempotent skip succeeds");
        assert_eq!(result.id, root_id);
        assert_eq!(result.status, TenantStatus::Active);

        // No second IdP provision must have occurred.
        assert!(idp.calls.lock().expect("lock").is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_deferred_to_reaper_when_root_is_provisioning() {
        let (root_id, repo, idp, svc) = make_bootstrap(FakeOutcome::Ok);
        // Pre-seed the repo with a `provisioning` root from a prior crash.
        let now = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        repo.insert_tenant_raw(TenantModel {
            id: root_id,
            parent_id: None,
            name: "platform-root".into(),
            status: TenantStatus::Provisioning,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 0,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });

        let deferred = svc.run().await.expect("defer succeeds");
        assert_eq!(deferred.status, TenantStatus::Provisioning);
        // Bootstrap must not re-run IdP for a stale provisioning root;
        // the provisioning reaper owns compensation.
        assert!(idp.calls.lock().expect("lock").is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_idp_clean_failure_compensates_and_retries_until_timeout() {
        // Tight 1s deadline + 1s backoff → exactly one retry then time
        // out. start_paused = true means tokio::time::sleep advances the
        // virtual clock instantly.
        let (root_id, repo, idp, svc) = make_bootstrap(FakeOutcome::CleanFailure);

        let err = svc.run().await.expect_err("must time out");
        assert!(
            matches!(err, AmError::IdpUnavailable { .. }),
            "expected IdpUnavailable, got {err:?}"
        );
        // Compensation must have removed any provisioning row.
        let state = repo.state.lock().expect("lock");
        assert!(
            !state.tenants.contains_key(&root_id),
            "provisioning row must be compensated on clean failure"
        );
        // The IdP plugin was invoked at least twice (one initial + at
        // least one retry within the deadline).
        assert!(idp.calls.lock().expect("lock").len() >= 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_idp_terminal_failure_returns_unsupported() {
        let (root_id, repo, _idp, svc) = make_bootstrap(FakeOutcome::Unsupported);

        let err = svc.run().await.expect_err("unsupported failure");
        assert!(
            matches!(err, AmError::IdpUnsupportedOperation { .. }),
            "expected IdpUnsupportedOperation, got {err:?}"
        );
        let state = repo.state.lock().expect("lock");
        assert!(
            !state.tenants.contains_key(&root_id),
            "provisioning row must be compensated on unsupported"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_idp_ambiguous_failure_leaves_provisioning_row_for_reaper() {
        let (root_id, repo, _idp, svc) = make_bootstrap(FakeOutcome::Ambiguous);

        let err = svc.run().await.expect_err("ambiguous failure");
        assert!(
            matches!(err, AmError::Internal { .. }),
            "expected Internal (ambiguous), got {err:?}"
        );
        // Provisioning row must persist so the reaper can compensate it.
        let state = repo.state.lock().expect("lock");
        let stored = state.tenants.get(&root_id).expect("provisioning row stays");
        assert_eq!(stored.status, TenantStatus::Provisioning);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bootstrap_invariant_violation_when_root_is_suspended() {
        let (root_id, repo, _idp, svc) = make_bootstrap(FakeOutcome::Ok);
        let now = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("epoch");
        repo.insert_tenant_raw(TenantModel {
            id: root_id,
            parent_id: None,
            name: "platform-root".into(),
            status: TenantStatus::Suspended,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0xAA),
            depth: 0,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        });

        let err = svc.run().await.expect_err("invariant violation");
        assert!(
            matches!(err, AmError::Internal { .. }),
            "expected Internal (invariant violation), got {err:?}"
        );
    }
}
