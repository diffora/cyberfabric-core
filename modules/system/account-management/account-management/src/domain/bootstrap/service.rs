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
use time::OffsetDateTime;
use tokio::time::Instant;
use tracing::{info, warn};

use account_management_sdk::{
    DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient, ProvisionFailure,
    ProvisionMetadataEntry, ProvisionRequest,
};

use crate::domain::bootstrap::config::BootstrapConfig;
use crate::domain::error::DomainError;
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
    /// Root row in `Provisioning` observed at classify time. The
    /// saga does NOT re-run `IdP` + activate from this branch:
    /// instead it falls through to the retry loop (no preflight, no
    /// availability wait) so a peer replica currently mid-saga can
    /// finalize its own attempt and we observe the outcome. If the
    /// row's age exceeds `2 × idp_wait_timeout_secs` (the FEATURE-§3
    /// stuck threshold) the branch surfaces `Internal` and defers
    /// cleanup to the provisioning reaper; if the bootstrap deadline
    /// expires while waiting, the branch surfaces `IdpUnavailable`.
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
    idp: Arc<dyn IdpTenantProvisionerClient>,
    types_registry: Option<Arc<dyn TypesRegistryClient>>,
    cfg: BootstrapConfig,
    /// Mirrors `cfg.idp.required` from the parent
    /// `AccountManagementConfig`. Threaded in via
    /// [`Self::with_idp_required`] so the step-3 compensator can
    /// treat `DeprovisionFailure::UnsupportedOperation` symmetrically
    /// with `TenantService::compensate_failed_activation`: under
    /// `idp.required = false` the variant means "no plugin wired,
    /// nothing to clean" and the local row may be deleted; under
    /// `idp.required = true` it means "the real plugin can't
    /// deprovision a tenant it provisioned" and the row MUST be
    /// left for the reaper to avoid orphaning vendor-side state.
    /// Defaults to `false` so test embedders inherit the
    /// Phase-1/2 default without having to thread the flag through.
    idp_required: bool,
}

impl<R: TenantRepo> BootstrapService<R> {
    /// Construct a fully-wired bootstrap service.
    ///
    /// # Caller contract
    ///
    /// Callers **MUST** call [`BootstrapConfig::validate`] before
    /// `new()`. The check below is a `debug_assert!` (stripped from
    /// release builds), so a nil-UUID config slips through release
    /// silently and breaks `fr-bootstrap-idempotency` on the next
    /// platform restart (`BootstrapConfig` uses `serde(default)`, so
    /// an empty TOML table deserialises to `Uuid::nil()`; see
    /// `feature-platform-bootstrap.md` lines 23-25).
    ///
    /// Module wiring (`module.rs::init`) is the canonical validate
    /// call site because it owns the strict/non-strict branching: a
    /// strict-mode validation failure is lifecycle-fatal, whereas a
    /// non-strict failure logs and skips bootstrap entirely. Tests
    /// and future embedders that construct the saga directly inherit
    /// the same obligation.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `cfg.validate()` returns `Err` — the
    /// caller violated the validate-before-construct contract above.
    /// Release builds strip the assertion, so the contract MUST be
    /// honored at every call site (production path is honored by
    /// `module.rs::init`).
    #[must_use]
    pub fn new(
        repo: Arc<R>,
        idp: Arc<dyn IdpTenantProvisionerClient>,
        cfg: BootstrapConfig,
    ) -> Self {
        // Single `validate()` call so the assertion message and the
        // boolean predicate cannot disagree (a previous shape called
        // `validate()` twice and could in principle produce different
        // error text on the second call once any non-pure check is
        // added; the form below stays correct under refactor).
        if cfg!(debug_assertions)
            && let Err(err) = cfg.validate()
        {
            panic!(
                "BootstrapConfig must be validated before constructing BootstrapService; \
                 module wiring is the canonical validate call site (see module.rs::init). \
                 Validation failed: {err}"
            );
        }
        Self {
            repo,
            idp,
            types_registry: None,
            cfg,
            idp_required: false,
        }
    }

    /// Attach the GTS Types Registry client used for root-tenant-type
    /// preflight. Tests that exercise non-GTS paths may omit this; module
    /// wiring supplies it when `ClientHub` resolves the registry client.
    #[must_use]
    pub fn with_types_registry(mut self, types_registry: Arc<dyn TypesRegistryClient>) -> Self {
        self.types_registry = Some(types_registry);
        self
    }

    /// Mirror the parent `AccountManagementConfig.idp.required` flag
    /// into the saga so step-3 compensation can apply the same
    /// `UnsupportedOperation` policy `TenantService::compensate_failed_activation`
    /// uses: refuse to delete the local row when a real plugin returns
    /// Unsupported under `idp.required = true`, because vendor-side
    /// state may exist that AM cannot reach. Module wiring sets this;
    /// tests that operate against `NoopProvisioner` (or that don't care
    /// about the orphan-prevention path) can omit it and inherit the
    /// `idp.required = false` default.
    #[must_use]
    pub fn with_idp_required(mut self, idp_required: bool) -> Self {
        self.idp_required = idp_required;
        self
    }

    /// Run the bootstrap saga to terminal state.
    ///
    /// # Returned tenant status
    ///
    /// On `Ok(_)` the returned [`TenantModel`] is always
    /// [`TenantStatus::Active`] — the saga either created and
    /// activated a fresh root, observed an already-active one, or
    /// waited for a peer replica's saga to flip the row to active.
    /// A row stuck in `Provisioning` (older than the FEATURE-§3
    /// stuck threshold) or a deadline-exhausted peer-wait surfaces
    /// as `Err(_)` rather than `Ok(Provisioning)` — the strict-mode
    /// `init` gate in `module::run_bootstrap_phase` decides whether
    /// to abort or proceed without an active root.
    ///
    /// # Errors
    ///
    /// * [`DomainError::IdpUnavailable`] when the `IdP` wait exhausts the
    ///   configured timeout or every retry returned `CleanFailure`.
    /// * [`DomainError::UnsupportedOperation`] when the `IdP` plugin signals
    ///   it cannot perform root provisioning at all (compensated).
    /// * [`DomainError::Internal`] for ambiguous `IdP` outcomes (provisioning
    ///   row left for reaper) and for invariant-violation root states.
    #[tracing::instrument(skip_all, fields(root_id = %self.cfg.root_id))]
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-wait-before-saga
    pub async fn run(&self) -> Result<TenantModel, DomainError> {
        let scope = AccessScope::allow_all();
        let deadline = Instant::now() + Duration::from_secs(self.cfg.idp_wait_timeout_secs);
        let cap = Duration::from_secs(self.cfg.idp_retry_backoff_max_secs.max(1));
        // `2 × idp_wait_timeout_secs` is the FEATURE-§3 stuck threshold
        // for distinguishing a crashed previous attempt from one
        // currently mid-saga on a peer replica (the peer's saga
        // budget is bounded by `idp_wait_timeout_secs`, so anything
        // older than 2× is by definition not in flight).
        let stuck_threshold = time::Duration::seconds(
            i64::try_from(self.cfg.idp_wait_timeout_secs.saturating_mul(2)).unwrap_or(i64::MAX),
        );

        // Initial classification runs BEFORE any IdP work so the three
        // idempotent fast-paths (already-Active root, invariant-
        // violation status, stuck-Provisioning row) decide without
        // contacting the IdP. A restart with an already-active root
        // therefore succeeds even when the IdP is down. Only `NoRoot`
        // and `ProvisioningRootResume`-in-flight enter the retry loop.
        //
        // `pending_takeover_precheck` defers the preflight + IdP-wait
        // pair when we enter the loop via `ProvisioningRootResume`.
        // The peer-mid-saga branch deliberately skips those checks
        // (the peer is doing them), but if the peer or reaper later
        // removes the row, the loop's `NoRoot` arm would otherwise
        // jump straight to `insert_root_provisioning` + `finalize`
        // without ever validating the root tenant type or waiting
        // for IdP availability. Run them lazily on the first NoRoot
        // observation in that case.
        let mut pending_takeover_precheck = false;
        match self.classify(&scope).await? {
            BootstrapClassification::ActiveRootExists(root) => {
                return Ok(handle_skip(root));
            }
            BootstrapClassification::InvariantViolation { observed_status } => {
                return Err(handle_invariant_violation(observed_status));
            }
            BootstrapClassification::ProvisioningRootResume(existing) => {
                let age = OffsetDateTime::now_utc() - existing.created_at;
                if age > stuck_threshold {
                    return Err(handle_deferred_to_reaper_stuck(&existing));
                }
                // peer-mid-saga: fall through to the retry loop
                // WITHOUT preflight + IdP wait; the peer is
                // performing those steps and we just observe its
                // outcome. If the row vanishes mid-wait the loop's
                // NoRoot arm will run preflight + wait once before
                // taking over (gated by `pending_takeover_precheck`).
                pending_takeover_precheck = true;
            }
            BootstrapClassification::NoRoot => {
                // Permanent type-misconfiguration fails fast before
                // sinking minutes into the IdP-availability wait.
                self.preflight_root_tenant_type().await?;
                // Saga path: each retryable phase (precheck, peer
                // wait, provision_tenant retry) gets its own backoff
                // accumulator so a long precheck does not elevate
                // the first saga retry's sleep.
                let mut precheck_backoff =
                    Duration::from_secs(self.cfg.idp_retry_backoff_initial_secs.max(1));
                self.wait_for_idp_availability(deadline, &mut precheck_backoff, cap)
                    .await?;
            }
        }

        let mut backoff = Duration::from_secs(self.cfg.idp_retry_backoff_initial_secs.max(1));
        // Bound the consecutive-`AlreadyExists` retries: a configured
        // root_id that drifted away from the actual DB root collides
        // with `ux_tenants_single_root` on every insert while the
        // next `classify` (filtered by configured id) keeps returning
        // `NoRoot`. Without a cap that pair would loop forever.
        let mut already_exists_streak = 0u32;
        const MAX_ALREADY_EXISTS_STREAK: u32 = 3;

        loop {
            match self.classify(&scope).await? {
                BootstrapClassification::ActiveRootExists(root) => {
                    return Ok(handle_skip(root));
                }
                BootstrapClassification::InvariantViolation { observed_status } => {
                    return Err(handle_invariant_violation(observed_status));
                }
                BootstrapClassification::ProvisioningRootResume(existing) => {
                    already_exists_streak = 0;
                    let age = OffsetDateTime::now_utc() - existing.created_at;
                    if age > stuck_threshold {
                        return Err(handle_deferred_to_reaper_stuck(&existing));
                    }
                    if Instant::now() >= deadline {
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[
                                ("phase", "provisioning_wait"),
                                ("classification", "in_progress_elsewhere"),
                                ("outcome", "timeout"),
                            ],
                        );
                        warn!(
                            target: "am.bootstrap",
                            root_id = %existing.id,
                            "bootstrap deadline exhausted while peer was finalizing root; surfacing idp_unavailable"
                        );
                        return Err(DomainError::IdpUnavailable {
                            detail: "peer replica did not finalize the root within the bootstrap deadline".to_owned(),
                        });
                    }
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[
                            ("phase", "provisioning_wait"),
                            ("classification", "in_progress_elsewhere"),
                            ("outcome", "retry"),
                        ],
                    );
                    let sleep_for = bounded_sleep(backoff, deadline);
                    tokio::time::sleep(sleep_for).await;
                    backoff = compute_next_backoff(backoff, cap);
                }
                BootstrapClassification::NoRoot => {
                    // Takeover path: the row we initially observed in
                    // `Provisioning` was removed by the peer's
                    // compensation or by the reaper, leaving us as the
                    // first writer. Run the same preflight + IdP-wait
                    // pair the initial-NoRoot arm above performs once,
                    // then proceed to insert. The flag flips off so a
                    // subsequent NoRoot iteration in the same `run()`
                    // (after another classify cycle) does not re-pay
                    // the precheck cost.
                    if pending_takeover_precheck {
                        self.preflight_root_tenant_type().await?;
                        let mut precheck_backoff =
                            Duration::from_secs(self.cfg.idp_retry_backoff_initial_secs.max(1));
                        self.wait_for_idp_availability(deadline, &mut precheck_backoff, cap)
                            .await?;
                        pending_takeover_precheck = false;
                    }
                    match self.insert_root_provisioning(&scope).await {
                        Ok(inserted) => {
                            already_exists_streak = 0;
                            match self.finalize(&scope, inserted, deadline).await {
                                Ok(root) => return Ok(root),
                                Err(err) if matches!(err, DomainError::IdpUnavailable { .. }) => {
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
                                    let sleep_for = bounded_sleep(backoff, deadline);
                                    tokio::time::sleep(sleep_for).await;
                                    backoff = compute_next_backoff(backoff, cap);
                                }
                                Err(err) => return Err(err),
                            }
                        }
                        // `ux_tenants_single_root` partial unique
                        // index surfaces a concurrent winner OR a
                        // root-id drift (configured `root_id`
                        // doesn't match the existing root row) as
                        // `AlreadyExists`. The first case resolves
                        // on the next `classify`; the second case
                        // produces an oscillating
                        // `NoRoot → AlreadyExists → NoRoot` loop
                        // because the classify is filtered by the
                        // configured id. Cap the consecutive streak
                        // so a drifted config escalates to a clean
                        // invariant error instead of spinning init.
                        Err(DomainError::AlreadyExists { .. }) => {
                            already_exists_streak += 1;
                            if already_exists_streak >= MAX_ALREADY_EXISTS_STREAK {
                                emit_metric(
                                    AM_BOOTSTRAP_LIFECYCLE,
                                    MetricKind::Counter,
                                    &[
                                        ("phase", "failed"),
                                        ("classification", "root_id_drift"),
                                        ("outcome", "failure"),
                                    ],
                                );
                                warn!(
                                    target: "am.bootstrap",
                                    streak = already_exists_streak,
                                    root_id = %self.cfg.root_id,
                                    "configured root_id does not match the existing platform root; aborting init"
                                );
                                return Err(DomainError::internal(format!(
                                    "platform root already exists with a different id; configured root_id={} cannot be inserted (likely a config drift between platform restarts)",
                                    self.cfg.root_id
                                )));
                            }
                            emit_metric(
                                AM_BOOTSTRAP_LIFECYCLE,
                                MetricKind::Counter,
                                &[
                                    ("phase", "root_creating"),
                                    ("classification", "race_loser"),
                                    ("outcome", "reclassify"),
                                ],
                            );
                            info!(
                                target: "am.bootstrap",
                                streak = already_exists_streak,
                                "concurrent root insert observed; re-classifying on next loop iteration"
                            );
                            // Yield once before the next classify so a
                            // legitimate concurrent-replica race does
                            // not burn through `MAX_ALREADY_EXISTS_STREAK`
                            // in microseconds. The other retry arms in
                            // this loop sleep on the same backoff
                            // accumulator, so re-using it here keeps
                            // the per-invocation envelope symmetric.
                            if Instant::now() >= deadline {
                                emit_metric(
                                    AM_BOOTSTRAP_LIFECYCLE,
                                    MetricKind::Counter,
                                    &[
                                        ("phase", "root_creating"),
                                        ("classification", "race_loser"),
                                        ("outcome", "timeout"),
                                    ],
                                );
                                return Err(DomainError::IdpUnavailable {
                                    detail: "bootstrap deadline exhausted while losing concurrent-root inserts".to_owned(),
                                });
                            }
                            let sleep_for = bounded_sleep(backoff, deadline);
                            tokio::time::sleep(sleep_for).await;
                            backoff = compute_next_backoff(backoff, cap);
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
        }
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-wait-before-saga

    // The previous `try_bootstrap_once` / `try_bootstrap_once_locked`
    // forwarders were folded into the unified retry loop in `run()`
    // above. Keeping a one-shot attempt helper would have re-classified
    // on every iteration and called `preflight_root_tenant_type` more
    // than once for a clean NoRoot path, both of which are unwanted.

    // @cpt-begin:cpt-cf-account-management-algo-platform-bootstrap-idp-wait-with-backoff:p1:inst-algo-wait-check-availability
    // @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-idp-probe
    //
    // Implements FEATURE §3 `algo-platform-bootstrap-idp-wait-with-backoff`:
    // probe `IdP::check_availability` with exponential backoff
    // (`idp_retry_backoff_initial` doubling up to
    // `idp_retry_backoff_max`) against an `idp_retry_timeout` (=
    // `idp_wait_timeout_secs`) deadline. The same deadline + backoff
    // envelope is reused by the saga retry loop in `run()` for
    // `IdpUnavailable` raised during step 2 (provision_tenant) — both
    // surfaces emit on `AM_BOOTSTRAP_LIFECYCLE`; the pre-saga probe
    // uses `phase=idp_precheck` so dashboards can isolate it from the
    // saga retries (`phase=idp_waiting`).
    async fn wait_for_idp_availability(
        &self,
        deadline: Instant,
        backoff: &mut Duration,
        cap: Duration,
    ) -> Result<(), DomainError> {
        loop {
            // Wrap the IdP probe in `timeout_at(deadline, ...)` so a
            // hung provider cannot run the bootstrap past the
            // configured wall-clock cap. Without this, the deadline
            // check below only fires AFTER the await returns, so a
            // probe that never completes would stretch the wait
            // indefinitely.
            if Instant::now() >= deadline {
                emit_metric(
                    AM_BOOTSTRAP_LIFECYCLE,
                    MetricKind::Counter,
                    &[("phase", "idp_precheck"), ("outcome", "timeout")],
                );
                return Err(DomainError::IdpUnavailable {
                    detail: "bootstrap IdP availability wait timed out".to_owned(),
                });
            }
            let failure =
                match tokio::time::timeout_at(deadline, self.idp.check_availability()).await {
                    Ok(Ok(())) => {
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[("phase", "idp_precheck"), ("outcome", "available")],
                        );
                        return Ok(());
                    }
                    Ok(Err(failure)) => failure,
                    Err(_elapsed) => {
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[("phase", "idp_precheck"), ("outcome", "timeout")],
                        );
                        return Err(DomainError::IdpUnavailable {
                            detail: "bootstrap IdP availability probe timed out".to_owned(),
                        });
                    }
                };
            if Instant::now() >= deadline {
                emit_metric(
                    AM_BOOTSTRAP_LIFECYCLE,
                    MetricKind::Counter,
                    &[("phase", "idp_precheck"), ("outcome", "timeout")],
                );
                return Err(DomainError::IdpUnavailable {
                    detail: failure.detail().to_owned(),
                });
            }
            emit_metric(
                AM_BOOTSTRAP_LIFECYCLE,
                MetricKind::Counter,
                &[("phase", "idp_precheck"), ("outcome", "retry")],
            );
            // `bounded_sleep` caps the requested backoff at the
            // remaining deadline so the precheck does not run past
            // `idp_wait_timeout_secs` even when the configured
            // backoff cap is larger than the remaining budget.
            let sleep_for = bounded_sleep(*backoff, deadline);
            tokio::time::sleep(sleep_for).await;
            *backoff = compute_next_backoff(*backoff, cap);
        }
    }
    // @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idp-wait-ordering:p1:inst-dod-bootstrap-idp-probe
    // @cpt-end:cpt-cf-account-management-algo-platform-bootstrap-idp-wait-with-backoff:p1:inst-algo-wait-check-availability

    async fn preflight_root_tenant_type(&self) -> Result<(), DomainError> {
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
            return Err(DomainError::service_unavailable(
                "types-registry client not attached",
            ));
        };

        let entity = registry
            .get_type_schema(self.cfg.root_tenant_type.as_ref())
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
                    DomainError::InvalidTenantType {
                        detail: self.cfg.root_tenant_type.to_string(),
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
                    DomainError::service_unavailable(format!("types-registry: {err}"))
                }
            })?;

        // `GtsTypeSchema` is by construction a type-schema (the
        // `is_schema` axis is implicit in the type), so the only check
        // remaining is the AM-tenant-type chain prefix on `type_id`.
        let entity_type_id = entity.type_id.as_ref();
        if !entity_type_id.starts_with("gts.cf.core.am.tenant_type.v1~") {
            emit_metric(
                AM_BOOTSTRAP_LIFECYCLE,
                MetricKind::Counter,
                &[
                    ("phase", "gts_preflight"),
                    ("classification", "invalid_tenant_type"),
                    ("outcome", "failure"),
                ],
            );
            return Err(DomainError::InvalidTenantType {
                detail: format!("{entity_type_id} is not an AM tenant type"),
            });
        }

        // `effective_traits` resolves the GTS chain (own + ancestors)
        // so a root type that inherits a non-empty
        // `allowed_parent_types` from a base schema is correctly
        // rejected. Reading `entity.raw_schema` directly only sees the
        // type's own declarations and would silently accept an
        // inherited rule, breaking the root-eligibility contract —
        // the same effective-trait resolution that
        // `GtsTenantTypeChecker` already uses for child create.
        let allowed = extract_allowed_parent_types_from_effective(&entity.effective_traits())?;
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
            return Err(DomainError::TypeNotAllowed {
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
    async fn classify(&self, scope: &AccessScope) -> Result<BootstrapClassification, DomainError> {
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
    async fn insert_root_provisioning(
        &self,
        scope: &AccessScope,
    ) -> Result<TenantModel, DomainError> {
        // The repo enforces the per-id uniqueness invariant; we accept
        // its `Conflict` mapping if a concurrent replica beat us to it.
        // Root tenants are the unique row with `parent_id = None` per
        // the migration's `ck_tenants_root_depth` constraint
        // (`parent_id IS NULL AND depth = 0`) and the
        // `ux_tenants_single_root` partial unique index.
        // Derive `tenant_type_uuid` from the configured GTS id via
        // `gts::GtsID::to_uuid()` — the same canonical V5-UUID
        // algorithm `create_child` uses, so the bootstrap and
        // child-create paths produce identical FK values for the
        // same `root_tenant_type`. `GtsID::new` additionally
        // validates the chain shape, surfacing
        // `DomainError::InvalidTenantType` early on a malformed
        // configuration rather than at the FK insert.
        let tenant_type_uuid = gts::GtsID::new(self.cfg.root_tenant_type.as_ref())
            .map_err(|e| DomainError::InvalidTenantType {
                detail: format!(
                    "invalid root_tenant_type chain `{}`: {e}",
                    self.cfg.root_tenant_type
                ),
            })?
            .to_uuid();
        let new_root = NewTenant {
            id: self.cfg.root_id,
            parent_id: None,
            name: self.cfg.root_name.clone(),
            self_managed: false,
            tenant_type_uuid,
            depth: 0,
        };
        let inserted = self.repo.insert_provisioning(scope, &new_root).await?;
        // Emit the success counter only after the insert returned
        // `Ok(_)`; emitting before the await would record a phantom
        // success on every `AlreadyExists` race-loser pass.
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "root_creating"), ("outcome", "success")],
        );
        Ok(inserted)
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
        deadline: Instant,
    ) -> Result<TenantModel, DomainError> {
        // The `idp_provisioning` success counter is emitted from
        // `handle_provision_success` after `provision_tenant` returns
        // `Ok`; emitting it here would record a success on every IdP
        // call attempt regardless of outcome.

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
        // Cap the IdP call at the bootstrap deadline so a hung
        // provider cannot stretch `module::init` past
        // `idp_wait_timeout_secs`. Treat a timeout as
        // `IdpUnavailable` after compensating the row — the saga
        // retry loop handles that variant the same way it handles a
        // `CleanFailure`.
        match tokio::time::timeout_at(deadline, self.idp.provision_tenant(&req)).await {
            Ok(Ok(result)) => {
                match self
                    .handle_provision_success(
                        scope,
                        provisioning_root.id,
                        &result.metadata_entries,
                    )
                    .await
                {
                    Ok(activated) => Ok(activated),
                    Err(err) => {
                        // Step-3 (activate_tenant) failed AFTER the IdP
                        // already created the tenant. Mirror the
                        // child-create saga: bound the IdP-side
                        // deprovision attempt by the bootstrap
                        // deadline, then run the local compensation
                        // ONLY if the IdP confirmed cleanup. On any
                        // other outcome (timeout, retryable, terminal,
                        // unsupported) leave the `Provisioning` row in
                        // place so the reaper picks it up — deleting
                        // locally while the vendor tenant is still
                        // alive turns step-3 rollback into an external
                        // orphan with no AM-side handle to clean it up.
                        self.compensate_step3_failure(scope, provisioning_root.id, deadline)
                            .await;
                        Err(err)
                    }
                }
            }
            Ok(Err(failure)) => Err(self
                .handle_provision_failure(scope, provisioning_root.id, failure)
                .await),
            Err(_elapsed) => {
                emit_metric(
                    AM_BOOTSTRAP_LIFECYCLE,
                    MetricKind::Counter,
                    &[
                        ("phase", "failed"),
                        ("classification", "idp_timeout"),
                        ("outcome", "failure"),
                    ],
                );
                // Do NOT compensate on timeout. `tokio::time::timeout_at`
                // only stops *local* waiting; it does not prove the
                // `provision_tenant` request never reached the `IdP` or
                // never completed. Deleting the local Provisioning row
                // here would let the retry loop re-insert and call
                // `provision_tenant` again, potentially duplicating or
                // orphaning vendor-side state when the original request
                // succeeded after the deadline. Treat this like
                // `ProvisionFailure::Ambiguous`: leave the row in place
                // so the provisioning reaper can take ownership and
                // classify it on its own tick.
                warn!(
                    target: "am.bootstrap",
                    root_id = %provisioning_root.id,
                    "bootstrap IdP provision_tenant exceeded the bootstrap deadline; leaving Provisioning row for the reaper (timeout is ambiguous, not a confirmed cancellation)"
                );
                Err(DomainError::IdpUnavailable {
                    detail: "bootstrap IdP provision_tenant timed out".to_owned(),
                })
            }
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
    ) -> Result<TenantModel, DomainError> {
        emit_metric(
            AM_BOOTSTRAP_LIFECYCLE,
            MetricKind::Counter,
            &[("phase", "idp_provisioning"), ("outcome", "success")],
        );
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
        info!(
            target: "am.bootstrap",
            root_id = %activated.id,
            classification = "fresh",
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
    ) -> DomainError {
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
                // The provider `detail` is logged via the
                // `phase=failed` metric label above; the public
                // envelope wraps it in `IdpUnavailable` whose
                // canonical mapping redacts vendor strings before
                // they reach the public Problem body.
                DomainError::IdpUnavailable { detail }
            }
            ProvisionFailure::Ambiguous { detail } => {
                // Leave the provisioning row in place — the reaper
                // compensates per FEATURE §3 step 8.2. Redact the
                // provider detail before placing it in the
                // `Internal::diagnostic` field: that field is
                // exposed verbatim through `CanonicalError::internal`
                // to API callers, so a vendor stack trace or token-
                // bearing string would otherwise leak through. The
                // raw detail is logged via the `phase=failed`
                // counter's classification label and the `am.idp`
                // log channel.
                let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                warn!(
                    target: "am.idp",
                    classification = "ambiguous",
                    detail_digest = digest,
                    detail_len_chars = len,
                    "idp provision returned Ambiguous; provisioning row left for reaper"
                );
                DomainError::internal(format!(
                    "idp provision ambiguous outcome (detail digest: {digest:016x}, len: {len})"
                ))
            }
            ProvisionFailure::UnsupportedOperation { detail } => {
                self.compensate(scope, root_id, "unsupported").await;
                DomainError::UnsupportedOperation { detail }
            }
            other => {
                // SDK marks `ProvisionFailure` as `#[non_exhaustive]`;
                // any new variant added later that hits the bootstrap
                // path with no dedicated AM mapping surfaces as a
                // conservative `Internal` so a failure-mode review is
                // forced before the new variant goes live.
                // Format via `Debug` so the actual variant + payload
                // appear in the diagnostic — `type_name_of_val` only
                // prints the type name (`ProvisionFailure`), which is
                // useless for triage.
                self.compensate(scope, root_id, "unknown").await;
                DomainError::internal(format!(
                    "unknown ProvisionFailure variant in bootstrap saga: {other:?}"
                ))
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
        // `expected_claimed_by = None` selects the saga-compensation
        // fence (`claimed_by IS NULL`): bootstrap holds exclusive
        // ownership of the row up to the IdP call boundary, so the
        // provisioning reaper has not yet had an opportunity to claim
        // it. If the reaper *does* race in (RETENTION_CLAIM_TTL
        // expired during a slow IdP round-trip), the row is left for
        // the reaper to compensate on its own tick.
        if let Err(comp_err) = self
            .repo
            .compensate_provisioning(scope, root_id, None)
            .await
        {
            warn!(
                target: "am.bootstrap",
                error = %comp_err,
                label,
                "bootstrap compensation failed; deferring to reaper"
            );
        }
    }

    /// Compensation for a step-3 (`activate_tenant`) failure that
    /// landed AFTER the `IdP` successfully provisioned the tenant.
    /// Mirrors the child-create saga's step-3 handling, with the
    /// `idp_clean` gate that decides whether the local row deletion
    /// is safe:
    ///
    /// * `Ok(())` / `NotFound` / `UnsupportedOperation` — `IdP`-side
    ///   cleanup is confirmed (or trivially complete because the
    ///   plugin has nothing to manage). The local
    ///   [`Self::compensate`] runs and the row is removed.
    /// * `Terminal` / `Retryable` / unknown variant / deadline
    ///   timeout — the vendor tenant may still exist. Skip the
    ///   local compensation and leave the `Provisioning` row in
    ///   place so the provisioning reaper can take ownership on a
    ///   subsequent tick. Deleting the local row in that state
    ///   would orphan the vendor resource with no AM-side handle to
    ///   reconcile it.
    ///
    /// The deprovision attempt is bounded by the bootstrap deadline
    /// so a hung provider cannot stretch `module::init` past the
    /// configured wall-clock cap.
    #[allow(
        clippy::cognitive_complexity,
        reason = "best-effort step-3 compensation: each DeprovisionFailure variant logs a distinct outcome (clean / unsupported_required / non-clean / timeout) and decides whether to run the local row-delete; collapsing the arms would obscure the per-variant contract that mirrors `TenantService::compensate_failed_activation`"
    )]
    async fn compensate_step3_failure(
        &self,
        scope: &AccessScope,
        root_id: uuid::Uuid,
        deadline: Instant,
    ) {
        let req = DeprovisionRequest { tenant_id: root_id };
        let idp_clean =
            match tokio::time::timeout_at(deadline, self.idp.deprovision_tenant(&req)).await {
                // `Ok(())` confirmed cleanup; `NotFound` is the
                // vendor-side already-absent success-equivalent per
                // the SDK doc — both are unconditionally safe.
                Ok(Ok(()) | Err(DeprovisionFailure::NotFound { .. })) => true,
                Ok(Err(DeprovisionFailure::UnsupportedOperation { .. })) => {
                    // Symmetric with
                    // `TenantService::compensate_failed_activation`:
                    // `UnsupportedOperation` is only safe to treat as
                    // "no IdP-side state retained" when the deployment
                    // explicitly opted out of an `IdP` via
                    // `cfg.idp.required = false` (the wired-in
                    // `NoopProvisioner` path). A real plugin returning
                    // this variant under `idp.required = true` signals
                    // that vendor-side state may exist but the plugin
                    // can't deprovision it — deleting the local row
                    // would orphan that state with no AM-side handle
                    // to reconcile it. Defer to the reaper instead.
                    if self.idp_required {
                        warn!(
                            target: "am.bootstrap",
                            outcome = "unsupported_required",
                            "bootstrap step-3 compensation: IdP plugin returned UnsupportedOperation but idp.required=true; refusing to orphan vendor-side state, leaving Provisioning row for the reaper"
                        );
                        emit_metric(
                            AM_BOOTSTRAP_LIFECYCLE,
                            MetricKind::Counter,
                            &[
                                ("phase", "step3_compensation"),
                                ("classification", "unsupported_required"),
                                ("outcome", "deferred_to_reaper"),
                            ],
                        );
                        false
                    } else {
                        true
                    }
                }
                Ok(Err(deprov_err)) => {
                    // Non-clean variant. `Ok` / `NotFound` /
                    // `UnsupportedOperation` are caught by the prior
                    // arms, so this only reaches `Terminal` /
                    // `Retryable` / a future `#[non_exhaustive]`
                    // variant. Redact the vendor detail before
                    // logging so DSN / hostname / token strings do
                    // not reach the `am.bootstrap` log channel —
                    // mirrors the redaction policy applied in
                    // `handle_provision_failure::Ambiguous`.
                    let label = deprov_err.as_metric_label();
                    let detail = match &deprov_err {
                        DeprovisionFailure::Terminal { detail }
                        | DeprovisionFailure::Retryable { detail } => detail.as_str(),
                        // SDK-side `as_metric_label` is itself an
                        // exhaustive `const fn`, so a new
                        // `DeprovisionFailure` variant is a compile-
                        // time event — this wildcard is dead code
                        // today and only exists as forward-compat
                        // scaffolding for the rare case where a new
                        // variant lands without an SDK rebuild here
                        // (vendored fork, dependency-resolution
                        // skew). Pattern matches the
                        // `reaper::classify_deprovision` and
                        // `retention::process_single_hard_delete`
                        // wildcards.
                        #[allow(
                            unreachable_patterns,
                            reason = "DeprovisionFailure is #[non_exhaustive]; the wildcard guards against future SDK variants"
                        )]
                        _ => "",
                    };
                    let (digest, len) = crate::domain::idp::redact_provider_detail(detail);
                    warn!(
                        target: "am.bootstrap",
                        outcome = label,
                        detail_digest = digest,
                        detail_len_chars = len,
                        "bootstrap step-3 compensation: idp deprovision_tenant returned a non-clean failure; leaving Provisioning row for the reaper"
                    );
                    // Mirror the `AM_BOOTSTRAP_LIFECYCLE` counter
                    // shape used elsewhere in the saga (phase /
                    // classification / outcome): step-3 deprovision
                    // failures are now observable on the same metric
                    // family that already covers `idp_provisioning`,
                    // `idp_waiting`, etc. — operators do not need a
                    // separate dashboard to spot the case where the
                    // saga left a Provisioning row behind because
                    // the IdP returned a non-clean variant.
                    emit_metric(
                        AM_BOOTSTRAP_LIFECYCLE,
                        MetricKind::Counter,
                        &[
                            ("phase", "step3_compensation"),
                            ("classification", label),
                            ("outcome", "deferred_to_reaper"),
                        ],
                    );
                    false
                }
                Err(_elapsed) => {
                    warn!(
                        target: "am.bootstrap",
                        "bootstrap step-3 compensation: idp deprovision_tenant exceeded the bootstrap deadline; leaving Provisioning row for the reaper"
                    );
                    false
                }
            };
        if idp_clean {
            self.compensate(scope, root_id, "step3-failure").await;
        }
    }
}

/// Idempotent skip path — emit the completed-skipped lifecycle metric
/// + info log, then return the existing active root.
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
    info!(
        target: "am.bootstrap",
        root_id = %root.id,
        classification = "skipped",
        "platform-bootstrap saga skipped: root tenant already active"
    );
    root
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-skip-telemetry
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-skip-existing

// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-defer-reaper
// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-defer-telemetry
/// Surface a `Provisioning` root older than `2 × idp_wait_timeout_secs`
/// (the FEATURE-§3 stuck threshold) as a non-success signal: the
/// previous attempt crashed mid-saga, the provisioning reaper will
/// compensate, and module init is NOT complete. Returning an error
/// (rather than `Ok(_)` with the still-Provisioning model) lets the
/// strict-mode init gate in `module::run_bootstrap_phase` decide
/// whether to abort or proceed without an active root.
fn handle_deferred_to_reaper_stuck(root: &TenantModel) -> DomainError {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", "failed"),
            ("classification", "deferred_to_reaper"),
            ("outcome", "failure"),
        ],
    );
    warn!(
        target: "am.bootstrap",
        root_id = %root.id,
        classification = "deferred_to_reaper",
        "platform-bootstrap found stuck provisioning root; reaper will compensate, init not complete"
    );
    DomainError::internal(format!(
        "platform-bootstrap deferred to reaper for stuck provisioning root {} (created_at={}); init not complete",
        root.id, root.created_at
    ))
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-defer-telemetry
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-idempotency:p1:inst-dod-bootstrap-defer-reaper

/// Cap `requested` at the time remaining until `deadline` so the
/// caller never sleeps past its own budget. Returns
/// `Duration::ZERO` if the deadline has already elapsed; the caller
/// is expected to check the deadline immediately after the sleep
/// and surface a timeout.
fn bounded_sleep(requested: Duration, deadline: Instant) -> Duration {
    let remaining = deadline.saturating_duration_since(Instant::now());
    requested.min(remaining)
}

// @cpt-begin:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-invariant-telemetry
fn handle_invariant_violation(observed_status: TenantStatus) -> DomainError {
    emit_metric(
        AM_BOOTSTRAP_LIFECYCLE,
        MetricKind::Counter,
        &[
            ("phase", "failed"),
            ("classification", "invariant_violation"),
            ("outcome", "failure"),
        ],
    );
    DomainError::internal(format!(
        "bootstrap invariant violation: root tenant in unexpected state {observed_status:?}"
    ))
}
// @cpt-end:cpt-cf-account-management-dod-platform-bootstrap-audit-and-metrics:p1:inst-dod-bootstrap-invariant-telemetry

/// Extract `allowed_parent_types` from a flat effective-traits map
/// (the shape returned by `GtsTypeSchema::effective_traits`), which
/// keys traits directly rather than nesting them under
/// `x-gts-traits` / `allOf`.
fn extract_allowed_parent_types_from_effective(
    effective: &serde_json::Value,
) -> Result<Vec<String>, DomainError> {
    let Some(value) = effective.get("allowed_parent_types") else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(DomainError::InvalidTenantType {
            detail: "allowed_parent_types trait must be an array".to_owned(),
        });
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| DomainError::InvalidTenantType {
                    detail: "allowed_parent_types trait must contain only strings".to_owned(),
                })
        })
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "service_tests.rs"]
mod service_tests;
