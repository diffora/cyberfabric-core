//! `UserService` -- domain orchestrator for tenant-scoped `IdP` user
//! operations.
//!
//! Composes a [`crate::domain::tenant::TenantRepo`] tenant-existence
//! guard with the resolved
//! [`account_management_sdk::IdpPluginClient`] plugin to
//! deliver the three flows defined by FEATURE
//! `idp-user-operations-contract`:
//!
//! * `provision_user`  -- `POST /tenants/{tenant_id}/users` (REST drop-in)
//! * `deprovision_user` -- `DELETE /tenants/{tenant_id}/users/{user_id}`
//! * `list_users`      -- `GET /tenants/{tenant_id}/users`
//!
//! Every method:
//!
//! 1. Resolves `tenant_id` via `TenantRepo::find_by_id`.
//! 2. Rejects non-existent tenants with [`DomainError::NotFound`] and
//!    non-`Active` tenants with [`DomainError::Validation`] BEFORE any
//!    `IdP` call is issued, satisfying
//!    `cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation`.
//! 3. Builds a tenant-scope-bound contract request and forwards it to
//!    the configured [`IdpPluginClient`] per
//!    `cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation`.
//! 4. Maps the SDK [`UserOperationFailure`] variants onto
//!    [`DomainError`] via the redacting boundary helper in
//!    [`crate::domain::idp`].
//!
//! `deprovision_user` additionally implements the
//! `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`
//! rule: an `Ok(DeprovisionUserOutcome::NotFoundInTenant)` from the plugin
//! is treated as idempotent success so the DELETE endpoint stays
//! retry-safe per `cpt-cf-account-management-fr-idp-user-deprovision`.
//!
//! The service holds NO storage handles. Per
//! `cpt-cf-account-management-constraint-no-user-storage` AM persists
//! no user table, projection cache, or membership cache; every read
//! and write is a live pass-through to the `IdP`.
// @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-no-local-user-storage:p1:inst-dod-idp-user-operations-contract-no-local-user-storage-service

use std::sync::Arc;

use account_management_sdk::{
    DeprovisionUserOutcome, DeprovisionUserRequest, IdpPluginClient, ListUsersRequest,
    NewUserPayload, ProvisionUserRequest, TenantContext, UserPage, UserPagination, UserProjection,
};
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use types_registry_sdk::TypesRegistryClient;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::idp::UserOperationFailureExt;
use crate::domain::tenant::model::TenantStatus;
use crate::domain::tenant::repo::TenantRepo;

/// Upper bound on `username` length enforced at the AM boundary
/// before the `IdP` round-trip. Matches the `child_tenant_name`
/// bound declared by `m0004_create_conversion_requests` so AM-side
/// length policy stays uniform across the two identifier surfaces.
/// Counts Unicode scalars (`chars().count()`), not bytes — the GTS
/// schema's `maxLength` is also character-counted.
const MAX_USERNAME_CHARS: usize = 255;

/// Upper bound on the secondary profile fields (`email`,
/// `display_name`, `avatar_url`) enforced at the AM boundary as
/// **defence-in-depth fallback** when the
/// `gts.cf.core.am.user.v1~` schema is not registered.
///
/// Unlike the tenant create path (where a missing schema still
/// hits a DB `CHECK (length(name) BETWEEN 1 AND 255)` as the
/// last-line guard), user operations have NO storage-side fallback
/// per `cpt-cf-account-management-constraint-no-user-storage` —
/// AM never persists users. Without these caps, a deployment
/// booting before the user schema is registered would forward
/// arbitrary-length / all-whitespace `email` / `display_name` /
/// `avatar_url` values straight to the `IdP`, turning AM into a
/// proxy that the published GTS contract pretends to validate.
///
/// The cap value matches `MAX_USERNAME_CHARS` so a future schema
/// tightening that lowers any of the per-field `maxLength`s still
/// passes through the AM boundary unchanged (the GTS validator
/// remains authoritative when the schema IS registered).
const MAX_PROFILE_FIELD_CHARS: usize = 255;

/// Central AM domain service for the `IdP` user-operations contract.
///
/// Construction mirrors [`crate::domain::conversion::service::ConversionService`]
/// -- every dependency is passed in as `Arc<dyn ...>` so production
/// wiring (`module.rs`) and tests (`FakeTenantRepo` /
/// `FakeIdpUserProvisioner`) share the same constructor surface. The
/// service holds no clock seam and no batch-size knobs because the
/// FEATURE doc state model is empty (no AM-side lifecycle here -- see
/// the section "States (CDSL): Not applicable").
#[domain_model]
pub struct UserService {
    tenant_repo: Arc<dyn TenantRepo>,
    idp_user: Arc<dyn IdpPluginClient>,
    /// GTS Types Registry client used to fetch the
    /// `gts.cf.core.am.user.v1~` schema at runtime so the structural
    /// contract (length bounds, formats) is enforced from the
    /// published JSON Schema rather than re-hardcoded here. Mirrors
    /// the wiring in `cf-resource-group::validate_metadata_via_gts`.
    types_registry: Arc<dyn TypesRegistryClient>,
}

impl UserService {
    /// Construct a fully-wired service.
    #[must_use]
    pub fn new(
        tenant_repo: Arc<dyn TenantRepo>,
        idp_user: Arc<dyn IdpPluginClient>,
        types_registry: Arc<dyn TypesRegistryClient>,
    ) -> Self {
        Self {
            tenant_repo,
            idp_user,
            types_registry,
        }
    }

    // ----------------------------------------------------------------
    // Provision user
    // ----------------------------------------------------------------

    /// Provision a user in `tenant_id` via the configured `IdP` plugin.
    ///
    /// Implements
    /// `cpt-cf-account-management-flow-idp-user-operations-contract-provision-user`.
    ///
    /// Guard ordering MUST match
    /// `cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation`:
    ///
    /// 1. Load tenant via `tenant_repo.find_by_id`.
    /// 2. Reject `None` with [`DomainError::NotFound`] -- no `IdP` call.
    /// 3. Reject any non-`Active` status with
    ///    [`DomainError::Validation`] -- no `IdP` call.
    /// 4. Forward to [`IdpPluginClient::provision_user`].
    ///
    /// `requested_by` is the principal UUID resolved from the platform
    /// `SecurityContext` at the REST layer; recorded on the outcome
    /// `am.events` line for audit correlation. AM does not validate
    /// the value -- platform `AuthN` is a precondition per
    /// `cpt-cf-account-management-nfr-authentication-context`.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] -- `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] -- tenant exists but is not
    ///   [`TenantStatus::Active`] (provisioning, suspended, deleted).
    /// * [`DomainError::IdpUnavailable`] -- transport failure or
    ///   timeout on the `IdP` call.
    /// * [`DomainError::UnsupportedOperation`] -- provider declined
    ///   the operation.
    /// * [`DomainError::Validation`] -- provider rejected the payload
    ///   (duplicate username, malformed email, etc.).
    /// * [`DomainError::ServiceUnavailable`] -- GTS Types Registry
    ///   transport failure while fetching the
    ///   `gts.cf.core.am.user.v1~` schema; AM cannot validate the
    ///   payload structurally, so the call fails closed rather than
    ///   forwarding an unvalidated payload to the `IdP`.
    // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-service
    pub async fn provision_user(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        mut payload: NewUserPayload,
        requested_by: Uuid,
    ) -> Result<UserProjection, DomainError> {
        // Fail closed on `Uuid::nil()` for the actor field — `requested_by`
        // flows into `am.events` as `actor_uuid` and a default-constructed
        // nil would coalesce every misuse into one audit bucket, hiding
        // the bug from downstream `(event, actor_uuid)` aggregations.
        // Mirrors the repo-side guard in `apply_conversion_approval`.
        if requested_by.is_nil() {
            return Err(DomainError::internal(
                "provision_user: requested_by MUST NOT be Uuid::nil() (service-layer bug)",
            ));
        }
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-puser
        // Tenant existence + status guard runs FIRST so a request
        // against a non-existent / soft-deleted / out-of-scope tenant
        // surfaces as `NotFound` / `Validation` without leaking
        // tenant topology through a payload-shape error. Earlier
        // ordering returned `Validation` for whitespace-only
        // `username` before resolving the tenant — that let an
        // unauthorised caller distinguish "this tenant does not
        // exist" from "this tenant rejects my payload".
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-puser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-resolve-tenant

        // AM business invariants on the username, enforced AFTER the
        // tenant guard so payload-shape feedback never leaks tenant
        // existence, and BEFORE the GTS schema round-trip so the
        // structural validator sees the canonical (trimmed) value:
        //   * Reject all-whitespace / empty — the schema's
        //     `minLength: 1` does not catch `"  "` which is
        //     semantically empty for a login identifier.
        //   * Reject lengths past 255 chars before the IdP round-trip
        //     — matches the `child_tenant_name` bound (`m0004` line
        //     45) so AM caps payload size at the boundary instead of
        //     forwarding megabyte-scale strings to the provider only
        //     to be rejected as `Validation` with a redacted detail.
        //   * Normalise surrounding whitespace — `" alice "` and
        //     `"alice"` MUST resolve to the same provider identity
        //     regardless of the vendor's storage semantics (literal /
        //     auto-trim / hard-reject).
        //
        // # Trim-before-schema ordering is deliberate
        //
        // AM-side trim is the **canonical normalisation** for the
        // username field — the published GTS schema declares
        // structural shape (`minLength` / `maxLength` / format) but
        // delegates whitespace-and-equivalence policy to the AM
        // service layer. If a future schema revision wants to
        // enforce a no-surrounding-whitespace pattern via JSON
        // Schema `pattern`, mirror it as an AM-side pre-trim
        // assertion here instead of inverting the order; the AM-side
        // normalisation MUST stay authoritative because the
        // schema-validation seam is structural-shape only.
        let trimmed = payload.username.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Validation {
                detail: "provision_user: username MUST not be all-whitespace".to_owned(),
            });
        }
        if trimmed.chars().count() > MAX_USERNAME_CHARS {
            return Err(DomainError::Validation {
                detail: format!(
                    "provision_user: username MUST be {MAX_USERNAME_CHARS} characters or fewer"
                ),
            });
        }
        if trimmed.len() != payload.username.len() {
            payload.username = trimmed.to_owned();
        }
        // Defence-in-depth caps on the secondary profile fields.
        // Runs BEFORE the GTS round-trip and is the load-bearing
        // guard when the `gts.cf.core.am.user.v1~` schema is not
        // registered (the helper short-circuits to `Ok(())` in
        // that case — no DB `CHECK` exists for users, so without
        // these AM-side caps a megabyte-scale `email` or a
        // 10MB `avatar_url` would reach the `IdP` verbatim).
        // When the schema IS registered the validator below will
        // ALSO enforce `maxLength` / `format`; this AM-side guard
        // stays for the schema-missing posture (dev/test deploys,
        // boot-before-registry race) and as belt-and-suspenders.
        check_profile_field_bound("email", payload.email.as_deref())?;
        check_profile_field_bound("display_name", payload.display_name.as_deref())?;
        check_profile_field_bound("avatar_url", payload.avatar_url.as_deref())?;
        crate::domain::gts_validation::validate_new_user_payload_via_gts(
            &payload,
            &*self.types_registry,
        )
        .await?;

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-puser
        let req = ProvisionUserRequest::new(tenant_context, payload);
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-puser

        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-puser
        let outcome = self.idp_user.provision_user(&req).await;
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-puser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-invoke-contract

        match outcome {
            Ok(projection) => {
                // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-success-return
                // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-puser
                // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-user-projection-schema:p1:inst-dod-user-projection-schema-puser
                // Response-side schema validation is NOT performed.
                // AM trusts the plugin's published `IdpPluginClient`
                // contract: a successful `Ok(UserProjection)` is, by
                // contract, a schema-conformant projection. Adding an
                // AM-side `validate_user_projection_via_gts` fence
                // here would either (a) fail closed on the entire
                // response when a drifted plugin emits a single bad
                // field — breaking the public surface that callers
                // depend on for existence checks — or (b) silently
                // drop bad rows, which would invent phantom-absent
                // users and corrupt downstream membership state. The
                // input-side gate (`validate_new_user_payload_via_gts`
                // above) keeps AM from forwarding bad payloads; the
                // output-side contract is owned by the plugin.
                // Audit-success line is the ONLY `am.events` emission
                // for this flow; failure-side correlation lives on
                // `am.idp` warn lines emitted by the redaction pipeline
                // in [`UserOperationFailureExt::into_domain_error`]
                // (digest + len + tenant_id). Mirrors the conversion
                // service which also emits `am.events` only on the Ok
                // arm so a downstream consumer grouping by `event`
                // counts successes, not attempts.
                tracing::info!(
                    target: "am.events",
                    event = "user_provisioned",
                    tenant_id = %tenant_id,
                    user_id = %projection.id,
                    actor_uuid = %requested_by,
                    outcome = "ok",
                    "am user provisioned"
                );
                Ok(projection)
                // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-user-projection-schema:p1:inst-dod-user-projection-schema-puser
                // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-puser
                // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-success-return
            }
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-provider-error-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-unavailable-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-unavailable-return
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-provider-error-return
            Err(failure) => Err(failure.into_domain_error(tenant_id)),
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-provider-error-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-unavailable-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-unavailable-branch
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-provider-error-branch
        }
    }
    // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-service

    // ----------------------------------------------------------------
    // Deprovision user
    // ----------------------------------------------------------------

    /// Deprovision `user_id` in `tenant_id` via the configured `IdP`
    /// plugin. Idempotent: an already-absent user returns `Ok(())`.
    ///
    /// Implements
    /// `cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user`
    /// and the
    /// `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`
    /// rule.
    ///
    /// Guard ordering mirrors [`Self::provision_user`]; the additional
    /// idempotency branch fires AFTER the contract returns: only the
    /// success-side `DeprovisionUserOutcome::NotFoundInTenant` qualifies as
    /// absent-equivalent. `Unavailable` and `UnsupportedOperation`
    /// pass through unchanged per
    /// `cpt-cf-account-management-dod-idp-user-operations-contract-deprovision-idempotency`.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] -- `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] -- tenant exists but is not
    ///   [`TenantStatus::Active`].
    /// * [`DomainError::IdpUnavailable`] -- transport failure or
    ///   timeout on the `IdP` call.
    /// * [`DomainError::UnsupportedOperation`] -- provider declined
    ///   the operation.
    /// * [`DomainError::Validation`] -- provider rejected the request.
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 4-arm match (Ok/NotFoundInTenant, Ok/Removed, Ok/forward-compat, Err) carrying paired CPT begin/end markers per arm; collapsing the arms would obscure the idempotency-guard contract reviewers must eyeball-check against the FEATURE doc"
    )]
    // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-service
    pub async fn deprovision_user(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        user_id: Uuid,
        requested_by: Uuid,
    ) -> Result<(), DomainError> {
        // Fail closed on `Uuid::nil()` for the actor field — same
        // rationale as `provision_user`.
        if requested_by.is_nil() {
            return Err(DomainError::internal(
                "deprovision_user: requested_by MUST NOT be Uuid::nil() (service-layer bug)",
            ));
        }
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-duser
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-duser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-resolve-tenant

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-duser
        let req = DeprovisionUserRequest::new(tenant_context, user_id);
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-duser
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-duser
        let outcome = self.idp_user.deprovision_user(&req).await;
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-duser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-invoke-contract

        match outcome {
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-branch
            // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-deprovision-idempotency:p1:inst-dod-deprovision-idempotency-service
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-absent-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotency-check
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotent-return
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-return
            Ok(DeprovisionUserOutcome::NotFoundInTenant) => {
                tracing::info!(
                    target: "am.events",
                    event = "user_deprovisioned",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    actor_uuid = %requested_by,
                    outcome = "already_absent",
                    "am user deprovision idempotent (target absent in tenant scope)"
                );
                Ok(())
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotent-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotency-check
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-absent-branch
            // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-deprovision-idempotency:p1:inst-dod-deprovision-idempotency-service
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-success-return
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-duser
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-branch-removed
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-return-removed
            Ok(DeprovisionUserOutcome::Removed) => {
                // Pass-through "non-absent success" arm of the
                // idempotency guard: caller surfaces 204 No Content
                // exactly as for the idempotent-absent arm above.
                // The `outcome = "ok"` label matches `provision_user`
                // and the `ConversionService` happy-path convention so
                // a downstream audit aggregator grouping by
                // `(event, outcome)` sees `user_deprovisioned/ok` for
                // the genuine-removal case symmetric to
                // `user_provisioned/ok`. The idempotent-absent arm
                // above keeps `outcome = "already_absent"` because
                // that genuinely is a different operational outcome
                // operators may want to alert on independently.
                tracing::info!(
                    target: "am.events",
                    event = "user_deprovisioned",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    actor_uuid = %requested_by,
                    outcome = "ok",
                    "am user deprovisioned"
                );
                Ok(())
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-return-removed
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-branch-removed
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-duser
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-success-return
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-unavailable-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-provider-error-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-unavailable-return
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-provider-error-return
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-branch-failure
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-return-failure
            // Pass-through "non-absent failure" arm of the
            // idempotency guard: error correlation lives on `am.idp`
            // warn lines emitted by [`UserOperationFailureExt::into_domain_error`].
            Err(failure) => Err(failure.into_domain_error(tenant_id)),
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-return-failure
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-other-branch-failure
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-provider-error-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-unavailable-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-provider-error-branch
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-unavailable-branch
            // SDK enum `DeprovisionUserOutcome` is `#[non_exhaustive]`. A
            // new variant added in a future SDK release lands here
            // until the AM-side mapping is updated; surface as
            // `Internal` with a loud `error!` so the gap shows up in
            // operator logs the moment the new variant flows through.
            // The variant identity is intentionally NOT formatted
            // through `Debug` -- a future variant might carry a
            // payload field with vendor text that would bypass the
            // redaction pipeline that protects every other operator-
            // log line on `am.idp`.
            Ok(other) => {
                // `DeprovisionUserOutcome::as_metric_label` returns a
                // stable, snake-case discriminator so a future SDK
                // variant landing here is grep-able (`variant=…`)
                // without requiring a `Debug` format that could leak
                // vendor text past the `am.idp` redaction pipeline.
                let variant = other.as_metric_label();
                tracing::error!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    variant,
                    "unknown DeprovisionUserOutcome variant; mapping conservatively to Internal -- update UserService::deprovision_user"
                );
                Err(DomainError::Internal {
                    diagnostic: format!(
                        "idp deprovision_user returned unknown outcome variant `{variant}` (update UserService::deprovision_user)"
                    ),
                    cause: None,
                })
            }
        }
    }
    // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-service

    // ----------------------------------------------------------------
    // List users
    // ----------------------------------------------------------------

    /// List users in `tenant_id` via the configured `IdP` plugin.
    /// `user_id_filter = Some(_)` is the authoritative existence
    /// signal consumed by sibling features (e.g. `feature-user-groups`).
    ///
    /// Implements
    /// `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] -- `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] -- tenant exists but is not
    ///   [`TenantStatus::Active`].
    /// * [`DomainError::IdpUnavailable`] -- transport failure or
    ///   timeout. NO stale projection is served per
    ///   `cpt-cf-account-management-principle-idp-agnostic`.
    /// * [`DomainError::UnsupportedOperation`] -- provider declined
    ///   the operation.
    /// * [`DomainError::Validation`] -- provider rejected the request.
    // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-service
    pub async fn list_users(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        user_id_filter: Option<Uuid>,
        pagination: UserPagination,
    ) -> Result<UserPage, DomainError> {
        // Tenant existence + status guard runs FIRST so a request
        // against a non-existent / soft-deleted / out-of-scope tenant
        // surfaces as `NotFound` / `Validation` without leaking
        // tenant topology through a pagination-shape error.
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-luser
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-luser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-resolve-tenant

        // When `user_id_filter` is set the call is an authoritative
        // existence check per the SDK doc on
        // `ListUsersRequest::user_id_filter` — both a one-element page
        // and an empty page are success and downstream callers
        // (feature-user-groups membership writes, RBAC mapping) treat
        // the empty page as authoritative absence. Enforce two
        // pagination disciplines at the AM boundary so the
        // existence-check semantics cannot be bypassed:
        //   * `skip` MUST be 0 — a non-zero skip would let the
        //     provider step past the matching row and return an
        //     empty page, turning the lookup into a false negative.
        //   * `top` MUST be 1 — an oversized `top` (e.g. 1000) plus
        //     a filter forwards both to a vendor that ignores the
        //     filter, returning up to `top` unrelated rows; the
        //     downstream `user_id_filter` contract check would then
        //     surface a caller-side bug as `Internal` (HTTP 500)
        //     instead of catching it at the AM seam.
        if user_id_filter.is_some() {
            if pagination.skip() != 0 {
                return Err(DomainError::Validation {
                    detail: "list_users: skip MUST be 0 when user_id_filter is set (filtered \
                        lookup is an authoritative existence check, not a paginated query)"
                        .to_owned(),
                });
            }
            if pagination.top() != 1 {
                return Err(DomainError::Validation {
                    detail: "list_users: top MUST be 1 when user_id_filter is set (filtered \
                        lookup returns at most one row)"
                        .to_owned(),
                });
            }
        }

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-luser
        let req = {
            let base = ListUsersRequest::new(tenant_context, pagination);
            if let Some(uid) = user_id_filter {
                base.with_user_id_filter(uid)
            } else {
                base
            }
        };
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-luser
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-luser
        let outcome = self.idp_user.list_users(&req).await;
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-luser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-invoke-contract

        match outcome {
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-success-return
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-project
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-luser
            Ok(page) => {
                // Plugin-contract validation when `user_id_filter` is set:
                // a buggy provider could echo back unrelated users or
                // multiple rows under a single-user lookup. Downstream
                // callers (existence checks, RBAC mapping) treat the
                // returned page as authoritative, so a contract drift
                // here is a security-relevant correctness bug. Surface
                // any drift as `Internal` rather than silently passing
                // wrong data through.
                if let Some(filter_id) = user_id_filter
                    && (page.items.len() > 1 || page.items.iter().any(|u| u.id != filter_id))
                {
                    let bad_ids: Vec<Uuid> = page.items.iter().map(|u| u.id).collect();
                    tracing::warn!(
                        target: "am.user.audit",
                        tenant_id = %tenant_id,
                        requested_user_id = %filter_id,
                        returned_ids = ?bad_ids,
                        count = page.items.len(),
                        "list_users: provider violated user_id_filter contract"
                    );
                    return Err(DomainError::Internal {
                        diagnostic: format!(
                            "list_users: provider returned {} item(s) for user_id_filter={filter_id}; \
                             expected at most 1 item with matching id",
                            page.items.len()
                        ),
                        cause: None,
                    });
                }
                // Response-side schema validation is NOT performed
                // (mirrors the `provision_user` rationale above): AM
                // trusts the plugin's published projection contract
                // and only enforces the `user_id_filter` discipline
                // here. The asymmetry vs the metadata path
                // (`validate_provision_metadata_entries_via_gts`) is
                // intentional — metadata is persisted into
                // `tenant_metadata` and read back by retention, so
                // bad entries lock in; user projections are
                // pass-through, never persisted, so the cost of
                // fail-closed (breaking the entire listing on a
                // single drifted row) outweighs the protection it
                // offers.
                Ok(page)
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-luser
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-project
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-success-return
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-unavailable-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-unavailable-return
            Err(failure) => Err(failure.into_domain_error(tenant_id)),
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-unavailable-return
            // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-unavailable-branch
        }
    }
    // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-service

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// Resolve `tenant_id` to an [`TenantStatus::Active`] tenant and
    /// build the [`TenantContext`] forwarded to the `IdP` plugin.
    ///
    /// Centralised so each flow shares one tenant guard implementation
    /// and CPT review can verify the precondition once instead of
    /// three times.
    ///
    /// `tenant_type` on the returned context is populated
    /// best-effort: a Types-Registry blip surfaces as `None`
    /// rather than a hard error. Plugins keying off the type
    /// SHOULD treat `None` as "use the provider default" per the
    /// SDK contract on [`TenantContext::tenant_type`].
    async fn resolve_active_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<TenantContext, DomainError> {
        let tenant = self
            .tenant_repo
            .find_by_id(scope, tenant_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
            })?;

        if !matches!(tenant.status, TenantStatus::Active) {
            return Err(DomainError::Validation {
                detail: format!(
                    "tenant {} is not active (status={})",
                    tenant.id,
                    tenant.status.as_str()
                ),
            });
        }

        let tenant_type = self.resolve_tenant_type(tenant.tenant_type_uuid).await;
        Ok(TenantContext::new(tenant.id, tenant.name, tenant_type))
    }

    /// Best-effort `tenant_type_uuid → chained GtsSchemaId` lookup
    /// via the configured Types Registry client. Mirrors
    /// `TenantService::resolve_tenant_type` (in
    /// `tenant/service/mod.rs`): a registry blip surfaces as
    /// `None` rather than failing the user-ops call, because the
    /// `tenant_type` field on [`TenantContext`] is documented as
    /// best-effort and plugins MUST tolerate `None`. Warn on
    /// failure so operators see the same signal the tenant-CRUD
    /// path emits.
    async fn resolve_tenant_type(&self, type_uuid: Uuid) -> Option<gts::GtsSchemaId> {
        match self.types_registry.get_type_schema_by_uuid(type_uuid).await {
            // `schema.type_id` is already a validated typed
            // `GtsSchemaId` from the registry; move it out
            // directly rather than round-tripping through `&str`
            // and `GtsSchemaId::new` (which re-allocates). The
            // sibling `TenantService::resolve_tenant_type` does
            // the round-trip because its return type is
            // `Option<String>` for wire-shape reasons; here the
            // return type is already typed so the move is the
            // zero-allocation equivalent step (the rest of
            // `schema` is dropped here).
            Ok(schema) => Some(schema.type_id),
            Err(err) => {
                tracing::warn!(
                    target: "am.user.service",
                    tenant_type_uuid = %type_uuid,
                    error = %err,
                    "tenant_type uuid -> chained-id resolution failed; TenantContext.tenant_type left as None"
                );
                None
            }
        }
    }
}

/// AM-side fallback length cap for the optional profile fields
/// (`email`, `display_name`, `avatar_url`) on `provision_user`.
/// `None` short-circuits to `Ok(())` because the public schema
/// declares the field optional and AM does not synthesise a value;
/// `Some(value)` is rejected with [`DomainError::Validation`] when
/// the **raw** char-count exceeds [`MAX_PROFILE_FIELD_CHARS`].
///
/// No trim normalisation is applied to these fields (unlike
/// `username`) — vendor profiles differ on whether `email`
/// uniqueness is whitespace-sensitive and `display_name` /
/// `avatar_url` are user-visible labels where surrounding
/// whitespace can be intentional. The cap is therefore on the
/// raw value as supplied; whitespace policy stays the provider's
/// call. The cap alone is enough to prevent megabyte-scale
/// forwards to the `IdP` when the GTS schema is not registered.
fn check_profile_field_bound(
    field_name: &'static str,
    value: Option<&str>,
) -> Result<(), DomainError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > MAX_PROFILE_FIELD_CHARS {
        return Err(DomainError::Validation {
            detail: format!(
                "provision_user: {field_name} MUST be {MAX_PROFILE_FIELD_CHARS} characters or fewer"
            ),
        });
    }
    Ok(())
}
// @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-no-local-user-storage:p1:inst-dod-idp-user-operations-contract-no-local-user-storage-service
