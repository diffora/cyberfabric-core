//! `UserService` -- domain orchestrator for tenant-scoped `IdP` user
//! operations.
//!
//! Composes a [`crate::domain::tenant::TenantRepo`] tenant-existence
//! guard with the resolved
//! [`account_management_sdk::IdpUserProvisionerClient`] plugin to
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
//!    the configured [`IdpUserProvisionerClient`] per
//!    `cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation`.
//! 4. Maps the SDK [`UserOperationFailure`] variants onto
//!    [`DomainError`] via the redacting boundary helper in
//!    [`crate::domain::idp`].
//!
//! `deprovision_user` additionally implements the
//! `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`
//! rule: an `Ok(DeleteUserOutcome::NotFoundInTenant)` from the plugin
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
    CreateUserRequest, DeleteUserOutcome, DeleteUserRequest, IdpUserProvisionerClient,
    ListUsersRequest, NewUserPayload, TenantContext, UserPage, UserPagination, UserProjection,
};
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::idp::UserOperationFailureExt;
use crate::domain::tenant::model::TenantStatus;
use crate::domain::tenant::repo::TenantRepo;

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
    idp_user: Arc<dyn IdpUserProvisionerClient>,
}

impl UserService {
    /// Construct a fully-wired service.
    #[must_use]
    pub fn new(
        tenant_repo: Arc<dyn TenantRepo>,
        idp_user: Arc<dyn IdpUserProvisionerClient>,
    ) -> Self {
        Self {
            tenant_repo,
            idp_user,
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
    /// 4. Forward to [`IdpUserProvisionerClient::create_user`].
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
    // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-service
    pub async fn provision_user(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        payload: NewUserPayload,
        requested_by: Uuid,
    ) -> Result<UserProjection, DomainError> {
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-puser
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-puser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-resolve-tenant

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-puser
        let req = CreateUserRequest {
            tenant_id,
            tenant_context,
            payload,
        };
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-puser

        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-puser
        let outcome = self.idp_user.create_user(&req).await;
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-puser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-invoke-contract

        match outcome {
            Ok(projection) => {
                // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-provision-user:p1:inst-flow-puser-success-return
                // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-success-return-puser
                // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-user-projection-schema:p1:inst-dod-user-projection-schema-puser
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
    /// success-side `DeleteUserOutcome::NotFoundInTenant` qualifies as
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
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-duser
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-duser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-resolve-tenant

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-duser
        let req = DeleteUserRequest {
            tenant_id,
            tenant_context,
            user_id,
        };
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-duser
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-duser
        let outcome = self.idp_user.delete_user(&req).await;
        // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-invoke-duser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-invoke-contract

        match outcome {
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-branch
            // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-deprovision-idempotency:p1:inst-dod-deprovision-idempotency-service
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-absent-branch
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotency-check
            // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-deprovision-user:p1:inst-flow-duser-idempotent-return
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard:p1:inst-algo-dig-absent-return
            Ok(DeleteUserOutcome::NotFoundInTenant) => {
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
            Ok(DeleteUserOutcome::Removed) => {
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
            // SDK enum `DeleteUserOutcome` is `#[non_exhaustive]`. A
            // new variant added in a future SDK release lands here
            // until the AM-side mapping is updated; surface as
            // `Internal` with a loud `error!` so the gap shows up in
            // operator logs the moment the new variant flows through.
            // The variant identity is intentionally NOT formatted
            // through `Debug` -- a future variant might carry a
            // payload field with vendor text that would bypass the
            // redaction pipeline that protects every other operator-
            // log line on `am.idp`.
            Ok(_other) => {
                tracing::error!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    "unknown DeleteUserOutcome variant; mapping conservatively to Internal -- update UserService::deprovision_user"
                );
                Err(DomainError::Internal {
                    diagnostic: "idp delete_user returned unknown outcome variant (update UserService::deprovision_user)"
                        .to_owned(),
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
        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-resolve-tenant
        // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-luser
        let tenant_context = self.resolve_active_tenant(scope, tenant_id).await?;
        // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-authenticated-tenant-scoped-invocation:p1:inst-dod-authenticated-tenant-scoped-invocation-luser
        // @cpt-end:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-resolve-tenant

        // @cpt-begin:cpt-cf-account-management-flow-idp-user-operations-contract-list-users:p1:inst-flow-luser-invoke-contract
        // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-package-request-luser
        let req = ListUsersRequest {
            tenant_id,
            tenant_context,
            user_id_filter,
            pagination,
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
            Ok(page) => Ok(page),
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

        Ok(TenantContext::new(tenant.id, tenant.name))
    }
}
// @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-no-local-user-storage:p1:inst-dod-idp-user-operations-contract-no-local-user-storage-service
