//! `IdP` user-operations contract.
//!
//! Sibling of [`crate::idp`] (tenant-side). Defines the trait surface
//! and DTOs that deployment-specific `IdP` plugins implement and that
//! AM consumes through `ClientHub` to provision, deprovision, and list
//! users in a tenant scope. Users are NOT modelled in AM storage per
//! `cpt-cf-account-management-constraint-no-user-storage` -- every call
//! is a live pass-through to the resolved provider plugin.
//!
//! # Trait surface
//!
//! [`IdpUserProvisionerClient`] carries three methods:
//!
//! * [`IdpUserProvisionerClient::create_user`] -- provision a user in
//!   a tenant scope; returns the `IdP`-assigned [`UserProjection`].
//! * [`IdpUserProvisionerClient::delete_user`] -- deprovision a user
//!   in a tenant scope; returns a [`DeleteUserOutcome`] that
//!   distinguishes `Removed` from `NotFoundInTenant` so AM's
//!   service layer can implement the
//!   `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`
//!   absent-is-success rule.
//! * [`IdpUserProvisionerClient::list_users`] -- enumerate users in a
//!   tenant scope (with optional single-user filter and pagination);
//!   returns a [`UserPage`] of projections.
//!
//! # User projection schema
//!
//! [`UserProjection`] mirrors the published GTS schema
//! `gts.cf.core.am.user.v1~` declared in
//! `modules/system/account-management/docs/schemas/user.v1.schema.json`.
//! The shape is intentionally tenant-minimal: no credentials, no
//! `IdP`-internal identifiers, no membership cache. Provider plugins
//! project only profile-like fields the `IdP` exposes.
//!
//! # Failure model
//!
//! [`UserOperationFailure`] discriminates between the categories AM's
//! service layer maps onto the public error envelope:
//!
//! * [`UserOperationFailure::Unavailable`] -- transport failure or
//!   timeout; AM surfaces `idp_unavailable` per
//!   `cpt-cf-account-management-dod-idp-user-operations-contract-idp-unavailability-contract`.
//!   AM holds NO fallback projection, so `list_users` during an outage
//!   returns the envelope-mapped error rather than a stale page.
//! * [`UserOperationFailure::UnsupportedOperation`] -- provider
//!   declines a mutating operation (read-only / legacy provider). AM
//!   surfaces `idp_unsupported_operation`. Providers MUST NOT silently
//!   no-op a mutating call; surface the variant explicitly.
//! * [`UserOperationFailure::Rejected`] -- provider returned a
//!   payload-rejection category (e.g. duplicate username, malformed
//!   email). AM surfaces a generic validation envelope; the canonical
//!   error catalog is owned by `feature-errors-observability` (sibling
//!   feature) and may refine the mapping in a follow-up.
//!
//! `provider_detail` strings carried by the failure variants are
//! routed through AM's redaction pipeline before reaching public
//! envelopes (see `cf-account-management::domain::idp` for the
//! `into_domain_error` boundary). Plugin authors do not need to redact
//! themselves -- they pass the raw vendor text and AM owns the public-
//! surface mapping.
//!
//! # `ClientHub` registration
//!
//! Plugins register themselves in `ClientHub` as
//! `Arc<dyn IdpUserProvisionerClient>`; AM's module entry-point
//! resolves the plugin via
//! `ctx.client_hub().get::<dyn IdpUserProvisionerClient>()` and falls
//! back to a noop provisioner when no plugin is registered (dev / test
//! deployments). The fallback returns
//! [`UserOperationFailure::UnsupportedOperation`] on every method.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Provider-defined non-authoritative attributes carried on the
/// `gts.cf.core.am.user.v1~` projection. The published JSON Schema
/// declares the field as `{"type": "object",
/// "additionalProperties": true}`; using a typed map here makes a
/// non-object payload (integer / array / string) unrepresentable at
/// the SDK boundary so plugin authors cannot accidentally emit a
/// shape that violates the schema.
///
/// `BTreeMap` is chosen over `serde_json::Map` so the iteration
/// order is deterministic, which matters for golden-file tests and
/// stable digests on the redaction pipeline.
pub type UserAttributes = BTreeMap<String, Value>;

/// Resolved tenant context surfaced to provider plugins so they can
/// resolve `IdP`-specific identifiers (effective Keycloak realm, Zitadel
/// organization, etc.).
///
/// AM resolves the tenant via `TenantService` before invoking the
/// contract; the resolved fields are forwarded here so the plugin does
/// not have to round-trip back to AM for tenant metadata it could have
/// received inline. The shape is deliberately slim: `tenant_id` and
/// `tenant_name` are sufficient for every provider profile observed in
/// DESIGN section 4.1; richer context (tenant type, opaque metadata)
/// can be added without breaking change because the struct is
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TenantContext {
    /// Stable tenant identifier (the same UUID stored in AM's
    /// `tenants.id` column).
    pub tenant_id: Uuid,
    /// Human-readable tenant name, useful for plugins that derive
    /// provider-side identifiers from the tenant label (e.g. a
    /// Keycloak realm whose name follows the tenant slug).
    pub tenant_name: String,
}

impl TenantContext {
    /// Build a [`TenantContext`] from the resolved tenant id and name.
    #[must_use]
    pub fn new(tenant_id: Uuid, tenant_name: impl Into<String>) -> Self {
        Self {
            tenant_id,
            tenant_name: tenant_name.into(),
        }
    }
}

/// Profile-minimal payload accepted by
/// [`IdpUserProvisionerClient::create_user`].
///
/// Shape mirrors the published `gts.cf.core.am.user.v1~` projection
/// minus the `IdP`-issued `id` (the provider assigns it on success) and
/// minus `attributes` flowing in the opposite direction (provider may
/// return them on the projection but AM does not synthesize them on
/// the create path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUserPayload {
    /// Login identifier (REQUIRED per the published schema). The
    /// provider enforces uniqueness within its tenant scope; AM
    /// neither caches nor validates the value beyond non-empty.
    pub username: String,
    /// Optional contact email surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional avatar URL surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded verbatim into the `IdP` create call. AM does not
    /// inspect or transform these. Typed as a string-keyed map so
    /// non-object payloads are unrepresentable at the SDK boundary
    /// per the published schema's `{"type": "object"}` declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

/// User projection matching the published GTS schema
/// `gts.cf.core.am.user.v1~`.
///
/// The shape is the contract for downstream consumers (e.g.
/// `feature-user-groups` membership existence checks, audit pipeline).
/// No `IdP`-internal identifier, credential, or membership cache is
/// included per `cpt-cf-account-management-adr-idp-user-identity-source-of-truth`
/// and `cpt-cf-account-management-adr-idp-user-tenant-binding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProjection {
    /// `IdP`-issued UUID user identifier. The provider owns the issuance
    /// and the value is stable across the user's lifetime in this
    /// tenant scope.
    pub id: Uuid,
    /// Login identifier (REQUIRED per the schema).
    pub username: String,
    /// Optional contact email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional avatar URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded from the `IdP`. Opaque to AM. Typed as a string-keyed
    /// map so non-object payloads are unrepresentable at the SDK
    /// boundary per the published schema's `{"type": "object"}`
    /// declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

/// Pagination parameters for [`IdpUserProvisionerClient::list_users`].
///
/// Mirrors the `top`/`skip` convention used by
/// `account_management_sdk::ListChildrenQuery` so REST handlers can
/// translate the same query parameters without reshaping the values.
///
/// Field visibility encodes the `top > 0` invariant:
/// * `top` is private. Construction goes through [`UserPagination::new`]
///   (which validates `top > 0`) or [`UserPagination::default`] (which
///   returns [`UserPagination::DEFAULT_TOP`] = 50). Read via
///   [`UserPagination::top`].
/// * `skip` is public; zero is a valid value.
///
/// `top = 0` would otherwise turn a tenant-scoped existence check
/// (`?user_id=<id>` -- `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`)
/// into a false-negative empty page on providers that honor the
/// literal value, since AM cannot disambiguate "user absent" from
/// "page size was zero".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RawUserPagination")]
#[non_exhaustive]
pub struct UserPagination {
    top: u32,
    /// Number of items to skip before the first returned row.
    pub skip: u32,
}

impl UserPagination {
    /// Default page size used by [`UserPagination::default`]. Chosen
    /// to match the AM tenant-CRUD listing default and stay below the
    /// `OpenAPI Top.maximum` typical value of 200.
    pub const DEFAULT_TOP: u32 = 50;

    /// Construct a validated pagination.
    ///
    /// # Errors
    ///
    /// Returns [`UserPaginationError::TopMustBePositive`] when `top`
    /// is zero.
    pub const fn new(top: u32, skip: u32) -> Result<Self, UserPaginationError> {
        if top == 0 {
            return Err(UserPaginationError::TopMustBePositive);
        }
        Ok(Self { top, skip })
    }

    /// Read-only access to the validated `top`. Always `>= 1` per the
    /// constructor invariant.
    #[must_use]
    pub const fn top(self) -> u32 {
        self.top
    }
}

impl Default for UserPagination {
    fn default() -> Self {
        Self {
            top: Self::DEFAULT_TOP,
            skip: 0,
        }
    }
}

/// Wire shape for [`UserPagination`] deserialization. Mirrors the
/// public fields but skips the `top > 0` invariant -- the
/// [`TryFrom<RawUserPagination>`] impl below routes the value
/// through [`UserPagination::new`] so the invariant is enforced on
/// every serde input path, not just constructor calls.
#[derive(Debug, Clone, Deserialize)]
struct RawUserPagination {
    top: u32,
    #[serde(default)]
    skip: u32,
}

impl TryFrom<RawUserPagination> for UserPagination {
    type Error = UserPaginationError;

    fn try_from(raw: RawUserPagination) -> Result<Self, Self::Error> {
        Self::new(raw.top, raw.skip)
    }
}

/// Validation errors reported by [`UserPagination::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserPaginationError {
    /// `top` was zero; the user-list contract treats `top` as a
    /// strict positive page size so an existence-check filter cannot
    /// silently return an empty page.
    TopMustBePositive,
}

impl core::fmt::Display for UserPaginationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TopMustBePositive => f.write_str("top must be at least 1"),
        }
    }
}

impl core::error::Error for UserPaginationError {}

/// Page envelope returned by [`IdpUserProvisionerClient::list_users`].
///
/// Mirrors `account_management_sdk::TenantPage<T>` but is specialised
/// to [`UserProjection`] so plugin authors do not need to depend on
/// the tenant CRUD shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserPage {
    pub items: Vec<UserProjection>,
    pub top: u32,
    pub skip: u32,
    /// Total count of matching rows when the provider can return it
    /// cheaply; left `None` if the provider does not expose a total
    /// for the underlying directory query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl UserPage {
    /// Construct a fresh `UserPage`. The `#[non_exhaustive]` marker
    /// requires plugin authors to use this constructor (or struct-
    /// update syntax with `..Default::default()` if a future field
    /// has a default) so future additions (e.g. `cursor`,
    /// `has_more`) are SemVer-safe.
    #[must_use]
    pub const fn new(items: Vec<UserProjection>, top: u32, skip: u32, total: Option<u64>) -> Self {
        Self {
            items,
            top,
            skip,
            total,
        }
    }
}

/// Request shape for [`IdpUserProvisionerClient::create_user`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// Tenant scope the user is being provisioned into. AM has
    /// already validated the scope is `Active` before invoking the
    /// contract.
    pub tenant_id: Uuid,
    /// Resolved tenant context used by plugins that derive
    /// provider-side identifiers from tenant attributes.
    pub tenant_context: TenantContext,
    /// Profile-minimal payload to forward into the `IdP`.
    pub payload: NewUserPayload,
}

/// Request shape for [`IdpUserProvisionerClient::delete_user`].
///
/// Carries the resolved tenant context so plugins that derive
/// provider-side identifiers from tenant attributes (effective
/// Keycloak realm, Zitadel organization) receive the same metadata
/// on every contract method per
/// `cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation`
/// step `package-request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserRequest {
    pub tenant_id: Uuid,
    pub tenant_context: TenantContext,
    pub user_id: Uuid,
}

/// Request shape for [`IdpUserProvisionerClient::list_users`].
///
/// Carries the resolved tenant context (see [`DeleteUserRequest`]
/// for the algo-step rationale).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersRequest {
    pub tenant_id: Uuid,
    pub tenant_context: TenantContext,
    /// Optional single-user filter. When `Some`, the provider returns
    /// either a one-element page (the user exists in this tenant
    /// scope) or an empty page (the user is absent). Both outcomes
    /// are success per
    /// `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`.
    pub user_id_filter: Option<Uuid>,
    pub pagination: UserPagination,
}

/// Outcome of [`IdpUserProvisionerClient::delete_user`] on the success
/// path.
///
/// Splitting the success path into two variants (instead of folding
/// `NotFoundInTenant` into [`UserOperationFailure`]) keeps the trait
/// contract aligned with `algo-deprovision-idempotency-guard`: only
/// the absent outcome is an idempotent success, and an `Err(_)` from
/// the trait method is unambiguously a real failure (transport,
/// unsupported, rejected). AM's service layer maps
/// `Ok(NotFoundInTenant)` to `Ok(())` so `DELETE
/// /tenants/{tenant_id}/users/{user_id}` stays retry-safe per
/// `cpt-cf-account-management-fr-idp-user-deprovision`.
///
/// # Adding a variant
///
/// `#[non_exhaustive]` lets new outcomes ship in a minor SDK release
/// without breaking compilation, BUT every existing `AM`-side
/// mapping (`UserService::deprovision_user`) treats unknown
/// variants as a loud `DomainError::Internal` rather than silently
/// mapping to success or failure — the deprovision idempotency
/// guard cannot classify a new outcome's safety properties without
/// an explicit `AM`-side review. A new variant added here therefore
/// REQUIRES a matching `cf-account-management` patch landing in the
/// same release; deploying the SDK without the `AM` update will
/// surface HTTP 500 on the new path even when the `IdP` plugin
/// returns it as a success-shaped value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteUserOutcome {
    /// The user existed in this tenant scope and the `IdP` removed it.
    Removed,
    /// The user was already absent in this tenant scope. AM treats
    /// this as idempotent success (HTTP 204) per
    /// `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`.
    NotFoundInTenant,
}

/// Failure discriminant shared by every user-operations contract
/// method.
///
/// AM's service layer maps each variant onto the canonical error
/// taxonomy via `cf-account-management::domain::idp` (the redaction +
/// public-envelope boundary). Plugin authors do not need to redact
/// `detail` themselves -- AM owns the public-surface mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserOperationFailure {
    /// Provider was unreachable, the call timed out, or the transport
    /// returned a retryable failure. AM maps this to the public
    /// `idp_unavailable` code; no fallback projection is served per
    /// `cpt-cf-account-management-constraint-no-user-storage`.
    Unavailable { detail: String },
    /// Provider declined the operation in its current implementation
    /// profile (typically a read-only or legacy provider that does
    /// not support mutating user operations). AM maps this to
    /// `idp_unsupported_operation`. Providers MUST NOT silently no-op
    /// a mutating call.
    UnsupportedOperation { detail: String },
    /// Provider returned a payload-rejection category (e.g. duplicate
    /// username, validation failure on email format). AM maps this to
    /// the canonical validation envelope; the catalog refinement is
    /// owned by `feature-errors-observability`.
    Rejected { detail: String },
}

impl UserOperationFailure {
    /// Stable, snake-case metric-label form of this variant. Used by
    /// AM-side observability when emitting per-call outcome metrics
    /// (the metric catalog itself is owned by
    /// `feature-errors-observability`); kept on the SDK type so
    /// producers do not duplicate the variant -> string mapping in
    /// match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "unavailable",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::Rejected { .. } => "rejected",
        }
    }
}

/// Trait implemented by the deployment-specific `IdP` user-operations
/// plugin.
///
/// # Retry, backoff, and rate-limiting are owned by the plugin
///
/// AM does NOT wrap calls into this trait in retry loops, exponential
/// backoff, jittered scheduling, or circuit-breakers. Each AM call
/// site issues exactly one invocation per logical request from the
/// public REST surface (or future inter-module SDK caller). Plugins
/// MUST own their transport-level resilience: retries with vendor-
/// appropriate backoff, ratelimit handling, and circuit breaking
/// after sustained failure.
///
/// # No silent no-op on mutating calls
///
/// `create_user` and `delete_user` MUST NOT silently no-op. A provider
/// that cannot perform a mutating operation MUST return
/// [`UserOperationFailure::UnsupportedOperation`] so AM surfaces
/// `idp_unsupported_operation` (HTTP 501) per PRD section 5.5 and
/// DESIGN section 3.8.
///
/// # `ClientHub` registration
///
/// Plugins register themselves in `ClientHub` as
/// `Arc<dyn IdpUserProvisionerClient>`; AM's module entry-point
/// resolves the plugin via
/// `ctx.client_hub().get::<dyn IdpUserProvisionerClient>()` and falls
/// back to a noop provisioner when no plugin is registered.
// @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-contract-trait-surface:p1:inst-dod-idp-user-operations-contract-trait-surface
#[async_trait]
pub trait IdpUserProvisionerClient: Send + Sync + 'static {
    /// Provision a user in the supplied tenant scope.
    ///
    /// On success the provider returns the `IdP`-assigned
    /// [`UserProjection`] (the `id` field is the authoritative,
    /// `IdP`-issued user UUID).
    ///
    /// # Errors
    ///
    /// Returns [`UserOperationFailure`] for transport failure,
    /// unsupported-operation, or payload rejection per the trait-
    /// level documentation.
    async fn create_user(
        &self,
        req: &CreateUserRequest,
    ) -> Result<UserProjection, UserOperationFailure>;

    /// Deprovision a user in the supplied tenant scope. Removes any
    /// active sessions where the provider supports session
    /// revocation.
    ///
    /// Returns a [`DeleteUserOutcome`] that distinguishes a real
    /// removal (`Removed`) from an already-absent target
    /// (`NotFoundInTenant`). AM's service layer maps
    /// `NotFoundInTenant` to an idempotent success per
    /// `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`.
    ///
    /// # Errors
    ///
    /// Returns [`UserOperationFailure::Unavailable`] on transport
    /// failure or timeout; [`UserOperationFailure::UnsupportedOperation`]
    /// when the provider does not support user deprovisioning;
    /// [`UserOperationFailure::Rejected`] for any other provider-
    /// returned error category.
    async fn delete_user(
        &self,
        req: &DeleteUserRequest,
    ) -> Result<DeleteUserOutcome, UserOperationFailure>;

    /// List users in the supplied tenant scope, optionally filtered to
    /// a single `user_id`. Pagination follows the `top`/`skip`
    /// convention.
    ///
    /// A `user_id_filter = Some(_)` returning an empty page is the
    /// authoritative existence signal AM consumes for downstream
    /// features (e.g. `feature-user-groups` membership checks); both
    /// the one-element and empty outcomes are success.
    ///
    /// # Errors
    ///
    /// Returns [`UserOperationFailure::Unavailable`] on transport
    /// failure or timeout; AM does NOT serve a stale projection when
    /// the provider is unavailable.
    async fn list_users(&self, req: &ListUsersRequest) -> Result<UserPage, UserOperationFailure>;
}
// @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-contract-trait-surface:p1:inst-dod-idp-user-operations-contract-trait-surface

#[cfg(test)]
#[path = "idp_user_tests.rs"]
mod tests;
