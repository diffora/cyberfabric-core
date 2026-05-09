//! `TenantResolverPluginClient` implementation backed by AM-owned
//! `tenants` + `tenant_closure`.
//!
//! Each trait method delegates to the matching free function in
//! [`super::queries`], threading both the shared AM `Db` handle and
//! the `TypesRegistryClient` used for `tenant_type` reverse-resolution.
//! Wiring to AM's `init()` is in [`crate::module`].

use std::sync::Arc;

use async_trait::async_trait;
use modkit_db::Db;
use modkit_security::SecurityContext;
use tenant_resolver_sdk::{
    GetAncestorsOptions, GetAncestorsResponse, GetDescendantsOptions, GetDescendantsResponse,
    GetTenantsOptions, IsAncestorOptions, TenantId, TenantInfo, TenantResolverError,
    TenantResolverPluginClient,
};
use types_registry_sdk::TypesRegistryClient;

/// In-process Tenant Resolver plugin co-located with AM.
///
/// Holds a clone of AM's `Db` handle (the plugin shares AM's pool —
/// DESIGN §3.5 calls for a dedicated read-only role, but provisioning
/// that role is an operator concern that lands once we have a
/// connection-pool-per-role abstraction in `modkit-db`) and a
/// `TypesRegistryClient` used by `super::queries` to reverse-resolve
/// `tenant_type_uuid → tenant_type` on every result.
///
/// # `SecurityContext` parameter
///
/// All trait methods accept `_ctx: &SecurityContext` but do not use it
/// directly. Authorization is the gateway's responsibility (DESIGN §4.2
/// "Trust Boundary"): the gateway authenticates the caller and decides
/// whether to forward the request to the plugin; the plugin trusts that
/// projection and reads from storage unconditionally under
/// `AccessScope::allow_all()`. The `_ctx` prefix signals this intentional
/// delegation rather than an accidental omission.
pub struct PluginImpl {
    /// Shared `Db` handle. `Db` is `Clone` (Arc-backed) so this is
    /// cheap; `Arc<Db>` is intentional here so the plugin can be
    /// stored behind `Arc<dyn TenantResolverPluginClient>` without a
    /// further indirection on each call.
    db: Arc<Db>,
    /// Types Registry client used to reverse-resolve
    /// `tenant_type_uuid → tenant_type` (DESIGN §3.4). Per the
    /// availability table in DESIGN §5, a registry failure surfaces
    /// as [`TenantResolverError::Internal`] (logged server-side via
    /// `tracing::warn`); the plugin must NOT return raw UUIDs in
    /// place of the public chained `tenant_type`. This is a
    /// deliberate divergence from AM's own
    /// `service::resolve_tenant_type` (which falls back to
    /// `tenant_type: None`) — see `super::queries` for the actual
    /// fail-closed policy.
    types_registry: Arc<dyn TypesRegistryClient>,
}

impl PluginImpl {
    /// Build the plugin from AM's already-resolved dependencies.
    ///
    /// Called from `AccountManagementModule::init` after the AM
    /// `TypesRegistryClient` and `Db` have been resolved from
    /// `ClientHub` / `ModuleCtx` respectively.
    #[must_use]
    pub fn new(db: Db, types_registry: Arc<dyn TypesRegistryClient>) -> Self {
        Self {
            db: Arc::new(db),
            types_registry,
        }
    }
}

#[async_trait]
impl TenantResolverPluginClient for PluginImpl {
    async fn get_tenant(
        &self,
        _ctx: &SecurityContext,
        id: TenantId,
    ) -> Result<TenantInfo, TenantResolverError> {
        super::queries::get_tenant(&self.db, &self.types_registry, id).await
    }

    async fn get_root_tenant(
        &self,
        _ctx: &SecurityContext,
    ) -> Result<TenantInfo, TenantResolverError> {
        super::queries::get_root_tenant(&self.db, &self.types_registry).await
    }

    async fn get_tenants(
        &self,
        _ctx: &SecurityContext,
        ids: &[TenantId],
        options: &GetTenantsOptions,
    ) -> Result<Vec<TenantInfo>, TenantResolverError> {
        super::queries::get_tenants(&self.db, &self.types_registry, ids, &options.status).await
    }

    async fn get_ancestors(
        &self,
        _ctx: &SecurityContext,
        id: TenantId,
        options: &GetAncestorsOptions,
    ) -> Result<GetAncestorsResponse, TenantResolverError> {
        super::queries::get_ancestors(&self.db, &self.types_registry, id, options.barrier_mode)
            .await
    }

    async fn get_descendants(
        &self,
        _ctx: &SecurityContext,
        id: TenantId,
        options: &GetDescendantsOptions,
    ) -> Result<GetDescendantsResponse, TenantResolverError> {
        super::queries::get_descendants(
            &self.db,
            &self.types_registry,
            id,
            options.barrier_mode,
            &options.status,
            options.max_depth,
        )
        .await
    }

    async fn is_ancestor(
        &self,
        _ctx: &SecurityContext,
        ancestor_id: TenantId,
        descendant_id: TenantId,
        options: &IsAncestorOptions,
    ) -> Result<bool, TenantResolverError> {
        super::queries::is_ancestor(&self.db, ancestor_id, descendant_id, options.barrier_mode)
            .await
    }
}
