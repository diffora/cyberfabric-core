//! `SeaORM`-backed implementation of [`TenantRepo`].
//!
//! Implementation is split across siblings (`reads`, `lifecycle`,
//! `updates`, `retention`, `helpers`) — each method on the
//! [`TenantRepo`] trait dispatches to a `pub(super)` free function in
//! the matching submodule. The `audit` submodule (integrity classifier
//! dispatch) arrives in a later PR.

mod helpers;
mod lifecycle;
mod reads;
mod retention;
mod updates;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use modkit_db::DBProvider;
use modkit_security::AccessScope;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{
    ChildCountFilter, ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantUpdate,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};

/// Shared alias used by tests.
pub type AmDbProvider = DBProvider<AmError>;

/// `SeaORM` repository adapter for [`TenantRepo`].
pub struct TenantRepoImpl {
    db: Arc<AmDbProvider>,
}

impl TenantRepoImpl {
    #[must_use]
    pub fn new(db: Arc<AmDbProvider>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl TenantRepo for TenantRepoImpl {
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, AmError> {
        reads::find_by_id(self, scope, id).await
    }

    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage, AmError> {
        reads::list_children(self, scope, query).await
    }

    async fn insert_provisioning(
        &self,
        scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, AmError> {
        lifecycle::insert_provisioning(self, scope, tenant).await
    }

    async fn activate_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        closure_rows: &[ClosureRow],
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, AmError> {
        lifecycle::activate_tenant(self, scope, tenant_id, closure_rows, metadata_entries).await
    }

    async fn compensate_provisioning(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), AmError> {
        lifecycle::compensate_provisioning(self, scope, tenant_id).await
    }

    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, AmError> {
        updates::update_tenant_mutable(self, scope, tenant_id, patch).await
    }

    async fn load_ancestor_chain_through_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, AmError> {
        updates::load_ancestor_chain_through_parent(self, scope, parent_id).await
    }

    async fn scan_retention_due(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, AmError> {
        retention::scan_retention_due(self, scope, now, default_retention, limit).await
    }

    async fn clear_retention_claim(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        worker_id: Uuid,
    ) -> Result<(), AmError> {
        retention::clear_retention_claim(self, scope, tenant_id, worker_id).await
    }

    async fn scan_stuck_provisioning(
        &self,
        scope: &AccessScope,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, AmError> {
        retention::scan_stuck_provisioning(self, scope, older_than, limit).await
    }

    async fn count_children(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        filter: ChildCountFilter,
    ) -> Result<u64, AmError> {
        reads::count_children(self, scope, parent_id, filter).await
    }

    async fn schedule_deletion(
        &self,
        scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, AmError> {
        updates::schedule_deletion(self, scope, id, now, retention).await
    }

    async fn hard_delete_one(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, AmError> {
        lifecycle::hard_delete_one(self, scope, id).await
    }

    async fn is_descendant(
        &self,
        scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, AmError> {
        reads::is_descendant(self, scope, ancestor, descendant).await
    }
}
