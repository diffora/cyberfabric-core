//! Read-only repo methods over `tenants` + `tenant_closure`:
//! `find_by_id`, `list_children`, `count_children`, `is_descendant`.
//! None of these mutate state; all are scope-checked against the
//! caller's [`AccessScope`] except `is_descendant` which answers a
//! structural closure question and intentionally bypasses the per-row
//! scope (PEP gate is the service-layer guard).

use modkit_db::secure::SecureEntityExt;
use modkit_security::AccessScope;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::tenant::model::{
    ChildCountFilter, ListChildrenQuery, TenantModel, TenantPage, TenantStatus,
};
use crate::infra::storage::entity::{tenant_closure, tenants};

use super::TenantRepoImpl;
use super::helpers::{entity_to_model, id_eq, map_scope_err};

pub(super) async fn find_by_id(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    id: Uuid,
) -> Result<Option<TenantModel>, DomainError> {
    let conn = repo.db.conn()?;
    let row = tenants::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(id_eq(id))
        .one(&conn)
        .await
        .map_err(map_scope_err)?;
    match row {
        Some(r) => Ok(Some(entity_to_model(r)?)),
        None => Ok(None),
    }
}

pub(super) async fn list_children(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    query: &ListChildrenQuery,
) -> Result<TenantPage, DomainError> {
    let conn = repo.db.conn()?;

    // Base filter: parent_id = query.parent_id AND status filter.
    // `None` and `Some(&[])` both fall through to the default
    // SDK-visible set, matching the contract documented on
    // `ListChildrenQuery::status_filter`.
    let status_filter_cond = match query.status_filter() {
        Some(statuses) if !statuses.is_empty() => {
            let mut any_of = Condition::any();
            for s in statuses {
                any_of = any_of.add(tenants::Column::Status.eq(s.as_smallint()));
            }
            any_of
        }
        _ => {
            // Default: active and suspended only. Callers must
            // explicitly request status=deleted to see soft-deleted
            // tenants.
            Condition::any()
                .add(tenants::Column::Status.eq(TenantStatus::Active.as_smallint()))
                .add(tenants::Column::Status.eq(TenantStatus::Suspended.as_smallint()))
        }
    };

    let base = Condition::all()
        .add(tenants::Column::ParentId.eq(query.parent_id))
        .add(status_filter_cond);

    // Stable ordering: (created_at ASC, id ASC) per DESIGN §3.3.
    let items_rows = tenants::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(base.clone())
        .order_by(tenants::Column::CreatedAt, Order::Asc)
        .order_by(tenants::Column::Id, Order::Asc)
        .limit(u64::from(query.top))
        .offset(u64::from(query.skip))
        .all(&conn)
        .await
        .map_err(map_scope_err)?;

    let total: u64 = tenants::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(base)
        .count(&conn)
        .await
        .map_err(map_scope_err)?;

    let mut items = Vec::with_capacity(items_rows.len());
    for r in items_rows {
        items.push(entity_to_model(r)?);
    }

    Ok(TenantPage {
        items,
        top: query.top,
        skip: query.skip,
        total: Some(total),
    })
}

pub(super) async fn count_children(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    parent_id: Uuid,
    filter: ChildCountFilter,
) -> Result<u64, DomainError> {
    let connection = repo.db.conn()?;
    let mut sql_filter = Condition::all().add(tenants::Column::ParentId.eq(parent_id));
    if matches!(filter, ChildCountFilter::NonDeleted) {
        sql_filter =
            sql_filter.add(tenants::Column::Status.ne(TenantStatus::Deleted.as_smallint()));
    }
    tenants::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(sql_filter)
        .count(&connection)
        .await
        .map_err(map_scope_err)
}

pub(super) async fn is_descendant(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    ancestor: Uuid,
    descendant: Uuid,
) -> Result<bool, DomainError> {
    // `is_descendant` answers a structural question — "does the
    // closure carry an `(ancestor, descendant)` row?" — that is
    // scope-independent by construction. `tenant_closure` is
    // `no_tenant/no_resource/no_owner/no_type`, so passing a
    // PDP-narrowed scope through `scope_with` would collapse to
    // `WHERE false` and silently return `false` for valid
    // ancestry edges. The PDP gate at the service layer is what
    // enforces caller scope; this read is the structural truth
    // that gate consults.
    let _ = scope;
    let conn = repo.db.conn()?;
    let count = tenant_closure::Entity::find()
        .secure()
        // TODO(InTenantSubtree): replace with the caller's narrowed
        // scope once the predicate lands. Today every `allow_all` /
        // `scope_unchecked` call site in this crate carries this
        // marker so `rg "TODO(InTenantSubtree)"` greps the full
        // bypass surface in one pass.
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenant_closure::Column::AncestorId.eq(ancestor))
                .add(tenant_closure::Column::DescendantId.eq(descendant)),
        )
        .count(&conn)
        .await
        .map_err(map_scope_err)?;
    Ok(count > 0)
}
