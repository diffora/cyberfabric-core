//! Tenant-row lifecycle writes that maintain the `tenant_closure`
//! invariant on create/destroy:
//! `insert_provisioning`, `activate_tenant`,
//! `compensate_provisioning`, `hard_delete_one`. All transactional
//! writes go through [`super::helpers::with_serializable_retry`] under
//! `SERIALIZABLE` isolation per AC#15.

use modkit_db::secure::{
    DbTx, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureUpdateExt, is_unique_violation,
};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::retention::HardDeleteOutcome;
use crate::infra::storage::entity::{tenant_closure, tenant_metadata, tenants};

use super::TenantRepoImpl;
use super::helpers::{
    entity_to_model, id_eq, map_scope_err, schema_uuid_from_gts_id, with_serializable_retry,
};

pub(super) async fn insert_provisioning(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant: &NewTenant,
) -> Result<TenantModel, AmError> {
    use sea_orm::ActiveValue;
    let conn = repo.db.conn()?;
    let now = OffsetDateTime::now_utc();
    let am = tenants::ActiveModel {
        id: ActiveValue::Set(tenant.id),
        parent_id: ActiveValue::Set(tenant.parent_id),
        name: ActiveValue::Set(tenant.name.clone()),
        status: ActiveValue::Set(TenantStatus::Provisioning.as_smallint()),
        self_managed: ActiveValue::Set(tenant.self_managed),
        tenant_type_uuid: ActiveValue::Set(tenant.tenant_type_uuid),
        depth: ActiveValue::Set(i32::try_from(tenant.depth).map_err(|_| {
            AmError::Internal {
                diagnostic: format!("depth overflow: {}", tenant.depth),
                cause: None,
            }
        })?),
        created_at: ActiveValue::Set(now),
        updated_at: ActiveValue::Set(now),
        deleted_at: ActiveValue::Set(None),
        deletion_scheduled_at: ActiveValue::Set(None),
        retention_window_secs: ActiveValue::Set(None),
        claimed_by: ActiveValue::Set(None),
        claimed_at: ActiveValue::Set(None),
    };
    // scope_unchecked: `tenants.tenant_col = "id"` so `scope_with` would
    // require an existing row with that id — there is none yet on INSERT.
    // The caller always passes `allow_all` (PEP gate is the real guard).
    let model: tenants::Model = tenants::Entity::insert(am)
        .secure()
        .scope_unchecked(scope)
        .map_err(map_scope_err)?
        .exec_with_returning(&conn)
        .await
        .map_err(|e| match e {
            modkit_db::secure::ScopeError::Db(ref db) if is_unique_violation(db) => {
                AmError::Conflict {
                    detail: format!("tenant {} already exists", tenant.id),
                }
            }
            other => map_scope_err(other),
        })?;
    entity_to_model(model)
}

pub(super) async fn activate_tenant(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    closure_rows: &[ClosureRow],
    metadata_entries: &[ProvisionMetadataEntry],
) -> Result<TenantModel, AmError> {
    let rows = closure_rows.to_vec();
    let metadata_entries = metadata_entries.to_vec();
    let scope = scope.clone();
    let result = with_serializable_retry(&repo.db, move || {
        let scope = scope.clone();
        let rows = rows.clone();
        let metadata_entries = metadata_entries.clone();
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                use sea_orm::ActiveValue;

                let existing = tenants::Entity::find()
                    .secure()
                    .scope_with(&scope)
                    .filter(id_eq(tenant_id))
                    .one(tx)
                    .await
                    .map_err(map_scope_err)?
                    .ok_or_else(|| AmError::NotFound {
                        detail: format!("tenant {tenant_id} not found for activation"),
                    })?;

                if existing.status != TenantStatus::Provisioning.as_smallint() {
                    return Err(AmError::Conflict {
                        detail: format!("tenant {tenant_id} not in provisioning state"),
                    });
                }

                // Defense-in-depth: validate the closure-row slice
                // matches the contract documented on
                // `TenantRepo::activate_tenant`. The slice is supposed
                // to come from `build_activation_rows` (which has its
                // own asserts), but flipping `status -> Active`
                // before the closure insert means a malformed slice
                // would persist a half-active tenant — leaf-row
                // missing or wrong-descendant rows would surface only
                // through a later integrity classifier. Fail fast
                // before the status flip so the saga compensation
                // path can run cleanly.
                if rows.is_empty()
                    || !rows
                        .iter()
                        .any(|r| r.ancestor_id == tenant_id && r.descendant_id == tenant_id)
                    || rows.iter().any(|r| r.descendant_id != tenant_id)
                {
                    return Err(AmError::Internal {
                        diagnostic: format!(
                            "activate_tenant received malformed closure rows for tenant {tenant_id}: \
                             rows must be non-empty, contain exactly one self-row \
                             ({tenant_id},{tenant_id}), and every row's descendant_id must equal {tenant_id}"
                        ),
                        cause: None,
                    });
                }

                // Flip status -> Active + bump updated_at via SecureUpdateMany.
                let now = OffsetDateTime::now_utc();
                let rows_affected = tenants::Entity::update_many()
                    .col_expr(
                        tenants::Column::Status,
                        Expr::value(TenantStatus::Active.as_smallint()),
                    )
                    .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                    .filter(id_eq(tenant_id))
                    .secure()
                    .scope_with(&scope)
                    .exec(tx)
                    .await
                    .map_err(map_scope_err)?
                    .rows_affected;
                if rows_affected == 0 {
                    return Err(AmError::NotFound {
                        detail: format!("tenant {tenant_id} missing during activation"),
                    });
                }

                // Insert closure rows in a single multi-row INSERT.
                // SeaORM `Entity::insert_many` returns the same
                // `Insert<A>` builder the secure wrapper extends,
                // so we keep the secure-execution path while
                // collapsing depth-N RT into one. The closure
                // entity is declared with `no_tenant, no_resource,
                // no_owner, no_type` — closure rows are
                // cross-tenant by definition — so `scope_unchecked`
                // is the appropriate scope mode (matches the
                // single-row insert path immediately above the
                // refactor).
                if !rows.is_empty() {
                    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                    let active_models = rows.iter().map(|row| tenant_closure::ActiveModel {
                        ancestor_id: ActiveValue::Set(row.ancestor_id),
                        descendant_id: ActiveValue::Set(row.descendant_id),
                        barrier: ActiveValue::Set(row.barrier),
                        descendant_status: ActiveValue::Set(row.descendant_status),
                    });
                    tenant_closure::Entity::insert_many(active_models)
                        .secure()
                        .scope_unchecked(&scope)
                        .map_err(map_scope_err)?
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                }

                if !metadata_entries.is_empty() {
                    let metadata_rows =
                        metadata_entries.iter().map(|entry| tenant_metadata::ActiveModel {
                            tenant_id: ActiveValue::Set(tenant_id),
                            schema_uuid: ActiveValue::Set(schema_uuid_from_gts_id(
                                &entry.schema_id,
                            )),
                            value: ActiveValue::Set(entry.value.clone()),
                            created_at: ActiveValue::Set(now),
                            updated_at: ActiveValue::Set(now),
                        });
                    tenant_metadata::Entity::insert_many(metadata_rows)
                        .secure()
                        .scope_unchecked(&scope)
                        .map_err(map_scope_err)?
                        .exec(tx)
                        .await
                        .map_err(|e| match e {
                            modkit_db::secure::ScopeError::Db(ref db)
                                if is_unique_violation(db) =>
                            {
                                AmError::Conflict {
                                    detail: format!(
                                        "tenant {tenant_id} metadata contains duplicate schema entries"
                                    ),
                                }
                            }
                            other => map_scope_err(other),
                        })?;
                }

                // Re-read so the caller gets a fresh model with the new status.
                let fresh = tenants::Entity::find()
                    .secure()
                    .scope_with(&scope)
                    .filter(id_eq(tenant_id))
                    .one(tx)
                    .await
                    .map_err(map_scope_err)?
                    .ok_or_else(|| AmError::Internal {
                        diagnostic: format!("tenant {tenant_id} disappeared after activation"),
                        cause: None,
                    })?;
                entity_to_model(fresh)
            })
        })
    })
    .await?;
    Ok(result)
}

pub(super) async fn compensate_provisioning(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
) -> Result<(), AmError> {
    // Same `allow_all` posture as `hard_delete_one`: this method is
    // called by the provisioning-reaper / saga-compensation path,
    // both of which operate as `actor=system`. A narrowed caller
    // scope on the existence read could mask a real `Provisioning`
    // row as `None` and silently fast-path to `Ok(())` (the
    // already-gone branch) while the row stays in the DB.
    let _ = scope;
    with_serializable_retry(&repo.db, move || {
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                let existing = tenants::Entity::find()
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .filter(id_eq(tenant_id))
                    .one(tx)
                    .await
                    .map_err(map_scope_err)?;
                match existing {
                    Some(row)
                        if row.status == TenantStatus::Provisioning.as_smallint() =>
                    {
                        tenants::Entity::delete_many()
                            .filter(
                                Condition::all()
                                    .add(tenants::Column::Id.eq(tenant_id))
                                    .add(
                                        tenants::Column::Status
                                            .eq(TenantStatus::Provisioning.as_smallint()),
                                    ),
                            )
                            .secure()
                            .scope_with(&AccessScope::allow_all())
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;
                        Ok(())
                    }
                    Some(_) => Err(AmError::Conflict {
                        detail: format!(
                            "refusing to compensate: tenant {tenant_id} not in provisioning state"
                        ),
                    }),
                    None => Ok(()),
                }
            })
        })
    })
    .await
}

pub(super) async fn hard_delete_one(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    id: Uuid,
) -> Result<HardDeleteOutcome, AmError> {
    // The trait keeps `scope` for symmetry with other write methods,
    // but every read/write inside the hard-delete TX runs under
    // `allow_all` (see in-tx comments). Suppress the unused-binding
    // warning explicitly so the contract remains visible.
    let _ = scope;
    with_serializable_retry(&repo.db, move || {
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                // The entire hard-delete path runs with `allow_all`:
                // the retention scheduler is the only legitimate caller
                // and it operates as `actor=system` per
                // `dod-audit-contract`. A narrowed caller scope on the
                // existence read could turn a live tenant into
                // `Cleaned` (idempotent fast-path) without ever
                // touching the row, leading to silently-orphaned
                // descendants. The scoped `tenants` find / delete
                // calls below match this rationale.
                let existing = tenants::Entity::find()
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .filter(id_eq(id))
                    .one(tx)
                    .await
                    .map_err(map_scope_err)?;
                let Some(row) = existing else {
                    // Row already gone — treat as cleaned for idempotency.
                    return Ok(HardDeleteOutcome::Cleaned);
                };
                if row.status != TenantStatus::Deleted.as_smallint()
                    || row.deletion_scheduled_at.is_none()
                {
                    return Ok(HardDeleteOutcome::NotEligible);
                }

                // In-tx child-existence guard. If any row (including
                // Deleted children that haven't been reclaimed yet)
                // still names this tenant as parent, defer.
                //
                // Uses `allow_all` for the same reason the closure +
                // metadata deletes below do: a narrow caller scope
                // could silently make this count return 0 (the
                // `tenants` entity is scoped on `id`, so a child
                // outside the caller's scope is invisible) and we
                // would proceed with the hard-delete, orphaning the
                // descendants. The retention pipeline already calls
                // with `allow_all`; this just removes the latent
                // footgun for any future caller that doesn't.
                let children = tenants::Entity::find()
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .filter(Condition::all().add(tenants::Column::ParentId.eq(id)))
                    .count(tx)
                    .await
                    .map_err(map_scope_err)?;
                if children > 0 {
                    return Ok(HardDeleteOutcome::DeferredChildPresent);
                }

                // Closure rows first (FK cascades would do this on
                // Postgres, but we clear explicitly to remain
                // dialect-portable). `allow_all` because the closure
                // entity is `no_tenant/no_resource/no_owner/no_type` —
                // see `update_tenant_mutable` for the full rationale.
                // The retention pipeline calls `hard_delete_one` with
                // `allow_all` today, so this also future-proofs the
                // method against any caller that might pass a
                // narrowed scope.
                // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete
                tenant_closure::Entity::delete_many()
                    .filter(
                        Condition::any()
                            .add(tenant_closure::Column::AncestorId.eq(id))
                            .add(tenant_closure::Column::DescendantId.eq(id)),
                    )
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_err)?;
                // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete

                // Metadata rows next. Same dialect-portability rule as
                // closure: SQLite does not enforce FK cascades because
                // `modkit-db` does not enable `PRAGMA foreign_keys`,
                // so the `ON DELETE CASCADE` declared on
                // `tenant_metadata` in `m0001_initial_schema` would
                // silently leak orphaned rows on SQLite-backed
                // deployments. `allow_all` matches the rest of the
                // hard-delete path so a narrow caller scope cannot
                // silently leave metadata rows behind.
                tenant_metadata::Entity::delete_many()
                    .filter(Condition::all().add(tenant_metadata::Column::TenantId.eq(id)))
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_err)?;

                // Tenant row — same `allow_all` rationale as the
                // existence read at the top of the function.
                tenants::Entity::delete_many()
                    .filter(id_eq(id))
                    .secure()
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_err)?;
                Ok(HardDeleteOutcome::Cleaned)
            })
        })
    })
    .await
}
