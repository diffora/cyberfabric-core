//! Tenant-row lifecycle writes that maintain the `tenant_closure`
//! invariant on create/destroy:
//! `insert_provisioning`, `activate_tenant`,
//! `compensate_provisioning`, `hard_delete_one`. All transactional
//! writes go through [`super::helpers::with_serializable_retry`] under
//! `SERIALIZABLE` isolation per AC#15.

use std::collections::HashSet;

use modkit_db::secure::{
    DbTx, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureUpdateExt, is_unique_violation,
};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::retention::HardDeleteOutcome;
use crate::infra::storage::entity::{tenant_closure, tenant_metadata, tenants};

use super::TenantRepoImpl;
use super::helpers::{
    TxError, entity_to_model, id_eq, map_scope_err, map_scope_to_tx, schema_uuid_from_gts_id,
    with_serializable_retry,
};

pub(super) async fn insert_provisioning(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant: &NewTenant,
) -> Result<TenantModel, DomainError> {
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
            DomainError::Internal {
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
    // scope_unchecked: `tenants` is declared `no_tenant, no_resource`
    // (see entity doc), so `scope_with` here would compile to a
    // no-op for the contract-required `allow_all` scope and to
    // `ScopeError::Denied` for any narrowed scope (since `Scopable`
    // resolves no properties on a no-* entity). `scope_unchecked`
    // makes the bypass explicit at the call site and keeps the
    // INSERT path safe regardless of what the caller passes —
    // authorization for the operation as a whole is enforced
    // upstream at the PDP gate in the service layer. The future
    // `InTenantSubtree` predicate will plumb subtree clamp into AM
    // reads, not into INSERTs.
    // Unique-violation handling: do NOT fold the duplicate-id case
    // into `DomainError::Conflict` here — `map_scope_err` runs the
    // SQLSTATE through the infra-side classifier which routes
    // unique-violation `DbErr` to `DomainError::AlreadyExists` (and
    // ultimately `CanonicalError::AlreadyExists`, HTTP 409).
    // Pre-classifying as `Conflict` would reroute duplicate-id to
    // `FailedPrecondition` (HTTP 400) and desynchronize this path
    // from the AlreadyExists/409 contract documented elsewhere.
    let model: tenants::Model = tenants::Entity::insert(am)
        .secure()
        // TODO(InTenantSubtree): once the predicate lands and AM
        // declares the `tenant_hierarchy` capability, INSERTs may
        // start carrying meaningful scope (e.g. "caller may insert
        // only under their own subtree"). Until then this bypass is
        // explicit at the call site for greppability —
        // `rg "TODO(InTenantSubtree)"` lists every bypass in one pass.
        .scope_unchecked(scope)
        .map_err(map_scope_err)?
        .exec_with_returning(&conn)
        .await
        .map_err(map_scope_err)?;
    entity_to_model(model)
}

#[allow(
    clippy::too_many_lines,
    reason = "saga step 3 — defense-in-depth closure validation + status flip + closure insert + metadata insert; splitting fragments the SERIALIZABLE retry boundary the helper owns"
)]
pub(super) async fn activate_tenant(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    closure_rows: &[ClosureRow],
    metadata_entries: &[ProvisionMetadataEntry],
) -> Result<TenantModel, DomainError> {
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
                    .map_err(map_scope_to_tx)?
                    .ok_or_else(|| DomainError::NotFound {
                        detail: format!("tenant {tenant_id} not found for activation"),
                        resource: tenant_id.to_string(),
                    })?;

                if existing.status != TenantStatus::Provisioning.as_smallint() {
                    return Err(DomainError::Conflict {
                        detail: format!("tenant {tenant_id} not in provisioning state"),
                    }
                    .into());
                }

                // Defense-in-depth: validate the closure-row slice
                // matches the contract documented on
                // `TenantRepo::activate_tenant`. The slice is supposed
                // to come from `build_activation_rows` (which has its
                // own release-mode asserts), but flipping
                // `status -> Active` before the closure insert means a
                // malformed slice would persist a half-active tenant
                // — DB-level CHECKs catch some shapes, but only AFTER
                // the status flip has committed, leaving a window the
                // integrity classifier would only flag retroactively.
                // Fail fast on every documented invariant so saga
                // compensation can run cleanly.
                let active_status = TenantStatus::Active.as_smallint();
                if rows.is_empty() {
                    return Err(DomainError::Internal {
                        diagnostic: format!(
                            "activate_tenant received empty closure rows for tenant {tenant_id}"
                        ),
                        cause: None,
                    }
                    .into());
                }
                let self_row_count = rows
                    .iter()
                    .filter(|r| r.ancestor_id == tenant_id && r.descendant_id == tenant_id)
                    .count();
                if self_row_count != 1 {
                    return Err(DomainError::Internal {
                        diagnostic: format!(
                            "activate_tenant closure rows for tenant {tenant_id} contain \
                             {self_row_count} self-row(s); expected exactly one \
                             ({tenant_id},{tenant_id})"
                        ),
                        cause: None,
                    }
                    .into());
                }
                for row in &rows {
                    if row.descendant_id != tenant_id {
                        return Err(DomainError::Internal {
                            diagnostic: format!(
                                "activate_tenant closure row for tenant {tenant_id} has \
                                 descendant_id {} (expected {tenant_id})",
                                row.descendant_id
                            ),
                            cause: None,
                        }
                        .into());
                    }
                    if row.descendant_status != active_status {
                        return Err(DomainError::Internal {
                            diagnostic: format!(
                                "activate_tenant closure row for tenant {tenant_id} carries \
                                 descendant_status {} (expected {active_status} = Active)",
                                row.descendant_status
                            ),
                            cause: None,
                        }
                        .into());
                    }
                    if !matches!(row.barrier, 0 | 1) {
                        return Err(DomainError::Internal {
                            diagnostic: format!(
                                "activate_tenant closure row for tenant {tenant_id} has barrier \
                                 {} (expected 0 or 1)",
                                row.barrier
                            ),
                            cause: None,
                        }
                        .into());
                    }
                    if row.ancestor_id == tenant_id && row.barrier != 0 {
                        return Err(DomainError::Internal {
                            diagnostic: format!(
                                "activate_tenant self-row for tenant {tenant_id} has non-zero \
                                 barrier {} (self-row barrier must be 0 per closure invariant)",
                                row.barrier
                            ),
                            cause: None,
                        }
                        .into());
                    }
                }

                // Coverage check: rows.len() must equal depth + 1 —
                // one self-row plus one (ancestor, child) row per
                // strict ancestor along the parent chain. A short
                // slice would activate a non-root tenant with
                // missing parent / root closure rows, breaking
                // hierarchy reads + barrier propagation; the bug
                // would only surface as integrity-classifier
                // violations after the status flip is durable.
                let expected_count = usize::try_from(existing.depth)
                    .unwrap_or(0)
                    .saturating_add(1);
                if rows.len() != expected_count {
                    return Err(DomainError::Internal {
                        diagnostic: format!(
                            "activate_tenant closure coverage mismatch for tenant {tenant_id} \
                             (depth={}): got {} rows, expected {expected_count} \
                             (one self-row plus one row per strict ancestor)",
                            existing.depth,
                            rows.len()
                        ),
                        cause: None,
                    }
                    .into());
                }

                // Strict-ancestor identity check: every non-self
                // ancestor_id in the input MUST match the parent's
                // existing closure ancestors. Parent is already
                // Active, so its closure rows (`(*, parent_id)`)
                // are populated and visible inside this TX. A
                // mismatch here means the caller built closure_rows
                // off a wrong parent or a stale chain — fail-fast
                // before persisting incorrect ancestry.
                if let Some(parent_id) = existing.parent_id {
                    // Fetch the parent's closure rows (descendant_id =
                    // parent_id). We need both the ancestor set (for the
                    // identity check) and the per-ancestor `barrier`
                    // value (for barrier recomputation below) — never
                    // trust the caller-supplied barriers.
                    let parent_closure_rows = tenant_closure::Entity::find()
                        .secure()
                        // TODO(InTenantSubtree): closure traversal is
                        // structural and intentionally bypasses caller
                        // scope; revisit once the predicate lands so
                        // `rg "TODO(InTenantSubtree)"` lists every bypass.
                        .scope_with(&AccessScope::allow_all())
                        .filter(
                            Condition::all()
                                .add(tenant_closure::Column::DescendantId.eq(parent_id)),
                        )
                        .all(tx)
                        .await
                        .map_err(map_scope_to_tx)?;
                    let parent_closure_ancestors: HashSet<Uuid> =
                        parent_closure_rows.iter().map(|r| r.ancestor_id).collect();
                    // Strict ancestors of the parent (excluding the
                    // (parent_id, parent_id) self-row, whose barrier is
                    // always 0 by invariant and carries no signal for
                    // child-row barriers).
                    let parent_strict_barriers: std::collections::HashMap<Uuid, i16> =
                        parent_closure_rows
                            .iter()
                            .filter(|r| r.ancestor_id != parent_id)
                            .map(|r| (r.ancestor_id, r.barrier))
                            .collect();
                    let input_strict_ancestors: HashSet<Uuid> = rows
                        .iter()
                        .filter(|r| r.ancestor_id != tenant_id)
                        .map(|r| r.ancestor_id)
                        .collect();
                    if input_strict_ancestors != parent_closure_ancestors {
                        return Err(DomainError::Internal {
                            diagnostic: format!(
                                "activate_tenant strict-ancestor IDs for tenant {tenant_id} do \
                                 not match parent {parent_id}'s closure ancestors (expected {}, \
                                 got {})",
                                parent_closure_ancestors.len(),
                                input_strict_ancestors.len()
                            ),
                            cause: None,
                        }
                        .into());
                    }

                    // Barrier recomputation. The canonical rule (see
                    // `domain::tenant::closure::build_activation_rows`):
                    //   - self-row (ancestor=child)         → barrier = 0
                    //   - ancestor=parent                   → barrier = child.self_managed
                    //   - strict ancestor != parent (A)     → barrier = child.self_managed OR barrier_AP
                    // where `barrier_AP` is the barrier on the parent's
                    // closure row `(A, parent)` already stored in this
                    // TX's snapshot. Recomputing here closes the trust
                    // gap on caller-supplied barrier values: a buggy
                    // saga step or future internal caller could submit
                    // an ancestor row with the wrong barrier and weaken
                    // self-managed boundary enforcement, which would
                    // only surface later as integrity-classifier
                    // findings on already-committed rows.
                    let child_self_managed = existing.self_managed;
                    for row in &rows {
                        let expected = if row.ancestor_id == tenant_id {
                            0_i16
                        } else if row.ancestor_id == parent_id {
                            i16::from(child_self_managed)
                        } else {
                            let parent_barrier = parent_strict_barriers
                                .get(&row.ancestor_id)
                                .copied()
                                .ok_or_else(|| DomainError::Internal {
                                    diagnostic: format!(
                                        "activate_tenant strict ancestor {} for tenant \
                                         {tenant_id} not present in parent {parent_id}'s \
                                         closure (post-identity-check invariant violation)",
                                        row.ancestor_id
                                    ),
                                    cause: None,
                                })?;
                            i16::from(child_self_managed || parent_barrier != 0)
                        };
                        if row.barrier != expected {
                            return Err(DomainError::Internal {
                                diagnostic: format!(
                                    "activate_tenant closure row \
                                     (ancestor={}, descendant={tenant_id}) has barrier {} \
                                     but canonical recomputation yields {expected} \
                                     (child_self_managed={child_self_managed})",
                                    row.ancestor_id, row.barrier
                                ),
                                cause: None,
                            }
                            .into());
                        }
                    }
                } else if rows.iter().any(|r| r.ancestor_id != tenant_id) {
                    // Root tenant has no parent_id; any non-self
                    // ancestor row is a contract violation by
                    // construction (depth=0 → only the self-row
                    // belongs in `rows`).
                    return Err(DomainError::Internal {
                        diagnostic: format!(
                            "activate_tenant root tenant {tenant_id} has strict-ancestor row(s); \
                             root depth is 0 and only the self-row is permitted"
                        ),
                        cause: None,
                    }
                    .into());
                }

                // Flip status -> Active + bump updated_at via SecureUpdateMany.
                // Atomic write-time guard: the WHERE clause includes
                // `status = Provisioning` so a concurrent finalizer
                // / compensator that has already moved the row out
                // of `Provisioning` between our read above and this
                // write produces zero affected rows — we surface it
                // as `Conflict`, not as a false success that would
                // then trip the closure / metadata insert. Pre-read
                // verification stays for a clean error message and
                // for the closure-coverage validation it gates.
                let now = OffsetDateTime::now_utc();
                let rows_affected =
                    tenants::Entity::update_many()
                        .col_expr(
                            tenants::Column::Status,
                            Expr::value(TenantStatus::Active.as_smallint()),
                        )
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                        .filter(Condition::all().add(id_eq(tenant_id)).add(
                            tenants::Column::Status.eq(TenantStatus::Provisioning.as_smallint()),
                        ))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_to_tx)?
                        .rows_affected;
                if rows_affected == 0 {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id} no longer in provisioning state at activation \
                             write (concurrent finalizer or compensator)"
                        ),
                    }
                    .into());
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
                        .map_err(map_scope_to_tx)?
                        .exec(tx)
                        .await
                        .map_err(map_scope_to_tx)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                }

                if !metadata_entries.is_empty() {
                    let metadata_rows =
                        metadata_entries
                            .iter()
                            .map(|entry| tenant_metadata::ActiveModel {
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
                        .map_err(map_scope_to_tx)?
                        .exec(tx)
                        .await
                        .map_err(|e| match e {
                            // PK is `(tenant_id, schema_uuid)` and `schema_uuid` is
                            // a deterministic UUIDv5 of `entry.schema_id`. The only
                            // way 23505 fires here is duplicate `schema_id` strings
                            // in the *same* `metadata_entries` slice — which the
                            // server-side `IdpTenantProvisioner` impl produced via
                            // `ProvisionResult.metadata_entries`. The API client
                            // does not supply this slice; activation always runs
                            // against a fresh `(tenant_id, *)` keyspace (first
                            // Provisioning → Active transition); SERIALIZABLE
                            // retry rolls back any partial inserts. So this is a
                            // provider bug, not a client-state conflict — surface
                            // it as `Internal` (500), not `Conflict` (409).
                            modkit_db::secure::ScopeError::Db(ref db)
                                if is_unique_violation(db) =>
                            {
                                TxError::Domain(DomainError::Internal {
                                    diagnostic: format!(
                                        "provider returned duplicate schema_id entries \
                                         for tenant {tenant_id}"
                                    ),
                                    cause: None,
                                })
                            }
                            other => map_scope_to_tx(other),
                        })?;
                }

                // Re-read so the caller gets a fresh model with the new status.
                let fresh = tenants::Entity::find()
                    .secure()
                    .scope_with(&scope)
                    .filter(id_eq(tenant_id))
                    .one(tx)
                    .await
                    .map_err(map_scope_to_tx)?
                    .ok_or_else(|| DomainError::Internal {
                        diagnostic: format!("tenant {tenant_id} disappeared after activation"),
                        cause: None,
                    })?;
                entity_to_model(fresh).map_err(TxError::Domain)
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
) -> Result<(), DomainError> {
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
                    // TODO(InTenantSubtree): system-actor compensation
                    // path; safe under current trait contract. Revisit
                    // when the predicate lands so the bypass is
                    // greppable in one pass.
                    .scope_with(&AccessScope::allow_all())
                    .filter(id_eq(tenant_id))
                    .one(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
                match existing {
                    Some(row) if row.status == TenantStatus::Provisioning.as_smallint() => {
                        // Atomic write-time guard mirrors
                        // `activate_tenant`: the DELETE filter
                        // includes `status = Provisioning` so a
                        // concurrent finalizer that flipped the row
                        // to `Active` between the read above and
                        // this delete produces zero affected rows
                        // — we MUST refuse rather than silently
                        // succeed, otherwise the caller treats the
                        // tenant as compensated while the row is
                        // actually live and finalized.
                        let rows_affected = tenants::Entity::delete_many()
                            .filter(
                                Condition::all().add(tenants::Column::Id.eq(tenant_id)).add(
                                    tenants::Column::Status
                                        .eq(TenantStatus::Provisioning.as_smallint()),
                                ),
                            )
                            .secure()
                            // TODO(InTenantSubtree): system-actor compensation
                            // delete; same posture as the read above.
                            .scope_with(&AccessScope::allow_all())
                            .exec(tx)
                            .await
                            .map_err(map_scope_to_tx)?
                            .rows_affected;
                        if rows_affected == 0 {
                            return Err(DomainError::Conflict {
                                detail: format!(
                                    "refusing to compensate: tenant {tenant_id} no longer in \
                                     provisioning state at delete (concurrent finalizer)"
                                ),
                            }
                            .into());
                        }
                        Ok(())
                    }
                    Some(_) => Err(DomainError::Conflict {
                        detail: format!(
                            "refusing to compensate: tenant {tenant_id} not in provisioning state"
                        ),
                    }
                    .into()),
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
) -> Result<HardDeleteOutcome, DomainError> {
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
                    // TODO(InTenantSubtree): hard-delete is the
                    // retention-pipeline / system-actor path; bypass
                    // intentional, kept greppable.
                    .scope_with(&AccessScope::allow_all())
                    .filter(id_eq(id))
                    .one(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
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
                    // TODO(InTenantSubtree): structural child-existence
                    // guard runs as system-actor.
                    .scope_with(&AccessScope::allow_all())
                    .filter(Condition::all().add(tenants::Column::ParentId.eq(id)))
                    .count(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
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
                    // TODO(InTenantSubtree): closure cleanup; system-actor.
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
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
                    // TODO(InTenantSubtree): metadata cleanup; system-actor.
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_to_tx)?;

                // Tenant row — same `allow_all` rationale as the
                // existence read at the top of the function.
                tenants::Entity::delete_many()
                    .filter(id_eq(id))
                    .secure()
                    // TODO(InTenantSubtree): tenant row delete; system-actor.
                    .scope_with(&AccessScope::allow_all())
                    .exec(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
                Ok(HardDeleteOutcome::Cleaned)
            })
        })
    })
    .await
}
