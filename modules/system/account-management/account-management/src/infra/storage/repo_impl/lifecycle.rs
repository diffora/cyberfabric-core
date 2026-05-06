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

use account_management_sdk::ProvisionMetadataEntry;

use crate::domain::error::DomainError;
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::model::{NewTenant, TenantModel, TenantStatus};
use crate::domain::tenant::retention::{HardDeleteEligibility, HardDeleteOutcome};
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
    let depth = i32::try_from(tenant.depth).map_err(|_| DomainError::Internal {
        diagnostic: format!("depth overflow: {}", tenant.depth),
        cause: None,
    })?;
    let tenant_id = tenant.id;
    let parent_id = tenant.parent_id;
    let name = tenant.name.clone();
    let self_managed = tenant.self_managed;
    let tenant_type_uuid = tenant.tenant_type_uuid;
    let scope = scope.clone();

    with_serializable_retry(&repo.db, move || {
        let scope = scope.clone();
        let name = name.clone();
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                use sea_orm::ActiveValue;

                // Root insert (`parent_id = None`) skips the parent-active fence:
                // platform-bootstrap's `insert_root_provisioning` is the only
                // caller and the schema enforces single-root via
                // `ck_tenants_root_depth (parent_id IS NULL AND depth = 0)` plus
                // the `ux_tenants_single_root` partial unique index. Child inserts
                // (`parent_id = Some`) re-read the parent in the same TX and reject
                // unless still Active so a concurrent soft-delete cannot commit a
                // deleted parent while a new child is being provisioned.
                //
                // Pre-insert depth fence on the root branch: a malformed root
                // with `depth != 0` would otherwise fall through and surface
                // as `ck_tenants_root_depth` violation classified by the
                // canonical mapping as `Internal` rather than the typed
                // `Validation` the contract promises for hierarchy-shape
                // errors. Fence here so the call site fails loudly with the
                // right category before the round trip.
                if parent_id.is_none() && depth != 0 {
                    return Err(DomainError::Validation {
                        detail: format!(
                            "root tenant {tenant_id} must have depth 0 (got {depth})"
                        ),
                    }
                    .into());
                }
                if let Some(parent_id) = parent_id {
                    let parent = tenants::Entity::find()
                        .secure()
                        .scope_with(&AccessScope::allow_all())
                        .filter(id_eq(parent_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_to_tx)?
                        .ok_or_else(|| DomainError::Validation {
                            detail: format!("parent tenant {parent_id} not found"),
                        })?;
                    if parent.status != TenantStatus::Active.as_smallint() {
                        return Err(DomainError::Validation {
                            detail: format!("parent tenant {parent_id} is not active"),
                        }
                        .into());
                    }
                }

                let now = OffsetDateTime::now_utc();
                let am = tenants::ActiveModel {
                    id: ActiveValue::Set(tenant_id),
                    parent_id: ActiveValue::Set(parent_id),
                    name: ActiveValue::Set(name),
                    status: ActiveValue::Set(TenantStatus::Provisioning.as_smallint()),
                    self_managed: ActiveValue::Set(self_managed),
                    tenant_type_uuid: ActiveValue::Set(tenant_type_uuid),
                    depth: ActiveValue::Set(depth),
                    created_at: ActiveValue::Set(now),
                    updated_at: ActiveValue::Set(now),
                    deleted_at: ActiveValue::Set(None),
                    deletion_scheduled_at: ActiveValue::Set(None),
                    retention_window_secs: ActiveValue::Set(None),
                    claimed_by: ActiveValue::Set(None),
                    claimed_at: ActiveValue::Set(None),
                    terminal_failure_at: ActiveValue::Set(None),
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
                // into `DomainError::Conflict` here — `map_scope_to_tx` carries
                // the raw DB error through the retry helper and then through the
                // infra-side classifier, which routes unique violations to
                // `DomainError::AlreadyExists`.
                let model: tenants::Model = tenants::Entity::insert(am)
                    .secure()
                    // TODO(InTenantSubtree): once the predicate lands and AM
                    // declares the `tenant_hierarchy` capability, INSERTs may
                    // start carrying meaningful scope (e.g. "caller may insert
                    // only under their own subtree"). Until then this bypass is
                    // explicit at the call site for greppability —
                    // `rg "TODO(InTenantSubtree)"` lists every bypass in one pass.
                    .scope_unchecked(&scope)
                    .map_err(map_scope_to_tx)?
                    .exec_with_returning(tx)
                    .await
                    .map_err(map_scope_to_tx)?;
                entity_to_model(model).map_err(TxError::Domain)
            })
        })
    })
    .await
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

                // Fence against the provisioning reaper. If
                // `provisioning_timeout_secs` elapsed while the saga's
                // IdP call was in flight, the reaper may have claimed
                // this row (`claimed_by` set) and may already have
                // started — or even completed — `deprovision_tenant`
                // on the vendor side. Activating now would publish an
                // `Active` AM row whose IdP-side state has been torn
                // down. Same rationale for `terminal_failure_at`: a
                // peer reaper that classified the in-flight provision
                // as `Terminal` parks the row out of the retry loop;
                // the saga must not resurrect it. Both are read-only
                // checks here for a clean error message; the WHERE
                // clause on the status-flip UPDATE re-asserts them as
                // the authoritative atomic guard.
                if existing.claimed_by.is_some() {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id} has been claimed by the provisioning reaper; \
                             refusing to activate (saga lost the race)"
                        ),
                    }
                    .into());
                }
                if existing.terminal_failure_at.is_some() {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id} is parked with terminal_failure_at; \
                             operator action required before activation"
                        ),
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
                //
                // `claimed_by IS NULL` AND `terminal_failure_at IS
                // NULL` are also re-asserted here as the authoritative
                // fence against the provisioning reaper: a reaper that
                // claimed the row (or stamped it terminal) between
                // our read and this write produces zero affected
                // rows, and the saga is rolled back to the
                // compensation path instead of publishing an Active
                // tenant whose IdP state has been torn down.
                let now = OffsetDateTime::now_utc();
                let rows_affected = tenants::Entity::update_many()
                    .col_expr(
                        tenants::Column::Status,
                        Expr::value(TenantStatus::Active.as_smallint()),
                    )
                    .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                    .filter(
                        Condition::all()
                            .add(id_eq(tenant_id))
                            .add(
                                tenants::Column::Status
                                    .eq(TenantStatus::Provisioning.as_smallint()),
                            )
                            .add(tenants::Column::ClaimedBy.is_null())
                            .add(tenants::Column::TerminalFailureAt.is_null()),
                    )
                    .secure()
                    .scope_with(&scope)
                    .exec(tx)
                    .await
                    .map_err(map_scope_to_tx)?
                    .rows_affected;
                if rows_affected == 0 {
                    return Err(DomainError::Conflict {
                        detail: format!(
                            "tenant {tenant_id} no longer eligible for activation \
                             (concurrent finalizer/compensator or reaper claim/terminal stamp)"
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
                            // server-side `IdpTenantProvisionerClient` impl produced via
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

pub(super) async fn mark_provisioning_terminal_failure(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    claimed_by: Uuid,
    now: OffsetDateTime,
) -> Result<bool, DomainError> {
    mark_terminal_failure_with_status(
        repo,
        scope,
        tenant_id,
        claimed_by,
        now,
        TenantStatus::Provisioning,
    )
    .await
}

pub(super) async fn mark_retention_terminal_failure(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    claimed_by: Uuid,
    now: OffsetDateTime,
) -> Result<bool, DomainError> {
    mark_terminal_failure_with_status(
        repo,
        scope,
        tenant_id,
        claimed_by,
        now,
        TenantStatus::Deleted,
    )
    .await
}

/// Shared body for the two parking variants
/// (`mark_provisioning_terminal_failure` /
/// `mark_retention_terminal_failure`). The only difference between
/// them is the `status` fence — the reaper parks `Provisioning`
/// rows the `IdP` classified as terminal; the retention pipeline
/// parks `Deleted` rows whose cleanup hooks or `IdP` deprovision were
/// classified as terminal — and centralising the body here keeps
/// the SERIALIZABLE-equivalent fence, idempotency, and claim posture
/// identical for both. The status enum is a closed set, so this is
/// not a "match-anything" generalization that a future caller could
/// abuse to park an `Active` tenant: callers must spell out which
/// pipeline path they sit on, and the two trait methods are the
/// only public entry-points.
async fn mark_terminal_failure_with_status(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    claimed_by: Uuid,
    now: OffsetDateTime,
    status: TenantStatus,
) -> Result<bool, DomainError> {
    // System-actor path; same `allow_all` posture as
    // `compensate_provisioning` and `hard_delete_one`. Whichever
    // pipeline calls in already ran a PEP-equivalent gate at scan
    // time (the row was claimed by this worker), and the marker
    // write itself is a structural state transition not a
    // tenant-scoped operation.
    let _ = scope;
    let conn = repo.db.conn()?;
    let res = tenants::Entity::update_many()
        .col_expr(tenants::Column::TerminalFailureAt, Expr::value(Some(now)))
        .filter(
            Condition::all()
                .add(tenants::Column::Id.eq(tenant_id))
                // Idempotency fence: only stamp `terminal_failure_at`
                // when it is NULL. Without this, the same worker
                // re-running the mark on an already-marked row would
                // rewrite the original timestamp — an operator
                // looking at `terminal_failure_at` as the
                // first-classified-as-terminal moment would see the
                // most recent retry instead. Returning
                // `rows_affected == 0` (treated by the caller as
                // `Ok(false)`) on the no-op retry is acceptable: the
                // scan filter excludes terminal-marked rows, so this
                // path is only reachable from a tight scan/mark race
                // and the row IS already parked.
                .add(tenants::Column::TerminalFailureAt.is_null())
                // Claim fence: only the worker that scan-claimed
                // the row can mark it. A peer that took over after
                // a TTL-expired stale claim would already see the
                // marker in its own scan filter and skip; the fence
                // here just refuses a stale write from this worker
                // if it lost the claim.
                .add(tenants::Column::ClaimedBy.eq(claimed_by))
                // Status fence: a parallel finalizer that flipped
                // the row out of the expected status between this
                // worker's IdP round-trip / cascade-hook step and
                // this UPDATE must NOT be relabeled as terminal
                // failure — that row is no longer ours.
                .add(tenants::Column::Status.eq(status.as_smallint())),
        )
        .secure()
        // TODO(InTenantSubtree): system-actor terminal-failure write;
        // same posture as the reaper's `compensate_provisioning`
        // sibling above. Greppable for the predicate-rollout pass.
        .scope_with(&AccessScope::allow_all())
        .exec(&conn)
        .await
        .map_err(map_scope_err)?;
    Ok(res.rows_affected > 0)
}

pub(super) async fn compensate_provisioning(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    expected_claimed_by: Option<Uuid>,
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
                        // Atomic write-time guards (per the trait
                        // contract on `compensate_provisioning`):
                        //
                        // * `status = Provisioning` mirrors
                        //   `activate_tenant`: a concurrent finalizer
                        //   that flipped the row to `Active` between
                        //   the read above and this delete must
                        //   produce zero affected rows — we MUST
                        //   refuse rather than silently succeed.
                        // * `claimed_by` fence (per
                        //   `expected_claimed_by`): keeps the saga's
                        //   no-claim path from racing a peer reaper
                        //   that already claimed the row, and keeps
                        //   reaper-A from erasing reaper-B's parked
                        //   work after A's IdP call exceeded
                        //   `RETENTION_CLAIM_TTL`.
                        // * `terminal_failure_at IS NULL` keeps the
                        //   compensable path from silently erasing a
                        //   row a peer already classified as
                        //   operator-action-required.
                        let mut filter = Condition::all()
                            .add(tenants::Column::Id.eq(tenant_id))
                            .add(
                                tenants::Column::Status
                                    .eq(TenantStatus::Provisioning.as_smallint()),
                            )
                            .add(tenants::Column::TerminalFailureAt.is_null());
                        filter = match expected_claimed_by {
                            Some(worker_id) => filter.add(tenants::Column::ClaimedBy.eq(worker_id)),
                            None => filter.add(tenants::Column::ClaimedBy.is_null()),
                        };
                        let rows_affected = tenants::Entity::delete_many()
                            .filter(filter)
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
                                    "refusing to compensate: tenant {tenant_id} no longer \
                                     eligible at delete (concurrent finalizer / peer-reaper \
                                     claim or terminal stamp)"
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

/// Read-only preflight that mirrors the in-tx eligibility checks of
/// [`hard_delete_one`] without taking row locks or running any
/// writes. The retention pipeline calls this BEFORE running cascade
/// hooks + `IdP` `deprovision_tenant`, so a row that is in fact
/// deferred (parent with live child, status drifted, claim lost)
/// short-circuits before any external side effect fires.
///
/// The check is intentionally racy — it does not hold a lock between
/// SELECT and the subsequent `hard_delete_one` invocation. In well-
/// formed deployments the race is unreachable: `schedule_deletion`
/// rejects soft-delete on parents with live children under
/// SERIALIZABLE, and `create_child` rejects under a `Deleted` parent.
/// `hard_delete_one`'s in-tx defense-in-depth still rejects on a lost
/// race, and the next-tick retry recovers via the
/// `DeprovisionFailure::NotFound` → `IdpUnsupported` path.
///
/// Reads run under `allow_all` for the same reason as
/// [`hard_delete_one`]: a narrowed caller scope could mask a
/// child row outside the scope and yield a false `Eligible`.
pub(super) async fn check_hard_delete_eligibility(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    id: Uuid,
    claimed_by: Uuid,
) -> Result<HardDeleteEligibility, DomainError> {
    let _ = scope;
    let conn = repo.db.conn()?;
    let existing = tenants::Entity::find()
        .secure()
        // TODO(InTenantSubtree): preflight runs as system-actor.
        .scope_with(&AccessScope::allow_all())
        .filter(id_eq(id))
        .one(&conn)
        .await
        .map_err(map_scope_err)?;
    let Some(row) = existing else {
        // Row already gone — preflight reports `NotEligible` so the
        // caller's metric ladder doesn't conflate "vanished mid-tick"
        // with "cleaned via this tick". `hard_delete_one`'s own
        // already-gone fast-path returns `Cleaned` if our caller does
        // proceed, but the preflight gate is a separate signal.
        return Ok(HardDeleteEligibility::NotEligible);
    };
    if row.status != TenantStatus::Deleted.as_smallint() || row.deletion_scheduled_at.is_none() {
        return Ok(HardDeleteEligibility::NotEligible);
    }
    if row.claimed_by != Some(claimed_by) {
        // Claim lost (TTL expired between scan and finalize, or a
        // peer worker took over). Skip — whoever currently holds the
        // claim will drive teardown.
        return Ok(HardDeleteEligibility::NotEligible);
    }
    let children = tenants::Entity::find()
        .secure()
        // TODO(InTenantSubtree): structural child-existence check;
        // system-actor.
        .scope_with(&AccessScope::allow_all())
        .filter(Condition::all().add(tenants::Column::ParentId.eq(id)))
        .count(&conn)
        .await
        .map_err(map_scope_err)?;
    if children > 0 {
        return Ok(HardDeleteEligibility::DeferredChildPresent);
    }
    Ok(HardDeleteEligibility::Eligible)
}

pub(super) async fn hard_delete_one(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    id: Uuid,
    claimed_by: Uuid,
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
                // Claim fence carried through the final delete. The
                // preflight (`check_hard_delete_eligibility`) verified
                // the claim before hooks + IdP fired, but that work
                // can stretch past `RETENTION_CLAIM_TTL`; if a peer
                // reaper reclaimed the row in the interval, we MUST
                // NOT proceed — otherwise both workers race the DB
                // teardown and the second cascade-hook / IdP call
                // becomes a duplicate (a real bug for non-idempotent
                // hooks).
                if row.claimed_by != Some(claimed_by) {
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
