//! Retention scanner + reaper scanner repo methods:
//! `scan_retention_due`, `clear_retention_claim`,
//! `scan_stuck_provisioning`. Read-mostly; the retention scan does
//! atomic claim-and-go inside a `READ COMMITTED` tx, the reaper scan
//! is a plain SELECT.

use std::time::Duration;

use modkit_db::secure::{
    SecureEntityExt, SecureUpdateExt, TxAccessMode, TxConfig, TxIsolationLevel,
};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant::model::TenantStatus;
use crate::domain::tenant::retention::{TenantProvisioningRow, TenantRetentionRow};
use crate::infra::storage::entity::tenants;

use super::TenantRepoImpl;
use super::helpers::{RETENTION_CLAIM_TTL, map_scope_err};

/// Apply the leaf-first ORDER BY chain used by `scan_retention_due`:
/// `(depth DESC, deletion_scheduled_at ASC, id ASC)`.
///
/// Pinned via this helper (and the snapshot test below) so a future
/// refactor cannot accidentally re-introduce the starvation regression
/// where `deletion_scheduled_at ASC` ran first and let an older parent
/// with surviving Deleted children monopolise the `LIMIT` window.
fn apply_retention_leaf_first_order<Q: sea_orm::QueryOrder>(q: Q) -> Q {
    q.order_by(tenants::Column::Depth, Order::Desc)
        .order_by(tenants::Column::DeletionScheduledAt, Order::Asc)
        .order_by(tenants::Column::Id, Order::Asc)
}

pub(super) async fn scan_retention_due(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    now: OffsetDateTime,
    default_retention: Duration,
    limit: usize,
) -> Result<Vec<TenantRetentionRow>, AmError> {
    // Push the per-row due-check into SQL so the `LIMIT` applies to
    // *due* rows only. The earlier implementation over-fetched
    // `4 × batch` rows ordered by `scheduled_at ASC` and applied
    // `is_due` in Rust afterwards — but a backlog of older
    // not-yet-due rows (typical case: NULL `retention_window_secs`
    // → default 90 days) could fill the over-fetch window and
    // starve newer due rows (e.g. soft-deleted with explicit
    // `retention_window_secs = 0`). The reviewer flagged this as
    // an indefinite-delay class of bug; by filtering at the DB the
    // due-set is exact and starvation is impossible.
    //
    // The effective due predicate is
    //   `scheduled_at + (retention_window_secs if non-negative else default) seconds <= now`.
    // The `CASE WHEN >= 0` clamp mirrors the Rust `is_due` fallback
    // (`Some(secs) if secs >= 0 => secs else default`) byte-for-byte:
    // NULL and negative `retention_window_secs` both fall through to
    // `default_secs`, while a meaningful admin-set `0` (immediate
    // hard-delete on next tick) is preserved. Without the clamp a
    // negative window would compute `scheduled_at + negative` and
    // mark the row instantly due — the Rust defense-in-depth check
    // catches it but emits warn-spam every tick. Both supported
    // backends express the comparison without engine-specific
    // INTERVAL arithmetic exposed to Rust. The MySQL backend is
    // unsupported by AM migrations (see `m0001_initial_schema`) so
    // it errors here for symmetry with the migration-set rejection.
    let engine = repo.db.db().db_engine();
    let default_secs = i64::try_from(default_retention.as_secs()).unwrap_or(i64::MAX);
    let due_check = match engine {
        "postgres" => Expr::cust_with_values(
            "deletion_scheduled_at + make_interval(secs => CASE WHEN retention_window_secs >= 0 THEN retention_window_secs ELSE $1 END) <= $2",
            vec![
                sea_orm::Value::from(default_secs),
                sea_orm::Value::from(now),
            ],
        ),
        "sqlite" => Expr::cust_with_values(
            // SQLite stores TIMESTAMP as TEXT (ISO-8601);
            // `julianday()` returns a numeric so the comparison
            // is monotonic regardless of the textual format
            // SeaORM uses for the bound `now`. Parens around the
            // `CASE` keep the `/ 86400.0` division scoped to the
            // chosen seconds value, not the comparison.
            "julianday(deletion_scheduled_at) + (CASE WHEN retention_window_secs >= 0 THEN retention_window_secs ELSE $1 END) / 86400.0 <= julianday($2)",
            vec![
                sea_orm::Value::from(default_secs),
                sea_orm::Value::from(now),
            ],
        ),
        other => {
            return Err(AmError::Internal {
                diagnostic: format!(
                    "scan_retention_due: backend '{other}' is not a supported AM backend"
                ),
                cause: None,
            });
        }
    };

    let cap = u64::try_from(limit).unwrap_or(u64::MAX);
    let worker_id = Uuid::new_v4();
    // Stale-claim cutoff: a row claimed before this instant whose
    // `clear_retention_claim` evidently never landed (else
    // `claimed_by` would be NULL) is up for re-claim by another
    // worker. Computed in Rust so the SQL stays portable across
    // the two supported engines.
    let stale_cutoff = match time::Duration::try_from(RETENTION_CLAIM_TTL) {
        Ok(d) => now - d,
        Err(_) => now,
    };
    let scope = scope.clone();
    let rows = repo
        .db
        .transaction_with_config(
            TxConfig {
                isolation: Some(TxIsolationLevel::ReadCommitted),
                access_mode: Some(TxAccessMode::ReadWrite),
            },
            move |tx| {
                Box::pin(async move {
                    // Claimable iff unclaimed OR the previous claim
                    // is older than `RETENTION_CLAIM_TTL`. The
                    // dedicated `claimed_at` column is the
                    // claim-age marker (see comment on
                    // `RETENTION_CLAIM_TTL`); decoupled from
                    // `updated_at` so any future patch path that
                    // bumps `updated_at` on a `Deleted`-status row
                    // does not inadvertently keep stale claims
                    // alive.
                    let claimable = Condition::any()
                        .add(tenants::Column::ClaimedBy.is_null())
                        .add(tenants::Column::ClaimedAt.lte(stale_cutoff));
                    let scan_filter = Condition::all()
                        .add(tenants::Column::Status.eq(TenantStatus::Deleted.as_smallint()))
                        .add(tenants::Column::DeletionScheduledAt.is_not_null())
                        .add(claimable.clone())
                        .add(due_check);

                    // No `FOR UPDATE SKIP LOCKED` here: the
                    // claim-and-go correctness relies on the
                    // atomic UPDATE below — only one worker can
                    // satisfy the `claimable` predicate for any
                    // given row, the others' UPDATE simply
                    // affects 0 rows. Skipping the lock keeps the
                    // scan portable across the two supported
                    // backends; under high concurrency two workers
                    // may scan overlapping candidate sets and
                    // waste a round-trip on the losing UPDATE,
                    // but no row is double-claimed.
                    // Leaf-first SQL ordering applied via the shared
                    // helper before the secure wrapping so the test
                    // and the impl share the column-sequence source
                    // of truth. See `apply_retention_leaf_first_order`
                    // doc + the snapshot test that pins the sequence
                    // to prevent the starvation regression.
                    let candidates = apply_retention_leaf_first_order(tenants::Entity::find())
                        .secure()
                        .scope_with(&scope)
                        .filter(scan_filter)
                        .limit(cap)
                        .all(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Defense-in-depth Rust-side `is_due` re-check: the
                    // SQL filter is the source of truth, but a divergence
                    // (timezone normalisation, NULL handling) would
                    // otherwise let a not-yet-due row reach the caller.
                    // Re-checking BEFORE we stamp the claim guarantees
                    // mismatched rows are simply ignored this tick rather
                    // than being marked claimed and held invisible until
                    // RETENTION_CLAIM_TTL expires.
                    let candidate_ids: Vec<Uuid> = candidates
                        .iter()
                        .filter_map(|row| {
                            let scheduled_at = row.deletion_scheduled_at?;
                            let retention = match row.retention_window_secs {
                                Some(secs) if secs >= 0 => {
                                    Duration::from_secs(u64::try_from(secs).unwrap_or(0))
                                }
                                _ => default_retention,
                            };
                            if crate::domain::tenant::retention::is_due(
                                now,
                                scheduled_at,
                                retention,
                            ) {
                                Some(row.id)
                            } else {
                                tracing::warn!(
                                    target: "am.tenant_retention",
                                    tenant_id = %row.id,
                                    "row matched SQL due-check but failed Rust is_due; skipping for this tick"
                                );
                                None
                            }
                        })
                        .collect();
                    if candidate_ids.is_empty() {
                        return Ok(Vec::new());
                    }

                    // Stamp `claimed_at` with `now` so the new
                    // claim's age can be aged out by the same TTL
                    // predicate above if `clear_retention_claim`
                    // later fails. `updated_at` is intentionally
                    // not touched: claim acquisition is a
                    // worker-side bookkeeping event, not a tenant
                    // mutation, and conflating the two columns
                    // would couple worker-liveness detection to
                    // any future patch path.
                    //
                    // Two-statement portable pattern (UPDATE then
                    // SELECT-by-claim-marker) instead of
                    // `UPDATE … RETURNING`: the latter is Postgres-
                    // and SQLite-only, but `modkit-db` is meant to
                    // stay backend-agnostic so MySQL deployments
                    // remain viable. We're inside the
                    // `with_serializable_retry` boundary, so the
                    // SELECT observes a snapshot consistent with
                    // the UPDATE we just issued — exactly the rows
                    // whose `claimed_by` is now `worker_id`
                    // restricted to the candidate window.
                    let candidate_ids_for_select = candidate_ids.clone();
                    tenants::Entity::update_many()
                        .col_expr(tenants::Column::ClaimedBy, Expr::value(worker_id))
                        .col_expr(tenants::Column::ClaimedAt, Expr::value(now))
                        .filter(
                            Condition::all()
                                .add(tenants::Column::Id.is_in(candidate_ids))
                                .add(claimable),
                        )
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    tenants::Entity::find()
                        .filter(
                            Condition::all()
                                .add(tenants::Column::Id.is_in(candidate_ids_for_select))
                                .add(tenants::Column::ClaimedBy.eq(worker_id)),
                        )
                        .secure()
                        .scope_with(&scope)
                        .all(tx)
                        .await
                        .map_err(map_scope_err)
                })
            },
        )
        .await?;

    // The Rust `is_due` re-check ran before claim acquisition inside
    // the transaction, so every row here is already verified due.
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let Some(scheduled_at) = r.deletion_scheduled_at else {
            continue;
        };
        let retention = match r.retention_window_secs {
            Some(secs) if secs >= 0 => Duration::from_secs(u64::try_from(secs).unwrap_or(0)),
            _ => default_retention,
        };
        out.push(TenantRetentionRow {
            id: r.id,
            depth: u32::try_from(r.depth).map_err(|_| AmError::Internal {
                diagnostic: format!(
                    "tenants.depth negative for retention row {}: {}",
                    r.id, r.depth
                ),
                cause: None,
            })?,
            deletion_scheduled_at: scheduled_at,
            retention_window: retention,
            claimed_by: worker_id,
        });
    }
    // The SQL ordering is already leaf-first
    // (`depth DESC, scheduled_at ASC, id ASC`); the post-TX re-sort
    // here is defensive against the `is_due` filter changing the
    // surviving subset's order (it wouldn't, since the filter is
    // boolean per-row, but the explicit sort makes the contract
    // local to this function rather than relying on the SELECT).
    out.sort_by(|a, b| {
        b.depth
            .cmp(&a.depth)
            .then_with(|| a.deletion_scheduled_at.cmp(&b.deletion_scheduled_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(out)
}

pub(super) async fn clear_retention_claim(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    worker_id: Uuid,
) -> Result<(), AmError> {
    let conn = repo.db.conn()?;
    // `claimed_by = worker_id` predicate fences this UPDATE to the
    // worker that originally claimed the row. If the TTL elapsed
    // and a peer worker took over, the predicate fails and this
    // call is a no-op — the peer's live claim is preserved.
    // `claimed_at` is cleared together with `claimed_by` so the
    // claim-age column never lingers on an unclaimed row.
    tenants::Entity::update_many()
        .col_expr(
            tenants::Column::ClaimedBy,
            Expr::value(Option::<Uuid>::None),
        )
        .col_expr(
            tenants::Column::ClaimedAt,
            Expr::value(Option::<OffsetDateTime>::None),
        )
        .filter(
            Condition::all()
                .add(tenants::Column::Id.eq(tenant_id))
                .add(tenants::Column::ClaimedBy.eq(worker_id)),
        )
        .secure()
        .scope_with(scope)
        .exec(&conn)
        .await
        .map_err(map_scope_err)?;
    Ok(())
}

pub(super) async fn scan_stuck_provisioning(
    repo: &TenantRepoImpl,
    scope: &AccessScope,
    older_than: OffsetDateTime,
    limit: usize,
) -> Result<Vec<TenantProvisioningRow>, AmError> {
    let conn = repo.db.conn()?;
    // Bound the query at the SQL layer so a large stuck-provisioning
    // backlog cannot load every row into memory in one round-trip.
    // Mirrors `scan_retention_due`'s capped fetch pattern.
    //
    // Unlike `scan_retention_due` this method does NOT take a row
    // lock or atomic claim. Two reaper instances scanning the same
    // window may both pick up the same `Provisioning` row and both
    // call `IdpTenantProvisioner::deprovision_tenant` for it. That
    // is acceptable because:
    // 1. `deprovision_tenant` is idempotent per the
    //    `idp-tenant-deprovision` DoD — a second invocation on an
    //    already-removed tenant returns Ok or `UnsupportedOperation`,
    //    not a hard error.
    // 2. The follow-up DB teardown for stale `Provisioning` rows
    //    flows through `compensate_provisioning`, which guards on
    //    `status = Provisioning` and is itself idempotent: the
    //    second worker's `delete_many` simply matches zero rows
    //    once the first worker's compensation TX has committed.
    //    `schedule_deletion` is the soft-delete entry point for
    //    SDK-visible (`Active` / `Suspended`) tenants and is NOT the
    //    correct teardown path for stuck-provisioning rows — those
    //    have no closure entries by construction (DESIGN §3.1
    //    provisioning-exclusion invariant).
    // The cost is a wasted IdP call window equal to one
    // `reaper_tick_secs`, traded against the schema cost of adding a
    // claim column purely for liveness.
    let cap = u64::try_from(limit).unwrap_or(u64::MAX);
    let rows = tenants::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(
            Condition::all()
                .add(tenants::Column::Status.eq(TenantStatus::Provisioning.as_smallint()))
                .add(tenants::Column::CreatedAt.lte(older_than)),
        )
        .order_by(tenants::Column::CreatedAt, Order::Asc)
        .order_by(tenants::Column::Id, Order::Asc)
        .limit(cap)
        .all(&conn)
        .await
        .map_err(map_scope_err)?;
    Ok(rows
        .into_iter()
        .map(|r| TenantProvisioningRow {
            id: r.id,
            created_at: r.created_at,
        })
        .collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, EntityTrait, QueryTrait};

    /// Pins the bind-renumbering contract for the `due_check`
    /// `cust_with_values` expression. `SeaQuery` renumbers the local
    /// `$1`/`$2` placeholders inside the cust string globally when
    /// composing them with surrounding filter clauses, so the bound
    /// values arrive in the right slots regardless of how many binds
    /// precede the cust expression.
    ///
    /// This test was added in response to a false-positive review
    /// finding that claimed the `$N` indices were bound to earlier
    /// filter values. The actual SQL output proves they are not — the
    /// values list is `[status, stale_cutoff, default_secs, now]` and
    /// the SQL placeholders renumber to `$1..$4` in the same order.
    /// If a future `SeaQuery` upgrade ever broke this, we would see it
    /// here before retention scanning silently misbehaved in prod.
    #[test]
    fn scan_retention_due_filter_binds_in_expected_order() {
        use sea_orm::sea_query::Expr;
        use sea_orm::{ColumnTrait, Condition, QueryFilter};

        let now = time::OffsetDateTime::UNIX_EPOCH;
        let stale_cutoff = now - time::Duration::seconds(120);

        let claimable = Condition::any()
            .add(tenants::Column::ClaimedBy.is_null())
            .add(tenants::Column::ClaimedAt.lte(stale_cutoff));
        let due = Expr::cust_with_values(
            "deletion_scheduled_at + make_interval(secs => CASE WHEN retention_window_secs >= 0 THEN retention_window_secs ELSE $1 END) <= $2",
            vec![
                sea_orm::Value::from(60_i64),
                sea_orm::Value::from(now),
            ],
        );
        let stmt = tenants::Entity::find()
            .filter(
                Condition::all()
                    .add(tenants::Column::Status.eq(3_i16))
                    .add(tenants::Column::DeletionScheduledAt.is_not_null())
                    .add(claimable)
                    .add(due),
            )
            .build(DatabaseBackend::Postgres);

        let values: Vec<sea_orm::Value> = stmt
            .values
            .as_ref()
            .map(|v| v.0.clone())
            .unwrap_or_default();
        assert_eq!(
            values.len(),
            4,
            "expected 4 binds (status, stale_cutoff, default_secs, now); got {} from SQL: {}",
            values.len(),
            stmt.sql
        );
        // Bind ordering is what matters for retention correctness:
        // position 2 (cust's `$1`) MUST be `default_secs` (i64 = 60),
        // position 3 (cust's `$2`) MUST be `now`.
        assert!(
            matches!(values[2], sea_orm::Value::BigInt(Some(60))),
            "bind position 3 (cust $1) must be default_secs (BigInt 60); got {:?}",
            values[2]
        );
        assert!(
            matches!(values[3], sea_orm::Value::TimeDateTimeWithTimeZone(_)),
            "bind position 4 (cust $2) must be `now` (TimeDateTimeWithTimeZone); got {:?}",
            values[3]
        );
    }

    /// Snapshot test pinning the leaf-first ORDER BY for
    /// `scan_retention_due`. Catches the starvation regression where
    /// `deletion_scheduled_at ASC` ran first and let an older parent
    /// with surviving Deleted children monopolise the LIMIT window
    /// (`hard_delete_one` defers parents-with-children, so the next
    /// tick re-picks the same parent and starves newer due leaves).
    ///
    /// The test calls the same `apply_retention_leaf_first_order`
    /// helper the impl uses, so a reordering of the helper's
    /// `.order_by(...)` chain breaks both at once.
    #[test]
    fn retention_scan_orders_leaf_first() {
        let stmt =
            apply_retention_leaf_first_order(tenants::Entity::find()).build(DatabaseBackend::Postgres);
        let sql = stmt.to_string();

        let depth_pos = sql
            .find("\"depth\" DESC")
            .or_else(|| sql.find("`depth` DESC"))
            .expect("ORDER BY must include `depth DESC`");
        let scheduled_pos = sql
            .find("\"deletion_scheduled_at\" ASC")
            .or_else(|| sql.find("`deletion_scheduled_at` ASC"))
            .expect("ORDER BY must include `deletion_scheduled_at ASC`");
        let id_pos = sql
            .find("\"id\" ASC")
            .or_else(|| sql.find("`id` ASC"))
            .expect("ORDER BY must include `id ASC`");

        assert!(
            depth_pos < scheduled_pos,
            "leaf-first ORDER BY: `depth DESC` must precede `deletion_scheduled_at ASC` to \
             prevent the parent-starvation regression. Full SQL: {sql}"
        );
        assert!(
            scheduled_pos < id_pos,
            "tiebreaker order: `deletion_scheduled_at ASC` must precede `id ASC`. \
             Full SQL: {sql}"
        );
    }
}
