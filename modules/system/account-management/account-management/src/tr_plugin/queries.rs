//! Query implementations for `PluginImpl` SDK methods.
//!
//! Every function in this module:
//! - Takes a borrowed [`Db`] handle (the plugin shares AM's pool —
//!   the dedicated read-only role from DESIGN §3.5 is provisioned
//!   externally; in-process privilege separation is left for a
//!   follow-up).
//! - Uses [`AccessScope::allow_all`] explicitly. AM's `tenants` /
//!   `tenant_closure` entities are declared `no_tenant, no_resource,
//!   no_owner, no_type`, so the secure layer adds no implicit
//!   `WHERE`. The plugin's authorization story is "gateway is
//!   trusted" (DESIGN §4.2).
//! - Applies the provisioning-invisibility predicate
//!   ([`projection::tenants_visible_status_condition`]) on every
//!   `tenants` read, including existence probes and JOIN-style
//!   bulk reads. `tenant_closure` already excludes provisioning by
//!   AM's contract (`descendant_status ∈ {1,2,3}`), so closure-only
//!   reads do not need a defense-in-depth predicate.
//! - Hydrates the public `tenant_type` field through
//!   [`TypesRegistryClient`] using either a single
//!   `get_type_schema_by_uuid` (single-row results) or a batched
//!   `get_type_schemas_by_uuid` (page-style results) — mirroring
//!   `domain::tenant::service::lower_to_tenant_info` /
//!   `lower_to_tenant_page`. Registry failure degrades to
//!   `tenant_type: None` with a `tracing::warn` (the SDK field is
//!   `Option<String>` precisely for this reason).
//! - Maps `sea_orm::DbErr` / `ScopeError` / `DbError` through the
//!   helpers in [`super::error_map`] so the SDK boundary only ever
//!   sees [`TenantResolverError::TenantNotFound`] or
//!   [`TenantResolverError::Internal`].
//!
//! # Pre-order for `get_descendants`
//!
//! AM's `tenant_closure` does not carry a pre-order column or a
//! depth-from-ancestor column. The DESIGN names a "single subtree
//! recursive read" implemented as a SQL recursive CTE; the secure
//! `modkit-db` extension does not expose raw `ConnectionTrait`
//! access today, so the v1 implementation here builds the parent
//! map in-memory from the **barrier-only** closure subtree
//! (system-invariants only), walks it pre-order on the client, and
//! applies the caller's `status_filter` as an emission predicate.
//! Splitting graph construction (system invariants) from emission
//! (caller predicate) is required for correctness — folding the
//! caller predicate into the closure scan would prune whole
//! branches whose intermediate parent fails the filter even when
//! deeper descendants match (e.g. `Root → Suspended → Active`
//! filtered by `[Active]`). The recursive CTE optimization is
//! tracked as a follow-up once `modkit-db` exposes a safe raw-SQL
//! hook.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use modkit_db::Db;
use modkit_db::secure::SecureEntityExt;
use modkit_security::AccessScope;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order};
use uuid::Uuid;

use tenant_resolver_sdk::{
    BarrierMode, GetAncestorsResponse, GetDescendantsResponse, TenantId, TenantInfo, TenantRef,
    TenantResolverError, TenantStatus as SdkTenantStatus,
};
use types_registry_sdk::TypesRegistryClient;

use crate::infra::storage::entity::{tenant_closure, tenants};

use super::error_map::{modkit_db_err_to_tr_err, scope_err_to_tr_err};
use super::projection::{
    row_to_tenant_info, row_to_tenant_ref, tenants_status_in_condition,
    tenants_visible_status_condition,
};

/// Projection failure helper. The projection helpers return `None` in
/// two cases: a provisioning row reaching them (defense-in-depth — the
/// query layer should already exclude it) or an out-of-domain `status`
/// SMALLINT. Both indicate a violation of AM's invariants visible at
/// read time, so we surface `Internal` per DESIGN §3.8 (with the
/// internal diagnostic logged server-side rather than embedded in the
/// SDK error so we don't leak storage shape to plugin consumers).
fn projection_internal(id: Uuid) -> TenantResolverError {
    tracing::warn!(
        target: "tr_plugin",
        tenant_id = %id,
        "tenants row failed SDK projection (provisioning leak or out-of-domain status)"
    );
    TenantResolverError::Internal("tenant resolver projection failure".to_owned())
}

/// Resolve a single `tenant_type_uuid` to its chained GTS identifier
/// via [`TypesRegistryClient::get_type_schema_by_uuid`].
///
/// Per DESIGN §3.4 (`cpt-cf-tr-plugin-contract-types-registry-reverse-lookup`)
/// and the availability table (§5): "Types Registry unavailable → fail with
/// `TenantResolverError::Internal`; must not return raw UUIDs in place of
/// public `tenant_type`." The detailed cause is logged server-side.
async fn resolve_tenant_type_one(
    registry: &Arc<dyn TypesRegistryClient>,
    type_uuid: Uuid,
) -> Result<String, TenantResolverError> {
    match registry.get_type_schema_by_uuid(type_uuid).await {
        Ok(schema) => Ok(schema.type_id.as_ref().to_owned()),
        Err(err) => {
            tracing::warn!(
                target: "tr_plugin",
                tenant_type_uuid = %type_uuid,
                error = %err,
                "tenant_type uuid -> chained-id resolution failed"
            );
            Err(TenantResolverError::Internal(
                "tenant resolver tenant_type hydration failed".to_owned(),
            ))
        }
    }
}

/// Batched companion to [`resolve_tenant_type_one`]. Issues one
/// `get_type_schemas_by_uuid` round-trip for the *distinct* uuids
/// extracted from `rows` so latency scales with pages, not rows.
///
/// Per DESIGN §3.4 / §5: any per-UUID resolution failure fails the
/// entire call with `TenantResolverError::Internal` (the plugin must
/// not return raw UUIDs in place of public chained `tenant_type`).
async fn resolve_tenant_types_for_rows(
    registry: &Arc<dyn TypesRegistryClient>,
    rows: &[tenants::Model],
) -> Result<HashMap<Uuid, String>, TenantResolverError> {
    let mut distinct: Vec<Uuid> = rows.iter().map(|r| r.tenant_type_uuid).collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.is_empty() {
        return Ok(HashMap::new());
    }
    let resolved = registry.get_type_schemas_by_uuid(distinct).await;
    let mut out: HashMap<Uuid, String> = HashMap::with_capacity(resolved.len());
    for (uuid, res) in resolved {
        match res {
            Ok(schema) => {
                out.insert(uuid, schema.type_id.as_ref().to_owned());
            }
            Err(err) => {
                tracing::warn!(
                    target: "tr_plugin",
                    tenant_type_uuid = %uuid,
                    error = %err,
                    "tenant_type uuid -> chained-id resolution failed"
                );
                return Err(TenantResolverError::Internal(
                    "tenant resolver tenant_type hydration failed".to_owned(),
                ));
            }
        }
    }
    Ok(out)
}

/// Read a single tenant row by id, applying the provisioning-exclusion
/// predicate. Returns `None` when the row is absent or filtered out by
/// the provisioning predicate.
async fn read_tenant_visible(
    db: &Db,
    id: Uuid,
) -> Result<Option<tenants::Model>, TenantResolverError> {
    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    tenants::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenants::Column::Id.eq(id))
                .add(tenants_visible_status_condition()),
        )
        .one(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))
}

/// Bulk-read visible tenants by a set of ids. Provisioning rows are
/// dropped via [`tenants_visible_status_condition`]; the caller is
/// responsible for deduplicating the input slice.
async fn read_tenants_visible_bulk(
    db: &Db,
    ids: &[Uuid],
) -> Result<Vec<tenants::Model>, TenantResolverError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    tenants::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenants::Column::Id.is_in(ids.iter().copied()))
                .add(tenants_visible_status_condition()),
        )
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))
}

/// Phase 3 — `get_tenant`.
pub(super) async fn get_tenant(
    db: &Db,
    registry: &Arc<dyn TypesRegistryClient>,
    id: TenantId,
) -> Result<TenantInfo, TenantResolverError> {
    let row = read_tenant_visible(db, id.0)
        .await?
        .ok_or(TenantResolverError::TenantNotFound { tenant_id: id })?;
    let tenant_type = resolve_tenant_type_one(registry, row.tenant_type_uuid).await?;
    row_to_tenant_info(row, Some(tenant_type)).ok_or_else(|| projection_internal(id.0))
}

/// Phase 4 — `get_root_tenant`.
pub(super) async fn get_root_tenant(
    db: &Db,
    registry: &Arc<dyn TypesRegistryClient>,
) -> Result<TenantInfo, TenantResolverError> {
    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    // `.limit(2)` keeps a corrupted multi-root hierarchy from pulling
    // an unbounded number of rows into memory just to surface the
    // invariant violation; two rows are enough to distinguish the
    // 0 / 1 / many cases for the diagnostic below.
    let mut roots = tenants::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenants::Column::ParentId.is_null())
                .add(tenants_visible_status_condition()),
        )
        .order_by(tenants::Column::Id, Order::Asc)
        .limit(2)
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?;

    match roots.len() {
        0 => {
            tracing::warn!(
                target: "tr_plugin",
                "am storage has no non-provisioning root tenant (bootstrap incomplete or hierarchy corrupt)"
            );
            Err(TenantResolverError::Internal(
                "tenant resolver root tenant unavailable".to_owned(),
            ))
        }
        1 => {
            let row = roots.swap_remove(0);
            let id = row.id;
            let tenant_type = resolve_tenant_type_one(registry, row.tenant_type_uuid).await?;
            row_to_tenant_info(row, Some(tenant_type)).ok_or_else(|| projection_internal(id))
        }
        _ => {
            tracing::warn!(
                target: "tr_plugin",
                "am storage single-root invariant violated: found multiple non-provisioning root tenants"
            );
            Err(TenantResolverError::Internal(
                "tenant resolver root tenant invariant violated".to_owned(),
            ))
        }
    }
}

/// Phase 5 — `get_tenants`.
pub(super) async fn get_tenants(
    db: &Db,
    registry: &Arc<dyn TypesRegistryClient>,
    ids: &[TenantId],
    status_filter: &[SdkTenantStatus],
) -> Result<Vec<TenantInfo>, TenantResolverError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // Dedup while preserving membership; output order is not required
    // to match input order per the SDK contract.
    let mut seen: HashSet<Uuid> = HashSet::with_capacity(ids.len());
    let unique_ids: Vec<Uuid> = ids
        .iter()
        .filter_map(|id| seen.insert(id.0).then_some(id.0))
        .collect();

    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    let rows = tenants::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenants::Column::Id.is_in(unique_ids))
                .add(tenants_status_in_condition(status_filter)),
        )
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?;

    let type_strings = resolve_tenant_types_for_rows(registry, &rows).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row.id;
        let tenant_type = type_strings.get(&row.tenant_type_uuid).cloned();
        out.push(row_to_tenant_info(row, tenant_type).ok_or_else(|| projection_internal(id))?);
    }
    Ok(out)
}

/// Phase 6 — `is_ancestor`.
pub(super) async fn is_ancestor(
    db: &Db,
    ancestor_id: TenantId,
    descendant_id: TenantId,
    barrier_mode: BarrierMode,
) -> Result<bool, TenantResolverError> {
    // Probe both endpoints exist and are non-provisioning. Use a
    // single bulk read so the round-trip count stays at 2 indexed
    // reads (existence probe + closure probe) per call, matching
    // DESIGN §3.6 `seq-is-ancestor`. An `IN (a, d)` bulk lookup
    // followed by a HashSet check on the returned ids handles both
    // the absent and provisioning cases uniformly.
    let probe_ids = if ancestor_id == descendant_id {
        vec![ancestor_id.0]
    } else {
        vec![ancestor_id.0, descendant_id.0]
    };
    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    let visible: HashSet<Uuid> = tenants::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(
            Condition::all()
                .add(tenants::Column::Id.is_in(probe_ids.iter().copied()))
                .add(tenants_visible_status_condition()),
        )
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?
        .into_iter()
        .map(|r| r.id)
        .collect();
    if !visible.contains(&ancestor_id.0) || !visible.contains(&descendant_id.0) {
        // SDK contract: `TenantNotFound` when either endpoint is
        // absent. We blame the descendant id; the SDK does not
        // distinguish which endpoint was missing.
        let missing = if visible.contains(&ancestor_id.0) {
            descendant_id
        } else {
            ancestor_id
        };
        return Err(TenantResolverError::TenantNotFound { tenant_id: missing });
    }
    if ancestor_id == descendant_id {
        // Strict-descendant contract: self is not an ancestor of self.
        // Returned after the visibility check so callers can still
        // distinguish "absent" from "self".
        return Ok(false);
    }

    // Self-row exclusion is implicit: the self-reference branch above
    // already returned `Ok(false)` when `ancestor_id == descendant_id`,
    // so the `(ancestor_id, descendant_id)` pair queried here is always
    // strict.
    let mut filter = Condition::all()
        .add(tenant_closure::Column::AncestorId.eq(ancestor_id.0))
        .add(tenant_closure::Column::DescendantId.eq(descendant_id.0));
    if matches!(barrier_mode, BarrierMode::Respect) {
        filter = filter.add(tenant_closure::Column::Barrier.eq(0_i16));
    }

    let count = tenant_closure::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(filter)
        .count(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?;
    Ok(count > 0)
}

/// Phase 7 — `get_ancestors`.
pub(super) async fn get_ancestors(
    db: &Db,
    registry: &Arc<dyn TypesRegistryClient>,
    id: TenantId,
    barrier_mode: BarrierMode,
) -> Result<GetAncestorsResponse, TenantResolverError> {
    let starting = read_tenant_visible(db, id.0)
        .await?
        .ok_or(TenantResolverError::TenantNotFound { tenant_id: id })?;

    // Closure rows for strict ancestors of `id`. Self-row is
    // excluded by predicate; under `Respect` the barrier filter is
    // appended so the returned set already obeys
    // `cpt-cf-tr-plugin-fr-barrier-semantics`.
    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    let mut closure_filter = Condition::all()
        .add(tenant_closure::Column::DescendantId.eq(id.0))
        .add(tenant_closure::Column::AncestorId.ne(id.0));
    if matches!(barrier_mode, BarrierMode::Respect) {
        closure_filter = closure_filter.add(tenant_closure::Column::Barrier.eq(0_i16));
    }
    let closure_rows = tenant_closure::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(closure_filter)
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?;
    let ancestor_ids: Vec<Uuid> = closure_rows.iter().map(|r| r.ancestor_id).collect();
    let _ = conn;

    // Hydrate ancestors. Provisioning rows are dropped on this read
    // as defense-in-depth — closure-driven reads can't surface
    // provisioning by AM's contract, but the explicit predicate
    // keeps the contract local.
    let ancestor_rows = read_tenants_visible_bulk(db, &ancestor_ids).await?;

    // Order: depth DESC (direct parent first, root last) with `id`
    // ASC as tie-break. Ordering happens here because we hydrated
    // through a bulk-by-id read instead of a JOIN; the two-call shape
    // is what the secure-extension's per-entity contract permits today.
    let mut sorted = ancestor_rows;
    sorted.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.id.cmp(&b.id)));

    // Hydrate `tenant_type` for the starting tenant + every ancestor
    // in one batched registry round-trip.
    let mut all_rows: Vec<tenants::Model> = Vec::with_capacity(sorted.len() + 1);
    all_rows.push(starting.clone());
    all_rows.extend_from_slice(&sorted);
    let type_strings = resolve_tenant_types_for_rows(registry, &all_rows).await?;

    let starting_ref = row_to_tenant_ref(
        &starting,
        type_strings.get(&starting.tenant_type_uuid).cloned(),
    )
    .ok_or_else(|| projection_internal(id.0))?;
    let mut ancestors = Vec::with_capacity(sorted.len());
    for row in &sorted {
        let tt = type_strings.get(&row.tenant_type_uuid).cloned();
        ancestors.push(row_to_tenant_ref(row, tt).ok_or_else(|| projection_internal(row.id))?);
    }
    Ok(GetAncestorsResponse {
        tenant: starting_ref,
        ancestors,
    })
}

/// Phase 8 — `get_descendants`.
///
/// # Filtering split: graph (system invariants) vs emission (caller predicate)
///
/// The closure scan applies **only** system invariants:
/// `(ancestor_id, descendant_id != ancestor_id)` plus the barrier
/// predicate when `BarrierMode::Respect`. The closure table already
/// excludes provisioning by AM's contract
/// (`descendant_status ∈ {1, 2, 3}`), so the scan returns the
/// barrier-bounded SDK-visible subtree without folding in the
/// caller's `status_filter`. Caller status is applied as an
/// **emission** predicate during the in-memory walk: the graph
/// remains coherent even when an intermediate parent fails the
/// caller's filter (e.g. `Root → Suspended → Active` filtered by
/// `[Active]` correctly yields `Active`).
///
/// # Cycle protection
///
/// `parent_id` cycles are an AM invariant violation, but the walk
/// runs on the auth hot path and must fail closed instead of
/// hanging. A `visited: HashSet<Uuid>` short-circuits any revisit.
///
/// # Implementation
///
/// 1. Closure-driven probe of the subtree (`barrier` only).
/// 2. Bulk hydrate the descendant `tenants` rows (defense-in-depth
///    provisioning predicate applied on the row read).
/// 3. Build a `parent_id → children` map and walk pre-order from
///    the starting tenant, bounded by `max_depth`, with
///    `visited`-based cycle protection.
/// 4. Emit a node iff its `tenants.status` matches the caller's
///    `status_filter` (empty = all SDK-visible statuses) per FEATURE
///    §3 `algo-…-descendant-bounded-preorder`.
#[allow(
    clippy::cognitive_complexity,
    reason = "single linear pipeline (closure scan → bulk hydrate → graph build → tenant_type batch resolve → DFS with cycle/depth/emit predicates) whose stages share state; splitting would only obscure the per-stage docstrings above"
)]
pub(super) async fn get_descendants(
    db: &Db,
    registry: &Arc<dyn TypesRegistryClient>,
    id: TenantId,
    barrier_mode: BarrierMode,
    status_filter: &[SdkTenantStatus],
    max_depth: Option<u32>,
) -> Result<GetDescendantsResponse, TenantResolverError> {
    let starting = read_tenant_visible(db, id.0)
        .await?
        .ok_or(TenantResolverError::TenantNotFound { tenant_id: id })?;

    let conn = db.conn().map_err(|e| modkit_db_err_to_tr_err(&e))?;
    // System-invariant filter only: ancestor pivot + strict-descendant
    // exclusion + (optional) barrier. Caller's `status_filter` is
    // intentionally NOT folded in here — see the top-of-fn doc for the
    // graph-vs-emission rationale.
    let mut closure_filter = Condition::all()
        .add(tenant_closure::Column::AncestorId.eq(id.0))
        .add(tenant_closure::Column::DescendantId.ne(id.0));
    if matches!(barrier_mode, BarrierMode::Respect) {
        closure_filter = closure_filter.add(tenant_closure::Column::Barrier.eq(0_i16));
    }
    let closure_rows = tenant_closure::Entity::find()
        .secure()
        .scope_with(&AccessScope::allow_all())
        .filter(closure_filter)
        .all(&conn)
        .await
        .map_err(|e| scope_err_to_tr_err(&e))?;

    // Release the borrowed DbConn before re-acquiring inside the bulk
    // read — `Db::conn()` short-circuits on an active task-local
    // transaction guard, so holding two simultaneous borrows is
    // unnecessary even if the type-level lifetime would permit it.
    let _ = conn;

    let descendant_ids: Vec<Uuid> = closure_rows.iter().map(|r| r.descendant_id).collect();
    let descendant_rows = read_tenants_visible_bulk(db, &descendant_ids).await?;

    // Compile the caller's status filter into an O(1) emission
    // predicate. Empty input means "all SDK-visible statuses".
    let user_statuses: Option<HashSet<SdkTenantStatus>> = if status_filter.is_empty() {
        None
    } else {
        Some(status_filter.iter().copied().collect())
    };
    let emit_allowed = |status: SdkTenantStatus| -> bool {
        user_statuses
            .as_ref()
            .is_none_or(|set| set.contains(&status))
    };

    // Build id→row and parent_id→children maps from the *full*
    // barrier-bounded SDK-visible subtree. Sorting children by id ASC
    // gives a deterministic SDK pre-order without per-node sorting at
    // walk time.
    let row_by_id: HashMap<Uuid, tenants::Model> =
        descendant_rows.into_iter().map(|r| (r.id, r)).collect();
    let mut children_by_parent: HashMap<Uuid, Vec<Uuid>> = HashMap::with_capacity(row_by_id.len());
    for row in row_by_id.values() {
        if let Some(parent) = row.parent_id {
            children_by_parent.entry(parent).or_default().push(row.id);
        }
    }
    for v in children_by_parent.values_mut() {
        v.sort_unstable();
    }

    // Hydrate `tenant_type` for every row we *might* emit (the entire
    // graph) plus the starting tenant in a single batched
    // `get_type_schemas_by_uuid` round-trip. Hydrating the whole
    // graph (rather than only the emit set) is intentional — distinct
    // tenant_type uuids are typically a small number relative to the
    // row count, and pre-resolving avoids a second registry round-trip
    // when a deep emission set straddles many types.
    let mut hydrate_pool: Vec<tenants::Model> = Vec::with_capacity(row_by_id.len() + 1);
    hydrate_pool.push(starting.clone());
    for row in row_by_id.values() {
        hydrate_pool.push(row.clone());
    }
    let type_strings = resolve_tenant_types_for_rows(registry, &hydrate_pool).await?;

    // Pre-order walk from the starting tenant. Iterative stack avoids
    // unbounded recursion on deep hierarchies. Stack entries are
    // `(node_id, depth_from_start)`: starting tenant is conceptually
    // depth 0, its children depth 1, so `max_depth = Some(N)` admits
    // nodes with `depth_from_start ∈ [1, N]`.
    //
    // `visited` provides cycle protection: `parent_id` cycles are an
    // AM invariant violation, but the walk is on the auth hot path
    // and must fail closed rather than spin forever on corrupted data.
    // The starting tenant is pre-marked so a back-edge to it from
    // some descendant cannot revisit.
    let mut emitted: Vec<TenantRef> = Vec::with_capacity(row_by_id.len());
    let mut stack: Vec<(Uuid, u32)> = Vec::new();
    let mut visited: HashSet<Uuid> = HashSet::with_capacity(row_by_id.len() + 1);
    visited.insert(id.0);

    if let Some(initial_children) = children_by_parent.get(&id.0) {
        for child in initial_children.iter().rev() {
            stack.push((*child, 1));
        }
    }
    while let Some((node_id, depth)) = stack.pop() {
        if !visited.insert(node_id) {
            tracing::warn!(
                target: "tr_plugin",
                tenant_id = %node_id,
                pivot = %id.0,
                "tenant_closure / parent_id graph revisit detected during pre-order walk; \
                 short-circuiting to avoid unbounded loop (hierarchy invariant violation)"
            );
            continue;
        }
        if max_depth.is_some_and(|limit| depth > limit) {
            continue;
        }
        let Some(row) = row_by_id.get(&node_id) else {
            continue;
        };
        let Some(domain_status) =
            crate::domain::tenant::model::TenantStatus::from_smallint(row.status)
        else {
            return Err(projection_internal(node_id));
        };
        let Some(sdk_status) = super::projection::map_status_to_sdk(domain_status) else {
            return Err(projection_internal(node_id));
        };
        if emit_allowed(sdk_status) {
            let tt = type_strings.get(&row.tenant_type_uuid).cloned();
            emitted.push(row_to_tenant_ref(row, tt).ok_or_else(|| projection_internal(node_id))?);
        }
        if let Some(children) = children_by_parent.get(&node_id) {
            for child in children.iter().rev() {
                stack.push((*child, depth.saturating_add(1)));
            }
        }
    }

    let starting_ref = row_to_tenant_ref(
        &starting,
        type_strings.get(&starting.tenant_type_uuid).cloned(),
    )
    .ok_or_else(|| projection_internal(id.0))?;
    Ok(GetDescendantsResponse {
        tenant: starting_ref,
        descendants: emitted,
    })
}
