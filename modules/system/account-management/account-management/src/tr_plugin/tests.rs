//! Integration tests for the `tr_plugin` module.
//!
//! Each test spins up a fresh in-memory `SQLite` database, seeds the
//! `tenants` / `tenant_closure` tables directly, and exercises
//! `PluginImpl` through the `TenantResolverPluginClient` trait.
//!
//! The two registry stubs (`TestRegistry { fail: false/true }`) cover
//! every call-site the plugin makes against `TypesRegistryClient`:
//! `get_type_schema_by_uuid` (single) and `get_type_schemas_by_uuid`
//! (batch). All other trait methods panic — if the plugin ever calls
//! them unexpectedly the test fails loudly.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    dead_code
)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use modkit_db::migration_runner::run_migrations_for_testing;
use modkit_db::secure::secure_insert;
use modkit_db::{ConnectOpts, Db, connect_db};
use modkit_security::{AccessScope, SecurityContext};
use sea_orm::ActiveValue;
use tenant_resolver_sdk::{
    BarrierMode, GetAncestorsOptions, GetDescendantsOptions, GetTenantsOptions, IsAncestorOptions,
    TenantId, TenantResolverError, TenantResolverPluginClient, TenantStatus as SdkStatus,
};
use time::OffsetDateTime;
use types_registry_sdk::TypesRegistryClient;
use types_registry_sdk::error::TypesRegistryError;
use types_registry_sdk::models::{
    GtsInstance, GtsTypeSchema, InstanceQuery, RegisterResult, TypeSchemaQuery,
};
use types_registry_sdk::testing::make_test_type_schema;
use uuid::Uuid;

use sea_orm_migration::MigratorTrait as _;

use super::PluginImpl;
use crate::Migrator;
use crate::infra::storage::entity::{tenant_closure, tenants};

// ── Status constants (mirror domain::tenant::model::TenantStatus SMALLINT) ──

const PROVISIONING: i16 = 0;
const ACTIVE: i16 = 1;
const SUSPENDED: i16 = 2;
const DELETED: i16 = 3;

// ── Registry stubs ────────────────────────────────────────────────────────

const TEST_TYPE_ID: &str = "gts.cf.core.test.tenant.v1~";

/// Dual-mode stub: when `fail=false` it returns a fixed `GtsTypeSchema` for
/// any UUID; when `fail=true` every lookup returns `GtsTypeSchemaNotFound`.
struct TestRegistry {
    fail: bool,
}

impl TestRegistry {
    fn ok() -> Arc<dyn TypesRegistryClient> {
        Arc::new(Self { fail: false })
    }

    fn fail() -> Arc<dyn TypesRegistryClient> {
        Arc::new(Self { fail: true })
    }
}

#[async_trait]
impl TypesRegistryClient for TestRegistry {
    async fn get_type_schema_by_uuid(
        &self,
        _uuid: Uuid,
    ) -> std::result::Result<GtsTypeSchema, TypesRegistryError> {
        if self.fail {
            Err(TypesRegistryError::gts_type_schema_not_found("test"))
        } else {
            Ok(make_test_type_schema(TEST_TYPE_ID))
        }
    }

    async fn get_type_schemas_by_uuid(
        &self,
        uuids: Vec<Uuid>,
    ) -> HashMap<Uuid, std::result::Result<GtsTypeSchema, TypesRegistryError>> {
        uuids
            .into_iter()
            .map(|u| {
                let res = if self.fail {
                    Err(TypesRegistryError::gts_type_schema_not_found("test"))
                } else {
                    Ok(make_test_type_schema(TEST_TYPE_ID))
                };
                (u, res)
            })
            .collect()
    }

    async fn register(
        &self,
        _: Vec<serde_json::Value>,
    ) -> std::result::Result<Vec<RegisterResult>, TypesRegistryError> {
        unimplemented!("tr_plugin does not call register")
    }

    async fn register_type_schemas(
        &self,
        _: Vec<serde_json::Value>,
    ) -> std::result::Result<Vec<RegisterResult>, TypesRegistryError> {
        unimplemented!("tr_plugin does not call register_type_schemas")
    }

    async fn get_type_schema(
        &self,
        _: &str,
    ) -> std::result::Result<GtsTypeSchema, TypesRegistryError> {
        unimplemented!("tr_plugin does not call get_type_schema by string id")
    }

    async fn get_type_schemas(
        &self,
        _: Vec<String>,
    ) -> HashMap<String, std::result::Result<GtsTypeSchema, TypesRegistryError>> {
        unimplemented!("tr_plugin does not call get_type_schemas by string ids")
    }

    async fn list_type_schemas(
        &self,
        _: TypeSchemaQuery,
    ) -> std::result::Result<Vec<GtsTypeSchema>, TypesRegistryError> {
        unimplemented!("tr_plugin does not call list_type_schemas")
    }

    async fn register_instances(
        &self,
        _: Vec<serde_json::Value>,
    ) -> std::result::Result<Vec<RegisterResult>, TypesRegistryError> {
        unimplemented!("tr_plugin does not call register_instances")
    }

    async fn get_instance(&self, _: &str) -> std::result::Result<GtsInstance, TypesRegistryError> {
        unimplemented!("tr_plugin does not call get_instance")
    }

    async fn get_instance_by_uuid(
        &self,
        _: Uuid,
    ) -> std::result::Result<GtsInstance, TypesRegistryError> {
        unimplemented!("tr_plugin does not call get_instance_by_uuid")
    }

    async fn get_instances(
        &self,
        _: Vec<String>,
    ) -> HashMap<String, std::result::Result<GtsInstance, TypesRegistryError>> {
        unimplemented!("tr_plugin does not call get_instances")
    }

    async fn get_instances_by_uuid(
        &self,
        _: Vec<Uuid>,
    ) -> HashMap<Uuid, std::result::Result<GtsInstance, TypesRegistryError>> {
        unimplemented!("tr_plugin does not call get_instances_by_uuid")
    }

    async fn list_instances(
        &self,
        _: InstanceQuery,
    ) -> std::result::Result<Vec<GtsInstance>, TypesRegistryError> {
        unimplemented!("tr_plugin does not call list_instances")
    }
}

// ── Harness helpers ───────────────────────────────────────────────────────

/// Spin up an in-memory `SQLite` DB, run AM migrations, and return the `Db`
/// handle. The same `Db` is shared between the seed helpers and the plugin
/// (both use `Arc<DbHandle>` internally via `Db::clone()`).
async fn setup() -> Result<Db> {
    // SQLite's `:memory:` DSN creates a *distinct* private in-memory
    // database per pooled connection. Combined with `ConnectOpts`'s
    // default `max_conns = 10`, migrations could land on connection A
    // while queries hit connection B → empty database, missing tables.
    // Pinning the pool to a single connection is the canonical
    // workaround (the alternative is a shared-cache URI like
    // `sqlite:file:am_test?mode=memory&cache=shared`); this matches
    // the pattern used by `resource-group` / `mini-chat` / outbox
    // integration tests in this repo.
    let opts = ConnectOpts {
        max_conns: Some(1),
        ..ConnectOpts::default()
    };
    let db = connect_db("sqlite::memory:", opts).await?;
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(db)
}

/// Build a `PluginImpl` backed by `db` with the given registry mode.
fn make_plugin(db: Db, fail_registry: bool) -> PluginImpl {
    let registry = if fail_registry {
        TestRegistry::fail()
    } else {
        TestRegistry::ok()
    };
    PluginImpl::new(db, registry)
}

/// Anonymous `SecurityContext` — the plugin ignores it per DESIGN §4.2.
fn ctx() -> SecurityContext {
    SecurityContext::anonymous()
}

/// Insert one tenant row directly (bypassing the create-tenant saga).
async fn insert_tenant(
    db: &Db,
    id: Uuid,
    parent_id: Option<Uuid>,
    status: i16,
    depth: i32,
) -> Result<()> {
    let conn = db.conn().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let now = OffsetDateTime::now_utc();
    let am = tenants::ActiveModel {
        id: ActiveValue::Set(id),
        parent_id: ActiveValue::Set(parent_id),
        name: ActiveValue::Set(format!("test-{id}")),
        status: ActiveValue::Set(status),
        self_managed: ActiveValue::Set(false),
        tenant_type_uuid: ActiveValue::Set(Uuid::nil()),
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
    secure_insert::<tenants::Entity>(am, &AccessScope::allow_all(), &conn)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(())
}

/// Insert one `tenant_closure` row directly.
async fn insert_closure(
    db: &Db,
    ancestor_id: Uuid,
    descendant_id: Uuid,
    barrier: i16,
    descendant_status: i16,
) -> Result<()> {
    let conn = db.conn().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let am = tenant_closure::ActiveModel {
        ancestor_id: ActiveValue::Set(ancestor_id),
        descendant_id: ActiveValue::Set(descendant_id),
        barrier: ActiveValue::Set(barrier),
        descendant_status: ActiveValue::Set(descendant_status),
    };
    secure_insert::<tenant_closure::Entity>(am, &AccessScope::allow_all(), &conn)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(())
}

/// Seed a single-root tenant with its self-row.
///
/// Provisioning tenants have no closure rows by AM's contract
/// (`tenant_closure.descendant_status IN (1,2,3)` CHECK constraint).
/// Pass `status = ACTIVE` / `SUSPENDED` / `DELETED` — not `PROVISIONING`.
async fn seed_root(db: &Db, status: i16) -> Result<Uuid> {
    assert_ne!(
        status, PROVISIONING,
        "seed_root: provisioning roots have no closure rows; use insert_tenant directly"
    );
    let root = Uuid::new_v4();
    insert_tenant(db, root, None, status, 0).await?;
    insert_closure(db, root, root, 0, status).await?;
    Ok(root)
}

/// Seed a two-level tree (root → child) with all required closure rows.
/// Returns `(root, child)`.
async fn seed_two_level(db: &Db, root_status: i16, child_status: i16) -> Result<(Uuid, Uuid)> {
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(db, root, None, root_status, 0).await?;
    insert_tenant(db, child, Some(root), child_status, 1).await?;
    insert_closure(db, root, root, 0, root_status).await?;
    insert_closure(db, child, child, 0, child_status).await?;
    insert_closure(db, root, child, 0, child_status).await?;
    Ok((root, child))
}

// ── Tests: get_tenant ─────────────────────────────────────────────────────

#[tokio::test]
async fn get_tenant_returns_info() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let info = plugin.get_tenant(&ctx(), TenantId(root)).await.unwrap();

    assert_eq!(info.id.0, root);
    assert_eq!(info.status, SdkStatus::Active);
    assert!(info.parent_id.is_none());
    assert!(
        info.tenant_type.is_some(),
        "registry must hydrate tenant_type"
    );
}

#[tokio::test]
async fn get_tenant_not_found() {
    let db = setup().await.unwrap();
    let missing = Uuid::new_v4();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_tenant(&ctx(), TenantId(missing))
        .await
        .unwrap_err();

    assert!(
        matches!(err, TenantResolverError::TenantNotFound { .. }),
        "expected TenantNotFound, got {err:?}"
    );
}

// ── Tests: provisioning invisibility ─────────────────────────────────────

#[tokio::test]
async fn provisioning_hidden_from_get_tenant() {
    let db = setup().await.unwrap();
    let id = Uuid::new_v4();
    // Provisioning tenants have no closure rows (descendant_status CHECK constraint
    // allows only 1/2/3). The tenant row exists; the status predicate hides it.
    insert_tenant(&db, id, None, PROVISIONING, 0).await.unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin.get_tenant(&ctx(), TenantId(id)).await.unwrap_err();
    assert!(matches!(err, TenantResolverError::TenantNotFound { .. }));
}

#[tokio::test]
async fn provisioning_only_root_yields_internal_error() {
    let db = setup().await.unwrap();
    // Only row in the DB is a provisioning tenant with parent_id=None.
    // No closure rows (AM invariant). get_root_tenant must return Internal
    // because the provisioning-visibility predicate hides it.
    insert_tenant(&db, Uuid::new_v4(), None, PROVISIONING, 0)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin.get_root_tenant(&ctx()).await.unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "expected Internal when no non-provisioning root; got {err:?}"
    );
}

#[tokio::test]
async fn provisioning_hidden_from_is_ancestor_as_ancestor() {
    let db = setup().await.unwrap();
    let anc = Uuid::new_v4(); // provisioning
    let desc = Uuid::new_v4(); // active
    // Provisioning tenants have no closure rows by AM invariant.
    insert_tenant(&db, anc, None, PROVISIONING, 0)
        .await
        .unwrap();
    insert_tenant(&db, desc, Some(anc), ACTIVE, 1)
        .await
        .unwrap();
    insert_closure(&db, desc, desc, 0, ACTIVE).await.unwrap();
    // (anc, desc) closure row: descendant_status=ACTIVE is valid, but we omit
    // it to match AM's invariant that provisioning tenants have no closure rows.

    let plugin = make_plugin(db, false);
    // The existence check reads tenants with status != PROVISIONING;
    // anc is filtered → TenantNotFound.
    let err = plugin
        .is_ancestor(
            &ctx(),
            TenantId(anc),
            TenantId(desc),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::TenantNotFound { .. }));
}

#[tokio::test]
async fn provisioning_hidden_from_is_ancestor_as_descendant() {
    let db = setup().await.unwrap();
    let anc = Uuid::new_v4(); // active root
    let desc = Uuid::new_v4(); // provisioning child
    insert_tenant(&db, anc, None, ACTIVE, 0).await.unwrap();
    // desc is provisioning: no closure rows (AM invariant + CHECK constraint).
    insert_tenant(&db, desc, Some(anc), PROVISIONING, 1)
        .await
        .unwrap();
    insert_closure(&db, anc, anc, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    // Existence check reads tenants with status != PROVISIONING; desc filtered → TenantNotFound.
    let err = plugin
        .is_ancestor(
            &ctx(),
            TenantId(anc),
            TenantId(desc),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::TenantNotFound { .. }));
}

#[tokio::test]
async fn provisioning_hidden_from_get_tenants() {
    let db = setup().await.unwrap();
    let active_id = Uuid::new_v4();
    let prov_id = Uuid::new_v4();
    insert_tenant(&db, active_id, None, ACTIVE, 0)
        .await
        .unwrap();
    // prov_id is a provisioning child (non-root to avoid the unique-root constraint).
    // No closure rows for provisioning tenants.
    insert_tenant(&db, prov_id, Some(active_id), PROVISIONING, 1)
        .await
        .unwrap();
    insert_closure(&db, active_id, active_id, 0, ACTIVE)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);
    let result = plugin
        .get_tenants(
            &ctx(),
            &[TenantId(active_id), TenantId(prov_id)],
            &GetTenantsOptions { status: vec![] },
        )
        .await
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id.0, active_id);
}

#[tokio::test]
async fn provisioning_parent_yields_empty_ancestors() {
    // Hierarchy: provisioning_root → active_child.
    // Per AM's invariant a provisioning tenant carries NO closure
    // rows (in either direction), so `tenant_closure` only contains
    // the child's self-row. `get_ancestors(child)` therefore reads
    // an empty closure set (after self-exclusion) and emits an
    // empty ancestor list — the provisioning-invisibility property
    // is delivered structurally by AM's writer, not by a downstream
    // filter.
    let db = setup().await.unwrap();
    let prov_root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&db, prov_root, None, PROVISIONING, 0)
        .await
        .unwrap();
    insert_tenant(&db, child, Some(prov_root), ACTIVE, 1)
        .await
        .unwrap();
    // Only the child's self-row — no closure rows reference
    // `prov_root` because it is provisioning.
    insert_closure(&db, child, child, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_ancestors(
            &ctx(),
            TenantId(child),
            &GetAncestorsOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();

    assert_eq!(resp.tenant.id.0, child);
    assert!(
        resp.ancestors.is_empty(),
        "provisioning parent must not appear in ancestors"
    );
}

#[tokio::test]
async fn corrupt_closure_to_provisioning_ancestor_yields_internal() {
    // Defense-in-depth: AM's writer is contractually required to
    // remove every closure row referencing a tenant that becomes
    // provisioning, but if the on-disk state ever diverges from
    // that invariant — bug, partial migration, manual surgery — the
    // plugin MUST surface `Internal` rather than silently truncate
    // the ancestor chain. This test deliberately seeds corrupt data
    // (a closure row from a `provisioning` ancestor to an `active`
    // descendant) and asserts the fail-closed surface.
    let db = setup().await.unwrap();
    let prov_root = Uuid::new_v4();
    let child = Uuid::new_v4();
    insert_tenant(&db, prov_root, None, PROVISIONING, 0)
        .await
        .unwrap();
    insert_tenant(&db, child, Some(prov_root), ACTIVE, 1)
        .await
        .unwrap();
    insert_closure(&db, child, child, 0, ACTIVE).await.unwrap();
    // Corrupt: closure row whose ancestor is provisioning. The
    // CHECK constraint on `descendant_status` accepts the row
    // (descendant is ACTIVE), and AM's writer would normally
    // never produce it — that is exactly the corruption the
    // plugin needs to fail closed on.
    insert_closure(&db, prov_root, child, 0, ACTIVE)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_ancestors(
            &ctx(),
            TenantId(child),
            &GetAncestorsOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "corrupt closure → provisioning ancestor must surface as Internal; got {err:?}"
    );
}

#[tokio::test]
async fn provisioning_start_hidden_from_get_descendants() {
    let db = setup().await.unwrap();
    let prov = Uuid::new_v4();
    // Provisioning tenant — no closure rows (AM invariant + CHECK constraint).
    insert_tenant(&db, prov, None, PROVISIONING, 0)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_descendants(
            &ctx(),
            TenantId(prov),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::TenantNotFound { .. }));
}

#[tokio::test]
async fn corrupt_closure_to_provisioning_descendant_yields_internal() {
    // Symmetric companion to
    // `corrupt_closure_to_provisioning_ancestor_yields_internal`:
    // here the corrupt row is on the descendant side. AM's writer
    // contractually removes every closure row referencing a tenant
    // that becomes provisioning; if on-disk state diverges, the
    // bulk-hydrate vs closure-id-set check inside `get_descendants`
    // MUST surface `Internal` rather than silently truncate the
    // emitted subtree.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let prov_child = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, prov_child, Some(root), PROVISIONING, 1)
        .await
        .unwrap();
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    // Corrupt: closure row whose descendant is provisioning. The
    // CHECK constraint on `descendant_status` would normally
    // reject `descendant_status = PROVISIONING (=0)`, but stamping
    // `ACTIVE` here lets the row land in storage while the
    // referenced `tenants` row carries `PROVISIONING` — exactly
    // the hydration mismatch the fail-close defends against.
    insert_closure(&db, root, prov_child, 0, ACTIVE)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "corrupt closure → provisioning descendant must surface as Internal; got {err:?}"
    );
}

// NOTE on the `visited.insert` revisit branch: structurally
// unreachable in valid `tenants` data because every row carries
// exactly one `parent_id`, so each node appears in exactly one
// `children_by_parent[parent]` entry and the walk pushes any given
// node at most once. The check exists as a paranoid guard against
// a future refactor that might break the single-parent invariant
// (e.g., a multi-parent tenant model). It is therefore covered by
// inspection rather than by an end-to-end test — every corruption
// shape we *can* construct from valid `(tenants, tenant_closure)`
// rows surfaces through the bulk-hydrate consistency check or the
// post-walk completeness check below, both of which ARE tested.

#[tokio::test]
async fn unreachable_closure_descendant_yields_internal() {
    // Hierarchy corruption where closure asserts X is a descendant
    // of pivot but X's parent_id chain never reaches pivot. The
    // post-walk completeness check must catch this: closure
    // hydrate succeeds (X resolves to a visible tenants row), but
    // the `parent_id` walk never visits X. With `max_depth = None`
    // the bound is unconstrained, so every closure descendant
    // MUST be visited. Setup: pivot=root, child reachable normally
    // (root → child), orphan in closure but its parent_id points
    // to a separate active tenant outside the subtree.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    let outsider = Uuid::new_v4();
    let orphan = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, child, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    // `outsider` is a separate ACTIVE tenant not in the test
    // subtree (we cheat: SQLite's partial unique-root index forbids
    // a second null-parent, so we make outsider a child of root
    // too). Its only role is to be `orphan.parent_id` so the walk
    // from `root` reaches `outsider` AND `child` legitimately.
    // The corruption is the closure row asserting `(root, orphan)`
    // when no such parent_id chain exists from the orphan back to
    // root through any descendant of root.
    insert_tenant(&db, outsider, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    // `orphan.parent_id = outsider` makes the parent_id walk from
    // root reach orphan via outsider — so this isn't actually
    // unreachable. We need orphan.parent_id pointing to a node
    // NOT under root's subtree. The cleanest construction is to
    // dangle the orphan: parent_id = orphan itself (self-parent),
    // which the walker never reaches from root.
    insert_tenant(&db, orphan, Some(orphan), ACTIVE, 99)
        .await
        .unwrap();
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    insert_closure(&db, child, child, 0, ACTIVE).await.unwrap();
    insert_closure(&db, outsider, outsider, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&db, orphan, orphan, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, child, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, outsider, 0, ACTIVE).await.unwrap();
    // Corrupt: closure asserts orphan is a descendant of root,
    // but orphan.parent_id is itself (no chain to root).
    insert_closure(&db, root, orphan, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "closure descendant unreachable via parent_id walk must surface as Internal; got {err:?}"
    );
}

#[tokio::test]
async fn unreachable_in_bound_descendant_with_max_depth_yields_internal() {
    // Companion to `unreachable_closure_descendant_yields_internal`
    // covering the bounded path: an unreachable closure descendant
    // that falls WITHIN the requested `max_depth` envelope MUST
    // still surface `Internal`. A descendant outside the depth
    // envelope (legitimate trim) does NOT surface — that case is
    // covered separately by `get_descendants_max_depth_limits_traversal`.
    //
    // Setup: root → child (depth 1, normal), plus orphan at
    // depth 1 in closure with parent_id = self (unreachable).
    // Walk with `max_depth = Some(1)` should still flag orphan
    // as in-bound-but-unreachable.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    let orphan = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, child, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    // orphan: depth=1 (in-bound for max_depth=1), parent_id=self.
    insert_tenant(&db, orphan, Some(orphan), ACTIVE, 1)
        .await
        .unwrap();
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    insert_closure(&db, child, child, 0, ACTIVE).await.unwrap();
    insert_closure(&db, orphan, orphan, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, child, 0, ACTIVE).await.unwrap();
    // Corrupt: closure says orphan is descendant of root.
    insert_closure(&db, root, orphan, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let err = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: Some(1),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "in-bound unreachable descendant under max_depth must surface as Internal; got {err:?}"
    );
}

// ── Tests: get_root_tenant ────────────────────────────────────────────────

#[tokio::test]
async fn get_root_tenant_finds_single_root() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let info = plugin.get_root_tenant(&ctx()).await.unwrap();
    assert_eq!(info.id.0, root);
}

#[tokio::test]
async fn get_root_tenant_no_root_yields_internal_error() {
    let db = setup().await.unwrap();
    // Empty DB — no tenant rows at all.
    let plugin = make_plugin(db, false);
    let err = plugin.get_root_tenant(&ctx()).await.unwrap_err();
    assert!(matches!(err, TenantResolverError::Internal(_)));
}

// NOTE: the "multiple roots → Internal" branch of get_root_tenant cannot be
// exercised on SQLite because the `ux_tenants_single_root` partial unique
// index (WHERE parent_id IS NULL) prevents a second root row from being
// inserted. The Postgres harness in `tests/lifecycle_integration_pg.rs` is
// the right place for that case once the pg feature is available.

// ── Tests: get_tenants ────────────────────────────────────────────────────

#[tokio::test]
async fn get_tenants_deduplicates_input_ids() {
    let db = setup().await.unwrap();
    let (root, _child) = seed_two_level(&db, ACTIVE, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    // Pass the root ID three times.
    let result = plugin
        .get_tenants(
            &ctx(),
            &[TenantId(root), TenantId(root), TenantId(root)],
            &GetTenantsOptions { status: vec![] },
        )
        .await
        .unwrap();

    assert_eq!(result.len(), 1, "duplicate IDs must be deduplicated");
    assert_eq!(result[0].id.0, root);
}

#[tokio::test]
async fn get_tenants_status_filter() {
    let db = setup().await.unwrap();
    let (root, child) = seed_two_level(&db, ACTIVE, SUSPENDED).await.unwrap();

    let plugin = make_plugin(db, false);
    let active_only = plugin
        .get_tenants(
            &ctx(),
            &[TenantId(root), TenantId(child)],
            &GetTenantsOptions {
                status: vec![SdkStatus::Active],
            },
        )
        .await
        .unwrap();

    assert_eq!(active_only.len(), 1);
    assert_eq!(active_only[0].id.0, root);
}

#[tokio::test]
async fn get_tenants_empty_status_equals_all_visible() {
    // The `tenants_status_in_condition` projection treats an empty
    // `status` slice as "all SDK-visible statuses" by short-circuiting
    // to the bare provisioning-exclusion predicate. This test pins
    // that equivalence behaviorally: passing `vec![]` and passing
    // `vec![Active, Suspended, Deleted]` must yield the same row set
    // for the same `(ids, db)` pair.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let sus = Uuid::new_v4();
    let del = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, sus, Some(root), SUSPENDED, 1)
        .await
        .unwrap();
    insert_tenant(&db, del, Some(root), DELETED, 1).await.unwrap();
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    insert_closure(&db, sus, sus, 0, SUSPENDED).await.unwrap();
    insert_closure(&db, del, del, 0, DELETED).await.unwrap();
    insert_closure(&db, root, sus, 0, SUSPENDED).await.unwrap();
    insert_closure(&db, root, del, 0, DELETED).await.unwrap();

    let plugin = make_plugin(db, false);
    let ids = [TenantId(root), TenantId(sus), TenantId(del)];

    let empty_filter = plugin
        .get_tenants(&ctx(), &ids, &GetTenantsOptions { status: vec![] })
        .await
        .unwrap();
    let explicit_filter = plugin
        .get_tenants(
            &ctx(),
            &ids,
            &GetTenantsOptions {
                status: vec![SdkStatus::Active, SdkStatus::Suspended, SdkStatus::Deleted],
            },
        )
        .await
        .unwrap();

    let mut empty_ids: Vec<Uuid> = empty_filter.iter().map(|t| t.id.0).collect();
    let mut explicit_ids: Vec<Uuid> = explicit_filter.iter().map(|t| t.id.0).collect();
    empty_ids.sort_unstable();
    explicit_ids.sort_unstable();
    assert_eq!(
        empty_ids, explicit_ids,
        "empty status slice must equal the explicit all-visible-statuses set"
    );
    assert_eq!(empty_ids.len(), 3);
}

#[tokio::test]
async fn get_tenants_empty_ids_returns_empty() {
    let db = setup().await.unwrap();
    let plugin = make_plugin(db, false);
    let result = plugin
        .get_tenants(&ctx(), &[], &GetTenantsOptions { status: vec![] })
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── Tests: is_ancestor ────────────────────────────────────────────────────

#[tokio::test]
async fn is_ancestor_direct_parent_returns_true() {
    let db = setup().await.unwrap();
    let (root, child) = seed_two_level(&db, ACTIVE, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(root),
            TenantId(child),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn is_ancestor_self_returns_false() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(root),
            TenantId(root),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();
    assert!(!ok, "self is not an ancestor of self");
}

#[tokio::test]
async fn is_ancestor_unrelated_siblings_returns_false() {
    // Both endpoints exist and are non-provisioning (so the visibility
    // probe passes), but no `(ancestor, descendant)` row exists in
    // `tenant_closure`. Exercises the `count == 0` terminal branch of
    // `is_ancestor` — distinct from `is_ancestor_self_returns_false`,
    // which short-circuits before the closure probe.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let sib_a = Uuid::new_v4();
    let sib_b = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, sib_a, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    insert_tenant(&db, sib_b, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    insert_closure(&db, sib_a, sib_a, 0, ACTIVE).await.unwrap();
    insert_closure(&db, sib_b, sib_b, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, sib_a, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, sib_b, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(sib_a),
            TenantId(sib_b),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();
    assert!(!ok, "siblings are not ancestors of each other");
}

#[tokio::test]
async fn is_ancestor_missing_endpoint_yields_not_found() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();
    let missing = Uuid::new_v4();

    let plugin = make_plugin(db, false);
    let err = plugin
        .is_ancestor(
            &ctx(),
            TenantId(root),
            TenantId(missing),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::TenantNotFound { .. }));
}

// ── Tests: barrier semantics ──────────────────────────────────────────────
//
// Hierarchy: A (root) → B → C, where the A→B edge carries barrier=1
// (simulating a self_managed tenant boundary as AM's writer would set it).
//
// The plugin only reads `tenant_closure.barrier`; it never inspects
// `tenants.self_managed` directly. Tests therefore seed the correct
// barrier values in the closure rows and leave `self_managed=false` on
// the tenant rows without loss of fidelity.
//
// Closure rows:
//   (A, A, barrier=0)  — self-row
//   (B, B, barrier=0)  — self-row
//   (C, C, barrier=0)  — self-row
//   (A, B, barrier=1)  — barrier set by AM writer at tenant-B creation
//   (B, C, barrier=0)  — within B's subtree, no additional barrier
//   (A, C, barrier=1)  — A→C inherits the barrier from the A→B edge

async fn seed_barrier_tree(db: &Db) -> Result<(Uuid, Uuid, Uuid)> {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let c = Uuid::new_v4();
    insert_tenant(db, a, None, ACTIVE, 0).await?;
    insert_tenant(db, b, Some(a), ACTIVE, 1).await?;
    insert_tenant(db, c, Some(b), ACTIVE, 2).await?;
    // Self-rows
    insert_closure(db, a, a, 0, ACTIVE).await?;
    insert_closure(db, b, b, 0, ACTIVE).await?;
    insert_closure(db, c, c, 0, ACTIVE).await?;
    // Cross-boundary rows
    insert_closure(db, a, b, 1, ACTIVE).await?;
    insert_closure(db, b, c, 0, ACTIVE).await?;
    insert_closure(db, a, c, 1, ACTIVE).await?;
    Ok((a, b, c))
}

#[tokio::test]
async fn barrier_respect_is_ancestor_blocked() {
    let db = setup().await.unwrap();
    let (a, _b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(a),
            TenantId(c),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Respect,
            },
        )
        .await
        .unwrap();
    assert!(!ok, "Respect should block cross-barrier ancestry");
}

#[tokio::test]
async fn barrier_ignore_is_ancestor_crosses() {
    let db = setup().await.unwrap();
    let (a, _b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(a),
            TenantId(c),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();
    assert!(ok, "Ignore should allow cross-barrier ancestry");
}

#[tokio::test]
async fn barrier_respect_get_ancestors_clamps_at_barrier() {
    let db = setup().await.unwrap();
    let (a, b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_ancestors(
            &ctx(),
            TenantId(c),
            &GetAncestorsOptions {
                barrier_mode: BarrierMode::Respect,
            },
        )
        .await
        .unwrap();

    let ancestor_ids: Vec<Uuid> = resp.ancestors.iter().map(|t| t.id.0).collect();
    assert!(
        ancestor_ids.contains(&b),
        "B (within-barrier ancestor) must appear"
    );
    assert!(
        !ancestor_ids.contains(&a),
        "A (cross-barrier ancestor) must NOT appear under Respect"
    );
}

#[tokio::test]
async fn barrier_ignore_get_ancestors_crosses_barrier() {
    let db = setup().await.unwrap();
    let (a, b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_ancestors(
            &ctx(),
            TenantId(c),
            &GetAncestorsOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();

    let ancestor_ids: Vec<Uuid> = resp.ancestors.iter().map(|t| t.id.0).collect();
    assert!(ancestor_ids.contains(&a), "A must appear under Ignore");
    assert!(ancestor_ids.contains(&b), "B must appear under Ignore");
}

#[tokio::test]
async fn barrier_respect_get_descendants_stops_at_boundary() {
    let db = setup().await.unwrap();
    let (a, b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_descendants(
            &ctx(),
            TenantId(a),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Respect,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap();

    let desc_ids: Vec<Uuid> = resp.descendants.iter().map(|t| t.id.0).collect();
    assert!(
        !desc_ids.contains(&b),
        "B (cross-barrier) must NOT appear under Respect"
    );
    assert!(
        !desc_ids.contains(&c),
        "C (cross-barrier) must NOT appear under Respect"
    );
    assert!(
        resp.descendants.is_empty(),
        "A has no non-barrier descendants"
    );
}

#[tokio::test]
async fn barrier_ignore_get_descendants_crosses_boundary() {
    let db = setup().await.unwrap();
    let (a, b, c) = seed_barrier_tree(&db).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_descendants(
            &ctx(),
            TenantId(a),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap();

    let desc_ids: Vec<Uuid> = resp.descendants.iter().map(|t| t.id.0).collect();
    assert!(desc_ids.contains(&b), "B must appear under Ignore");
    assert!(desc_ids.contains(&c), "C must appear under Ignore");
}

// ── Tests: status filter semantics ───────────────────────────────────────

#[tokio::test]
async fn status_filter_does_not_prune_branches() {
    // Root (Active) → Mid (Suspended) → Leaf (Active)
    // Filtering by [Active] must still return Leaf even though Mid is
    // Suspended — the filter is an emission predicate, not a branch prune.
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let mid = Uuid::new_v4();
    let leaf = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, mid, Some(root), SUSPENDED, 1)
        .await
        .unwrap();
    insert_tenant(&db, leaf, Some(mid), ACTIVE, 2)
        .await
        .unwrap();
    // Self-rows
    insert_closure(&db, root, root, 0, ACTIVE).await.unwrap();
    insert_closure(&db, mid, mid, 0, SUSPENDED).await.unwrap();
    insert_closure(&db, leaf, leaf, 0, ACTIVE).await.unwrap();
    // Ancestor rows (barrier=0 everywhere — no self_managed tenant)
    insert_closure(&db, root, mid, 0, SUSPENDED).await.unwrap();
    insert_closure(&db, root, leaf, 0, ACTIVE).await.unwrap();
    insert_closure(&db, mid, leaf, 0, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, false);
    let resp = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![SdkStatus::Active],
                max_depth: None,
            },
        )
        .await
        .unwrap();

    let desc_ids: Vec<Uuid> = resp.descendants.iter().map(|t| t.id.0).collect();
    assert!(
        desc_ids.contains(&leaf),
        "Leaf (Active) must be emitted even though Mid (Suspended) is on the path"
    );
    assert!(
        !desc_ids.contains(&mid),
        "Mid (Suspended) must not be emitted when filter=[Active]"
    );
}

// ── Tests: get_descendants max_depth ─────────────────────────────────────

#[tokio::test]
async fn get_descendants_max_depth_limits_traversal() {
    // ROOT → CHILD → GRANDCHILD → GREAT
    let db = setup().await.unwrap();
    let root = Uuid::new_v4();
    let child = Uuid::new_v4();
    let grandchild = Uuid::new_v4();
    let great = Uuid::new_v4();
    insert_tenant(&db, root, None, ACTIVE, 0).await.unwrap();
    insert_tenant(&db, child, Some(root), ACTIVE, 1)
        .await
        .unwrap();
    insert_tenant(&db, grandchild, Some(child), ACTIVE, 2)
        .await
        .unwrap();
    insert_tenant(&db, great, Some(grandchild), ACTIVE, 3)
        .await
        .unwrap();
    // Self-rows
    for (id, st) in [
        (root, ACTIVE),
        (child, ACTIVE),
        (grandchild, ACTIVE),
        (great, ACTIVE),
    ] {
        insert_closure(&db, id, id, 0, st).await.unwrap();
    }
    // Ancestor rows
    insert_closure(&db, root, child, 0, ACTIVE).await.unwrap();
    insert_closure(&db, root, grandchild, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&db, root, great, 0, ACTIVE).await.unwrap();
    insert_closure(&db, child, grandchild, 0, ACTIVE)
        .await
        .unwrap();
    insert_closure(&db, child, great, 0, ACTIVE).await.unwrap();
    insert_closure(&db, grandchild, great, 0, ACTIVE)
        .await
        .unwrap();

    let plugin = make_plugin(db, false);

    // max_depth=1 → only CHILD
    let r1 = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: Some(1),
            },
        )
        .await
        .unwrap();
    assert_eq!(r1.descendants.len(), 1);
    assert_eq!(r1.descendants[0].id.0, child);

    // max_depth=2 → CHILD + GRANDCHILD
    let r2 = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: Some(2),
            },
        )
        .await
        .unwrap();
    let ids2: Vec<Uuid> = r2.descendants.iter().map(|t| t.id.0).collect();
    assert!(ids2.contains(&child));
    assert!(ids2.contains(&grandchild));
    assert!(!ids2.contains(&great));

    // max_depth=None → all three
    let r_all = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(r_all.descendants.len(), 3);
}

// ── Tests: TypesRegistry failure → Internal ───────────────────────────────

#[tokio::test]
async fn registry_fail_get_tenant_yields_internal() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true);
    let err = plugin.get_tenant(&ctx(), TenantId(root)).await.unwrap_err();
    assert!(
        matches!(err, TenantResolverError::Internal(_)),
        "registry failure must surface as Internal; got {err:?}"
    );
}

#[tokio::test]
async fn registry_fail_get_root_tenant_yields_internal() {
    let db = setup().await.unwrap();
    seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true);
    let err = plugin.get_root_tenant(&ctx()).await.unwrap_err();
    assert!(matches!(err, TenantResolverError::Internal(_)));
}

#[tokio::test]
async fn registry_fail_get_tenants_yields_internal() {
    let db = setup().await.unwrap();
    let root = seed_root(&db, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true);
    let err = plugin
        .get_tenants(
            &ctx(),
            &[TenantId(root)],
            &GetTenantsOptions { status: vec![] },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::Internal(_)));
}

#[tokio::test]
async fn registry_fail_get_ancestors_yields_internal() {
    let db = setup().await.unwrap();
    let (_root, child) = seed_two_level(&db, ACTIVE, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true);
    let err = plugin
        .get_ancestors(
            &ctx(),
            TenantId(child),
            &GetAncestorsOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::Internal(_)));
}

#[tokio::test]
async fn registry_fail_get_descendants_yields_internal() {
    let db = setup().await.unwrap();
    let (root, _child) = seed_two_level(&db, ACTIVE, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true);
    let err = plugin
        .get_descendants(
            &ctx(),
            TenantId(root),
            &GetDescendantsOptions {
                barrier_mode: BarrierMode::Ignore,
                status: vec![],
                max_depth: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TenantResolverError::Internal(_)));
}

#[tokio::test]
async fn is_ancestor_not_affected_by_registry_failure() {
    // `is_ancestor` probes `tenants` for visibility and `tenant_closure` for
    // the edge — it never calls TypesRegistryClient. A failing registry must
    // not affect the result.
    let db = setup().await.unwrap();
    let (root, child) = seed_two_level(&db, ACTIVE, ACTIVE).await.unwrap();

    let plugin = make_plugin(db, true); // registry always fails
    let ok = plugin
        .is_ancestor(
            &ctx(),
            TenantId(root),
            TenantId(child),
            &IsAncestorOptions {
                barrier_mode: BarrierMode::Ignore,
            },
        )
        .await
        .unwrap();
    assert!(ok, "is_ancestor must not depend on TypesRegistry");
}
