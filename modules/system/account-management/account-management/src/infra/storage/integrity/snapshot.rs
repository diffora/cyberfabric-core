//! In-memory snapshot of `(tenants, tenant_closure)` consumed by the
//! pure-Rust integrity classifiers.
//!
//! The shape mirrors a projection of the `SeaORM` entities
//! `crate::infra::storage::entity::{tenants, tenant_closure}`. The loader
//! (Phase 3, `audit/loader.rs`) produces `Vec<TenantSnap>` +
//! `Vec<ClosureSnap>` from a `REPEATABLE READ` `SecureSelect` and hands
//! them to [`Snapshot::new`], which precomputes the indexes used by the
//! classifiers in `audit/classifiers/`.
//!
//! Per the spec (phase-01 §4) provisioning rows MUST NOT enter the
//! snapshot — the loader filters `tenants.status` to the SDK-visible set
//! `{Active, Suspended, Deleted}`, so classifiers can assume they never
//! observe `TenantStatus::Provisioning`.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::domain::tenant::model::TenantStatus;

/// Projection of a `tenants` row used by classifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSnap {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub status: TenantStatus,
    pub depth: i32,
    pub self_managed: bool,
}

/// Projection of a `tenant_closure` row used by classifiers.
///
/// The schema has no `depth` column on closure (see
/// `migrations/0001_create_tenants.sql`); only `tenants.depth` carries the
/// stored depth, and the depth classifier compares it to the parent-walk
/// derived depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureSnap {
    pub ancestor_id: Uuid,
    pub descendant_id: Uuid,
    pub barrier: i16,
    pub descendant_status: TenantStatus,
}

/// Owned snapshot + precomputed indexes consumed by the classifiers.
///
/// Memory footprint is `O(tenants)` where `tenants` is the number of
/// tenants in the snapshot. The per-classifier output is
/// `O(violations)`; the soft NFR is `O(tenants + violations)` per the
/// phase-01 spec handoff.
#[derive(Debug, Clone)]
pub struct Snapshot {
    tenants: Vec<TenantSnap>,
    closure: Vec<ClosureSnap>,

    tenant_by_id: HashMap<Uuid, TenantSnap>,
    closure_set: HashSet<(Uuid, Uuid)>,
}

impl Snapshot {
    /// Build a snapshot from owned tenants + closure rows. Indexes are
    /// allocated eagerly so classifiers run in `O(tenants + violations)`
    /// without per-call rebuilds.
    #[must_use]
    pub fn new(tenants: Vec<TenantSnap>, closure: Vec<ClosureSnap>) -> Self {
        let mut tenant_by_id: HashMap<Uuid, TenantSnap> = HashMap::with_capacity(tenants.len());
        for t in &tenants {
            tenant_by_id.insert(t.id, t.clone());
        }
        let mut closure_set: HashSet<(Uuid, Uuid)> = HashSet::with_capacity(closure.len());
        for c in &closure {
            closure_set.insert((c.ancestor_id, c.descendant_id));
        }
        Self {
            tenants,
            closure,
            tenant_by_id,
            closure_set,
        }
    }

    /// All tenant rows in the snapshot.
    #[must_use]
    pub(crate) fn tenants(&self) -> &[TenantSnap] {
        &self.tenants
    }

    /// All closure rows in the snapshot.
    #[must_use]
    pub(crate) fn closure(&self) -> &[ClosureSnap] {
        &self.closure
    }

    /// Lookup a tenant by id.
    #[must_use]
    pub(crate) fn tenant(&self, id: Uuid) -> Option<&TenantSnap> {
        self.tenant_by_id.get(&id)
    }

    /// Whether any tenant with the given id is present in the snapshot.
    #[must_use]
    pub(crate) fn has_tenant(&self, id: Uuid) -> bool {
        self.tenant_by_id.contains_key(&id)
    }

    /// Whether the closure contains the `(ancestor, descendant)` pair.
    #[must_use]
    pub(crate) fn has_closure_edge(&self, ancestor: Uuid, descendant: Uuid) -> bool {
        self.closure_set.contains(&(ancestor, descendant))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn t(id: u128, parent: Option<u128>, depth: i32) -> TenantSnap {
        TenantSnap {
            id: Uuid::from_u128(id),
            parent_id: parent.map(Uuid::from_u128),
            status: TenantStatus::Active,
            depth,
            self_managed: false,
        }
    }

    fn c(a: u128, d: u128) -> ClosureSnap {
        ClosureSnap {
            ancestor_id: Uuid::from_u128(a),
            descendant_id: Uuid::from_u128(d),
            barrier: 0,
            descendant_status: TenantStatus::Active,
        }
    }

    #[test]
    fn indexes_are_built_from_input() {
        let snap = Snapshot::new(
            vec![t(1, None, 0), t(2, Some(1), 1)],
            vec![c(1, 1), c(2, 2), c(1, 2)],
        );
        assert!(snap.has_tenant(Uuid::from_u128(1)));
        assert!(snap.has_tenant(Uuid::from_u128(2)));
        assert!(!snap.has_tenant(Uuid::from_u128(3)));
        assert!(snap.has_closure_edge(Uuid::from_u128(1), Uuid::from_u128(2)));
        assert!(!snap.has_closure_edge(Uuid::from_u128(2), Uuid::from_u128(1)));
        assert_eq!(snap.tenants().len(), 2);
        assert_eq!(snap.closure().len(), 3);
    }
}
