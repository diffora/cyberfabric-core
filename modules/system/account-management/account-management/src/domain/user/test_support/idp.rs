//! Test stub for the [`IdpPluginClient`] contract.
//!
//! Pairs with the [`FakeUserOutcome`] enum that drives the per-call
//! outcome independently for `provision_user`, `deprovision_user`, and
//! `list_users`. Tests configure the desired outcome via the
//! `set_*_outcome` helpers, then exercise [`crate::domain::user::service::UserService`]
//! against the fake to pin the contract behaviour without touching a
//! real provider.
//!
//! State is stored behind `Arc<Mutex<...>>` so the fake is `Clone +
//! Send + Sync` and can be shared across tasks the way
//! `FakeIdpProvisioner` is.

#![allow(
    dead_code,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::expect_used,
    reason = "test-support fake; canonical mutex-locking pattern with helper getters that not every test exercises today"
)]

use std::sync::Mutex;

use account_management_sdk::{
    CheckAvailabilityFailure, DeprovisionUserRequest, IdpPluginClient, ListUsersRequest,
    ProvisionUserRequest, User, UserOperationFailure,
};
use async_trait::async_trait;
use modkit_macros::domain_model;
use modkit_odata::{Page, PageInfo};
use uuid::Uuid;

/// Four-outcome stub for an `IdP` user-operations call.
///
/// Each method (`provision_user`, `deprovision_user`, `list_users`) carries
/// its own configurable outcome stored on [`FakeIdpUserProvisioner`];
/// tests that need different verdicts per method set them
/// independently. `RejectPayload` exists so the
/// `UserOperationFailure::Rejected` -> `Validation` mapping branch is
/// exercised; `Unavailable` and `Unsupported` cover the other two
/// SDK failure variants.
#[domain_model]
#[derive(Clone)]
pub enum FakeUserOutcome {
    /// `deprovision_user` returns `Ok(())`; `provision_user` returns
    /// the configured projection; `list_users` returns the configured
    /// page. Per the collapsed `IdpPluginClient::deprovision_user`
    /// contract a successful call is the same whether the plugin
    /// actually removed the user or saw it already absent — both
    /// surface as `Ok(())` to AM.
    Ok,
    /// Returns `Err(UserOperationFailure::Unavailable)`.
    Unavailable,
    /// Returns `Err(UserOperationFailure::UnsupportedOperation)`.
    Unsupported,
    /// Returns `Err(UserOperationFailure::Rejected)`.
    RejectPayload,
}

/// In-memory `FakeIdpUserProvisioner` implementing
/// [`IdpPluginClient`]. Per-method outcomes default to
/// [`FakeUserOutcome::Ok`]; tests override them via the
/// `set_*_outcome` helpers below.
///
/// `record_calls` is enabled by default so tests can assert "no `IdP`
/// call issued" cases. Each method append-records a per-call entry
/// (`tenant_id` + the per-method scoped value) to a dedicated `Vec`.
#[domain_model]
pub struct FakeIdpUserProvisioner {
    create_outcome: Mutex<FakeUserOutcome>,
    delete_outcome: Mutex<FakeUserOutcome>,
    list_outcome: Mutex<FakeUserOutcome>,
    create_calls: Mutex<Vec<(Uuid, String)>>,
    delete_calls: Mutex<Vec<(Uuid, Uuid)>>,
    list_calls: Mutex<Vec<(Uuid, Option<Uuid>)>>,
    /// Optional projection returned on the `provision_user` happy path.
    /// Defaults to a synthesized projection with `id = Uuid::new_v4()`.
    create_projection: Mutex<Option<User>>,
    /// Optional page returned on the `list_users` happy path.
    /// Defaults to an empty page with the request's `top` / `skip`.
    list_page_items: Mutex<Vec<User>>,
}

impl FakeIdpUserProvisioner {
    pub fn new() -> Self {
        Self {
            create_outcome: Mutex::new(FakeUserOutcome::Ok),
            delete_outcome: Mutex::new(FakeUserOutcome::Ok),
            list_outcome: Mutex::new(FakeUserOutcome::Ok),
            create_calls: Mutex::new(Vec::new()),
            delete_calls: Mutex::new(Vec::new()),
            list_calls: Mutex::new(Vec::new()),
            create_projection: Mutex::new(None),
            list_page_items: Mutex::new(Vec::new()),
        }
    }

    pub fn set_create_outcome(&self, oc: FakeUserOutcome) {
        *self.create_outcome.lock().expect("lock") = oc;
    }

    pub fn set_delete_outcome(&self, oc: FakeUserOutcome) {
        *self.delete_outcome.lock().expect("lock") = oc;
    }

    pub fn set_list_outcome(&self, oc: FakeUserOutcome) {
        *self.list_outcome.lock().expect("lock") = oc;
    }

    /// Override the projection returned on the `provision_user` happy
    /// path. Without this override the fake returns a
    /// `User` whose `id` is freshly minted on every call.
    pub fn set_create_projection(&self, projection: User) {
        *self.create_projection.lock().expect("lock") = Some(projection);
    }

    /// Replace the items returned by the `list_users` happy path. The
    /// fake echoes the request's `top` / `skip` on every page; this
    /// helper only governs the `items` vector.
    pub fn set_list_items(&self, items: Vec<User>) {
        *self.list_page_items.lock().expect("lock") = items;
    }

    pub fn create_call_count(&self) -> usize {
        self.create_calls.lock().expect("lock").len()
    }

    pub fn delete_call_count(&self) -> usize {
        self.delete_calls.lock().expect("lock").len()
    }

    pub fn list_call_count(&self) -> usize {
        self.list_calls.lock().expect("lock").len()
    }

    pub fn create_calls_snapshot(&self) -> Vec<(Uuid, String)> {
        self.create_calls.lock().expect("lock").clone()
    }

    pub fn delete_calls_snapshot(&self) -> Vec<(Uuid, Uuid)> {
        self.delete_calls.lock().expect("lock").clone()
    }

    pub fn list_calls_snapshot(&self) -> Vec<(Uuid, Option<Uuid>)> {
        self.list_calls.lock().expect("lock").clone()
    }
}

impl Default for FakeIdpUserProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdpPluginClient for FakeIdpUserProvisioner {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        // User-side fake assumes the IdP is reachable; tests that
        // exercise availability failure use `FakeIdpProvisioner`
        // instead.
        Ok(())
    }

    async fn provision_user(
        &self,
        req: &ProvisionUserRequest,
    ) -> Result<User, UserOperationFailure> {
        self.create_calls
            .lock()
            .expect("lock")
            .push((req.tenant_context.tenant_id, req.payload.username.clone()));
        let oc = self.create_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::Ok => {
                let projection = self.create_projection.lock().expect("lock").clone();
                Ok(projection.unwrap_or_else(|| {
                    let mut p = User::new(Uuid::new_v4(), req.payload.username.clone());
                    if let Some(email) = req.payload.email.clone() {
                        p = p.with_email(email);
                    }
                    if let Some(display_name) = req.payload.display_name.clone() {
                        p = p.with_display_name(display_name);
                    }
                    if let Some(attributes) = req.payload.attributes.clone() {
                        p = p.with_attributes(attributes);
                    }
                    p
                }))
            }
            FakeUserOutcome::Unavailable => Err(UserOperationFailure::Unavailable {
                detail: "fake unavailable".into(),
            }),
            FakeUserOutcome::Unsupported => Err(UserOperationFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
            FakeUserOutcome::RejectPayload => Err(UserOperationFailure::Rejected {
                detail: "fake rejected".into(),
            }),
        }
    }

    async fn deprovision_user(
        &self,
        req: &DeprovisionUserRequest,
    ) -> Result<(), UserOperationFailure> {
        self.delete_calls
            .lock()
            .expect("lock")
            .push((req.tenant_context.tenant_id, req.user_id));
        let oc = self.delete_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::Ok => Ok(()),
            FakeUserOutcome::Unavailable => Err(UserOperationFailure::Unavailable {
                detail: "fake unavailable".into(),
            }),
            FakeUserOutcome::Unsupported => Err(UserOperationFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
            FakeUserOutcome::RejectPayload => Err(UserOperationFailure::Rejected {
                detail: "fake rejected".into(),
            }),
        }
    }

    async fn list_users(&self, req: &ListUsersRequest) -> Result<Page<User>, UserOperationFailure> {
        self.list_calls
            .lock()
            .expect("lock")
            .push((req.tenant_context.tenant_id, req.user_id_filter));
        let oc = self.list_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::Ok => {
                let items = self.list_page_items.lock().expect("lock").clone();
                let filtered: Vec<_> = if let Some(uid) = req.user_id_filter {
                    items.into_iter().filter(|u| u.id == uid).collect()
                } else {
                    items
                };
                // Emulate a paginating IdP backed by a stable Vec
                // ordering. The opaque cursor is just the decimal
                // offset into the Vec — sufficient to exercise
                // continuation semantics in unit tests without
                // pulling in `modkit_odata::pagination` (which is the
                // shape real plugins use). Production plugins SHOULD
                // embed a filter hash + sort key per the SDK doc;
                // here the test contract is single-process and
                // single-threaded so the simpler offset cursor
                // suffices.
                let start: usize = req
                    .pagination
                    .cursor()
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(0);
                let top = usize::try_from(req.pagination.top()).unwrap_or(usize::MAX);
                let end = start.saturating_add(top).min(filtered.len());
                let page_items = filtered[start.min(filtered.len())..end].to_vec();
                let next_cursor = (end < filtered.len()).then(|| end.to_string());
                Ok(Page::new(
                    page_items,
                    PageInfo {
                        next_cursor,
                        prev_cursor: None,
                        limit: u64::from(req.pagination.top()),
                    },
                ))
            }
            FakeUserOutcome::Unavailable => Err(UserOperationFailure::Unavailable {
                detail: "fake unavailable".into(),
            }),
            FakeUserOutcome::Unsupported => Err(UserOperationFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
            FakeUserOutcome::RejectPayload => Err(UserOperationFailure::Rejected {
                detail: "fake rejected".into(),
            }),
        }
    }
}
