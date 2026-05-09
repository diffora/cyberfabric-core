//! Test stub for the [`IdpUserProvisionerClient`] contract.
//!
//! Pairs with the [`FakeUserOutcome`] enum that drives the per-call
//! outcome independently for `create_user`, `delete_user`, and
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
    CreateUserRequest, DeleteUserOutcome, DeleteUserRequest, IdpUserProvisionerClient,
    ListUsersRequest, UserOperationFailure, UserPage, UserProjection,
};
use async_trait::async_trait;
use modkit_macros::domain_model;
use uuid::Uuid;

/// Five-outcome stub for an `IdP` user-operations call.
///
/// Each method (`create_user`, `delete_user`, `list_users`) carries
/// its own configurable outcome stored on [`FakeIdpUserProvisioner`];
/// tests that need different verdicts per method set them
/// independently. `RejectPayload` exists so the
/// `UserOperationFailure::Rejected` -> `Validation` mapping branch is
/// exercised; `Unavailable` and `Unsupported` cover the other two
/// SDK failure variants.
///
/// `OkNotFound` is meaningful ONLY for `delete_user` (where it maps
/// to `DeleteUserOutcome::NotFoundInTenant`, the idempotency guard's
/// absent-equivalent). Setting it on `create_user` / `list_users`
/// is a misconfigured test -- the fake panics in that case so the
/// test fails loudly rather than silently producing a happy-path
/// projection or empty page that would mask the misuse.
#[domain_model]
#[derive(Clone)]
pub enum FakeUserOutcome {
    /// `delete_user` returns `Ok(Removed)`; `create_user` returns the
    /// configured projection; `list_users` returns the configured page.
    Ok,
    /// `delete_user` returns `Ok(NotFoundInTenant)` (idempotency
    /// guard branch). MUST NOT be set on `create_user` / `list_users`
    /// outcomes -- doing so panics the fake (see type-level doc).
    OkNotFound,
    /// Returns `Err(UserOperationFailure::Unavailable)`.
    Unavailable,
    /// Returns `Err(UserOperationFailure::UnsupportedOperation)`.
    Unsupported,
    /// Returns `Err(UserOperationFailure::Rejected)`.
    RejectPayload,
}

/// In-memory `FakeIdpUserProvisioner` implementing
/// [`IdpUserProvisionerClient`]. Per-method outcomes default to
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
    /// Optional projection returned on the `create_user` happy path.
    /// Defaults to a synthesized projection with `id = Uuid::new_v4()`.
    create_projection: Mutex<Option<UserProjection>>,
    /// Optional page returned on the `list_users` happy path.
    /// Defaults to an empty page with the request's `top` / `skip`.
    list_page_items: Mutex<Vec<UserProjection>>,
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

    /// Override the projection returned on the `create_user` happy
    /// path. Without this override the fake returns a
    /// `UserProjection` whose `id` is freshly minted on every call.
    pub fn set_create_projection(&self, projection: UserProjection) {
        *self.create_projection.lock().expect("lock") = Some(projection);
    }

    /// Replace the items returned by the `list_users` happy path. The
    /// fake echoes the request's `top` / `skip` on every page; this
    /// helper only governs the `items` vector.
    pub fn set_list_items(&self, items: Vec<UserProjection>) {
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
impl IdpUserProvisionerClient for FakeIdpUserProvisioner {
    async fn create_user(
        &self,
        req: &CreateUserRequest,
    ) -> Result<UserProjection, UserOperationFailure> {
        self.create_calls
            .lock()
            .expect("lock")
            .push((req.tenant_id, req.payload.username.clone()));
        let oc = self.create_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::Ok => {
                let projection = self.create_projection.lock().expect("lock").clone();
                Ok(projection.unwrap_or_else(|| UserProjection {
                    id: Uuid::new_v4(),
                    username: req.payload.username.clone(),
                    email: req.payload.email.clone(),
                    display_name: req.payload.display_name.clone(),
                    avatar_url: req.payload.avatar_url.clone(),
                    attributes: req.payload.attributes.clone(),
                }))
            }
            FakeUserOutcome::OkNotFound => panic!(
                "FakeIdpUserProvisioner: FakeUserOutcome::OkNotFound is only meaningful \
                 for delete_user; setting it on create_user is a misconfigured test"
            ),
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

    async fn delete_user(
        &self,
        req: &DeleteUserRequest,
    ) -> Result<DeleteUserOutcome, UserOperationFailure> {
        self.delete_calls
            .lock()
            .expect("lock")
            .push((req.tenant_id, req.user_id));
        let oc = self.delete_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::Ok => Ok(DeleteUserOutcome::Removed),
            FakeUserOutcome::OkNotFound => Ok(DeleteUserOutcome::NotFoundInTenant),
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

    async fn list_users(&self, req: &ListUsersRequest) -> Result<UserPage, UserOperationFailure> {
        self.list_calls
            .lock()
            .expect("lock")
            .push((req.tenant_id, req.user_id_filter));
        let oc = self.list_outcome.lock().expect("lock").clone();
        match oc {
            FakeUserOutcome::OkNotFound => panic!(
                "FakeIdpUserProvisioner: FakeUserOutcome::OkNotFound is only meaningful \
                 for delete_user; setting it on list_users is a misconfigured test"
            ),
            FakeUserOutcome::Ok => {
                let items = self.list_page_items.lock().expect("lock").clone();
                // When a single-user filter is active the SDK doc
                // allows leaving `total` as `None` (the underlying
                // directory total is not meaningful for a one-off
                // existence check). The fake returns `None` here so
                // tests that assert pagination behaviour exercise
                // the contract rather than a fake-specific quirk.
                let (filtered, total) = if let Some(uid) = req.user_id_filter {
                    (
                        items
                            .into_iter()
                            .filter(|u| u.id == uid)
                            .collect::<Vec<_>>(),
                        None,
                    )
                } else {
                    let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
                    (items, Some(total))
                };
                Ok(UserPage::new(
                    filtered,
                    req.pagination.top(),
                    req.pagination.skip,
                    total,
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
