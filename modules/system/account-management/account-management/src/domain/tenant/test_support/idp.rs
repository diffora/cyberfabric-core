//! Test stub for the [`IdpTenantProvisionerClient`] contract. Pairs
//! with the four-outcome enums [`FakeOutcome`] /
//! [`FakeDeprovisionOutcome`] that drive the provision / deprovision
//! branches independently so tests can exercise both compensable and
//! non-compensable paths.

#![allow(
    dead_code,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::sync::Mutex;

use account_management_sdk::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisionerClient,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
use async_trait::async_trait;
use modkit_macros::domain_model;
use uuid::Uuid;

/// Four-outcome stub for the `IdP` provisioner.
#[domain_model]
#[derive(Clone)]
pub enum FakeOutcome {
    Ok,
    CleanFailure,
    Ambiguous,
    Unsupported,
}

/// Stub for `deprovision_tenant` outcomes. Defaults to `Ok`.
#[domain_model]
#[derive(Clone)]
pub enum FakeDeprovisionOutcome {
    Ok,
    Retryable,
    Terminal,
    Unsupported,
    NotFound,
}

#[domain_model]
pub struct FakeIdpProvisioner {
    pub outcome: Mutex<FakeOutcome>,
    pub deprovision_outcome: Mutex<FakeDeprovisionOutcome>,
    pub metadata_entries: Mutex<Vec<ProvisionMetadataEntry>>,
    pub availability_failures: Mutex<u32>,
    pub availability_calls: Mutex<u32>,
    pub calls: Mutex<Vec<Uuid>>,
    pub deprovision_calls: Mutex<Vec<Uuid>>,
}

impl FakeIdpProvisioner {
    pub fn new(outcome: FakeOutcome) -> Self {
        Self {
            outcome: Mutex::new(outcome),
            deprovision_outcome: Mutex::new(FakeDeprovisionOutcome::Ok),
            metadata_entries: Mutex::new(Vec::new()),
            availability_failures: Mutex::new(0),
            availability_calls: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
            deprovision_calls: Mutex::new(Vec::new()),
        }
    }

    pub fn set_deprovision_outcome(&self, oc: FakeDeprovisionOutcome) {
        *self.deprovision_outcome.lock().expect("lock") = oc;
    }

    pub fn set_metadata_entries(&self, entries: Vec<ProvisionMetadataEntry>) {
        *self.metadata_entries.lock().expect("lock") = entries;
    }

    pub fn fail_availability_times(&self, failures: u32) {
        *self.availability_failures.lock().expect("lock") = failures;
    }

    /// Mutate the provision outcome between calls. Tests that need to
    /// flip from `FakeOutcome::CleanFailure` to `FakeOutcome::Ok` on
    /// the second saga attempt (retry-then-finalize coverage) call
    /// this between awaits.
    pub fn set_outcome(&self, oc: FakeOutcome) {
        *self.outcome.lock().expect("lock") = oc;
    }

    /// Read the current count of `provision_tenant` calls observed by
    /// this fake. Used by retry-loop tests to assert the saga actually
    /// advanced past `CleanFailure` rather than short-circuiting.
    pub fn provision_call_count(&self) -> usize {
        self.calls.lock().expect("lock").len()
    }

    /// Read the current count of `check_availability` calls observed
    /// by this fake. Used by `wait_for_idp_availability` tests to pin
    /// the attempt-count contract.
    pub fn availability_call_count(&self) -> u32 {
        *self.availability_calls.lock().expect("lock")
    }
}

#[async_trait]
impl IdpTenantProvisionerClient for FakeIdpProvisioner {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        *self.availability_calls.lock().expect("lock") += 1;
        let mut failures = self.availability_failures.lock().expect("lock");
        if *failures > 0 {
            *failures -= 1;
            return Err(CheckAvailabilityFailure::TransientError(
                "fake availability failure".into(),
            ));
        }
        Ok(())
    }

    async fn provision_tenant(
        &self,
        req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure> {
        self.calls.lock().expect("lock").push(req.tenant_id);
        let oc = self.outcome.lock().expect("lock").clone();
        match oc {
            FakeOutcome::Ok => Ok(ProvisionResult {
                metadata_entries: self.metadata_entries.lock().expect("lock").clone(),
            }),
            FakeOutcome::CleanFailure => Err(ProvisionFailure::CleanFailure {
                detail: "fake clean".into(),
            }),
            FakeOutcome::Ambiguous => Err(ProvisionFailure::Ambiguous {
                detail: "fake ambiguous".into(),
            }),
            FakeOutcome::Unsupported => Err(ProvisionFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
        }
    }

    async fn deprovision_tenant(&self, req: &DeprovisionRequest) -> Result<(), DeprovisionFailure> {
        self.deprovision_calls
            .lock()
            .expect("lock")
            .push(req.tenant_id);
        let oc = self.deprovision_outcome.lock().expect("lock").clone();
        match oc {
            FakeDeprovisionOutcome::Ok => Ok(()),
            FakeDeprovisionOutcome::Retryable => Err(DeprovisionFailure::Retryable {
                detail: "fake retryable".into(),
            }),
            FakeDeprovisionOutcome::Terminal => Err(DeprovisionFailure::Terminal {
                detail: "fake terminal".into(),
            }),
            FakeDeprovisionOutcome::Unsupported => Err(DeprovisionFailure::UnsupportedOperation {
                detail: "fake unsupported".into(),
            }),
            FakeDeprovisionOutcome::NotFound => Err(DeprovisionFailure::NotFound {
                detail: "fake not found".into(),
            }),
        }
    }
}
