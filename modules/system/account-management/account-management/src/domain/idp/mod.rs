//! `IdP` provider contract surface.
//!
//! Phase 1 ships the `provision_tenant` contract used by the
//! create-child saga. The `deprovision_tenant` surface is added by the
//! deletion-pipeline phase — see the plan manifest.

pub mod provisioner;

pub use provisioner::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
