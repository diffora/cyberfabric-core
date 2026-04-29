//! `IdP` provider contract surface.
//!
//! Ships the [`IdpTenantProvisioner`] trait and its request/result/failure
//! shapes. Used by the create-child saga (`provision_tenant`), the deletion
//! pipeline (`deprovision_tenant`), and the bootstrap availability probe
//! (`check_availability`).

pub mod provisioner;

pub use provisioner::{
    CheckAvailabilityFailure, DeprovisionFailure, DeprovisionRequest, IdpTenantProvisioner,
    ProvisionFailure, ProvisionMetadataEntry, ProvisionRequest, ProvisionResult,
};
