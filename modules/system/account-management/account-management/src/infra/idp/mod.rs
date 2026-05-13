//! Infrastructure-layer glue for the optional
//! [`account_management_sdk::IdpPluginClient`] plugin.
//!
//! AM can boot without an `IdP` adapter present — dev deployments and
//! tests do not need one. The services store the provisioner as
//! `Arc<dyn IdpPluginClient>` directly; this module contributes
//! the [`NoopIdpProvider`] fallback wired in when no plugin resolves
//! from `ClientHub`.
//!
//! The fallback overrides only `check_availability` (returning
//! `Unreachable`) and inherits the trait's per-method
//! `UnsupportedOperation` defaults for every mutating call, so a
//! deployment without an `IdP` plugin keeps booting and surfaces a
//! consistent error envelope at the call site for both tenant and
//! user operations.

use account_management_sdk::{CheckAvailabilityFailure, IdpPluginClient};
use async_trait::async_trait;

/// No-op `IdP` provider plugin: reports the deployment as `Unreachable`
/// on the health probe and inherits the trait's
/// `UnsupportedOperation` defaults for every mutating tenant /
/// user operation. Used when AM boots without an `IdP` plugin.
#[derive(Debug, Default, Clone)]
pub struct NoopIdpProvider;

#[async_trait]
impl IdpPluginClient for NoopIdpProvider {
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
        Err(CheckAvailabilityFailure::Unreachable {
            detail: "no IdP provider plugin is registered in this deployment".to_owned(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "noop_tests.rs"]
mod noop_tests;
