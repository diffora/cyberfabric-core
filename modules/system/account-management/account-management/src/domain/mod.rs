//! Domain layer for the Account Management storage floor.
//!
//! Houses the error taxonomy, metric catalog, `IdP` provisioner contract,
//! and tenant domain model + repository trait. Domain-service logic,
//! bootstrap saga, audit emission, and tenant-type checks arrive in
//! later PRs.

pub mod error;
pub mod idp;
pub mod metrics;
pub mod tenant;
