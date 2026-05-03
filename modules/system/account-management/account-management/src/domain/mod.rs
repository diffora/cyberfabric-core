//! Domain layer for the Account Management storage floor.
//!
//! Houses the error taxonomy, metric catalog, `IdP` provisioner contract,
//! tenant domain model + repository trait. Domain-service logic, bootstrap
//! saga, and tenant-type checks arrive in later PRs. State-changing
//! transitions log placeholder lines on `target="am.events"`; those
//! sites become event-bus emit points when the platform audit transport
//! lands.

pub mod error;
pub mod idp;
pub mod metrics;
pub mod tenant;
pub mod tenant_type;
