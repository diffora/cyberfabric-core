//! Domain layer for the Account Management foundation feature.
//!
//! Houses the error taxonomy, metric catalog, and audit-emission helper.
//! Every future AM feature layers on top of these primitives.

pub mod audit;
pub mod bootstrap;
pub mod error;
pub mod idp;
pub mod metrics;
pub mod tenant;
pub mod tenant_type;
pub mod util;
