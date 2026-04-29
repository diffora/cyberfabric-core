//! Infrastructure layer for Account Management.
//!
//! Houses the DB-error converter and the SeaORM-backed storage adapter
//! (entities, migrations, repository implementation). Observability,
//! `IdP` integration, resource-group checker, and types-registry checker
//! arrive in later PRs.

pub mod error_conv;
pub mod storage;
