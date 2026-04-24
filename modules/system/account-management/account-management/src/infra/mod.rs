//! Infrastructure layer for Account Management.
//!
//! Houses `SeaORM` entities today (`storage::entity`) and will hold the
//! `SeaORM`-backed repository implementations in the next phase. The
//! `infra` boundary is the only place allowed to import `sea_orm::*`
//! types from inside AM.

pub mod error_conv;
pub mod idp;
pub mod observability;
pub mod rg;
pub mod storage;
pub mod types_registry;
