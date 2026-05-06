//! `SeaORM` entity definitions for AM-owned tables.
//!
//! Each module mirrors exactly one table declared in the migration set.
//! Entities contain no domain logic — they are `sea_orm` value types used
//! by the repository implementation layer.

pub mod integrity_check_runs;
pub mod tenant_closure;
pub mod tenant_metadata;
pub mod tenants;
