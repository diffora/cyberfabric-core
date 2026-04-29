//! `SeaORM` entity definitions for AM-owned tables.
//!
//! Each module mirrors exactly one table declared in the migration set.
//! Entities contain no domain logic — they are `sea_orm` value types used
//! by the repository implementation layer. The `running_audits` entity
//! (migration 0005) arrives in a later PR.

pub mod tenant_closure;
pub mod tenant_metadata;
pub mod tenants;
