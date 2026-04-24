//! `SeaORM` entity definitions for AM-owned tables.
//!
//! Each module in this tree mirrors exactly one table declared in
//! `migrations/0001_create_tenants.sql`. Entities here contain no domain
//! logic — they are `sea_orm` value types used by the repository
//! implementation layer.

pub mod running_audits;
pub mod tenant_closure;
pub mod tenant_metadata;
pub mod tenants;
