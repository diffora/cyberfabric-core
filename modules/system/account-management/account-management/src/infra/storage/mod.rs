//! Storage layer — `SeaORM` entities and repository implementations for
//! Account Management tables.
//!
//! Exposes `entity` (column-for-column entities), `migrations` (the AM
//! migration set), and `repo_impl` (the SeaORM-backed `TenantRepo`
//! implementation that owns all writes through `SecureConn`).

pub mod entity;
pub mod migrations;
pub mod repo_impl;
