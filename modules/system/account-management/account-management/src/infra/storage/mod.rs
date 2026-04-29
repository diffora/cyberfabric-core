//! Storage layer — `SeaORM` entities and repository implementations for
//! Account Management tables.
//!
//! Exposes `entity` (column-for-column entities), `migrations` (the AM
//! migration set 0001–0004), and `repo_impl` (the SeaORM-backed
//! `TenantRepo` implementation). The audit classifier set (`audit/`)
//! arrives in a later PR.

pub mod entity;
pub mod migrations;
pub mod repo_impl;
