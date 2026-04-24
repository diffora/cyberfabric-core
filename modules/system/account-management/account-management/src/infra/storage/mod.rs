//! Storage layer — `SeaORM` entities and repository implementations for
//! Account Management tables.
//!
//! Phase 1 ships entity definitions only. The SeaORM-backed `TenantRepo`
//! implementation (`repo_impl.rs`) is introduced in the REST-wiring phase.

pub mod entity;
pub mod migrations;
pub mod repo_impl;
