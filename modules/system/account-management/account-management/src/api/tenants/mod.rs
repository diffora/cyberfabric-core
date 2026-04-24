//! REST wiring for `/api/account-management/v1/tenants`.
//!
//! Split into three files:
//!
//! * `models.rs` — request / response DTOs matching the `OpenAPI` contract
//!   field-for-field, plus `From`/`TryFrom` conversions to / from the
//!   domain types.
//! * `handlers.rs` — the four Axum handlers + `register_routes` + the
//!   `am_error_to_problem` helper.
//!
//! Handler tests live in `handlers.rs::tests` (hermetic — no DB / no
//! network).

pub mod handlers;
pub mod models;

pub use handlers::register_routes;
