//! Product-owned, rebuildable audit search. Audit remains the sole source of facts.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (explicit bounded settlement).
mod cursor;
mod model;
mod projection;
mod service;
pub use model::{Coverage, Error, FactView, Page, Query};
pub use projection::project;
pub use service::Timeline;
/// Fresh product read-model schema; does not modify the Audit component.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Exact application-role privileges for this product read model.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

/// Read-only association profile checked with the App's composed capability admission.
pub const ACCESS_ADMISSION_SQL: &str = include_str!("source-admission.sql");
