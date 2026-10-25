//! Tenant-owned certificate archive. Runtime certificate consumers remain file-configured.
//! ref: rust-openssl openssl/src/x509/mod.rs; sqlx v0.9.0 sqlx-core/src/transaction.rs.
pub mod directory;
mod generation;
mod materials;
mod model;
mod presentation;
mod protection;
mod service;
mod store;
pub use model::*;
pub use service::{Archive, Clock};
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

#[cfg(test)]
#[path = "../tests/behavior.rs"]
mod tests;
