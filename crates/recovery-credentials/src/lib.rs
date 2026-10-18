//! Product recovery material ownership; execution and platform channels retain their lifecycles.
//! ref: rust-openssl openssl-v0.10.81 openssl/src/cms.rs.
mod model;
mod protection;
mod service;
pub mod storage;
pub use model::*;
pub use protection::{KeyRing, Protection, Recipient};
pub use service::Credentials;
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
