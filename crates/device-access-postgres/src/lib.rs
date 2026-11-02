//! Device Access's PostgreSQL business authority and same-transaction participants.
#![forbid(unsafe_code)]
mod database;
pub mod device_access;
pub mod enterprise;
mod error;
pub mod recovery;
mod service;
pub use error::Error;
pub use service::{Assembly, Service};
pub type Pending<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>> + Send + 'a>>;

pub mod configuration;
pub mod delivery;
pub mod evidence;
mod operations;
pub mod platform_sso;

pub const AUTHORITY_SQL: &str = include_str!("../schema/authority.sql");

pub const PROOF_SQL: &str = include_str!("../schema/proof-grants.sql");
pub const DIRECTORY_SQL: &str = include_str!("../schema/directory.sql");
pub mod admission;
