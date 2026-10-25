//! Product recovery material ownership; execution and platform channels retain their lifecycles.
//! ref: rust-openssl openssl-v0.10.81 openssl/src/cms.rs.
pub mod directory;
pub mod filevault;
mod filevault_service;
pub use filevault_service::{FilevaultSelection, FilevaultService, Link as FilevaultLink};
mod model;
mod protection;
mod service;
pub mod storage;
pub use model::*;
pub use protection::{KeyRing, Protection, Recipient};
pub use service::{Credentials, DisclosureRequest};
pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/filevault.sql")
);
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
