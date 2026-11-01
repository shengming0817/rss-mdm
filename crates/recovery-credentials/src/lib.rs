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
    include_str!("../schema/filevault.sql"),
    "\n",
    include_str!("../schema/tasks.sql"),
    "\n",
    include_str!("../schema/native.sql"),
    "\n",
    include_str!("../schema/task-relations.sql")
);
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub mod access;
pub mod cleanup;
pub mod lock_pin;
pub mod maintenance;
pub mod native;
pub mod native_receipts;
pub mod tasks;

mod storage_admission;
pub use storage_admission::verify_storage;
