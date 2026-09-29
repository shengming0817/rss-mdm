//! Product planning, execution and automation. Protocol transports borrow Flow-owned transactions.
pub mod action_admission;
pub mod automation;
pub mod clock;
mod database;
mod diagnostic;
mod error;
mod error_projection;
pub mod execution;
pub mod operation;
pub mod planning;
pub mod resource_catalog;
pub mod software_publication;
pub mod task_signing;
pub mod transaction;
pub mod worker_wake;
pub use diagnostic::{ConfigIssue, Failure};
pub use error::Error;
use rss_mdm_authorization_service as authorization;
use rss_mdm_inventory_service::{assets, collection, compliance};
use rss_mdm_registration_service::device;

pub mod content;

pub mod software_catalog;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod storage;
