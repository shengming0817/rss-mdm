//! Policy/Scope coordination, resource management and durable planning automation.
pub mod action_admission;
pub mod automation;
pub mod clock;
mod diagnostic;
mod error;
mod error_projection;
pub mod operation;
pub mod planning;
pub mod resource_catalog;
pub mod transaction;
pub mod worker_wake;
pub use diagnostic::Failure;
pub use error::Error;
use rss_mdm_authorization_service as authorization;
use rss_mdm_inventory_service::{assets, compliance};
use rss_mdm_registration_service::device;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod storage;

/// Exact read-only execution authority required by native Agent registration.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
pub const ACCESS_ADMISSION_SQL: &str = include_str!("access-admission.sql");
