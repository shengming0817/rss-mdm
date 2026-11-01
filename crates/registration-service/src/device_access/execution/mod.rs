//! Per-account access delivery and reconciliation belong to Registration.
pub mod activity;
pub mod admission;
pub mod agent;
mod error;
pub mod policy_recovery;
pub mod poll;
pub mod production;
mod provisioning;
pub mod recovery;
mod service;
pub mod storage;
pub mod transaction;
pub mod wake;
pub mod worker;
use crate::participants::agent as agent_facts;
pub use error::Error;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service as authorization;
use rss_transactional_messaging_postgres::PgTransaction;
pub use service::{Materials, Service, Transactions};
use std::sync::Arc;
pub use transaction::{Result, checked_input, stored};
use uuid::Uuid;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
pub const INSTALL_SQL: &str = include_str!("../../../schema/device-access-tasks.sql");

pub mod events;

pub mod queries;
pub mod retirement;

mod storage_admission;
pub use storage_admission::verify_storage;
