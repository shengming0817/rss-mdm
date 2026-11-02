//! Recovery owns credential tasks, candidate material correlation and durable reconciliation.
pub mod actions;
pub mod credential_tasks;
mod error;
pub mod policy;
pub mod policy_recovery;
pub mod product;
pub mod publication;
mod service;
pub mod transaction;
pub mod wake;
pub mod worker;
pub use error::Error;
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::participants::agent as agent_facts;
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
pub use actions::production::messaging_domain;
pub use actions::storage;

pub mod events;

pub mod queries;
pub mod retirement;
