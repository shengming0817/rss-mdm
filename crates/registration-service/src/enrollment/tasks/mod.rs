//! Enrollment task runs and request entries belong to Registration.
pub mod activity;
pub mod admission;
pub mod agent;
pub mod agent_facts;
pub mod eligibility;
mod error;
pub mod events;
pub mod native;
pub mod policy;
pub mod policy_recovery;
pub mod poll;
pub mod recovery;
pub mod runs;
pub mod self_service;
mod service;
pub mod storage;
mod target;
pub mod transaction;
pub mod wake;
pub mod worker;
use super::task::FrozenEnrollment;
pub use error::Error;
use rss_mdm_authorization_service as authorization;
pub use service::{Materials, Service, Transactions};
pub use target::Target;
pub use transaction::{Result, checked_input, stored};
pub trait Inventory: Send + Sync {
    fn enrollment_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        registration: uuid::Uuid,
        generation: i64,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = std::result::Result<rss_mdm_inventory::channel::Observation, Error>>
                + Send
                + 'a,
        >,
    >;
}

pub mod retirement;

pub mod queries;

pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
