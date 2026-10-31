//! Stable collection tasks, distinct from per-attempt report identity and projection.
pub mod agent_facts;
pub mod agent_result;
pub mod eligibility;
pub mod frozen;
pub mod inputs;
pub mod model;
pub mod output;
pub mod participants;
pub mod result;

pub mod native;
pub mod policy;
pub mod service;
pub mod storage;
pub mod wake;
pub use service::{CollectionService, Materials, Transactions};
