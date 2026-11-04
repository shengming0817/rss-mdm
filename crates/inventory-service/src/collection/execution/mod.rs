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

mod activity;
pub mod agent;
pub mod poll;

pub mod admission;

pub mod recovery;

pub mod policy_recovery;

pub mod checkins;
pub mod scheduled;

pub mod worker;

pub mod events;

pub mod retirement;

mod storage_admission;
pub use storage_admission::verify_storage;

pub mod preview;

mod windows_wake;

pub mod queries;

pub mod assignment;
