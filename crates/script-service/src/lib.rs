//! Script execution owns frozen inputs, runs and the device execution lifecycle.
mod activity;
pub mod admission;
pub mod agent;
pub mod agent_facts;
pub mod eligibility;
pub mod frozen;
mod output;
pub mod policy;
pub mod poll;
pub mod recovery;
pub mod results;
pub mod runs;
pub mod self_service;
mod service;
pub mod storage;
pub mod wake;
pub use service::{DeviceCapacity, Materials, ScriptService, Transactions};
pub mod inputs;
mod parameters;
pub mod preparation;
pub use parameters::Parameters;
mod error;
mod payload;
mod target;
pub mod transaction;
pub use error::Error;
pub use frozen::FrozenScript;
pub use target::Target;
pub use transaction::{Result, checked_input, stored};

use rss_mdm_authorization_service as authorization;

/// Fresh installation and cross-owner privileges for Script execution.
pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/task-retirement.sql")
);
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod policy_recovery;

pub mod worker;

pub mod events;

pub mod retirement;

mod storage_admission;
pub use storage_admission::verify_storage;

pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub mod preview;

pub mod queries;

pub mod assignment;
