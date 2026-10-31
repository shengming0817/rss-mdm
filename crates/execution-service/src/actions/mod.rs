//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod activity;
pub(crate) mod agent;

pub mod production;
pub mod recovery;
pub(crate) mod scheduled;

#[cfg(test)]
#[path = "../../tests/actions/state_schedule_unit.rs"]
mod state_schedule_tests;
pub mod storage;

mod agent_collection;
mod collection;
pub mod native_collection;
pub(crate) mod native_recovery;
mod output;

mod poll;

pub mod history;

pub(crate) mod software;

pub(crate) mod evidence;

mod native_enrollment;

pub(crate) mod native_software;

pub mod result;
