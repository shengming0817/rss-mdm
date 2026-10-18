//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod agent;

pub mod production;
pub mod recovery;

pub mod state;
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
