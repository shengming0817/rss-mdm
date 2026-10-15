//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod agent;

pub mod production;
pub mod recovery;

pub mod state;
pub mod storage;

mod agent_collection;
mod collection;
pub mod native_collection;
mod output;

mod poll;

pub mod history;

pub(crate) mod software;

pub(crate) mod evidence;
