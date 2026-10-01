//! Product-owned side-effect runs, deliberately separate from desired-state execution.
mod agent;

pub mod production;
pub mod recovery;

pub mod state;
pub mod storage;

mod collection;
pub mod native_collection;
mod output;

mod poll;

pub mod history;

mod payload;
mod software;

pub mod model;

pub(crate) mod software_exports;
pub(crate) mod software_wire;
