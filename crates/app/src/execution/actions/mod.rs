//! Product-owned side-effect runs, deliberately separate from desired-state execution.
mod agent;

pub(crate) mod http;

pub(in crate::execution) mod production;
pub(in crate::execution) mod recovery;

pub(crate) mod state;
pub(in crate::execution) mod storage;

mod collection;

mod poll;

pub(crate) mod history;

mod payload;

pub(in crate::execution) mod model;
