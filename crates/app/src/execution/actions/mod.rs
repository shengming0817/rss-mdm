//! Product-owned side-effect runs, deliberately separate from desired-state execution.
mod agent;

pub(crate) mod http;

mod production;
pub(in crate::execution) mod recovery;

pub(crate) mod state;
mod storage;

mod collection;

mod poll;

mod history;

mod plan_dispatch;

mod payload;

mod model;
