//! Product-owned side-effect runs, deliberately separate from desired-state commands.
mod agent;
pub(crate) mod content;
pub(crate) mod http;
mod model;
mod production;
pub(in crate::commands) mod recovery;
mod schedule;
mod service;
mod state;
mod storage;

mod collection;
