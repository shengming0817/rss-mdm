//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod activity;
pub mod agent;

pub mod production;
pub mod recovery;

pub mod storage;

pub(crate) mod run_recovery;

pub mod poll;

pub mod history;

pub(crate) mod evidence;

pub mod result;
