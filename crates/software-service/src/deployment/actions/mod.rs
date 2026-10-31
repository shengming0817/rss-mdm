//! Product-owned side-effect runs, deliberately separate from desired-state execution.
pub(crate) mod activity;
pub mod agent;

pub mod production;
pub mod recovery;
pub(crate) mod scheduled;

pub mod storage;

pub(crate) mod run_recovery;

pub mod poll;

pub mod history;

pub(crate) mod software;

pub(crate) mod evidence;

pub(crate) mod native_software;

pub mod result;
