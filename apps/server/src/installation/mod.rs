//! Product deployment and complete tenant provisioning. No generic workflow or configuration store.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs; Rust std/fs File::try_lock.
#[cfg(unix)]
mod application;
#[cfg(unix)]
pub mod backup;
#[cfg(unix)]
pub mod configure;
#[cfg(unix)]
pub mod content_storage;
#[cfg(unix)]
pub mod default_telemetry;
pub mod host;
#[cfg(unix)]
pub mod install;
#[cfg(unix)]
use rss_mdm_install_support::maintenance::journal as local;
pub mod model;
#[cfg(unix)]
mod postgres;
#[cfg(unix)]
pub mod protection;
#[cfg(unix)]
pub mod providers;
pub mod public_configuration;
#[cfg(unix)]
pub mod runtime_files;
#[cfg(unix)]
use rss_mdm_install_support::maintenance::snapshot_tree;
#[cfg(unix)]
pub mod tenant_hosts;
pub use rss_mdm_install_support::maintenance::{Error, Result};
