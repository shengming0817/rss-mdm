//! Product deployment and complete tenant provisioning. No generic workflow or configuration store.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs; Rust std/fs File::try_lock.
#[cfg(unix)]
mod application;
#[cfg(unix)]
pub mod backup;
#[cfg(unix)]
pub mod configure;
#[cfg(unix)]
pub mod deployment;
pub mod host;
#[cfg(unix)]
pub mod installation;
#[cfg(unix)]
mod local;
pub mod model;
#[cfg(unix)]
mod postgres;
#[cfg(unix)]
pub mod protection;
#[cfg(unix)]
pub mod providers;
pub mod public_configuration;
#[cfg(unix)]
mod snapshot_tree;
#[cfg(unix)]
mod supervisor;
#[cfg(unix)]
pub mod tenant_hosts;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("installation input rejected")]
    Input,
    #[error("installation journal is busy")]
    Busy,
    #[error("installation input conflicts with the original operation")]
    Conflict,
    #[error("installation journal is incomplete or corrupt; restore its original state")]
    Corrupt,
    #[error("installation storage unavailable; query the original operation")]
    Storage,
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(test, unix))]
pub(crate) async fn content_snapshot_fixture(
    connection: &mut sqlx::PgConnection,
    directory: &std::path::Path,
    host: uuid::Uuid,
    runtime: &serde_json::Value,
    restore: bool,
) -> Result<()> {
    let journal = local::Journal::open(directory)?;
    if restore {
        backup::storage::restore(connection, &journal, host, runtime).await
    } else {
        backup::storage::capture(connection, &journal, host, runtime).await
    }
}
