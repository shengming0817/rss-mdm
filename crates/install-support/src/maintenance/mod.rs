//! Bounded filesystem journals, archive integrity and database fencing for product operators.
pub mod archive;
pub mod fence;
pub mod journal;
pub mod snapshot_tree;
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
