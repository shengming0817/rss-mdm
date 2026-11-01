//! Facts borrowed by Registration capabilities; no business execution or transaction settlement.
pub mod agent;
pub mod capacity;
pub mod scope;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid participant facts")]
    Malformed,
    #[error("participant identity rejected")]
    Unauthorized,
    #[error("participant access denied")]
    Forbidden,
    #[error("participant facts changed")]
    Conflict,
    #[error("participant unavailable")]
    Unavailable,
    #[error("participant commit unknown")]
    CommitUnknown,
    #[error("participant rollback unconfirmed")]
    RollbackFailed,
}
impl From<rss_transactional_messaging_postgres::PgError> for Error {
    fn from(_: rss_transactional_messaging_postgres::PgError) -> Self {
        Self::Unavailable
    }
}
