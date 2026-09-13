use rss_transactional_messaging_postgres::PgError;
/// Input or business rejection; no effects have been staged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("request rejected: {self:?}")]
pub enum Rejection {
    InvalidInput,
    TenantMismatch,
    NotFound,
    Conflict,
    IdentityConflict,
    BudgetExceeded,
}
/// Propagate the outer error to the transaction owner; the inner value is a business result.
pub type InTransaction<T> = Result<Result<T, Rejection>, PgError>;
/// Database settlement retains the RSS commit/rollback certainty.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Rejected(#[from] Rejection),
    #[error("transaction not started: {0}")]
    NotStarted(PgError),
    #[error("transaction rolled back: {0}")]
    RolledBack(PgError),
    #[error("rollback unconfirmed: {0}")]
    RollbackFailed(PgError),
    #[error("commit unconfirmed; resolve original request: {0}")]
    CommitUnknown(PgError),
    #[error("transaction fenced: {0}")]
    Fenced(PgError),
}
pub(crate) fn settle<T>(
    a: rss_transactional_messaging::transaction::LocalTxAttempt<Result<T, Rejection>, PgError>,
) -> Result<T, Error> {
    a.fold(
        |v| v.map_err(Error::Rejected),
        |e| Err(Error::NotStarted(e)),
        |e| Err(Error::RolledBack(e)),
        |e| Err(Error::RollbackFailed(e)),
        |e| Err(Error::CommitUnknown(e)),
        |e| Err(Error::Fenced(e)),
    )
}
macro_rules! input {
    ($v:expr) => {
        match $v {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        }
    };
}
pub(crate) use input;
