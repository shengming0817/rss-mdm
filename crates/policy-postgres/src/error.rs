use rss_transactional_messaging_postgres::PgError;
/// Input or business rejection; no effects have been staged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("request rejected: {self:?}")]
pub enum Rejection {
    /// Input violates the current closed contract or a core invariant.
    InvalidInput,
    /// An identity belongs to another tenant.
    TenantMismatch,
    /// The required aggregate or immutable input does not exist.
    NotFound,
    /// Expected revision or lifecycle precondition no longer matches.
    Conflict,
    /// An existing immutable identity or request was reused with different bytes.
    IdentityConflict,
    /// A bounded document, fact or target limit would be exceeded.
    BudgetExceeded,
}
/// Propagate the outer error to the transaction owner; the inner value is a business result.
pub type InTransaction<T> = Result<Result<T, Rejection>, PgError>;
/// Database settlement retains the RSS commit/rollback certainty.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The adapter rejected the input before staging its mutation.
    #[error(transparent)]
    Rejected(#[from] Rejection),
    /// The transaction did not start; no transaction effects were submitted.
    #[error("transaction not started: {0}")]
    NotStarted(#[source] PgError),
    /// The transaction was confirmed rolled back.
    #[error("transaction rolled back: {0}")]
    RolledBack(#[source] PgError),
    /// Rollback could not be confirmed; retain request identity for recovery.
    #[error("rollback unconfirmed: {0}")]
    RollbackFailed(#[source] PgError),
    /// Commit may have succeeded; query or replay the identical original request.
    #[error("commit unconfirmed; resolve original request: {0}")]
    CommitUnknown(#[source] PgError),
    /// Runtime execution was fenced by RSS; do not bypass the fence.
    #[error("transaction fenced: {0}")]
    Fenced(#[source] PgError),
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

pub(crate) fn decode_domain<T>(
    stage: &'static str,
    result: Result<T, crate::core::PolicyError>,
) -> Result<T, PgError> {
    result.map_err(|error| {
        let category = match error {
            crate::core::PolicyError::InvalidKey => "InvalidKey",
            crate::core::PolicyError::InvalidRevision => "InvalidRevision",
            crate::core::PolicyError::TenantMismatch => "TenantMismatch",
            crate::core::PolicyError::PolicyMismatch => "PolicyMismatch",
            crate::core::PolicyError::RevisionConflict { .. } => "RevisionConflict",
            crate::core::PolicyError::RevisionOverflow => "RevisionOverflow",
            crate::core::PolicyError::InvalidTransition { .. } => "InvalidTransition",
            crate::core::PolicyError::InvalidSnapshot { .. } => "InvalidSnapshot",
            crate::core::PolicyError::StaleVersion { .. } => "StaleVersion",
            crate::core::PolicyError::VersionConflict { .. } => "VersionConflict",
            crate::core::PolicyError::PayloadConflict { .. } => "PayloadConflict",
            crate::core::PolicyError::IncompleteTargets => "IncompleteTargets",
            crate::core::PolicyError::InvalidExecution { .. } => "InvalidExecution",
            crate::core::PolicyError::ConflictingExecution { .. } => "ConflictingExecution",
        };
        crate::STORAGE.domain_error(
            stage,
            std::any::type_name::<crate::core::PolicyError>(),
            category,
        )
    })
}
