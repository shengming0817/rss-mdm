use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
pub(crate) fn settle<R>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_audit_postgres::Committed<R>,
        rss_audit_postgres::TransactionError<Error>,
    >,
    audit: &RequestAudit,
) -> Result<R, Error> {
    attempt.fold(
        |value| {
            // Optional protocol branches can commit only admission reads and return
            // control to another producer. Only that producer's marked write phase
            // changes the request's business outcome.
            if audit.snapshot().write_outcome == rss_mdm_audit_integration::WriteOutcome::Unknown {
                audit.mark_committed();
            }
            Ok(value.into_value())
        },
        |error| Err(transaction_error(error)),
        |error| {
            audit.mark_rolled_back();
            Err(transaction_error(error))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |error| Err(transaction_error(error)),
    )
}

fn transaction_error(error: rss_audit_postgres::TransactionError<Error>) -> Error {
    match error {
        rss_audit_postgres::TransactionError::Operation(error) => error,
        rss_audit_postgres::TransactionError::Audit(error) => {
            rss_mdm_audit_integration::Error::from(error).into()
        }
        rss_audit_postgres::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
