//! Product error propagation over the RSS transaction owner; no product commit/rollback engine.
use crate::{Error, budget::SourceControl};
use futures::future::BoxFuture;
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use sqlx::PgConnection;

/// A borrowed source transaction. Only RSS owns its connection lifetime and settlement.
pub struct SourceTransaction<'a, 'tx> {
    pub(crate) inner: &'a mut PgTransaction<'tx>,
    pub(crate) facts: Vec<crate::queue::StagedFact>,
}
impl SourceTransaction<'_, '_> {
    pub fn tenant_id(&self) -> TenantId {
        self.inner.tenant_id()
    }
    pub async fn with_connection<R: Send, E: Send + From<Error>, F>(
        &mut self,
        operation: F,
    ) -> Result<R, E>
    where
        F: for<'a> FnOnce(&'a mut PgConnection) -> BoxFuture<'a, Result<R, E>> + Send,
    {
        self.with_connection_context(&mut Some(operation), |operation, connection| {
            operation
                .take()
                .expect("connection callback is invoked once")(connection)
        })
        .await
    }

    pub async fn with_connection_context<R: Send, E: Send + From<Error>, C: Send, F>(
        &mut self,
        context: &mut C,
        operation: F,
    ) -> Result<R, E>
    where
        F: for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> BoxFuture<'a, Result<R, E>> + Send,
    {
        self.inner
            .with_connection_context(
                &mut (context, Some(operation)),
                |(context, operation), connection| {
                    Box::pin(async move {
                        let operation = operation
                            .take()
                            .expect("connection callback is invoked once");
                        Ok(operation(context, connection).await)
                    })
                },
            )
            .await
            .map_err(|error| E::from(Error::Audit(error.into())))?
    }
}

/// Typed operation failures do not change the enclosing canonical settlement outcome.
#[derive(thiserror::Error)]
pub enum TransactionError<E> {
    #[error("source operation rejected")]
    Operation(E),
    #[error("source storage unavailable")]
    Storage(Error),
    #[error("source rollback was not acknowledged")]
    Rollback {
        operation: Box<Self>,
        settlement: Error,
    },
}

impl<E> std::fmt::Debug for TransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(_) => f.write_str("Operation([redacted])"),
            Self::Storage(error) => f.debug_tuple("Storage").field(error).finish(),
            Self::Rollback {
                operation,
                settlement,
            } => f
                .debug_struct("Rollback")
                .field("operation", operation)
                .field("settlement", settlement)
                .finish(),
        }
    }
}

pub(crate) async fn write<T: ExecutionTimer, C: Send, R: Send, E: Send + From<Error>, F>(
    runtime: &PgRuntime,
    tenant: TenantId,
    control: &SourceControl<'_, T>,
    context: C,
    operation: F,
) -> LocalTxAttempt<R, TransactionError<E>>
where
    F: for<'a> FnOnce(&'a mut C, &'a mut SourceTransaction<'_, '_>) -> BoxFuture<'a, Result<R, E>>
        + Send,
{
    if let Err(error) = control.check() {
        return LocalTxAttempt::not_started(TransactionError::Storage(error));
    }
    let mut failure = None;
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            control.deadline(),
            (context, Some(operation), control, &mut failure),
            |(context, operation, control, failure), tx| {
                Box::pin(async move {
                    let operation = operation
                        .take()
                        .expect("RSS invokes the transaction callback once");
                    let mut source = SourceTransaction {
                        inner: tx,
                        facts: Vec::new(),
                    };
                    match control.run(operation(context, &mut source)).await {
                        Ok(value) => Ok(value),
                        Err(error) => {
                            **failure = Some(error);
                            Err(sqlx::Error::Protocol("source operation rejected".into()).into())
                        }
                    }
                })
            },
        )
        .await;
    let failure = std::cell::RefCell::new(failure);
    let error = |error| {
        failure.borrow_mut().take().map_or_else(
            || TransactionError::Storage(Error::Audit(rss_audit_postgres::Error::from(error))),
            TransactionError::Operation,
        )
    };
    attempt.fold(
        LocalTxAttempt::committed,
        |value| LocalTxAttempt::not_started(error(value)),
        |value| LocalTxAttempt::rolled_back(error(value)),
        |value| {
            LocalTxAttempt::rollback_failed(TransactionError::Rollback {
                operation: Box::new(failure.borrow_mut().take().map_or(
                    TransactionError::Storage(Error::RollbackFailed),
                    TransactionError::Operation,
                )),
                settlement: Error::Audit(value.into()),
            })
        },
        |value| LocalTxAttempt::commit_unknown(error(value)),
        |value| LocalTxAttempt::fenced(error(value)),
    )
}
