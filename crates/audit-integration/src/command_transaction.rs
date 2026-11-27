//! Settle a product command on the original fenced RSS transaction.
//! ref: rss transactional-messaging-postgres/src/transaction.rs@9843ec49
use crate::RequestAudit;
use futures::future::BoxFuture;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{marker::PhantomData, sync::Mutex, time::Duration};

pub enum Failure {
    Storage,
    Invariant,
    Conflict,
    CommitUnknown,
    RollbackFailed,
}
pub enum Rejection<E> {
    Request(E),
    Storage(PgError),
    Sql(sqlx::Error),
}
pub trait CommandFault: From<crate::Error> + Send {
    type Error: From<Failure> + Send;
    fn into_rejection(self) -> Rejection<Self::Error>;
}
pub const TRANSACTION_BUDGET: Duration = Duration::from_secs(6);
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(TRANSACTION_BUDGET)
}
pub struct Transaction<F>(PhantomData<F>);
impl<F: CommandFault> Transaction<F> {
    pub fn rejection(error: F, failure: &Mutex<Option<F::Error>>) -> PgError {
        let (reason, db) = match error.into_rejection() {
            Rejection::Request(e) => (e, sqlx::Error::Protocol("request rejected".into()).into()),
            Rejection::Storage(e) => {
                use rss_transactional_messaging::error::MessagingErrorKind;
                let reason = match e.kind() {
                    MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => {
                        Failure::Conflict.into()
                    }
                    MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                        Failure::Invariant.into()
                    }
                    _ => Failure::Storage.into(),
                };
                (reason, e)
            }
            Rejection::Sql(e) => {
                let reason = if e
                    .as_database_error()
                    .and_then(|e| e.code())
                    .is_some_and(|c| c == "40001" || c == "40P01")
                {
                    Failure::Conflict.into()
                } else {
                    Failure::Storage.into()
                };
                (reason, e.into())
            }
        };
        *failure.lock().expect("request result") = Some(reason);
        db
    }
    pub fn settle<T>(
        attempt: rss_transactional_messaging::transaction::LocalTxAttempt<T, PgError>,
        audit: &RequestAudit,
        failure: Mutex<Option<F::Error>>,
    ) -> Result<T, F::Error> {
        audit.observe_attempt(attempt).fold(
            Ok,
            |_| Err(Failure::Storage.into()),
            |_| {
                Err(failure
                    .into_inner()
                    .expect("request result")
                    .unwrap_or(Failure::Storage.into()))
            },
            |_| Err(Failure::RollbackFailed.into()),
            |_| Err(Failure::CommitUnknown.into()),
            |_| Err(Failure::Conflict.into()),
        )
    }
    /// The owner locks its actual business objects before declaring partitions.
    pub async fn run<C: Send, R: Send, Op>(
        audit_store: &crate::AuditStore,
        runtime: &PgRuntime,
        binding: ExecutionBinding,
        audit: &RequestAudit,
        context: C,
        operation: Op,
    ) -> Result<R, F::Error>
    where
        Op: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, F>>
            + Send,
    {
        let failure = Mutex::new(None);
        let attempt = runtime
            .local_tx_with_context(
                binding,
                deadline(),
                (audit_store, context, Some(operation), audit, &failure),
                |state, tx| {
                    Box::pin(async move {
                        let (audit_store, context, operation, audit, failure) = state;
                        if let Err(error) = audit_store.bind_in(tx).await {
                            return Err(Self::rejection(F::from(error), failure));
                        }
                        let f = operation.take().expect("one callback");
                        match f(context, tx).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => Err(Self::rejection(e, failure)),
                        }
                    })
                },
            )
            .await;
        Self::settle(attempt, audit, failure)
    }
    /// Short preflight read/row-lock transaction. It must not persist business changes or audit facts.
    /// It deliberately does not advance the outer request's single mutation settlement state.
    pub async fn inspect<C: Send, R: Send, Op>(
        runtime: &PgRuntime,
        binding: ExecutionBinding,
        context: C,
        operation: Op,
    ) -> Result<R, F::Error>
    where
        Op: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, F>>
            + Send,
    {
        Self::inspect_budget(runtime, binding, deadline(), context, operation).await
    }

    pub async fn inspect_budget<C: Send, R: Send, Op>(
        runtime: &PgRuntime,
        binding: ExecutionBinding,
        budget: rss_transactional_messaging::policy::OperationDeadline,
        context: C,
        operation: Op,
    ) -> Result<R, F::Error>
    where
        Op: for<'c> FnOnce(&'c mut C, &'c mut PgTransaction<'_>) -> BoxFuture<'c, Result<R, F>>
            + Send,
    {
        let failure = Mutex::new(None);
        let attempt = runtime
            .local_tx_with_context(
                binding,
                budget,
                (context, Some(operation), &failure),
                |state, tx| {
                    Box::pin(async move {
                        let (context, operation, failure) = state;
                        operation.take().expect("one preflight")(context, tx)
                            .await
                            .map_err(|e| Self::rejection(e, failure))
                    })
                },
            )
            .await;
        attempt.fold(
            Ok,
            |_| Err(Failure::Storage.into()),
            |_| {
                Err(failure
                    .into_inner()
                    .expect("preflight result")
                    .unwrap_or(Failure::Storage.into()))
            },
            |_| Err(Failure::RollbackFailed.into()),
            |_| Err(Failure::Storage.into()),
            |_| Err(Failure::Conflict.into()),
        )
    }
}

/// Background admission evidence is appended by the owner on the projection transaction.
pub fn dispatch_audit(
    profile: crate::StorageProfile,
    binding: ExecutionBinding,
    owner: crate::operation::OperationOwner,
    id: uuid::Uuid,
    actor: &'static str,
) -> RequestAudit {
    let audit = RequestAudit::new(
        crate::Origin::Background,
        profile,
        binding,
        "command_dispatch",
        crate::AuditIntent::Management,
    );
    audit.owned_operation(
        owner,
        id,
        "command_dispatch",
        crate::AuditIntent::Management,
    );
    audit.identify_service(actor);
    audit
}
