//! Participants borrow the initiating transaction; only the initiating owner settles it.
use crate::enrollment::tasks::Error;
#[derive(Debug, thiserror::Error)]
pub enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] rss_transactional_messaging_postgres::PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub type Result<T> = std::result::Result<T, Fault>;
pub fn checked_input<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Malformed.into())
}
pub fn stored<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Invariant.into())
}

impl From<rss_mdm_task_state::Error> for Fault {
    fn from(e: rss_mdm_task_state::Error) -> Self {
        Self::Request(e.into())
    }
}

pub fn checked<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Conflict.into())
}
pub fn json(value: &impl serde::Serialize) -> Result<serde_json::Value> {
    checked_input(serde_json::to_value(value))
}
impl From<crate::Error> for Fault {
    fn from(e: crate::Error) -> Self {
        Self::Request(e.into())
    }
}
impl From<rss_mdm_audit_integration::Error> for Fault {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::Request(e.into())
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Fault {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::from(rss_mdm_audit_integration::Error::Fact(e))
    }
}
impl From<crate::participants::scope::SourceError> for Fault {
    fn from(e: crate::participants::scope::SourceError) -> Self {
        use crate::participants::scope::SourceError as S;
        match e {
            S::Missing => Error::NotFound.into(),
            S::Conflict => Error::Conflict.into(),
            S::Invariant => Error::Invariant.into(),
            S::Capacity => Error::Unavailable.into(),
            S::Storage(e) => Self::Sql(e),
        }
    }
}
impl From<rss_mdm_policy::Error> for Fault {
    fn from(e: rss_mdm_policy::Error) -> Self {
        Self::Request(e.into())
    }
}

pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(6),
    )
}

use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::sync::Mutex;
pub fn rejection(error: Fault, failure: &Mutex<Option<Error>>) -> PgError {
    let (reason, db) = match error {
        Fault::Request(e) => (e, sqlx::Error::Protocol("request rejected".into()).into()),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => Error::Invariant,
                _ => Error::Unavailable,
            };
            (reason, e)
        }
        Fault::Sql(e) => {
            let reason = if e
                .as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|c| c == "40001" || c == "40P01")
            {
                Error::Conflict
            } else {
                Error::Unavailable
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
    failure: Mutex<Option<Error>>,
) -> std::result::Result<T, Error> {
    attempt.fold(
        |v| {
            audit.mark_committed();
            Ok(v)
        },
        |_| Err(Error::Unavailable),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable),
    )
}
/// The owner locks its actual business objects before declaring partitions.
pub async fn run<C: Send, R: Send, F>(
    audit_store: &rss_mdm_audit_integration::AuditStore,
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &RequestAudit,
    context: C,
    operation: F,
) -> std::result::Result<R, Error>
where
    F: for<'c> FnOnce(
            &'c mut C,
            &'c mut PgTransaction<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<R>> + Send + 'c>,
        > + Send,
{
    let failure = Mutex::new(None);
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            deadline(),
            (audit_store, context, Some(operation), audit, &failure),
            |state, tx| {
                Box::pin(async move {
                    let (audit_store, context, operation, audit, failure) = state;
                    if let Err(error) = audit_store.bind_in(tx).await {
                        return Err(rejection(Error::from(error).into(), failure));
                    }
                    let f = operation.take().expect("one callback");
                    match f(context, tx).await {
                        Ok(v) => {
                            audit.mark_commit_started();
                            Ok(v)
                        }
                        Err(e) => Err(rejection(e, failure)),
                    }
                })
            },
        )
        .await;
    settle(attempt, audit, failure)
}
/// Short preflight read/row-lock transaction. It must not persist business changes or audit facts.
/// It deliberately does not advance the outer request's single mutation settlement state.
pub async fn inspect<C: Send, R: Send, F>(
    runtime: &PgRuntime,
    tenant: TenantId,
    context: C,
    operation: F,
) -> std::result::Result<R, Error>
where
    F: for<'c> FnOnce(
            &'c mut C,
            &'c mut PgTransaction<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<R>> + Send + 'c>,
        > + Send,
{
    inspect_budget(runtime, tenant, deadline(), context, operation).await
}

pub(crate) async fn inspect_budget<C: Send, R: Send, F>(
    runtime: &PgRuntime,
    tenant: TenantId,
    budget: rss_transactional_messaging::policy::OperationDeadline,
    context: C,
    operation: F,
) -> std::result::Result<R, Error>
where
    F: for<'c> FnOnce(
            &'c mut C,
            &'c mut PgTransaction<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<R>> + Send + 'c>,
        > + Send,
{
    let failure = Mutex::new(None);
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            budget,
            (context, Some(operation), &failure),
            |state, tx| {
                Box::pin(async move {
                    let (context, operation, failure) = state;
                    operation.take().expect("one preflight")(context, tx)
                        .await
                        .map_err(|e| rejection(e, failure))
                })
            },
        )
        .await;
    attempt.fold(
        Ok,
        |_| Err(Error::Unavailable),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable),
        |_| Err(Error::Unavailable),
    )
}

impl From<crate::enrollment::tasks::authorization::error::AuthorizationError> for Fault {
    fn from(e: crate::enrollment::tasks::authorization::error::AuthorizationError) -> Self {
        Self::Request(e.into())
    }
}
impl From<crate::enrollment::tasks::authorization::Error> for Fault {
    fn from(e: crate::enrollment::tasks::authorization::Error) -> Self {
        Self::Request(e.into())
    }
}
pub fn fingerprint(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(checked_input(serde_json::to_vec(value))?).to_vec())
}
pub(crate) async fn prepare_audit_in(
    store: &rss_mdm_audit_integration::AuditStore,
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    business: &[rss_transactional_messaging::message::PartitionIdentity],
) -> Result<()> {
    store.prepare_in(tx, audit, business).await?;
    Ok(())
}

impl From<crate::participants::Error> for Fault {
    fn from(error: crate::participants::Error) -> Self {
        use crate::participants::Error as P;
        Self::Request(match error {
            P::Malformed => Error::Malformed,
            P::Unauthorized => Error::Unauthorized,
            P::Forbidden => Error::Forbidden,
            P::Conflict => Error::Conflict,
            P::Unavailable => Error::Unavailable,
            P::CommitUnknown => Error::CommitUnknown,
            P::RollbackFailed => Error::RollbackFailed,
        })
    }
}
