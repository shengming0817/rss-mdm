//! Host transaction settlement for execution and action-plan requests.
use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{sync::Mutex, time::Duration};
#[derive(Debug, thiserror::Error)]
pub enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub type Result<T> = std::result::Result<T, Fault>;
pub fn checked_input<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Malformed.into())
}
pub fn stored<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Unavailable(Failure::ResourceStorage).into())
}
pub fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
pub fn json(v: &impl serde::Serialize) -> Result<Value> {
    checked_input(serde_json::to_value(v))
}
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6))
}
pub fn rejection(error: Fault, failure: &Mutex<Option<Error>>) -> PgError {
    #[cfg(any(test, feature = "integration"))]
    eprintln!("transaction rejected: {error:?}");
    let (reason, db) = match error {
        Fault::Request(e) => (e, sqlx::Error::Protocol("request rejected".into()).into()),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                    Error::Unavailable(Failure::ResourceStorage)
                }
                _ => Error::Unavailable(Failure::ResourceStorage),
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
                Error::Unavailable(Failure::ResourceStorage)
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
        |_| Err(Error::Unavailable(Failure::ResourceStorage)),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(Failure::ResourceStorage)))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::ResourceStorage)),
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "transaction context retains owner, deadline and complete message partition declaration"
)]
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
impl From<crate::authorization::error::AuthorizationError> for Fault {
    fn from(error: crate::authorization::error::AuthorizationError) -> Self {
        Error::from(error).into()
    }
}

use rss_mdm_audit_integration::RequestAudit;

impl From<rss_mdm_audit_integration::Error> for Fault {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        Self::Request(error.into())
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Fault {
    fn from(error: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::Request(rss_mdm_audit_integration::Error::Fact(error).into())
    }
}

use serde_json::Value;
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
    let failure = Mutex::new(None);
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            deadline(),
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
        |_| Err(Error::Unavailable(Failure::ResourceStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable(Failure::ResourceStorage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable(Failure::ResourceStorage)),
        |_| Err(Error::Unavailable(Failure::ResourceStorage)),
    )
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(error.into())
    }
}

/// Read authority on the original transaction, preserving the lifecycle-before-authorization order.
pub async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<crate::authorization::Snapshot> {
    if proof.tenant_id() != tx.tenant_id().to_string() {
        return Err(Error::Forbidden.into());
    }
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::authorization::lock_shared_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??)
}
