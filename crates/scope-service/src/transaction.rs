//! Scope request settlement over the initiating RSS transaction.
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
    r.map_err(|_| Error::Unavailable(Failure::Storage).into())
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
                    Error::Unavailable(Failure::Storage)
                }
                _ => Error::Unavailable(Failure::Storage),
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
                Error::Unavailable(Failure::Storage)
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
        |_| Err(Error::Unavailable(Failure::Storage)),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(Failure::Storage)))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::Storage)),
    )
}
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

use sha2::{Digest, Sha256};
pub fn fingerprint(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(checked_input(serde_json::to_vec(value))?).to_vec())
}

use serde_json::Value;
pub async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_registration_service::lifecycle::lock_write_watermarks_in(c, &tenant).await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                .bind(tenant)
                .execute(&mut *c)
                .await?;

            Ok(())
        })
    })
    .await?;
    Ok(())
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
        |_| Err(Error::Unavailable(Failure::Storage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable(Failure::Storage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable(Failure::Storage)),
        |_| Err(Error::Unavailable(Failure::Storage)),
    )
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(e.into())
    }
}
impl From<rss_mdm_scope_postgres::BindingError> for Fault {
    fn from(e: rss_mdm_scope_postgres::BindingError) -> Self {
        use rss_mdm_scope_postgres::BindingError as E;
        match e {
            E::Storage(e) => Self::Storage(e),
            E::TenantMismatch => Error::Forbidden.into(),
            E::Missing => Error::NotFound.into(),
            E::Conflict => Error::Conflict.into(),
            E::Invalid => Error::Malformed.into(),
        }
    }
}
impl From<rss_mdm_audit_integration::operation_receipts::Error> for Fault {
    fn from(e: rss_mdm_audit_integration::operation_receipts::Error) -> Self {
        use rss_mdm_audit_integration::operation_receipts::Error as E;
        match e {
            E::Storage(e) => Self::Storage(e),
            E::Sql(e) => Self::Sql(e),
            E::Conflict => Error::Conflict.into(),
            E::Malformed => Error::Malformed.into(),
            E::Invariant => Error::Unavailable(Failure::Storage).into(),
        }
    }
}
