//! Host transaction settlement for execution and action-plan requests.
use crate::control::{Error, Failure};
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
    r.map_err(|_| Error::Unavailable(Failure::CommandStorage).into())
}
pub fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
pub fn json(v: &impl serde::Serialize) -> Result<Value> {
    checked_input(serde_json::to_value(v))
}
pub(crate) const TRANSACTION_BUDGET: Duration = Duration::from_secs(6);
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(TRANSACTION_BUDGET)
}
pub fn rejection(error: Fault, failure: &Mutex<Option<Error>>) -> PgError {
    let (reason, db) = match error {
        Fault::Request(e) => (e, sqlx::Error::Protocol("request rejected".into()).into()),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                    Error::Unavailable(Failure::CommandInvariant)
                }
                _ => Error::Unavailable(Failure::CommandStorage),
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
                Error::Unavailable(Failure::CommandStorage)
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
    audit.observe_attempt(attempt).fold(
        Ok,
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(Failure::CommandStorage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
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
impl From<crate::control::authorization::error::AuthorizationError> for Fault {
    fn from(error: crate::control::authorization::error::AuthorizationError) -> Self {
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
impl From<crate::control::device::DeviceError> for Fault {
    fn from(error: crate::control::device::DeviceError) -> Self {
        Error::from(error).into()
    }
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
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable(Failure::CommandStorage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
        |_| Err(Error::Unavailable(Failure::CommandStorage)),
    )
}

impl From<rss_mdm_policy::Error> for Error {
    fn from(value: rss_mdm_policy::Error) -> Self {
        match value {
            rss_mdm_policy::Error::Malformed => Self::Malformed,
            rss_mdm_policy::Error::Conflict => Self::Conflict,
            rss_mdm_policy::Error::NotFound => Self::NotFound,
        }
    }
}
impl From<rss_mdm_policy::Error> for Fault {
    fn from(value: rss_mdm_policy::Error) -> Self {
        Self::Request(value.into())
    }
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(error.into())
    }
}

impl From<rss_mdm_registration_service::Error> for Fault {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<rss_mdm_inventory_service::Error> for Fault {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<rss_mdm_inventory_service::transaction::Fault> for Fault {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        use rss_mdm_inventory_service::transaction::Fault as I;
        match e {
            I::Request(e) => Self::Request(e.into()),
            I::Storage(e) => Self::Storage(e),
            I::Sql(e) => Self::Sql(e),
        }
    }
}

pub(crate) async fn prepare_audit_in(
    store: &rss_mdm_audit_integration::AuditStore,
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    business: &[rss_transactional_messaging::message::PartitionIdentity],
) -> std::result::Result<(), rss_mdm_audit_integration::Error> {
    store.prepare_in(tx, audit, business).await
}

impl From<rss_mdm_task_state::Error> for Fault {
    fn from(error: rss_mdm_task_state::Error) -> Self {
        Self::Request(error.into())
    }
}

impl From<rss_mdm_registration_service::command_authority::CommandAuthorityError> for Fault {
    fn from(e: rss_mdm_registration_service::command_authority::CommandAuthorityError) -> Self {
        use rss_mdm_registration_service::command_authority::CommandAuthorityError as E;
        match e {
            E::Storage(e) => Self::Storage(e),
            E::Sql(e) => Self::Sql(e),
            E::Registration(e) => Error::from(e).into(),
            E::Conflict => Error::Conflict.into(),
        }
    }
}
