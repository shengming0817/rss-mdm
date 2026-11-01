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
    r.map_err(|_| Error::Unavailable(Failure::PlanningStorage).into())
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
    let (reason, db) = match error {
        Fault::Request(e) => {
            let e = match e {
                Error::Unavailable(Failure::PlanningStorage) => {
                    Error::Unavailable(Failure::ComplianceStorage)
                }
                other => other,
            };
            (e, sqlx::Error::Protocol("request rejected".into()).into())
        }
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                    Error::Unavailable(Failure::ComplianceStorage)
                }
                _ => Error::Unavailable(Failure::ComplianceStorage),
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
                Error::Unavailable(Failure::ComplianceStorage)
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
        |_| Err(Error::Unavailable(Failure::ComplianceStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(Failure::ComplianceStorage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::ComplianceStorage)),
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
    run_budget(
        audit_store,
        runtime,
        tenant,
        audit,
        context,
        operation,
        deadline(),
    )
    .await
}

/// Reuse the request cutoff after a committed-input read, without extending its lifetime.
#[allow(
    clippy::too_many_arguments,
    reason = "same transaction owner with an explicit preflight cutoff"
)]
pub async fn run_budget<C: Send, R: Send, F>(
    audit_store: &rss_mdm_audit_integration::AuditStore,
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &RequestAudit,
    context: C,
    operation: F,
    cutoff: rss_transactional_messaging::policy::OperationDeadline,
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
            cutoff,
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
impl From<crate::device::DeviceError> for Fault {
    fn from(error: crate::device::DeviceError) -> Self {
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
        |_| Err(Error::Unavailable(Failure::ComplianceStorage)),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable(Failure::ComplianceStorage)))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable(Failure::ComplianceStorage)),
        |_| Err(Error::Unavailable(Failure::ComplianceStorage)),
    )
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(e.into())
    }
}
impl From<rss_mdm_registration_service::Error> for Fault {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::Request(e.into())
    }
}

/// Re-read authorization inside the transaction before binding a directory continuation.
pub async fn query_authority(
    tx: &mut PgTransaction<'_>,
    p: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<crate::authorization::Snapshot> {
    let tenant = p.tenant_id().to_owned();
    let instance = p.instance_id().to_owned();
    if tenant != tx.tenant_id().to_string() {
        return Err(Error::Forbidden.into());
    }
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::authorization::lock_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &instance,
                )
                .await
                .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &instance,
                )
                .await)
            })
        })
        .await??;
    Ok(snapshot)
}

impl From<rss_mdm_task_state::Error> for Fault {
    fn from(e: rss_mdm_task_state::Error) -> Self {
        match e {
            rss_mdm_task_state::Error::Malformed => Error::Malformed.into(),
            rss_mdm_task_state::Error::Conflict => Error::Conflict.into(),
        }
    }
}
impl From<rss_mdm_policy::Error> for Fault {
    fn from(e: rss_mdm_policy::Error) -> Self {
        match e {
            rss_mdm_policy::Error::Malformed => Error::Malformed.into(),
            rss_mdm_policy::Error::Conflict => Error::Conflict.into(),
            rss_mdm_policy::Error::NotFound => Error::NotFound.into(),
        }
    }
}

impl From<rss_mdm_inventory_service::transaction::Fault> for Fault {
    fn from(value: rss_mdm_inventory_service::transaction::Fault) -> Self {
        match value {
            rss_mdm_inventory_service::transaction::Fault::Request(e) => Self::Request(e.into()),
            rss_mdm_inventory_service::transaction::Fault::Storage(e) => Self::Storage(e),
            rss_mdm_inventory_service::transaction::Fault::Sql(e) => Self::Sql(e),
        }
    }
}
impl From<rss_mdm_inventory_service::Error> for Fault {
    fn from(value: rss_mdm_inventory_service::Error) -> Self {
        Self::Request(value.into())
    }
}
