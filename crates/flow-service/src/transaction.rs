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
    r.map_err(|_| Error::Unavailable(Failure::FlowStorage).into())
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
pub fn rejection(error: Fault, failure: &Mutex<Option<Error>>, owner: TransactionOwner) -> PgError {
    #[cfg(any(test, feature = "integration"))]
    eprintln!("transaction rejected: {error:?}");
    let (reason, db) = match error {
        Fault::Request(e) => {
            let e = match e {
                Error::Unavailable(Failure::FlowStorage) => Error::Unavailable(owner.failure()),
                other => other,
            };
            (e, sqlx::Error::Protocol("request rejected".into()).into())
        }
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => {
                    Error::Unavailable(owner.invariant())
                }
                _ => Error::Unavailable(owner.failure()),
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
                Error::Unavailable(owner.failure())
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
    owner: TransactionOwner,
) -> std::result::Result<T, Error> {
    attempt.fold(
        |v| {
            audit.mark_committed();
            Ok(v)
        },
        |_| Err(Error::Unavailable(owner.failure())),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Unavailable(owner.failure())))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(owner.failure())),
    )
}
pub async fn run<C: Send, R: Send, F>(
    audit_store: &rss_mdm_audit_integration::AuditStore,
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &RequestAudit,
    context: C,
    operation: F,
    owner: TransactionOwner,
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
                    if let Err(error) = audit_store.lock_in(tx).await {
                        return Err(rejection(Error::from(error).into(), failure, owner));
                    }
                    if matches!(owner, TransactionOwner::Execution)
                        && let Err(e) = crate::execution::storage::admit(tx).await
                    {
                        return Err(rejection(e, failure, owner));
                    }
                    let f = operation.take().expect("one callback");
                    match f(context, tx).await {
                        Ok(v) => {
                            audit.mark_commit_started();
                            Ok(v)
                        }
                        Err(e) => Err(rejection(e, failure, owner)),
                    }
                })
            },
        )
        .await;
    settle(attempt, audit, failure, owner)
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
#[derive(Clone, Copy)]
pub enum TransactionOwner {
    Planning,
    Assets,
    Compliance,
    ResourceCatalog,
    Execution,
}
impl TransactionOwner {
    fn failure(self) -> Failure {
        match self {
            Self::Planning => Failure::PlanningStorage,
            Self::Assets => Failure::AssetsStorage,
            Self::Compliance => Failure::ComplianceStorage,
            Self::ResourceCatalog => Failure::ResourceStorage,
            Self::Execution => Failure::CommandStorage,
        }
    }
    fn invariant(self) -> Failure {
        match self {
            Self::Execution => Failure::CommandInvariant,
            _ => self.failure(),
        }
    }
}
impl From<crate::device::DeviceError> for Fault {
    fn from(error: crate::device::DeviceError) -> Self {
        Error::from(error).into()
    }
}
pub async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                .bind(tenant)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}

impl From<crate::planning::error::PlanningError> for Fault {
    fn from(error: crate::planning::error::PlanningError) -> Self {
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
    owner: TransactionOwner,
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
                        .map_err(|e| rejection(e, failure, owner))
                })
            },
        )
        .await;
    attempt.fold(
        Ok,
        |_| Err(Error::Unavailable(owner.failure())),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Unavailable(owner.failure())))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Unavailable(owner.failure())),
        |_| Err(Error::Unavailable(owner.failure())),
    )
}

impl From<rss_mdm_policy::Error> for Error {
    fn from(value: rss_mdm_policy::Error) -> Self {
        match value {
            rss_mdm_policy::Error::Malformed => Self::Malformed,
            rss_mdm_policy::Error::Conflict => Self::Conflict,
            rss_mdm_policy::Error::NotFound => {
                Self::Planning(crate::planning::error::PlanningError::Missing(
                    crate::planning::error::Missing::Policy,
                ))
            }
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

use rss_mdm_software_service::catalog;
impl From<catalog::Error> for Fault {
    fn from(e: catalog::Error) -> Self {
        match e {
            catalog::Error::Storage(e) => Self::Storage(e),
            catalog::Error::Sql(e) => Self::Sql(e),
            catalog::Error::Audit(e) => Self::from(e),
            catalog::Error::Fact(e) => Self::from(e),
            catalog::Error::Input => Error::Malformed.into(),
            catalog::Error::Unsupported => Error::Unsupported.into(),
            catalog::Error::Dependency => Error::Forbidden.into(),
            catalog::Error::Conflict => Error::Conflict.into(),
            catalog::Error::NotAdmitted => Error::Forbidden.into(),
            catalog::Error::Missing => {
                Error::Resource(crate::resource_catalog::error::ResourceError::Missing).into()
            }
            catalog::Error::Integrity => {
                Error::Unavailable(crate::Failure::SoftwareCatalogInvariant).into()
            }
            catalog::Error::Content => Error::Unavailable(crate::Failure::ContentInvariant).into(),
        }
    }
}

impl From<rss_mdm_content_service::bindings::Error> for Fault {
    fn from(e: rss_mdm_content_service::bindings::Error) -> Self {
        use rss_mdm_content_service::bindings::Error as C;
        match e {
            C::Content(e) => Self::Request(e.into()),
            C::Storage(e) => Self::Storage(e),
            C::Sql(e) => Self::Sql(e),
        }
    }
}

impl From<rss_mdm_execution_service::Error> for Fault {
    fn from(error: rss_mdm_execution_service::Error) -> Self {
        Error::from(error).into()
    }
}
