//! Local software request settlement over RSS transactions; participants never commit.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use super::{Error, Failure};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{future::Future, pin::Pin, sync::Mutex};
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
#[derive(Clone, Copy)]
pub(crate) enum TransactionOwner {
    SoftwareCatalog,
    Publication,
}
impl TransactionOwner {
    fn storage(self) -> Error {
        Error::Unavailable(match self {
            Self::SoftwareCatalog => Failure::SoftwareCatalogStorage,
            Self::Publication => Failure::PublicationStorage,
        })
    }
    fn invariant(self) -> Error {
        Error::Unavailable(match self {
            Self::SoftwareCatalog => Failure::SoftwareCatalogInvariant,
            Self::Publication => Failure::PublicationStorage,
        })
    }
}
pub(crate) fn checked_input<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Malformed.into())
}
fn rejected(fault: Fault, failure: &Mutex<Option<Error>>, owner: TransactionOwner) -> PgError {
    let (error, database) = match fault {
        Fault::Request(e) => (
            e,
            sqlx::Error::Protocol("software request rejected".into()).into(),
        ),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind as K;
            let error = match e.kind() {
                K::OwnershipLost | K::Conflict => Error::Conflict,
                K::Permanent | K::Invariant => owner.invariant(),
                _ => owner.storage(),
            };
            (error, e)
        }
        Fault::Sql(e) => {
            let error = if e
                .as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|code| code == "40001" || code == "40P01")
            {
                Error::Conflict
            } else {
                owner.storage()
            };
            (error, e.into())
        }
    };
    *failure.lock().expect("software request result") = Some(error);
    database
}
type TxFuture<'a, R> = Pin<Box<dyn Future<Output = Result<R>> + Send + 'a>>;
async fn execute<C: Send, R: Send, F>(
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: Option<(&AuditStore, &RequestAudit)>,
    context: C,
    operation: F,
    owner: TransactionOwner,
) -> std::result::Result<R, Error>
where
    F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> TxFuture<'a, R> + Send,
{
    let failure = Mutex::new(None);
    let deadline = rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(6),
    );
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            deadline,
            (context, Some(operation), &failure, audit),
            |state, tx| {
                Box::pin(async move {
                    let (context, operation, failure, audit) = state;
                    if let Some((store, _)) = *audit {
                        store
                            .lock_in(tx)
                            .await
                            .map_err(|e| rejected(Error::from(e).into(), failure, owner))?;
                    }
                    let result = operation.take().expect("one software callback")(context, tx)
                        .await
                        .map_err(|e| rejected(e, failure, owner))?;
                    if let Some((_, audit)) = *audit {
                        audit.mark_commit_started();
                    }
                    Ok(result)
                })
            },
        )
        .await;
    attempt.fold(
        |value| {
            if let Some((_, audit)) = audit {
                audit.mark_committed();
            }
            Ok(value)
        },
        |_| Err(owner.storage()),
        |_| {
            if let Some((_, audit)) = audit {
                audit.mark_rolled_back();
            }
            Err(failure
                .into_inner()
                .expect("software request result")
                .unwrap_or_else(|| owner.storage()))
        },
        |_| {
            if let Some((_, audit)) = audit {
                audit.mark_rollback_failed();
            }
            Err(Error::RollbackFailed)
        },
        |_| {
            Err(if audit.is_some() {
                Error::CommitUnknown
            } else {
                owner.storage()
            })
        },
        |_| Err(owner.storage()),
    )
}
pub(crate) async fn run<C: Send, R: Send, F>(
    store: &AuditStore,
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &RequestAudit,
    context: C,
    work: F,
    owner: TransactionOwner,
) -> std::result::Result<R, Error>
where
    F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> TxFuture<'a, R> + Send,
{
    execute(runtime, tenant, Some((store, audit)), context, work, owner).await
}
pub(crate) async fn inspect<C: Send, R: Send, F>(
    runtime: &PgRuntime,
    tenant: TenantId,
    context: C,
    work: F,
    owner: TransactionOwner,
) -> std::result::Result<R, Error>
where
    F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> TxFuture<'a, R> + Send,
{
    execute(runtime, tenant, None, context, work, owner).await
}
pub(crate) async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
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
pub(crate) async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
) -> Result<rss_mdm_authorization_service::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(rss_mdm_authorization_service::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??;
    Ok(snapshot)
}
impl From<crate::catalog::Error> for Fault {
    fn from(e: crate::catalog::Error) -> Self {
        use crate::catalog::Error as C;
        match e {
            C::Storage(e) => Self::Storage(e),
            C::Sql(e) => Self::Sql(e),
            C::Audit(e) => Self::Request(e.into()),
            C::Fact(e) => Self::Request(e.into()),
            C::Input => Error::Malformed.into(),
            C::Unsupported => Error::Unsupported.into(),
            C::Dependency | C::NotAdmitted => Error::Forbidden.into(),
            C::Conflict => Error::Conflict.into(),
            C::Missing => Error::ResourceMissing.into(),
            C::Integrity => Error::Unavailable(Failure::SoftwareCatalogInvariant).into(),
            C::Content => Error::Unavailable(Failure::ContentInvariant).into(),
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Fault {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
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
        Self::Request(e.into())
    }
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(e.into())
    }
}
