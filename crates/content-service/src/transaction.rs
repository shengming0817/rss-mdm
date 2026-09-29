//! Content transaction settlement on the supplied product runtime.
use crate::service::Error;
use rss_mdm_audit_integration::RequestAudit;
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
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6))
}
pub fn rejection(error: Fault, failure: &Mutex<Option<Error>>) -> PgError {
    #[cfg(test)]
    eprintln!("transaction rejected: {error:?}");
    let (reason, db) = match error {
        Fault::Request(e) => (e, sqlx::Error::Protocol("request rejected".into()).into()),
        Fault::Storage(e) => {
            use rss_transactional_messaging::error::MessagingErrorKind;
            let reason = match e.kind() {
                MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
                MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => Error::Invariant,
                _ => Error::Storage,
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
                Error::Storage
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
        |_| Err(Error::Storage),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request result")
                .unwrap_or(Error::Storage))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Storage),
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
                    if let Err(error) = audit_store.lock_in(tx).await {
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
        |_| Err(Error::Storage),
        |_| {
            Err(failure
                .into_inner()
                .expect("preflight result")
                .unwrap_or(Error::Storage))
        },
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::Storage),
        |_| Err(Error::Storage),
    )
}

impl From<crate::Error> for Fault {
    fn from(e: crate::Error) -> Self {
        Self::Request(e.into())
    }
}
impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(e.into())
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
impl From<crate::bindings::Error> for Fault {
    fn from(e: crate::bindings::Error) -> Self {
        match e {
            crate::bindings::Error::Content(e) => e.into(),
            crate::bindings::Error::Storage(e) => Self::Storage(e),
            crate::bindings::Error::Sql(e) => Self::Sql(e),
        }
    }
}
impl From<rss_mdm_software_service::catalog::Error> for Fault {
    fn from(e: rss_mdm_software_service::catalog::Error) -> Self {
        use rss_mdm_software_service::catalog::Error as C;
        match e {
            C::Storage(e) => Self::Storage(e),
            C::Sql(e) => Self::Sql(e),
            C::Audit(e) => e.into(),
            C::Fact(e) => e.into(),
            C::Input => Error::Malformed.into(),
            C::Conflict => Error::Conflict.into(),
            C::NotAdmitted => Error::Forbidden.into(),
            C::Missing => Error::Missing.into(),
            C::Integrity | C::Content => Error::Invariant.into(),
        }
    }
}
pub fn fingerprint(value: &impl serde::Serialize) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(checked_input(serde_json::to_vec(value))?).into())
}
pub async fn lock_resource(tx: &mut PgTransaction<'_>) -> Result<()> {
    // The resource author and reclaimer share the existing product ordering lock.
    let key = format!("{}:action-owner", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub async fn authorize(
    tx: &mut PgTransaction<'_>,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
) -> Result<rss_mdm_authorization_service::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                let result = async {
                    rss_mdm_authorization_service::lock_on(c, &tenant, &instance).await?;
                    rss_mdm_authorization_service::snapshot_on(c, &tenant, &instance).await
                }
                .await;
                Ok(result)
            })
        })
        .await??)
}

pub fn storage_error(error: PgError) -> Error {
    use rss_transactional_messaging::error::MessagingErrorKind;
    match error.kind() {
        MessagingErrorKind::OwnershipLost | MessagingErrorKind::Conflict => Error::Conflict,
        MessagingErrorKind::Permanent | MessagingErrorKind::Invariant => Error::Invariant,
        _ => Error::Storage,
    }
}
