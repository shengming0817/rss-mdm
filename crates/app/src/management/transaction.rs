//! Shared host transaction settlement; capabilities own the work inside the transaction.
use super::*;
use std::{future::Future, pin::Pin};
pub(super) async fn run<C: Sync>(
    audit_store: &rss_mdm_audit_integration::AuditStore,
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &RequestAudit,
    context: &C,
    execute: impl for<'a, 'tx> Fn(
        &'a C,
        &'a mut PgTransaction<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>>
    + Sync,
) -> std::result::Result<Value, Error> {
    let failure = std::sync::Mutex::new(None);
    let attempt = runtime
        .local_tx_with_context(
            tenant,
            deadline(),
            (audit_store, context, audit, &failure, &execute),
            |(audit_store, context, audit, failure, execute), tx| {
                Box::pin(async move {
                    if let Err(error) = audit_store.lock_in(tx).await {
                        *failure.lock().expect("request failure lock") =
                            Some(Error::Unavailable(Failure::Audit));
                        return Err(PgError::from(error));
                    }
                    match execute(context, tx).await {
                        Ok(v) => {
                            audit.mark_commit_started();
                            Ok(v)
                        }
                        Err(e) => {
                            let (reason, db) = match e {
                                Fault::Request(e) => (
                                    e,
                                    sqlx::Error::Protocol("management rejected".into()).into(),
                                ),
                                Fault::Storage(e) => {
                                    (Error::Unavailable(Failure::ManagementStorage), e)
                                }
                                Fault::Sql(e) => {
                                    let reason = if e
                                        .as_database_error()
                                        .and_then(|d| d.code())
                                        .is_some_and(|c| c == "40001" || c == "40P01")
                                    {
                                        Error::Conflict
                                    } else {
                                        Error::Unavailable(Failure::Runtime)
                                    };
                                    (reason, e.into())
                                }
                            };
                            *failure.lock().expect("request failure lock") = Some(reason);
                            Err(db)
                        }
                    }
                })
            },
        )
        .await;
    attempt.fold(
        |v| {
            audit.mark_committed();
            Ok(v)
        },
        |_| Err(Error::Unavailable(Failure::Runtime)),
        |_| {
            audit.mark_rolled_back();
            Err(failure
                .into_inner()
                .expect("request failure lock")
                .unwrap_or(Error::Unavailable(Failure::Runtime)))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::Runtime)),
    )
}
