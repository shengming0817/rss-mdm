//! Shared host transaction settlement; capabilities own the work inside the transaction.
use super::*;
use std::{future::Future, pin::Pin};
pub(super) async fn run<C: Sync>(
    runtime: &PgRuntime,
    tenant: TenantId,
    audit: &Audit,
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
            (context, audit, &failure, &execute),
            |(context, audit, failure, execute), tx| {
                Box::pin(async move {
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
            Err(failure
                .into_inner()
                .expect("request failure lock")
                .unwrap_or(Error::Unavailable(Failure::Runtime)))
        },
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(Failure::Runtime)),
    )
}
