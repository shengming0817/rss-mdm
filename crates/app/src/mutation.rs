use crate::{Error, Failure};
use rss_request_context::Deadline;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgError;
use serde_json::Value;
use std::time::Duration;
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub(crate) type Result<T> = std::result::Result<T, Fault>;
pub(crate) fn input<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Malformed.into())
}
pub(crate) fn stored<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Unavailable(Failure::ManagementStorage).into())
}
pub(crate) fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
pub(crate) fn json(v: &impl serde::Serialize) -> Result<Value> {
    input(serde_json::to_value(v))
}
pub(crate) fn deadline() -> OperationDeadline {
    let timer = crate::lifecycle::RuntimeTimer;
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&timer, Duration::from_secs(6)).expect("constant budget"),
        &timer,
    )
}
// Shared host transaction settlement; capabilities own the work inside the transaction.
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::{future::Future, pin::Pin};
pub(crate) async fn run<C: Sync>(
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
                        *failure.lock().expect("request failure lock") = Some(Error::from(&error));
                        return Err(PgError::from(error));
                    }
                    match execute(context, tx).await {
                        Ok(v) => {
                            audit.mark_commit_started();
                            Ok(v)
                        }
                        Err(e) => {
                            let (reason, db) = match e {
                                Fault::Request(e) => {
                                    (e, sqlx::Error::Protocol("planning rejected".into()).into())
                                }
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

use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation<T> {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub input: T,
}

use sqlx::Row;
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
pub(crate) async fn audit(
    tx: &mut PgTransaction<'_>,
    store: &rss_mdm_audit_integration::AuditStore,
    audit: &RequestAudit,
    operation: Option<(Uuid, &[u8])>,
    replayed: bool,
) -> Result<()> {
    let admitted = audit
        .snapshot()
        .software
        .as_ref()
        .is_some_and(|f| f.stage == "management_admission");
    let (status, result) = if admitted {
        (202, "unknown")
    } else {
        (200, "success")
    };
    let result = if let Some((id, fingerprint)) = operation {
        let fact = rss_mdm_audit_integration::Fact::business(
            audit,
            &format!("planning:{id}"),
            fingerprint,
            status,
            result,
            None,
        )
        .map_err(Error::from)?;
        store.append_in(tx, &fact, replayed).await
    } else {
        store.append_request_in(tx, audit, status, result).await
    };
    result.map_err(Error::from)?;
    Ok(())
}
pub(crate) async fn replay(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT fingerprint,response::text FROM mdm_flow.operations WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(tenant).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    if let Some(row) = row {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        return Ok(Some(stored(serde_json::from_str(
            &row.try_get::<String, _>("response")?,
        ))?));
    }
    Ok(None)
}
pub(crate) async fn receipt(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
    value: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let digest = fingerprint.to_vec();
    let response = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("INSERT INTO mdm_flow.operations VALUES($1::uuid,$2::uuid,$3,$4::jsonb)")
                .bind(tenant)
                .bind(id.to_string())
                .bind(digest)
                .bind(response)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
