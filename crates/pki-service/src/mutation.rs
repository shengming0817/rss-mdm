//! Business mutation under the existing product Audit owner, with exact durable replay.
use crate::{Error, registry::Registry};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::{future::Future, pin::Pin, time::Duration};
use uuid::Uuid;
pub(crate) type Pending<'a, R> =
    Pin<Box<dyn Future<Output = Result<Change<R>, Error>> + Send + 'a>>;
pub(crate) struct Change<R> {
    pub value: R,
    pub replay: bool,
    pub key: String,
}
impl Registry {
    pub(crate) async fn mutation<C: Send, R: Send>(
        &self,
        tenant: TenantId,
        a: &RequestAudit,
        ctx: C,
        f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, R> + Send,
    ) -> Result<R, Error> {
        run(&self.audit, tenant, a, ctx, f).await
    }
}
pub(crate) async fn run<C: Send, R: Send>(
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: TenantId,
    a: &RequestAudit,
    ctx: C,
    f: impl for<'a> FnOnce(&'a mut C, &'a mut PgConnection) -> Pending<'a, R> + Send,
) -> Result<R, Error> {
    if a.tenant() != tenant.to_string() {
        return Err(Error::Forbidden);
    }
    let budget = AuditBudget::new(Duration::from_secs(5));
    let outcome = store
        .write(
            tenant,
            &budget.source_control(),
            (store, a, ctx, Some(f)),
            |ctx, tx| {
                Box::pin(async move {
                    let (store, a, context, f) = ctx;
                    let f = f.take().ok_or(Error::Storage)?;
                    let change = tx
                        .with_connection_context(context, |ctx, c| f(ctx, c))
                        .await?;
                    if change.key.is_empty() {
                        return Ok((change.value, false));
                    }
                    let fact = Fact::business(a, &change.key, 200, "success", None)
                        .map_err(|e| Error::Audit(e.into()))?;
                    (if change.replay {
                        Ok(())
                    } else {
                        store.append(tx, &fact).await
                    })?;
                    a.mark_commit_started();
                    Ok((change.value, true))
                })
            },
        )
        .await;
    let result = outcome.fold(
        |r| {
            let (value, committed) = r;
            if committed {
                a.mark_committed();
            }
            Ok(value)
        },
        |e| Err(error(e)),
        |e| {
            a.mark_rolled_back();
            Err(error(e))
        },
        |_| {
            a.mark_rollback_failed();
            Err(Error::Audit(
                rss_mdm_audit_integration::Error::RollbackFailed,
            ))
        },
        |_| {
            eprintln!(
                "device_pki_audit: {:?}",
                rss_mdm_audit_integration::ErrorClass::CommitUnknown
            );
            Err(Error::Unknown {
                attempt: a.snapshot().operation_id.unwrap_or(a.request_id()),
            })
        },
        |e| Err(error(e)),
    );
    if let Err(Error::Audit(error)) = &result {
        eprintln!("device_pki_audit: {:?}", error.class());
    }
    result
}

fn error(e: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match e {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => Error::Audit(e),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => {
            Error::Audit(rss_mdm_audit_integration::Error::RollbackFailed)
        }
    }
}
pub async fn replay(
    c: &mut PgConnection,
    tenant: &str,
    actor: &str,
    instance: &str,
    operation: Uuid,
    phase: &str,
    digest: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    let row=sqlx::query("SELECT instance,digest,receipt FROM mdm_pki.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3 AND phase=$4")
        .bind(tenant).bind(actor).bind(operation).bind(phase).fetch_optional(c).await.map_err(|_|Error::Storage)?;
    row.map(|r| {
        if r.try_get::<String, _>("instance")
            .map_err(|_| Error::Storage)?
            != instance
            || r.try_get::<Vec<u8>, _>("digest")
                .map_err(|_| Error::Storage)?
                != digest
        {
            return Err(Error::Conflict);
        }
        r.try_get("receipt").map_err(|_| Error::Storage)
    })
    .transpose()
}
pub async fn save(
    c: &mut PgConnection,
    identity: (&str, &str, &str),
    operation: Uuid,
    phase: &str,
    digest: &[u8],
    receipt: &[u8],
) -> Result<(), Error> {
    let (tenant, actor, instance) = identity;
    sqlx::query("INSERT INTO mdm_pki.operations(tenant_id,actor,instance,operation,phase,digest,receipt) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
        .bind(tenant).bind(actor).bind(instance).bind(operation).bind(phase).bind(digest).bind(receipt).execute(c).await.map_err(|_|Error::Storage)?;
    Ok(())
}
