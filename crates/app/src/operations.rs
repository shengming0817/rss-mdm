//! Host-owned operation receipts and transaction settlement.
#[cfg(test)]
use crate::Failure;
use crate::{Error, audit::Audit, database::db};
use sqlx::{Postgres, Row, Transaction};
#[cfg(test)]
use std::sync::atomic::Ordering;
use uuid::Uuid;
pub(crate) async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    operation: &Operation<'_>,
) -> Result<Option<String>, Error> {
    let Operation {
        actor: proof,
        key,
        digest,
    } = operation;
    let lock = format!(
        "{}:{}:{}:{}",
        proof.tenant,
        proof.subject.len(),
        proof.subject,
        key
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2347))")
        .bind(lock)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    let old = sqlx::query("SELECT digest,result,instance FROM mdm_access.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).fetch_optional(&mut **tx).await.map_err(db)?;
    old.map(|old| {
        if old.try_get::<String, _>("digest").map_err(db)? != *digest
            || old.try_get::<String, _>("instance").map_err(db)? != proof.instance
        {
            return Err(Error::Conflict);
        }
        old.try_get("result").map_err(db)
    })
    .transpose()
}
pub(crate) async fn finish(
    database: &crate::database::Database,
    tx: Transaction<'_, Postgres>,
    operation: &Operation<'_>,
    result: &str,
    audit: &Audit,
    request: Option<Uuid>,
) -> Result<(), Error> {
    crate::operations::finish_status(database, tx, operation, result, audit, request, 200).await
}
pub(crate) async fn finish_status(
    database: &crate::database::Database,
    mut tx: Transaction<'_, Postgres>,
    operation: &Operation<'_>,
    result: &str,
    audit: &Audit,
    request: Option<Uuid>,
    status: u16,
) -> Result<(), Error> {
    let Operation {
        actor: proof,
        key,
        digest,
    } = operation;
    let facts = audit.snapshot();
    if audit.tenant() != proof.tenant
        || facts.actor.as_deref() != Some(proof.subject)
        || facts.instance.as_deref() != Some(proof.instance)
        || facts.operation_id != Some(*key)
    {
        return Err(Error::Forbidden);
    }
    sqlx::query("INSERT INTO mdm_access.operations(tenant_id,actor,operation_id,digest,result,instance) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).bind(*digest).bind(result).bind(proof.instance).execute(&mut *tx).await.map_err(db)?;
    crate::operations::commit_audited_status(database, tx, audit, request, status).await
}
#[cfg(test)]
pub(crate) async fn commit_audited(
    database: &crate::database::Database,
    tx: Transaction<'_, Postgres>,
    audit: &Audit,
    request: Option<Uuid>,
) -> Result<(), Error> {
    crate::operations::commit_audited_status(database, tx, audit, request, 200).await
}
pub(crate) async fn commit_audited_status(
    _database: &crate::database::Database,
    mut tx: Transaction<'_, Postgres>,
    audit: &Audit,
    request: Option<Uuid>,
    status: u16,
) -> Result<(), Error> {
    crate::audit::append(&mut tx, audit, status, "success", request).await?;
    #[cfg(test)]
    if _database
        .fault
        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tx.rollback().await.map_err(db)?;
        return Err(Error::Unavailable(Failure::Database));
    }
    audit.mark_commit_started();
    #[cfg(test)]
    if _database
        .fault
        .compare_exchange(3, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Cancel at COMMIT entry; Drop can still roll this transaction back.
        std::future::pending::<()>().await;
    }
    tx.commit().await.map_err(|_| Error::CommitUnknown)?;
    #[cfg(test)]
    match _database.fault.swap(0, Ordering::AcqRel) {
        2 => return Err(Error::CommitUnknown),
        // Real COMMIT succeeded; its acknowledgement never reaches the caller.
        4 => std::future::pending::<()>().await,
        _ => {}
    }
    audit.mark_committed();
    Ok(())
}
#[derive(Clone, Copy)]
pub(crate) struct Actor<'a> {
    pub tenant: &'a str,
    pub subject: &'a str,
    pub instance: &'a str,
}
pub(crate) struct Operation<'a> {
    pub actor: Actor<'a>,
    pub key: Uuid,
    pub digest: &'a str,
}
