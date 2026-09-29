//! Inventory collection-owned operation receipts and transaction settlement.
use crate::{Error, database::db};
use sqlx::Row;
use uuid::Uuid;
pub(crate) async fn replay(
    tx: &mut sqlx::PgConnection,
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2471))")
        .bind(lock)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let old = sqlx::query("SELECT digest,result,instance FROM mdm_inventory.collection_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).fetch_optional(&mut *tx).await.map_err(db)?;
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
pub(crate) async fn save(
    tx: &mut sqlx::PgConnection,
    operation: &Operation<'_>,
    result: &str,
    audit: &RequestAudit,
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
    sqlx::query("INSERT INTO mdm_inventory.collection_operations(tenant_id,actor,operation_id,digest,result,instance) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).bind(*digest).bind(result).bind(proof.instance).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct Actor<'a> {
    tenant: &'a str,
    subject: &'a str,
    instance: &'a str,
}
pub(crate) struct Operation<'a> {
    pub actor: Actor<'a>,
    pub key: Uuid,
    pub digest: &'a str,
}

impl<'a> Actor<'a> {
    pub(crate) fn from_authorized(
        proof: &'a crate::authorization::context::AuthorizedPrincipal,
    ) -> Self {
        Self {
            tenant: proof.tenant_id(),
            subject: proof.principal_id(),
            instance: proof.instance_id(),
        }
    }
}

use rss_mdm_audit_integration::RequestAudit;
