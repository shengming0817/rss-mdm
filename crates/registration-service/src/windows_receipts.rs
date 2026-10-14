//! Windows registration receipt persistence; callers retain transaction ownership.
use crate::{Error, database::db};
use rss_mdm_audit_integration::RequestAudit;
use sqlx::Row;
use uuid::Uuid;
pub async fn replay(
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2351))")
        .bind(lock)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let old = sqlx::query("SELECT digest,result,instance FROM mdm_windows.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid")
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
pub async fn save(
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
    sqlx::query("INSERT INTO mdm_windows.operations(tenant_id,actor,operation_id,digest,result,instance) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).bind(*digest).bind(result).bind(proof.instance).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Actor<'a> {
    tenant: &'a str,
    subject: &'a str,
    instance: &'a str,
}

/// Windows registration operation identity, shared with Entra policy writes.
pub struct Operation<'a> {
    actor: Actor<'a>,
    key: Uuid,
    digest: &'a str,
}
impl<'a> Operation<'a> {
    pub fn from_coordinates(
        d: &'a crate::enrollment::native::Coordinates,
        digest: &'a str,
    ) -> Self {
        Self {
            actor: Actor {
                tenant: &d.tenant,
                subject: &d.actor,
                instance: &d.instance,
            },
            key: d.operation,
            digest,
        }
    }
    pub(crate) fn from_authorized(
        p: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
        key: Uuid,
        digest: &'a str,
    ) -> Self {
        Self {
            actor: Actor {
                tenant: p.tenant_id(),
                subject: p.principal_id(),
                instance: p.instance_id(),
            },
            key,
            digest,
        }
    }
    pub fn digest(&self) -> &str {
        self.digest
    }
}
