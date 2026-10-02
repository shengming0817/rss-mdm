use crate::Error;
use crate::transaction::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;
pub async fn replay(
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT fingerprint,response::text FROM mdm_planning.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND actor=$3")
            .bind(tenant).bind(id.to_string()).bind(actor).fetch_optional(c).await
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
pub async fn receipt(
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    id: Uuid,
    fingerprint: &[u8],
    value: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
    let digest = fingerprint.to_vec();
    let response = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_planning.operations(tenant_id,id,fingerprint,response,actor) VALUES($1::uuid,$2::uuid,$3,$4::jsonb,$5)",
            )
            .bind(tenant)
            .bind(id.to_string())
            .bind(digest)
            .bind(response).bind(actor)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
