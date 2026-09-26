use crate::Error;
use crate::transaction::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;
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
        sqlx::query("SELECT fingerprint,response::text FROM mdm_publication.operations WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
            sqlx::query(
                "INSERT INTO mdm_publication.operations VALUES($1::uuid,$2::uuid,$3,$4::jsonb)",
            )
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
