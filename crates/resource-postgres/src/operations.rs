//! Application receipts are stored in the initiating Resource transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use sqlx::Row;
/// Lock and read a complete application receipt in the caller transaction.
pub async fn replay_operation_in(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: &str,
    fingerprint: &[u8],
) -> crate::InTransaction<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let id = id.to_owned();
    let row = tx.with_connection(move |c| Box::pin(async move {
        // Serialize the actual receipt key before observing absence or changing business state.
        // JSON framing keeps actor text unambiguous; a hash collision only adds contention.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text,$3::text,$4::text)::text,2889))")
            .bind(&tenant).bind("resource_catalog").bind(&actor).bind(id.to_string())
            .execute(&mut *c).await?;
        sqlx::query("SELECT fingerprint,response::text FROM mdm_resource_catalog.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND actor=$3")
            .bind(tenant).bind(id.to_string()).bind(actor).fetch_optional(c).await
    })).await?;
    if let Some(row) = row {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Ok(Err(crate::Rejection::IdentityConflict));
        }
        return Ok(Ok(Some(
            crate::STORAGE.decode(&row.try_get::<String, _>("response")?.into_bytes())?,
        )));
    }
    Ok(Ok(None))
}
/// Persist the response atomically with the originating business mutation.
pub async fn record_operation_in(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: &str,
    fingerprint: &[u8],
    value: &Value,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let id = id.to_owned();
    let digest = fingerprint.to_vec();
    let response = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("INSERT INTO mdm_resource_catalog.operations(tenant_id,id,fingerprint,response,actor) VALUES($1::uuid,$2::uuid,$3,$4::jsonb,$5)")
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
