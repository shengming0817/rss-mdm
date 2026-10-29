//! Read projections owned by this capability; the caller owns the transaction.
pub async fn latest_quality(
    c: &mut sqlx::PgConnection,
    tenant: String,
    scopes: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT DISTINCT ON(r.scope) r.scope,r.id::text,r.sequence,r.result,CASE WHEN v.metadata_bytes<=67108864 THEN v.metadata::text END AS metadata,r.delivery_pending FROM mdm_access.collection_runs r JOIN mdm_access.collection_versions v ON (v.tenant_id,v.version)=(r.tenant_id,r.progress_version) WHERE r.tenant_id=$1::uuid AND r.scope=ANY($2) ORDER BY r.scope,r.sequence DESC,r.id DESC")
                .bind(tenant).bind(scopes).fetch_all(c).await
}

/// Collection authority is read by protocol participants on the transaction owner's connection.
pub async fn pending_apple_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: uuid::Uuid,
    ids: &[uuid::Uuid],
) -> Result<std::collections::BTreeSet<uuid::Uuid>, crate::Error> {
    let rows=sqlx::query_scalar::<_,uuid::Uuid>("SELECT id FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='mdm.apple' AND id=ANY($3) AND sealed_at IS NULL AND deadline>clock_timestamp()")
 .bind(tenant).bind(registration).bind(ids).fetch_all(c).await.map_err(crate::database::db)?;
    Ok(rows.into_iter().collect())
}
