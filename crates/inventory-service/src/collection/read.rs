//! Read projections owned by this capability; the caller owns the transaction.
pub async fn latest_quality(
    c: &mut sqlx::PgConnection,
    tenant: String,
    scopes: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT DISTINCT ON(scope) scope,id::text,sequence,result,attempts,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND scope=ANY($2) ORDER BY scope,sequence DESC,id DESC")
                .bind(tenant).bind(scopes).fetch_all(c).await
}

pub async fn quality_at(
    c: &mut sqlx::PgConnection,
    tenant: String,
    scopes: Vec<String>,
    watermark: i64,
    field_scope: String,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(
        r#"
                WITH latest AS (
                  SELECT DISTINCT ON(scope,run) scope,sequence,run,document
                  FROM mdm_access.collection_history
                  WHERE tenant_id=$1::uuid AND scope=ANY($2) AND revision<=$3
                  ORDER BY scope,run,revision DESC
                ), fields AS (
                  SELECT DISTINCT ON(h.scope,f->'definition'->>'key') h.scope,h.sequence,h.run,h.document,f->'definition'->>'key' AS field
                  FROM latest h CROSS JOIN LATERAL jsonb_array_elements((h.document->>'attempts')::jsonb->'definition'->'fields') f
                  WHERE h.document IS NOT NULL AND f->'scope'=$4::jsonb
                  ORDER BY h.scope,f->'definition'->>'key',h.sequence DESC,h.run DESC
                ) SELECT scope,sequence,run::text AS id,
                    document->>'result' AS result,document->>'attempts' AS attempts,
                    (document->>'delivery_pending')::boolean AS delivery_pending,
                    array_agg(field ORDER BY field) AS selected_fields
                  FROM fields GROUP BY scope,sequence,run,document ORDER BY scope,sequence,run
            "#,
    )
    .bind(tenant)
    .bind(scopes)
    .bind(watermark)
    .bind(field_scope)
    .fetch_all(c)
    .await
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
