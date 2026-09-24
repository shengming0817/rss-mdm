//! Read projections owned by this capability; the caller owns the transaction.
pub(crate) async fn latest_quality(
    c: &mut sqlx::PgConnection,
    tenant: String,
    scopes: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT DISTINCT ON(scope) scope,id::text,sequence,result,attempts,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND scope=ANY($2) ORDER BY scope,sequence DESC,id DESC")
                .bind(tenant).bind(scopes).fetch_all(c).await
}

pub(crate) async fn quality_at(
    c: &mut sqlx::PgConnection,
    tenant: String,
    scopes: Vec<String>,
    watermark: i64,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(
        r#"
                WITH latest AS (
                  SELECT DISTINCT ON(scope,run) scope,sequence,run,document
                  FROM mdm_access.collection_history
                  WHERE tenant_id=$1::uuid AND scope=ANY($2) AND revision<=$3
                  ORDER BY scope,run,revision DESC
                ) SELECT DISTINCT ON(scope) scope,sequence,run::text AS id,
                    document->>'result' AS result,document->>'attempts' AS attempts,
                    (document->>'delivery_pending')::boolean AS delivery_pending
                  FROM latest WHERE document IS NOT NULL ORDER BY scope,sequence DESC,run DESC
            "#,
    )
    .bind(tenant)
    .bind(scopes)
    .bind(watermark)
    .fetch_all(c)
    .await
}
