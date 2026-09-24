//! Read projections owned by this capability; the caller owns the transaction.
pub(crate) async fn find(
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant)
        .bind(device)
        .fetch_optional(c)
        .await
}

pub(crate) async fn active_sources(
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT r.device,r.id::text AS registration,r.generation,r.channel,s.source,s.epoch::text FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=ANY($2) AND r.state='active' AND s.enabled AND c.state='active' ORDER BY r.device,s.source")
                .bind(tenant).bind(devices).fetch_all(c).await
}

pub(crate) async fn exists(
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2)",
    )
    .bind(tenant)
    .bind(device)
    .fetch_one(c)
    .await
}

pub(crate) async fn live_at(
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    watermark: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
                WITH latest AS (
                    SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                    FROM mdm_access.asset_authority_history
                    WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
                      AND kind IN('registration','credential','source')
                    ORDER BY kind,identity,revision DESC
                ), live AS (
                    SELECT device,registration FROM latest GROUP BY device,registration
                    HAVING bool_or(kind='registration' AND document->>'state'='active')
                       AND bool_or(kind='credential' AND document->>'state'='active')
                       AND bool_or(kind='source' AND document->>'enabled'='true')
                ) SELECT DISTINCT device FROM live
            "#,
    )
    .bind(tenant)
    .bind(devices)
    .bind(watermark)
    .fetch_all(c)
    .await
}

pub(crate) async fn page_at(
    c: &mut sqlx::PgConnection,
    tenant: String,
    watermark: i64,
    after: Option<String>,
    all: bool,
    allowed: Vec<String>,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
              WITH latest AS (
                SELECT DISTINCT ON(identity COLLATE "C") identity,document
                FROM mdm_access.asset_authority_history
                WHERE tenant_id=$1::uuid AND kind='device' AND revision<=$2
                  AND identity COLLATE "C">coalesce($3::text,'') COLLATE "C"
                  AND ($4 OR identity=ANY($5))
                ORDER BY identity COLLATE "C",revision DESC
              ) SELECT identity FROM latest WHERE document IS NOT NULL
                ORDER BY identity COLLATE "C" LIMIT $6
            "#,
    )
    .bind(tenant)
    .bind(watermark)
    .bind(after)
    .bind(all)
    .bind(allowed)
    .bind(limit)
    .fetch_all(c)
    .await
}

pub(crate) async fn sources_at(
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    watermark: i64,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(r#"
              WITH latest AS (
                SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                FROM mdm_access.asset_authority_history
                WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
                  AND kind IN('registration','credential','source')
                ORDER BY kind,identity,revision DESC
              ) SELECT r.device,r.identity AS registration,r.document->>'generation' AS generation,
                  r.document->>'channel' AS channel,s.document->>'source' AS source,s.document->>'epoch' AS epoch
                FROM latest r JOIN latest s ON s.registration=r.registration AND s.kind='source'
                JOIN latest c ON c.registration=r.registration AND c.kind='credential'
                WHERE r.kind='registration' AND r.document->>'state'='active'
                  AND c.document->>'state'='active' AND s.document->>'enabled'='true'
                ORDER BY r.device,s.identity LIMIT 2001
            "#).bind(tenant).bind(devices).bind(watermark).fetch_all(c).await
}

pub(crate) async fn registered(
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')").bind(tenant).bind(device).fetch_one(c).await
}
