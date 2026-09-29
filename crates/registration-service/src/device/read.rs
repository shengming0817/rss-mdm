//! Read projections owned by this capability; the caller owns the transaction.
pub async fn find(
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

pub async fn active_sources(
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT r.device,r.id::text AS registration,r.generation,r.channel,s.source,s.epoch::text FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=ANY($2) AND r.state='active' AND s.enabled AND c.state='active' ORDER BY r.device,s.source")
                .bind(tenant).bind(devices).fetch_all(c).await
}

pub async fn exists(
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

pub async fn live_at(
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

pub async fn page_at(
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

pub async fn sources_at(
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

pub async fn registered(
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')").bind(tenant).bind(device).fetch_one(c).await
}

/// Active registry coordinates only; protocol capabilities remain with their channel.
pub async fn active_channel_in(
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    channel: rss_mdm_inventory::Channel,
) -> Result<Vec<(String, uuid::Uuid, i64)>, sqlx::Error> {
    sqlx::query_as("SELECT device,id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=ANY($2) AND channel=$3 AND state='active' ORDER BY device,id").bind(tenant).bind(devices).bind(channel.as_str()).fetch_all(c).await
}

/// Read-only worker hints; a mutating caller must recheck under the channel lock.
pub async fn active_sources_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    ids: &[uuid::Uuid],
    source: rss_mdm_inventory::ReportSource,
) -> Result<std::collections::BTreeMap<uuid::Uuid, (String, i64)>, crate::Error> {
    let rows=sqlx::query_as::<_,(uuid::Uuid,String,i64)>("SELECT r.id,r.device,r.generation FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.id=ANY($2) AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id) AND s.source=$3 AND s.enabled)").bind(tenant).bind(ids).bind(source.as_str()).fetch_all(c).await.map_err(crate::database::db)?;
    Ok(rows
        .into_iter()
        .map(|(id, device, generation)| (id, (device, generation)))
        .collect())
}
pub async fn lock_active_source_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Option<(String, i64)>, crate::Error> {
    let Some((device, _)) = active_sources_in(c, tenant, &[id], source)
        .await?
        .remove(&id)
    else {
        return Ok(None);
    };
    super::store::lock_channel(c, tenant, &device, source.channel()).await?;
    sqlx::query_as::<_,(String,i64)>("SELECT r.device,r.generation FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id) AND s.source=$3 AND s.enabled) FOR UPDATE OF r").bind(tenant).bind(id).bind(source.as_str()).fetch_optional(c).await.map_err(crate::database::db)
}

/// Check the complete current registration/source authority without renewing any proof.
pub async fn enabled_source_in(
    c: &mut sqlx::PgConnection,
    tenant: String,
    registration: uuid::Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) JOIN mdm_access.credentials k ON (k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.state='active' AND k.state='active' AND q.source=$3 AND s.source=$3 AND s.enabled)").bind(tenant).bind(registration).bind(source.as_str()).fetch_one(c).await
}
pub async fn stale_registration_in(
    c: &mut sqlx::PgConnection,
    tenant: String,
    registration: uuid::Uuid,
    device: String,
    generation: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.device=$3 AND r.generation=$4 AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND c.state='active'))").bind(tenant).bind(registration).bind(device).bind(generation).fetch_one(c).await
}
