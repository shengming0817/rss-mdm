//! Controlled primary-registration projections for product consumers.
//! No consumer is invoked by registration or credential lifecycle mutations.
use crate::{Error, database::db};
use rss_mdm_inventory::Channel;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrimaryRegistration {
    pub device: String,
    pub channel: Channel,
    pub registration_id: Uuid,
    pub generation: i64,
}
/// Current active primary and credential. Renewal leaves registration identity unchanged.
pub async fn current_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<Option<PrimaryRegistration>, Error> {
    let row = sqlx::query("SELECT r.id,r.generation FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.purpose='primary' AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')")
        .bind(tenant).bind(device).bind(channel.as_str()).fetch_optional(c).await.map_err(db)?;
    row.map(|r| {
        Ok(PrimaryRegistration {
            device: device.into(),
            channel,
            registration_id: r.try_get("id").map_err(db)?,
            generation: r.try_get("generation").map_err(db)?,
        })
    })
    .transpose()
}
/// Borrow the same lifecycle lock as bind/revoke; callers order multiple endpoints lexically.
pub async fn lock_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<(), Error> {
    super::store::lock_channel(c, tenant, device, channel).await
}
/// Bounded endpoint enumeration; the consumer applies its own authorization before projection.
pub async fn page_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    after: &str,
    limit: i64,
) -> Result<Vec<String>, Error> {
    if !(1..=1001).contains(&limit) {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar("SELECT id FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id COLLATE \"C\">$2 COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT $3")
        .bind(tenant).bind(after).bind(limit).fetch_all(c).await.map_err(db)
}

/// Current selected-primary-channel endpoints filtered to the consumer's authorized IDs.
pub async fn candidate_page_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    channel: Channel,
    after: &str,
    allowed: Option<Vec<String>>,
    limit: i64,
) -> Result<Vec<String>, Error> {
    if !(1..=1001).contains(&limit) {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar(r#"SELECT r.device FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.channel=$2 AND r.purpose='primary' AND r.state='active' AND r.device COLLATE "C">$3 COLLATE "C" AND ($4::text[] IS NULL OR r.device=ANY($4)) ORDER BY r.device COLLATE "C" LIMIT $5"#)
        .bind(tenant).bind(channel.as_str()).bind(after).bind(allowed).bind(limit).fetch_all(c).await.map_err(db)
}

/// Fixed-watermark management facts, independent of collected Inventory values.
#[derive(Clone, Debug)]
pub struct Lifecycle {
    /// Stable endpoint identity in this tenant.
    pub device: String,
    /// A primary registration, active credential and enabled source exist together.
    pub managed: bool,
    /// Platform agreed by every live authenticated source, when known.
    pub platform: Option<rss_mdm_agent_wire::runtime::TaskPlatform>,
    /// Live sources disagree, or a live source cannot establish its platform.
    pub platform_conflict: bool,
}
/// Read at most one page; selected identities include deleted endpoints for delta removal.
pub async fn lifecycle_page_at(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    watermark: i64,
    after: Option<String>,
    selected: Option<Vec<String>>,
    limit: usize,
) -> Result<Vec<Lifecycle>, Error> {
    if watermark < 0
        || !(1..=1000).contains(&limit)
        || selected.as_ref().is_some_and(|v| v.len() > 1000)
    {
        return Err(Error::Malformed);
    }
    let ids: Vec<String> = if let Some(selected) = selected {
        sqlx::query_scalar("SELECT id FROM unnest($1::text[]) id WHERE id COLLATE \"C\">coalesce($2,'') COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT $3")
            .bind(selected).bind(after).bind(limit as i64).fetch_all(&mut *c).await.map_err(db)?
    } else {
        super::read::page_at(
            c,
            tenant.into(),
            watermark,
            after,
            true,
            vec![],
            limit as i64,
        )
        .await
        .map_err(db)?
    };
    let rows = sqlx::query(r#"
        WITH latest AS (
            SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
            FROM mdm_access.asset_authority_history
            WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
            ORDER BY kind,identity,revision DESC
        ), live AS (
            SELECT r.device,CASE s.document->>'source'
                WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos'
                ELSE r.document->>'platform' END AS platform
            FROM latest r JOIN latest s ON s.registration=r.registration AND s.kind='source'
                JOIN latest k ON k.registration=r.registration AND k.kind='credential'
                JOIN latest d ON d.device=r.device AND d.kind='device' AND d.document IS NOT NULL
            WHERE r.kind='registration' AND r.document->>'purpose'='primary'
                AND r.document->>'state'='active' AND k.document->>'state'='active'
                AND s.document->>'enabled'='true'
        ) SELECT d AS device,count(l.device)>0 AS managed,
            min(l.platform) AS platform,count(DISTINCT l.platform)>1 OR bool_or(l.device IS NOT NULL AND l.platform IS NULL) AS conflict
        FROM unnest($2::text[]) d LEFT JOIN live l ON l.device=d GROUP BY d ORDER BY d COLLATE "C"
    "#).bind(tenant).bind(ids).bind(watermark).fetch_all(c).await.map_err(db)?;
    rows.into_iter()
        .map(|r| {
            let conflict: bool = r.try_get("conflict").map_err(db)?;
            let platform = if conflict {
                None
            } else {
                match r
                    .try_get::<Option<String>, _>("platform")
                    .map_err(db)?
                    .as_deref()
                {
                    Some("windows") => Some(rss_mdm_agent_wire::runtime::TaskPlatform::Windows),
                    Some("macos") => Some(rss_mdm_agent_wire::runtime::TaskPlatform::Macos),
                    None => None,
                    _ => return Err(Error::Corrupt),
                }
            };
            Ok(Lifecycle {
                device: r.try_get("device").map_err(db)?,
                managed: r.try_get("managed").map_err(db)?,
                platform,
                platform_conflict: conflict,
            })
        })
        .collect()
}
