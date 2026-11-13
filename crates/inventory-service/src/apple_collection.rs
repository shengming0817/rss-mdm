//! Current authenticated collection authority for the Apple native adapter.
use crate::{Error, database::db};
use rss_mdm_inventory::ReportSource;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn current(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<bool, Error> {
    let row=sqlx::query("SELECT device, epoch, attempts, deadline > clock_timestamp() AND sealed_at IS NULL AS live, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint) AS now FROM mdm_access.collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = CAST($2 AS uuid) AND source = 'mdm.apple' FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let current = crate::device::store::source_current_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        &row.try_get::<uuid::Uuid, _>("device")
            .and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .map_err(db)?,
        ReportSource::MdmApple,
        row.try_get("epoch").map_err(db)?,
    )
    .await?;
    let progress: rss_mdm_inventory::CollectionProgress =
        serde_json::from_str(row.try_get("attempts").map_err(db)?).map_err(|_| Error::Malformed)?;
    let first = progress
        .definition()
        .bindings()
        .first()
        .ok_or(Error::Malformed)?;
    if progress
        .definition()
        .bindings()
        .iter()
        .any(|f| f.scope != first.scope)
    {
        return Err(Error::Malformed);
    }
    let user = match &first.scope {
        rss_mdm_inventory::CollectionScope::Device => "",
        rss_mdm_inventory::CollectionScope::AppleUser { identity } => identity.as_str(),
        _ => return Ok(false),
    };
    let active: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_apple.channels AS ch INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (ch.tenant_id, ch.device) WHERE ch.tenant_id = CAST($1 AS uuid) AND ch.device = $2 AND ch.user_key = $3 AND ch.state = 'active' AND r.state = 'active')")
        .bind(tenant).bind(row.try_get::<Uuid, _>("device").map_err(db)?).bind(user).fetch_one(c).await.map_err(db)?;
    Ok(current && active && row.try_get::<bool, _>("live").map_err(db)?)
}
