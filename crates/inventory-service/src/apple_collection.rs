//! Current authenticated collection authority for the Apple native adapter.
use crate::{Error, database::db};
use rss_mdm_inventory::ReportSource;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn current(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<bool, Error> {
    let row=sqlx::query("SELECT registration,epoch,deadline>clock_timestamp() AND sealed_at IS NULL AS live,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid AND source='mdm.apple' FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let current = crate::device::store::source_current_in(
        c,
        tenant,
        row.try_get("registration").map_err(db)?,
        ReportSource::MdmApple,
        row.try_get("epoch").map_err(db)?,
    )
    .await?;
    Ok(current && row.try_get::<bool, _>("live").map_err(db)?)
}
