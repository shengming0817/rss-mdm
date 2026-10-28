use rss_mdm_inventory::ReportSource;
use serde::Deserialize;
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinates {
    pub source: ReportSource,
}
#[cfg(test)]
#[path = "../../tests/coordinates.rs"]
mod tests;

/// Read the Device authority coordinate at a committed input boundary.
/// This is a fact read on the initiating connection; it neither grants access nor commits.
pub async fn authority_at_on(
    connection: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    watermark: i64,
) -> Result<u64, sqlx::Error> {
    let revision=sqlx::query_scalar::<_,i64>("SELECT coalesce(max(revision),0) FROM mdm_access.asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND revision<=$3")
        .bind(tenant.to_string()).bind(device).bind(watermark).fetch_one(connection).await?;
    u64::try_from(revision)
        .map_err(|_| sqlx::Error::Protocol("invalid device authority coordinate".into()))
}
