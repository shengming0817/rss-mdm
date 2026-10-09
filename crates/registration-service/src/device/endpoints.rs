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
