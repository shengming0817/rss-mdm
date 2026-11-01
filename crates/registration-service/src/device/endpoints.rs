//! Controlled primary-registration projections for product consumers.
//! No consumer is invoked by registration or credential lifecycle mutations.
use crate::{Error, database::db};
use rss_mdm_inventory::Channel;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrimaryRegistration {
    pub device: String,
    pub channel: Channel,
    pub registration_id: Uuid,
    pub generation: i64,
}
/// Current active primary and credential. Renewal leaves registration identity unchanged.
pub async fn current_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<Option<PrimaryRegistration>, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_current_in_1)
        .bind(tenant)
        .bind(device)
        .bind(channel.as_str())
        .fetch_optional(c)
        .await
        .map_err(db)?;
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
/// Bounded set projection with the same active primary and credential predicates.
pub async fn current_page_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<Vec<PrimaryRegistration>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_current_page_in_1)
        .bind(tenant)
        .bind(devices)
        .fetch_all(c)
        .await
        .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(PrimaryRegistration {
                device: row.try_get("device").map_err(db)?,
                channel: match row.try_get::<&str, _>("channel").map_err(db)? {
                    "mdm" => Channel::Mdm,
                    "agent" => Channel::Agent,
                    _ => return Err(Error::Corrupt),
                },
                registration_id: row.try_get("id").map_err(db)?,
                generation: row.try_get("generation").map_err(db)?,
            })
        })
        .collect()
}
/// Historical primary registrations and credentials from one committed asset cut.
pub async fn page_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    cut: &rss_mdm_inventory::AssetCut,
    devices: &[String],
) -> Result<Vec<PrimaryRegistration>, Error> {
    if devices.len() > 1000 || cut.tenant().to_string() != tenant {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_page_at_1)
        .bind(tenant)
        .bind(devices)
        .bind(cut.to_json())
        .fetch_all(c)
        .await
        .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(PrimaryRegistration {
                device: row.try_get("device").map_err(db)?,
                channel: match row.try_get::<&str, _>("channel").map_err(db)? {
                    "mdm" => Channel::Mdm,
                    "agent" => Channel::Agent,
                    _ => return Err(Error::Corrupt),
                },
                registration_id: row.try_get("id").map_err(db)?,
                generation: row.try_get("generation").map_err(db)?,
            })
        })
        .collect()
}
/// Borrow the same lifecycle lock as bind/revoke; callers order multiple endpoints lexically.
pub async fn lock_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<(), Error> {
    super::store::lock_channel(profile, c, tenant, device, channel).await
}
/// Bounded endpoint enumeration; the consumer applies its own authorization before projection.
pub async fn page_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    after: &str,
    limit: i64,
) -> Result<Vec<String>, Error> {
    if !(1..=1001).contains(&limit) {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_endpoints_page_in_1)
        .bind(tenant)
        .bind(after)
        .bind(limit)
        .fetch_all(c)
        .await
        .map_err(db)
}

/// Current selected-primary-channel endpoints filtered to the consumer's authorized IDs.
pub async fn candidate_page_in(
    profile: rss_mdm_install_support::StorageProfile,
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
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_endpoints_candidate_page_in_1)
        .bind(tenant)
        .bind(channel.as_str())
        .bind(after)
        .bind(allowed)
        .bind(limit)
        .fetch_all(c)
        .await
        .map_err(db)
}

/// Fixed-cut management facts, independent of collected Inventory values.
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    cut: &rss_mdm_inventory::AssetCut,
    after: Option<String>,
    selected: Option<Vec<String>>,
    limit: usize,
) -> Result<Vec<Lifecycle>, Error> {
    if cut.tenant().to_string() != tenant
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
            profile,
            c,
            tenant.into(),
            cut,
            after,
            true,
            vec![],
            limit as i64,
        )
        .await
        .map_err(db)?
    };
    let rows =
        sqlx::query(crate::storage_profile::sql(profile).device_endpoints_lifecycle_page_at_1)
            .bind(tenant)
            .bind(ids)
            .bind(cut.to_json())
            .fetch_all(c)
            .await
            .map_err(db)?;
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

/// Recheck a frozen channel membership on the caller's locked transaction.
pub async fn current_members_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    input: &serde_json::Value,
    channel: rss_mdm_inventory::Channel,
) -> Result<Option<PrimaryRegistration>, sqlx::Error> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).current_members)
            .bind(input)
            .bind(channel.as_str())
            .fetch_one(c)
            .await?;
    value
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|_| sqlx::Error::Protocol("invalid member authority".into()))
        })
        .transpose()
}
