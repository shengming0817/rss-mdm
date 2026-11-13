//! Controlled primary-registration projections for product consumers.
//! No consumer is invoked by registration or credential lifecycle mutations.
use crate::{Error, database::db};
use rss_mdm_inventory::Channel;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrimaryRegistration {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub channel: Channel,
}
/// Current active primary and credential. Renewal leaves registration identity unchanged.
pub async fn current_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    channel: Channel,
) -> Result<Option<PrimaryRegistration>, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_current_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(channel.as_str())
        .fetch_optional(c)
        .await
        .map_err(db)?;
    row.map(|_| {
        Ok(PrimaryRegistration {
            device: *device,
            channel,
        })
    })
    .transpose()
}
/// Bounded set projection with the same active primary and credential predicates.
pub async fn current_page_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[rss_mdm_agent_wire::DeviceId],
) -> Result<Vec<PrimaryRegistration>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_current_page_in_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .fetch_all(c)
        .await
        .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(PrimaryRegistration {
                device: row
                    .try_get::<uuid::Uuid, _>("device")
                    .and_then(crate::database::device_id)
                    .map_err(db)?,
                channel: match row.try_get::<&str, _>("channel").map_err(db)? {
                    "mdm" => Channel::Mdm,
                    "agent" => Channel::Agent,
                    _ => return Err(Error::Corrupt),
                },
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
    devices: &[rss_mdm_agent_wire::DeviceId],
) -> Result<Vec<PrimaryRegistration>, Error> {
    if devices.len() > 1000 || cut.tenant().to_string() != tenant {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).device_endpoints_page_at_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(cut.to_json())
        .fetch_all(c)
        .await
        .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(PrimaryRegistration {
                device: row
                    .try_get::<uuid::Uuid, _>("device")
                    .and_then(crate::database::device_id)
                    .map_err(db)?,
                channel: match row.try_get::<&str, _>("channel").map_err(db)? {
                    "mdm" => Channel::Mdm,
                    "agent" => Channel::Agent,
                    _ => return Err(Error::Corrupt),
                },
            })
        })
        .collect()
}
/// Borrow the same lifecycle lock as bind/revoke; callers order multiple endpoints lexically.
pub async fn lock_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    channel: Channel,
) -> Result<(), Error> {
    super::store::lock_channel(profile, c, tenant, device, channel).await
}
/// Bounded endpoint enumeration; the consumer applies its own authorization before projection.
pub async fn page_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    after: Option<rss_mdm_agent_wire::DeviceId>,
    limit: i64,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, Error> {
    if !(1..=1001).contains(&limit) {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_endpoints_page_in_1)
        .bind(tenant)
        .bind(after.map(|id| id.into_uuid()))
        .bind(limit)
        .fetch_all(c)
        .await
        .and_then(crate::database::device_ids)
        .map_err(db)
}

/// Current selected-primary-channel endpoints filtered to the consumer's authorized IDs.
pub async fn candidate_page_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    channel: Channel,
    after: Option<rss_mdm_agent_wire::DeviceId>,
    allowed: Option<Vec<rss_mdm_agent_wire::DeviceId>>,
    limit: i64,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, Error> {
    if !(1..=1001).contains(&limit) {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_endpoints_candidate_page_in_1)
        .bind(tenant)
        .bind(channel.as_str())
        .bind(after.map(|id| id.into_uuid()))
        .bind(allowed.map(|ids| ids.into_iter().map(|id| id.into_uuid()).collect::<Vec<_>>()))
        .bind(limit)
        .fetch_all(c)
        .await
        .and_then(crate::database::device_ids)
        .map_err(db)
}

/// Fixed-cut management facts, independent of collected Inventory values.
#[derive(Clone, Debug)]
pub struct Lifecycle {
    /// Stable endpoint identity in this tenant.
    pub device: rss_mdm_agent_wire::DeviceId,
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
    after: Option<rss_mdm_agent_wire::DeviceId>,
    selected: Option<Vec<rss_mdm_agent_wire::DeviceId>>,
    limit: usize,
) -> Result<Vec<Lifecycle>, Error> {
    if cut.tenant().to_string() != tenant
        || !(1..=1000).contains(&limit)
        || selected.as_ref().is_some_and(|v| v.len() > 1000)
    {
        return Err(Error::Malformed);
    }
    let ids = if let Some(mut selected) = selected {
        selected.sort_unstable();
        selected.dedup();
        selected
            .into_iter()
            .filter(|id| after.is_none_or(|after| *id > after))
            .take(limit)
            .collect::<Vec<_>>()
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
            .bind(ids.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
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
                device: r
                    .try_get::<uuid::Uuid, _>("device")
                    .and_then(crate::database::device_id)
                    .map_err(db)?,
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

/// Independent DA registration, without an Inventory channel or a paired endpoint.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaRegistration {
    pub device: rss_mdm_agent_wire::DeviceId,
}
/// Uses the registrar's lifecycle fence; callers retain it until their transaction settles.
pub async fn lock_da_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    super::store::lock_registration(
        rss_mdm_install_support::StorageProfile::Da,
        c,
        tenant,
        device,
        super::RegistrationKind::DaDevice,
    )
    .await
}
pub async fn current_da_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<DaRegistration>, Error> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT rss_da.current_da_registration($1) WHERE current_setting('rss.tenant_id',true)=$2",
    )
    .bind(device.into_uuid())
    .bind(tenant)
    .fetch_one(c)
    .await
    .map_err(db)?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Corrupt))
        .transpose()
}

/// Shared registrar projection installed only for DA's independent registration profile.
pub const DA_INSTALL_SQL: &str = r#"
CREATE FUNCTION rss_da.current_da_registration(p_device uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('device',r.id)
 FROM rss_da.devices r
 WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.id=p_device AND r.channel IS NULL AND r.purpose='da_device' AND r.state='active' AND r.retirement IS NULL
 AND EXISTS(SELECT FROM rss_da.credentials k JOIN rss_da.certificate_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id)
  WHERE (k.tenant_id,k.device)=(r.tenant_id,r.id) AND k.state='active' AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp()))
$$;
REVOKE ALL ON FUNCTION rss_da.current_da_registration(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.current_da_registration(uuid) TO da_access,da_command_runtime,da_policy_runtime,da_identity_runtime;
"#;
