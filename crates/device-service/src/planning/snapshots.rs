//! Immutable cuts are produced by Device; readers never build or supersede them.
use super::*;
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::device::endpoints::{self, PrimaryRegistration};
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, sqlx::Error> {
    serde_json::from_value(value).map_err(storage)
}
fn version(cut: &rss_mdm_inventory::AssetCut, through: i64) -> String {
    use sha2::Digest;
    format!(
        "{:x}",
        sha2::Sha256::digest(format!("{}:{through}", cut.to_json()).as_bytes())
    )
}
pub(super) async fn capture(
    c: &mut PgConnection,
    tenant: TenantId,
    after: Option<Uuid>,
) -> Result<ObjectSnapshot, sqlx::Error> {
    let (id, cut, through): (Uuid,serde_json::Value,i64) = sqlx::query_as("SELECT s.id,s.asset_cut,s.through FROM mdm_devices.checkpoints p JOIN mdm_devices.object_cuts s ON s.tenant_id=p.tenant_id WHERE p.tenant_id=$1::uuid AND NOT p.rebuilding AND (($2::uuid IS NULL AND s.id=p.current_cut) OR ($2::uuid IS NOT NULL AND (s.through>(SELECT through FROM mdm_devices.object_cuts WHERE tenant_id=p.tenant_id AND id=$2) OR s.id=p.current_cut AND s.id=$2))) ORDER BY s.through LIMIT 1")
        .bind(tenant.to_string()).bind(after).fetch_one(c).await?;
    let asset_cut = rss_mdm_inventory::AssetCut::from_json(cut).map_err(storage)?;
    Ok(ObjectSnapshot {
        id,
        version: version(&asset_cut, through),
        asset_cut,
    })
}
pub(super) async fn complete(
    c: &mut PgConnection,
    tenant: TenantId,
    s: &ObjectSnapshot,
) -> Result<bool, sqlx::Error> {
    let through:Option<i64>=sqlx::query_scalar("SELECT through FROM mdm_devices.object_cuts WHERE tenant_id=$1::uuid AND id=$2 AND asset_cut=$3")
        .bind(tenant.to_string()).bind(s.id).bind(s.asset_cut.to_json()).fetch_optional(c).await?;
    Ok(through.is_some_and(|through| version(&s.asset_cut, through) == s.version))
}
pub(super) async fn endpoint(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<DeviceObject, sqlx::Error> {
    let mut members = Vec::new();
    for channel in [Channel::Mdm, Channel::Agent] {
        if let Some(member) = endpoints::current_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant.to_string(),
            device,
            channel,
        )
        .await
        .map_err(storage)?
        {
            members.push(member);
        }
    }
    Ok(DeviceObject {
        object: ObjectRef::Endpoint(device.into()),
        association_version: None,
        verified: true,
        members,
    })
}

pub(super) async fn endpoint_at(
    c: &mut PgConnection,
    tenant: TenantId,
    cut: &rss_mdm_inventory::AssetCut,
    device: &str,
) -> Result<DeviceObject, sqlx::Error> {
    let members = endpoints::page_at(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &tenant.to_string(),
        cut,
        &[device.to_owned()],
    )
    .await
    .map_err(storage)?;
    Ok(DeviceObject {
        object: ObjectRef::Endpoint(device.into()),
        association_version: None,
        verified: true,
        members,
    })
}

pub(super) async fn lookup(
    c: &mut PgConnection,
    tenant: TenantId,
    snapshot: Uuid,
    object: &ObjectRef,
    max_bytes: usize,
) -> Result<Option<(DeviceObject, usize)>, sqlx::Error> {
    let (input, bytes): (Option<serde_json::Value>, i64) = sqlx::query_as(
        "SELECT CASE WHEN octet_length(o.input::text)+1024<=$4 THEN o.input END,octet_length(o.input::text)::bigint+1024 FROM mdm_devices.object_cuts s CROSS JOIN LATERAL (SELECT input FROM mdm_devices.object_versions WHERE tenant_id=s.tenant_id AND object=$3 AND revision<=s.through ORDER BY revision DESC LIMIT 1) o WHERE s.tenant_id=$1::uuid AND s.id=$2 AND o.input IS NOT NULL"
    ).bind(tenant.to_string()).bind(snapshot).bind(object.key()).bind(max_bytes as i64).fetch_one(c).await?;
    input
        .map(|input| Ok((decode(input)?, usize::try_from(bytes).map_err(storage)?)))
        .transpose()
}
pub(super) async fn validate(
    c: &mut PgConnection,
    _tenant: TenantId,
    input: &DeviceObject,
    channel: Channel,
) -> Result<Option<PrimaryRegistration>, sqlx::Error> {
    if !input.verified {
        return Ok(None);
    }
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT mdm_devices.object_current($1,$2)")
            .bind(serde_json::to_value(input).map_err(storage)?)
            .bind(channel.as_str())
            .fetch_one(c)
            .await?;
    value
        .map(|value| serde_json::from_value(value).map_err(storage))
        .transpose()
}

pub(super) async fn page(
    c: &mut PgConnection,
    tenant: TenantId,
    snapshot: Uuid,
    after: Option<String>,
    limit: usize,
    selected: Option<Vec<String>>,
) -> Result<Vec<DeviceObject>, sqlx::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(storage("object page limit"));
    }
    let rows:Vec<serde_json::Value> = sqlx::query_scalar("SELECT live.input FROM mdm_devices.object_cuts s CROSS JOIN LATERAL (SELECT DISTINCT ON(object) object,input FROM mdm_devices.object_versions WHERE tenant_id=s.tenant_id AND revision<=s.through AND ($5::text[] IS NULL OR object=ANY($5)) AND object>coalesce($3,'') COLLATE \"C\" ORDER BY object,revision DESC) live WHERE s.tenant_id=$1::uuid AND s.id=$2 AND live.input IS NOT NULL ORDER BY live.object LIMIT $4")
        .bind(tenant.to_string()).bind(snapshot).bind(after).bind(limit as i64).bind(selected).fetch_all(c).await?;
    rows.into_iter().map(decode).collect()
}
pub(super) async fn memberships(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<MembershipObjects, sqlx::Error> {
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_versions v JOIN mdm_devices.object_heads h USING(tenant_id,object,revision) WHERE v.tenant_id=$1::uuid AND v.devices @> ARRAY[$2::text] AND v.input IS NOT NULL ORDER BY v.object LIMIT 3")
        .bind(tenant.to_string()).bind(device).fetch_all(&mut *c).await?;
    if rows.len() > 2 {
        return Err(storage("ambiguous membership"));
    }
    let mut objects = Vec::new();
    let mut current = true;
    for row in rows {
        let input: DeviceObject = decode(row)?;
        current &= input.verified;
        for member in &input.members {
            current &= validate(c, tenant, &input, member.channel).await?.as_ref() == Some(member);
        }
        objects.push(input.object);
    }
    Ok(MembershipObjects { objects, current })
}

/// Select the last version first: an older membership is not proof at this cut.
pub(super) async fn memberships_at(
    c: &mut PgConnection,
    tenant: TenantId,
    snapshot: Uuid,
    device: &str,
    channel: Channel,
    max_bytes: usize,
) -> Result<Option<(Vec<DeviceObject>, usize)>, sqlx::Error> {
    let through: i64 = sqlx::query_scalar(
        "SELECT through FROM mdm_devices.object_cuts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant.to_string())
    .bind(snapshot)
    .fetch_one(&mut *c)
    .await?;
    let rows: Vec<(Option<serde_json::Value>,i64)> = sqlx::query_as(
        "WITH candidates AS (SELECT DISTINCT object FROM mdm_devices.object_versions WHERE tenant_id=$1::uuid AND revision<=$2 AND devices @> ARRAY[$3::text]), live AS (SELECT v.input,v.devices FROM candidates k CROSS JOIN LATERAL (SELECT input,devices FROM mdm_devices.object_versions WHERE tenant_id=$1::uuid AND object=k.object AND revision<=$2 ORDER BY revision DESC LIMIT 1) v WHERE v.input IS NOT NULL AND v.devices @> ARRAY[$3::text] ORDER BY k.object LIMIT 3), sized AS (SELECT input,octet_length(input::text)::bigint+1024 AS bytes FROM live) SELECT CASE WHEN sum(bytes) OVER ()<=$4 THEN input ELSE NULL END,bytes FROM sized"
    ).bind(tenant.to_string()).bind(through).bind(device).bind(max_bytes as i64).fetch_all(c).await?;
    if rows.len() > 2 {
        return Err(storage("ambiguous frozen membership"));
    }
    if rows.iter().any(|(input, _)| input.is_none()) {
        return Ok(None);
    }
    let mut objects = Vec::new();
    let mut bytes = 0usize;
    for (input, size) in rows {
        bytes = bytes
            .checked_add(usize::try_from(size).map_err(storage)?)
            .ok_or_else(|| storage("object bytes"))?;
        let object: DeviceObject = decode(input.ok_or_else(|| storage("object budget"))?)?;
        if object
            .members
            .iter()
            .any(|m| m.device == device && m.channel == channel)
        {
            objects.push(object);
        }
    }
    Ok(Some((objects, bytes)))
}
