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
    device: &rss_mdm_agent_wire::DeviceId,
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
        object: ObjectRef::Endpoint(*device),
        association_version: None,
        verified: true,
        members,
    })
}

pub(super) async fn endpoint_at(
    c: &mut PgConnection,
    tenant: TenantId,
    cut: &rss_mdm_inventory::AssetCut,
    device: &rss_mdm_agent_wire::DeviceId,
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
        object: ObjectRef::Endpoint(*device),
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
        "SELECT CASE WHEN octet_length(o.input::text)+1024<=$5 THEN o.input END,octet_length(o.input::text)::bigint+1024 FROM mdm_devices.object_cuts s CROSS JOIN LATERAL (SELECT input FROM mdm_devices.object_versions WHERE tenant_id=s.tenant_id AND (object_kind,object_id)=($3,$4) AND revision<=s.through ORDER BY revision DESC LIMIT 1) o WHERE s.tenant_id=$1::uuid AND s.id=$2 AND o.input IS NOT NULL"
    ).bind(tenant.to_string()).bind(snapshot).bind(object.kind()).bind(object.uuid()).bind(max_bytes as i64).fetch_one(c).await?;
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
    after: Option<ObjectRef>,
    limit: usize,
    selected: Option<Vec<ObjectRef>>,
) -> Result<Vec<DeviceObject>, sqlx::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(storage("object page limit"));
    }
    let selected_kinds = selected
        .as_ref()
        .map(|v| v.iter().map(|o| o.kind()).collect::<Vec<_>>());
    let selected_ids = selected
        .as_ref()
        .map(|v| v.iter().map(|o| o.uuid()).collect::<Vec<_>>());
    let rows:Vec<serde_json::Value>=sqlx::query_scalar("SELECT live.input FROM mdm_devices.object_cuts s CROSS JOIN LATERAL (SELECT DISTINCT ON(object_kind,object_id) object_kind,object_id,input FROM mdm_devices.object_versions WHERE tenant_id=s.tenant_id AND revision<=s.through AND ($6::smallint[] IS NULL OR EXISTS(SELECT FROM unnest($6::smallint[],$7::uuid[]) x(kind,id) WHERE (object_kind,object_id)=(x.kind,x.id))) AND ($3::smallint IS NULL OR (object_kind,object_id)>($3,$4::uuid)) ORDER BY object_kind,object_id,revision DESC) live WHERE s.tenant_id=$1::uuid AND s.id=$2 AND live.input IS NOT NULL ORDER BY live.object_kind,live.object_id LIMIT $5")
        .bind(tenant.to_string()).bind(snapshot).bind(after.map(ObjectRef::kind)).bind(after.map(ObjectRef::uuid)).bind(limit as i64).bind(selected_kinds).bind(selected_ids).fetch_all(c).await?;
    rows.into_iter().map(decode).collect()
}
pub(super) async fn memberships(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<MembershipObjects, sqlx::Error> {
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_versions v JOIN mdm_devices.object_heads h USING(tenant_id,object_kind,object_id,revision) WHERE v.tenant_id=$1::uuid AND v.devices @> ARRAY[$2::uuid] AND v.input IS NOT NULL ORDER BY v.object_kind,v.object_id LIMIT 3")
        .bind(tenant.to_string()).bind(device.into_uuid()).fetch_all(&mut *c).await?;
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
    device: &rss_mdm_agent_wire::DeviceId,
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
        "WITH candidates AS (SELECT DISTINCT object_kind,object_id FROM mdm_devices.object_versions WHERE tenant_id=$1::uuid AND revision<=$2 AND devices @> ARRAY[$3::uuid]), live AS (SELECT v.input,v.devices FROM candidates k CROSS JOIN LATERAL (SELECT input,devices FROM mdm_devices.object_versions WHERE tenant_id=$1::uuid AND (object_kind,object_id)=(k.object_kind,k.object_id) AND revision<=$2 ORDER BY revision DESC LIMIT 1) v WHERE v.input IS NOT NULL AND v.devices @> ARRAY[$3::uuid] ORDER BY k.object_kind,k.object_id LIMIT 3), sized AS (SELECT input,octet_length(input::text)::bigint+1024 AS bytes FROM live) SELECT CASE WHEN sum(bytes) OVER ()<=$4 THEN input ELSE NULL END,bytes FROM sized"
    ).bind(tenant.to_string()).bind(through).bind(device.into_uuid()).bind(max_bytes as i64).fetch_all(c).await?;
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
            .any(|m| m.device == *device && m.channel == channel)
        {
            objects.push(object);
        }
    }
    Ok(Some((objects, bytes)))
}
