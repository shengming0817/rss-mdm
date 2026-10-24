//! A bounded builder, driven by the existing Group job. Only sealed inputs are readable.
use super::*;
use crate::{identity, model::State};
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::device::endpoints::{self, PrimaryRegistration};
use sqlx::Row;
use std::collections::BTreeSet;
const PAGE: usize = 64;
const OBJECTS: i64 = 1_000_000;
const BYTES: i64 = 1_073_741_824;
async fn coordinates(c: &mut PgConnection, tenant: TenantId) -> Result<(i64, i64), sqlx::Error> {
    let watermark = rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let relation=sqlx::query_scalar("SELECT coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)").bind(tenant.to_string()).fetch_one(c).await?;
    Ok((watermark, relation))
}
fn version(watermark: i64, relation: i64) -> String {
    use sha2::Digest;
    format!(
        "{:x}",
        sha2::Sha256::digest(format!("{watermark}:{relation}").as_bytes())
    )
}
pub(super) async fn begin(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<ObjectSnapshot, sqlx::Error> {
    let (watermark, relation) = coordinates(c, tenant).await?;
    let version = version(watermark, relation);
    let existing=sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_devices.input_snapshots WHERE tenant_id=$1::uuid AND watermark=$2 AND version=$3").bind(tenant.to_string()).bind(watermark).bind(&version).fetch_optional(&mut *c).await?;
    let id = if let Some(id) = existing {
        id
    } else {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_devices.input_snapshots(tenant_id,id,watermark,version,relation_revision,phase) VALUES($1::uuid,$2,$3,$4,$5,'endpoints')").bind(tenant.to_string()).bind(id).bind(watermark).bind(&version).bind(relation).execute(c).await?;
        id
    };
    Ok(ObjectSnapshot {
        id,
        watermark,
        version,
    })
}
pub(super) async fn current(
    c: &mut PgConnection,
    tenant: TenantId,
    s: &ObjectSnapshot,
) -> Result<bool, sqlx::Error> {
    let (watermark, relation) = coordinates(c, tenant).await?;
    Ok(watermark==s.watermark && version(watermark,relation)==s.version && sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.input_snapshots WHERE tenant_id=$1::uuid AND id=$2 AND watermark=$3 AND version=$4 AND phase='sealed')").bind(tenant.to_string()).bind(s.id).bind(s.watermark).bind(&s.version).fetch_one(c).await?)
}
async fn insert(
    c: &mut PgConnection,
    tenant: TenantId,
    s: Uuid,
    key: String,
    input: &DeviceObject,
    hardware: serde_json::Value,
) -> Result<i64, sqlx::Error> {
    let doc =
        serde_json::to_value(input).map_err(|_| sqlx::Error::Protocol("object encoding".into()))?;
    let bytes = (doc.to_string().len() + hardware.to_string().len()) as i64;
    let devices: Vec<_> = input
        .members
        .iter()
        .map(|m| m.device.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    sqlx::query("INSERT INTO mdm_devices.input_objects(tenant_id,snapshot,object,input,hardware,devices) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(tenant.to_string()).bind(s).bind(key).bind(doc).bind(hardware).bind(devices).execute(c).await?;
    Ok(bytes)
}
async fn update(
    c: &mut PgConnection,
    tenant: TenantId,
    s: Uuid,
    phase: &str,
    cursor: &str,
    count: i64,
    bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE mdm_devices.input_snapshots SET phase=$3,cursor=$4,object_count=object_count+$5,byte_count=byte_count+$6 WHERE tenant_id=$1::uuid AND id=$2 AND phase<>'sealed'").bind(tenant.to_string()).bind(s).bind(phase).bind(cursor).bind(count).bind(bytes).execute(c).await?;
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, sqlx::Error> {
    serde_json::from_value(value).map_err(|_| sqlx::Error::Protocol("object decoding".into()))
}
pub(super) async fn advance(
    c: &mut PgConnection,
    tenant: TenantId,
    s: &ObjectSnapshot,
) -> Result<SnapshotProgress, sqlx::Error> {
    let (watermark, relation) = coordinates(c, tenant).await?;
    if watermark != s.watermark || version(watermark, relation) != s.version {
        return Ok(SnapshotProgress::Superseded);
    }
    let row=sqlx::query("SELECT phase,cursor,object_count,byte_count FROM mdm_devices.input_snapshots WHERE tenant_id=$1::uuid AND id=$2 AND watermark=$3 AND version=$4 FOR UPDATE").bind(tenant.to_string()).bind(s.id).bind(s.watermark).bind(&s.version).fetch_one(&mut *c).await?;
    let phase: String = row.try_get("phase")?;
    let cursor: String = row.try_get("cursor")?;
    let count: i64 = row.try_get("object_count")?;
    let previous_bytes: i64 = row.try_get("byte_count")?;
    if phase == "sealed" {
        return Ok(SnapshotProgress::Ready);
    }
    let mut bytes = 0;
    if phase == "endpoints" {
        let mut limit = PAGE;
        let (ids, raw) = loop {
            let ids = endpoints::page_in(c, &tenant.to_string(), &cursor, limit as i64)
                .await
                .map_err(storage)?;
            if count + ids.len() as i64 > OBJECTS {
                return Ok(SnapshotProgress::ObjectLimit);
            }
            match identity::endpoint_page(c, tenant, watermark, &ids).await {
                Ok(raw) => break (ids, raw),
                Err(crate::Error::Storage) if limit > 1 => {
                    limit = (limit / 2).max(1);
                }
                Err(error) => return Err(storage(error)),
            }
        };
        for id in &ids {
            let entries: Vec<_> = raw
                .iter()
                .filter(|e| &e.member.device == id)
                .cloned()
                .collect();
            let serial: Vec<_> = entries
                .iter()
                .flat_map(|e| e.hardware.serial.iter().cloned())
                .collect();
            let uuid: Vec<_> = entries
                .iter()
                .flat_map(|e| e.hardware.uuid.iter().cloned())
                .collect();
            let input = DeviceObject {
                object: ObjectRef::Endpoint(id.clone()),
                association_version: None,
                verified: true,
                members: entries.iter().map(|e| e.member.clone()).collect(),
            };
            bytes += insert(
                c,
                tenant,
                s.id,
                format!("source-endpoint:{id}"),
                &input,
                serde_json::json!({"endpoints":entries,"serial":serial,"uuid":uuid}),
            )
            .await?;
        }
        if previous_bytes + bytes > BYTES {
            return Ok(SnapshotProgress::ByteLimit);
        }
        update(
            c,
            tenant,
            s.id,
            if ids.is_empty() {
                "associations"
            } else {
                "endpoints"
            },
            ids.last().map(String::as_str).unwrap_or(""),
            ids.len() as i64,
            bytes,
        )
        .await?;
    } else if phase == "associations" {
        let after = if cursor.is_empty() {
            Uuid::nil()
        } else {
            Uuid::parse_str(&cursor)
                .map_err(|_| sqlx::Error::Protocol("association cursor".into()))?
        };
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_devices.associations WHERE tenant_id=$1::uuid AND id>$2 ORDER BY id LIMIT $3").bind(tenant.to_string()).bind(after).bind(PAGE as i64).fetch_all(&mut *c).await?;
        for id in &ids {
            let association = crate::read::load(c, &tenant.to_string(), *id)
                .await
                .map_err(storage)?;
            if association.state == State::Revoked {
                continue;
            }
            let devices: Vec<_> = association
                .members
                .iter()
                .map(|m| m.device.clone())
                .collect();
            let keys: Vec<_> = devices
                .iter()
                .map(|d| format!("source-endpoint:{d}"))
                .collect();
            let docs:Vec<serde_json::Value>=sqlx::query_scalar("SELECT hardware FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 AND object=ANY($3)").bind(tenant.to_string()).bind(s.id).bind(keys).fetch_all(&mut *c).await?;
            let mut endpoints = Vec::new();
            for doc in docs {
                endpoints.extend(decode::<Vec<identity::EndpointIdentity>>(
                    doc["endpoints"].clone(),
                )?);
            }
            let serial: Vec<_> = endpoints
                .iter()
                .flat_map(|e| e.hardware.serial.iter().cloned())
                .collect();
            let uuid: Vec<_> = endpoints
                .iter()
                .flat_map(|e| e.hardware.uuid.iter().cloned())
                .collect();
            // At most three neighboring endpoints suffice to disprove pair uniqueness.
            let peers:Vec<serde_json::Value>=sqlx::query_scalar("SELECT hardware FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 AND object LIKE 'source-endpoint:%' AND NOT(input->'object'->>'id'=ANY($3)) AND ((hardware->'serial') ?| $4 OR (hardware->'uuid') ?| $5) ORDER BY object LIMIT 3").bind(tenant.to_string()).bind(s.id).bind(devices).bind(serial).bind(uuid).fetch_all(&mut *c).await?;
            for doc in peers {
                endpoints.extend(decode::<Vec<identity::EndpointIdentity>>(
                    doc["endpoints"].clone(),
                )?);
            }
            let world = identity::endpoint_world(endpoints);
            let effective = world.effective(association.clone());
            let verified = effective.state == State::Confirmed
                && association
                    .members
                    .iter()
                    .all(|m| world.current(m).is_some_and(|e| e.member == *m));
            let input = DeviceObject {
                object: ObjectRef::Association(*id),
                association_version: Some(association.version),
                verified,
                members: association.members,
            };
            bytes += insert(
                c,
                tenant,
                s.id,
                input.object.key(),
                &input,
                serde_json::json!([]),
            )
            .await?;
        }
        if previous_bytes + bytes > BYTES {
            return Ok(SnapshotProgress::ByteLimit);
        }
        update(
            c,
            tenant,
            s.id,
            if ids.is_empty() {
                "standalone"
            } else {
                "associations"
            },
            &ids.last().map(Uuid::to_string).unwrap_or_default(),
            0,
            bytes,
        )
        .await?;
    } else if phase == "standalone" {
        let rows=sqlx::query("SELECT object,input FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 AND object LIKE 'source-endpoint:%' AND object>$3 COLLATE \"C\" ORDER BY object LIMIT $4").bind(tenant.to_string()).bind(s.id).bind(&cursor).bind(PAGE as i64).fetch_all(&mut *c).await?;
        for row in &rows {
            let input: DeviceObject = decode(row.try_get("input")?)?;
            let ObjectRef::Endpoint(ref id) = input.object else {
                return Err(sqlx::Error::Protocol("endpoint snapshot invariant".into()));
            };
            let associated:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 AND object LIKE 'association:%' AND devices @> ARRAY[$3])").bind(tenant.to_string()).bind(s.id).bind(id).fetch_one(&mut *c).await?;
            if !associated {
                bytes += insert(
                    c,
                    tenant,
                    s.id,
                    input.object.key(),
                    &input,
                    serde_json::json!([]),
                )
                .await?;
            }
        }
        if previous_bytes + bytes > BYTES {
            return Ok(SnapshotProgress::ByteLimit);
        }
        let last = rows
            .last()
            .map(|r| r.try_get::<String, _>("object"))
            .transpose()?
            .unwrap_or_default();
        update(
            c,
            tenant,
            s.id,
            if rows.is_empty() {
                "sealed"
            } else {
                "standalone"
            },
            &last,
            0,
            bytes,
        )
        .await?;
        if rows.is_empty() {
            return Ok(SnapshotProgress::Ready);
        }
    } else {
        return Err(sqlx::Error::Protocol("snapshot phase".into()));
    }
    Ok(SnapshotProgress::Building)
}
pub(super) async fn endpoint(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<DeviceObject, sqlx::Error> {
    let mut members = Vec::new();
    for channel in [Channel::Mdm, Channel::Agent] {
        endpoints::lock_in(c, &tenant.to_string(), device, channel)
            .await
            .map_err(storage)?;
        if let Some(member) = endpoints::current_in(c, &tenant.to_string(), device, channel)
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
pub(super) async fn lookup(
    c: &mut PgConnection,
    tenant: TenantId,
    snapshot: Uuid,
    object: &ObjectRef,
) -> Result<DeviceObject, sqlx::Error> {
    let value=sqlx::query_scalar("SELECT o.input FROM mdm_devices.input_objects o JOIN mdm_devices.input_snapshots s ON(s.tenant_id,s.id)=(o.tenant_id,o.snapshot) WHERE o.tenant_id=$1::uuid AND o.snapshot=$2 AND o.object=$3 AND s.phase='sealed'").bind(tenant.to_string()).bind(snapshot).bind(object.key()).fetch_one(c).await?;
    decode(value)
}
pub(super) async fn validate(
    c: &mut PgConnection,
    tenant: TenantId,
    input: &DeviceObject,
    channel: Channel,
) -> Result<Option<PrimaryRegistration>, sqlx::Error> {
    if !input.verified {
        return Ok(None);
    }
    if matches!(input.object, ObjectRef::Association(_)) {
        rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    }
    // Keep the existing lifecycle/channel lock order outside the shared read kernel.
    let mut members: Vec<_> = input.members.iter().collect();
    members.sort_by(|a, b| (&a.device, a.channel.as_str()).cmp(&(&b.device, b.channel.as_str())));
    for member in members {
        endpoints::lock_in(c, &tenant.to_string(), &member.device, member.channel)
            .await
            .map_err(storage)?;
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
) -> Result<Vec<DeviceObject>, sqlx::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(sqlx::Error::Protocol("object page budget".into()));
    }
    let rows:Vec<serde_json::Value>=sqlx::query_scalar("SELECT o.input FROM mdm_devices.input_objects o JOIN mdm_devices.input_snapshots s ON(s.tenant_id,s.id)=(o.tenant_id,o.snapshot) WHERE o.tenant_id=$1::uuid AND o.snapshot=$2 AND s.phase='sealed' AND (o.object LIKE 'endpoint:%' OR o.object LIKE 'association:%') AND o.object>coalesce($3,'') COLLATE \"C\" ORDER BY o.object LIMIT $4").bind(tenant.to_string()).bind(snapshot).bind(after).bind(limit as i64).fetch_all(c).await?;
    rows.into_iter().map(decode).collect()
}

pub(super) async fn memberships(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<rss_mdm_inventory_service::objects::MembershipObjects, sqlx::Error> {
    use rss_mdm_inventory_service::objects::MembershipObjects;
    use sqlx::Row;
    let rows=sqlx::query("WITH latest AS (SELECT s.id,s.watermark,s.relation_revision FROM mdm_devices.input_snapshots s WHERE s.tenant_id=$1::uuid AND s.phase='sealed' ORDER BY s.watermark DESC,s.relation_revision DESC LIMIT 1) SELECT s.id,s.watermark>=k.identity_watermark AND s.relation_revision=k.relation_revision AS current,o.input FROM latest s JOIN mdm_devices.checkpoints k ON k.tenant_id=$1::uuid LEFT JOIN mdm_devices.input_objects o ON o.tenant_id=$1::uuid AND o.snapshot=s.id AND o.devices @> ARRAY[$2::text] ORDER BY o.object LIMIT 33").bind(tenant.to_string()).bind(device).fetch_all(c).await?;
    if rows.len() > 32 {
        return Err(sqlx::Error::Protocol("membership object limit".into()));
    }
    let mut objects = Vec::new();
    let mut current = !rows.is_empty();
    for row in rows {
        current &= row.try_get::<bool, _>("current")?;
        if let Some(value) = row.try_get::<Option<serde_json::Value>, _>("input")? {
            let object: DeviceObject = decode(value)?;
            current &= object.verified;
            objects.push(object.object);
        }
    }
    Ok(MembershipObjects { objects, current })
}
