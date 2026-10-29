//! Device-owned input projection and recoverable, bounded key fan-out.
use crate::{Association, Error, Result, State, identity, read};
use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};
use rss_mdm_registration_service::device::endpoints;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::collections::BTreeSet;
use uuid::Uuid;
const PAGE: usize = 64;

async fn initialize(c: &mut PgConnection, tenant: TenantId) -> Result<()> {
    sqlx::query(
        "INSERT INTO mdm_devices.checkpoints(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.to_string())
    .execute(c)
    .await?;
    Ok(())
}
pub(crate) async fn pending(c: &mut PgConnection, tenant: TenantId) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid) OR EXISTS(SELECT FROM mdm_devices.checkpoints p WHERE p.tenant_id=$1::uuid AND (p.rebuilding OR p.consumed<coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=p.tenant_id),0)))").bind(tenant.to_string()).fetch_one(c).await?)
}
async fn request(c: &mut PgConnection, tenant: TenantId, kind: &str, value: &str) -> Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO mdm_devices.association_work(tenant_id,id,kind,value) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,kind,value) DO UPDATE SET requested=association_work.requested+1 RETURNING id")
        .bind(tenant.to_string()).bind(Uuid::new_v4()).bind(kind).bind(value).fetch_one(c).await?)
}
/// Every input transaction records both old and new keys before replacing the projection.
async fn project(
    c: &mut PgConnection,
    tenant: TenantId,
    watermark: i64,
    ids: &[String],
) -> Result<Vec<Uuid>> {
    let t = tenant.to_string();
    let prior:Vec<(String,String,serde_json::Value,serde_json::Value)>=sqlx::query_as("SELECT device,channel,input,hardware FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=ANY($2)").bind(&t).bind(ids).fetch_all(&mut *c).await?;
    let endpoints = identity::endpoint_page(c, tenant, watermark, ids).await?;
    let mut changed = BTreeSet::new();
    for id in ids {
        let old = prior
            .iter()
            .filter(|e| &e.0 == id)
            .map(|e| (e.1.clone(), (e.2.clone(), e.3.clone())))
            .collect::<std::collections::BTreeMap<_, _>>();
        let new = endpoints
            .iter()
            .filter(|e| &e.member.device == id)
            .map(|e| {
                Ok((
                    e.member.channel.as_str().to_owned(),
                    (
                        serde_json::to_value(&e.member).map_err(|_| Error::Storage)?,
                        serde_json::to_value(&e.hardware).map_err(|_| Error::Storage)?,
                    ),
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        if old != new {
            changed.insert(id.clone());
        }
    }
    let changed_ids = changed.iter().cloned().collect::<Vec<_>>();
    let mut keys:BTreeSet<(String,String)>=sqlx::query_as("SELECT DISTINCT kind,value FROM mdm_devices.identity_keys WHERE tenant_id=$1::uuid AND device=ANY($2)").bind(&t).bind(&changed_ids).fetch_all(&mut *c).await?.into_iter().collect();
    sqlx::query(
        "DELETE FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=ANY($2)",
    )
    .bind(&t)
    .bind(&changed_ids)
    .execute(&mut *c)
    .await?;
    for endpoint in endpoints
        .iter()
        .filter(|e| changed.contains(&e.member.device))
    {
        sqlx::query("INSERT INTO mdm_devices.endpoint_identities(tenant_id,device,channel,input,hardware) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(&t).bind(&endpoint.member.device).bind(endpoint.member.channel.as_str()).bind(serde_json::to_value(&endpoint.member).map_err(|_|Error::Storage)?).bind(serde_json::to_value(&endpoint.hardware).map_err(|_|Error::Storage)?).execute(&mut *c).await?;
        for (kind, value) in endpoint.hardware.keys() {
            keys.insert((kind.to_owned(), value.clone()));
            sqlx::query("INSERT INTO mdm_devices.identity_keys(tenant_id,kind,value,device,channel) VALUES($1::uuid,$2,$3,$4,$5)")
                .bind(&t).bind(kind).bind(value).bind(&endpoint.member.device).bind(endpoint.member.channel.as_str()).execute(&mut *c).await?;
        }
    }
    let mut work = Vec::new();
    for id in ids {
        publish_endpoint(c, tenant, id, true).await?;
        if changed.contains(id) {
            work.push(request(c, tenant, "device", id).await?);
        }
    }
    // Input projection can invalidate evidence, but only the association owner
    // can validate it again. Group members across this page and preserve a prior
    // invalidation across later ordinary updates and subsequent input windows.
    let associations: Vec<(Uuid, bool)> = sqlx::query_as("SELECT DISTINCT m.association_id,coalesce(v.input->>'verified'='true',false) FROM mdm_devices.members m LEFT JOIN mdm_devices.object_heads h ON h.tenant_id=m.tenant_id AND h.object='association:'||m.association_id::text LEFT JOIN mdm_devices.object_versions v ON(v.tenant_id,v.object,v.revision)=(h.tenant_id,h.object,h.revision) WHERE m.tenant_id=$1::uuid AND m.device=ANY($2) AND NOT m.released ORDER BY m.association_id")
        .bind(&t).bind(ids).fetch_all(&mut *c).await?;
    for (association, verified) in associations {
        let a = read::load(c, &t, association).await?;
        let input = DeviceObject {
            object: ObjectRef::Association(a.id),
            association_version: Some(a.version),
            verified: verified
                && a.state == State::Confirmed
                && !a.members.iter().any(|m| changed.contains(&m.device)),
            members: a.members,
        };
        publish(c, tenant, &input.object.key(), Some(input), true).await?;
    }
    for (kind, value) in keys {
        work.push(request(c, tenant, &kind, &value).await?);
    }
    Ok(work)
}
/// Fixed input windows contain at most 64 facts; only one endpoint page is materialized.
pub(crate) async fn advance(c: &mut PgConnection, tenant: TenantId) -> Result<Vec<Uuid>> {
    initialize(c, tenant).await?;
    let t = tenant.to_string();
    let (consumed,mut watermark,cursor,rebuilding,rebuild_after):(i64,i64,Option<String>,bool,Option<String>)=sqlx::query_as("SELECT consumed,watermark,cursor,rebuilding,rebuild_after FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE").bind(&t).fetch_one(&mut *c).await?;
    if watermark == consumed {
        watermark=sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 64) p").bind(&t).bind(consumed).fetch_one(&mut *c).await?;
    }
    // Field interpretation changes require an explicit rebuild; ordinary facts stay local.
    let rebuild:bool=rebuilding || sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 AND identity->>'device' IS NULL AND fields && ARRAY['device.serial_number','device.hardware_uuid','device.manufacturer']::text[])").bind(&t).bind(consumed).bind(watermark).fetch_one(&mut *c).await?;
    let ids: Vec<String> = if rebuild {
        endpoints::page_in(
            c,
            &t,
            rebuild_after.as_deref().unwrap_or(""),
            (PAGE + 1) as i64,
        )
        .await?
    } else {
        sqlx::query_scalar(r#"WITH changed AS (SELECT DISTINCT coalesce(a.identity->>'device',(SELECT h.device FROM mdm_access.asset_authority_history h WHERE h.tenant_id=a.tenant_id AND h.kind='registration' AND h.identity=a.identity->>'registration' AND h.revision<=a.revision ORDER BY h.revision DESC LIMIT 1)) COLLATE "C" device FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND a.revision>$2 AND a.revision<=$3) SELECT device FROM changed WHERE device IS NOT NULL AND device>coalesce($4,'') COLLATE "C" ORDER BY device LIMIT $5"#)
            .bind(&t).bind(consumed).bind(watermark).bind(cursor).bind((PAGE+1) as i64).fetch_all(&mut *c).await?
    };
    let more = ids.len() > PAGE;
    let selected = &ids[..ids.len().min(PAGE)];
    let work = project(c, tenant, watermark, selected).await?;
    let next = more.then(|| selected[PAGE - 1].clone());
    sqlx::query("UPDATE mdm_devices.checkpoints SET consumed=CASE WHEN $4 THEN consumed ELSE $2 END,watermark=$2,cursor=CASE WHEN NOT $5 THEN $3 END,rebuild_after=CASE WHEN $5 THEN $3 END,rebuilding=$4 AND $5 WHERE tenant_id=$1::uuid")
        .bind(&t).bind(watermark).bind(next).bind(more).bind(rebuild).execute(&mut *c).await?;
    if !more {
        seal(c, tenant).await?;
    }
    Ok(work)
}
/// A cut costs one row regardless of tenant size; immutable evidence is shared across cuts.
pub(crate) async fn seal(c: &mut PgConnection, tenant: TenantId) -> Result<()> {
    let t = tenant.to_string();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_devices.object_cuts(tenant_id,id,watermark,through) SELECT tenant_id,$2,consumed,object_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid AND NOT rebuilding AND watermark=consumed").bind(&t).bind(id).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_devices.checkpoints SET current_cut=$2 WHERE tenant_id=$1::uuid AND NOT rebuilding AND watermark=consumed").bind(t).bind(id).execute(c).await?;
    Ok(())
}
async fn publish(
    c: &mut PgConnection,
    tenant: TenantId,
    key: &str,
    input: Option<DeviceObject>,
    force: bool,
) -> Result<()> {
    initialize(c, tenant).await?;
    let t = tenant.to_string();
    let old:Option<(Option<serde_json::Value>,Vec<String>)>=sqlx::query_as("SELECT v.input,v.devices FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object,revision) WHERE h.tenant_id=$1::uuid AND h.object=$2").bind(&t).bind(key).fetch_optional(&mut *c).await?;
    let devices = input
        .as_ref()
        .map(|o| {
            o.members
                .iter()
                .map(|m| m.device.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let doc = input
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Storage)?;
    if !force && old.as_ref().map(|o| &o.0) == Some(&doc) || old.is_none() && doc.is_none() {
        return Ok(());
    }
    let revision:i64=sqlx::query_scalar("UPDATE mdm_devices.checkpoints SET object_revision=object_revision+1 WHERE tenant_id=$1::uuid RETURNING object_revision").bind(&t).fetch_one(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_versions(tenant_id,object,revision,input,devices) VALUES($1::uuid,$2,$3,$4,$5)").bind(&t).bind(key).bind(revision).bind(doc).bind(&devices).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_changes(tenant_id,revision,object,old_devices,new_devices) VALUES($1::uuid,$2,$3,$4,$5)").bind(&t).bind(revision).bind(key).bind(old.map(|o|o.1).unwrap_or_default()).bind(devices).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_heads(tenant_id,object,revision) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,object) DO UPDATE SET revision=excluded.revision").bind(t).bind(key).bind(revision).execute(c).await?;
    Ok(())
}
async fn publish_endpoint(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
    force: bool,
) -> Result<()> {
    let occupied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released)").bind(tenant.to_string()).bind(device).fetch_one(&mut *c).await?;
    let members:Vec<serde_json::Value>=sqlx::query_scalar("SELECT input FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=$2 ORDER BY channel").bind(tenant.to_string()).bind(device).fetch_all(&mut *c).await?;
    let members = members
        .into_iter()
        .map(|m| serde_json::from_value(m).map_err(|_| Error::Storage))
        .collect::<Result<Vec<_>>>()?;
    let object = ObjectRef::Endpoint(device.to_owned());
    let input = (!occupied && !members.is_empty()).then(|| DeviceObject {
        object: object.clone(),
        association_version: None,
        verified: true,
        members,
    });
    publish(c, tenant, &object.key(), input, force).await
}
/// Call after the owner has changed the association and its members in the original transaction.
pub(crate) async fn association(
    c: &mut PgConnection,
    tenant: TenantId,
    a: &Association,
) -> Result<()> {
    let object = ObjectRef::Association(a.id);
    let input = (a.state != State::Revoked).then(|| DeviceObject {
        object: object.clone(),
        association_version: Some(a.version),
        verified: a.state == State::Confirmed,
        members: a.members.clone(),
    });
    publish(c, tenant, &object.key(), input, false).await?;
    for m in &a.members {
        publish_endpoint(c, tenant, &m.device, false).await?;
    }
    seal(c, tenant).await
}
pub(crate) async fn work_pending(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT requested>completed FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).fetch_optional(c).await?.unwrap_or(false))
}
pub(crate) async fn key_page(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<(Option<(String, i64)>, Vec<Uuid>)> {
    let t = tenant.to_string();
    let (kind,value,requested,completed,window,cursor):(String,String,i64,i64,i64,Option<String>)=sqlx::query_as("SELECT kind,value,requested,completed,watermark,cursor FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE NOWAIT").bind(&t).bind(id).fetch_one(&mut *c).await?;
    if requested == completed {
        return Ok((None, vec![]));
    }
    let window = if window == completed {
        requested
    } else {
        window
    };
    if kind == "device" {
        return Ok((Some((value, window)), vec![]));
    }
    let devices:Vec<String>=sqlx::query_scalar("SELECT DISTINCT device FROM mdm_devices.identity_keys WHERE tenant_id=$1::uuid AND kind=$2 AND value=$3 AND device>coalesce($4,'') COLLATE \"C\" ORDER BY device LIMIT 65").bind(&t).bind(kind).bind(value).bind(cursor).fetch_all(&mut *c).await?;
    let mut work = Vec::new();
    for device in devices.iter().take(PAGE) {
        work.push(request(c, tenant, "device", device).await?);
    }
    let more = devices.len() > PAGE;
    sqlx::query("UPDATE mdm_devices.association_work SET watermark=$3,completed=CASE WHEN $4 THEN completed ELSE $3 END,cursor=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(id).bind(window).bind(more).bind(more.then(||devices[PAGE-1].clone())).execute(c).await?;
    Ok((None, work))
}
pub(crate) async fn complete_work(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    window: i64,
) -> Result<()> {
    sqlx::query("UPDATE mdm_devices.association_work SET watermark=$3,completed=$3,cursor=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).bind(window).execute(c).await?;
    Ok(())
}
