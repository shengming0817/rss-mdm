//! Device-owned input projection and recoverable, bounded key fan-out.
use crate::{Association, Error, Result, State, identity, read};
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_inventory::AssetCut;
use rss_mdm_inventory_service::objects::DeviceObject;
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
    Ok(sqlx::query_scalar("WITH input_cut AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context((SELECT from_cut FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid))) SELECT NOT EXISTS(SELECT FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid) OR EXISTS(SELECT FROM mdm_devices.checkpoints p WHERE p.tenant_id=$1::uuid AND (p.rebuilding OR EXISTS(SELECT FROM mdm.asset_changes a WHERE a.tenant_id=p.tenant_id AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM input_cut),false))))").bind(tenant.to_string()).fetch_one(c).await?)
}
enum AssociationKey<'a> {
    Device(rss_mdm_agent_wire::DeviceId),
    Hardware(&'a str, &'a str),
}
async fn request(c: &mut PgConnection, tenant: TenantId, key: AssociationKey<'_>) -> Result<Uuid> {
    let (kind, value, device) = match key {
        AssociationKey::Device(id) => ("device", None, Some(id.into_uuid())),
        AssociationKey::Hardware(kind, value) => (kind, Some(value), None),
    };
    Ok(sqlx::query_scalar("INSERT INTO mdm_devices.association_work(tenant_id,id,kind,value,device) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,kind,value,device) DO UPDATE SET requested=association_work.requested+1 RETURNING id")
        .bind(tenant.to_string()).bind(Uuid::new_v4()).bind(kind).bind(value).bind(device).fetch_one(c).await?)
}
/// Every input transaction records both old and new keys before replacing the projection.
async fn project(
    c: &mut PgConnection,
    tenant: TenantId,
    cut: &AssetCut,
    ids: &[rss_mdm_agent_wire::DeviceId],
) -> Result<Vec<Uuid>> {
    let t = tenant.to_string();
    let prior:Vec<(Uuid,String,serde_json::Value,serde_json::Value)>=sqlx::query_as("SELECT device,channel,input,hardware FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=ANY($2)").bind(&t).bind(ids.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(&mut *c).await?;
    let endpoints = identity::endpoint_page(c, tenant, cut, ids).await?;
    let mut changed = BTreeSet::new();
    for id in ids {
        let old = prior
            .iter()
            .filter(|e| e.0 == id.into_uuid())
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
            changed.insert(*id);
        }
    }
    let changed_ids = changed.iter().cloned().collect::<Vec<_>>();
    let mut keys:BTreeSet<(String,String)>=sqlx::query_as("SELECT DISTINCT kind,value FROM mdm_devices.identity_keys WHERE tenant_id=$1::uuid AND device=ANY($2)").bind(&t).bind(changed_ids.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(&mut *c).await?.into_iter().collect();
    sqlx::query(
        "DELETE FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=ANY($2)",
    )
    .bind(&t)
    .bind(
        changed_ids
            .iter()
            .map(|id| id.into_uuid())
            .collect::<Vec<_>>(),
    )
    .execute(&mut *c)
    .await?;
    for endpoint in endpoints
        .iter()
        .filter(|e| changed.contains(&e.member.device))
    {
        sqlx::query("INSERT INTO mdm_devices.endpoint_identities(tenant_id,device,channel,input,hardware) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(&t).bind(endpoint.member.device.into_uuid()).bind(endpoint.member.channel.as_str()).bind(serde_json::to_value(&endpoint.member).map_err(|_|Error::Storage)?).bind(serde_json::to_value(&endpoint.hardware).map_err(|_|Error::Storage)?).execute(&mut *c).await?;
        for (kind, value) in endpoint.hardware.keys() {
            keys.insert((kind.to_owned(), value.clone()));
            sqlx::query("INSERT INTO mdm_devices.identity_keys(tenant_id,kind,value,device,channel) VALUES($1::uuid,$2,$3,$4,$5)")
                .bind(&t).bind(kind).bind(value).bind(endpoint.member.device.into_uuid()).bind(endpoint.member.channel.as_str()).execute(&mut *c).await?;
        }
    }
    let mut work = Vec::new();
    for id in ids {
        publish_endpoint(c, tenant, id, true).await?;
        if changed.contains(id) {
            work.push(request(c, tenant, AssociationKey::Device(*id)).await?);
        }
    }
    // Input projection can invalidate evidence, but only the association owner
    // can validate it again. Group members across this page and preserve a prior
    // invalidation across later ordinary updates and subsequent input windows.
    let associations: Vec<(Uuid, bool)> = sqlx::query_as("SELECT DISTINCT m.association_id,coalesce(v.input->>'verified'='true',false) FROM mdm_devices.members m LEFT JOIN mdm_devices.object_heads h ON h.tenant_id=m.tenant_id AND h.object_kind=1 AND h.object_id=m.association_id LEFT JOIN mdm_devices.object_versions v ON(v.tenant_id,v.object_kind,v.object_id,v.revision)=(h.tenant_id,h.object_kind,h.object_id,h.revision) WHERE m.tenant_id=$1::uuid AND m.device=ANY($2) AND NOT m.released ORDER BY m.association_id")
        .bind(&t).bind(ids.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(&mut *c).await?;
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
        let object = input.object;
        publish(c, tenant, &object, Some(input), true).await?;
    }
    for (kind, value) in keys {
        work.push(request(c, tenant, AssociationKey::Hardware(&kind, &value)).await?);
    }
    Ok(work)
}
#[derive(sqlx::FromRow)]
struct InputWindow {
    from_cut: Option<serde_json::Value>,
    to_cut: Option<serde_json::Value>,
    event_after: i64,
    page_through: Option<i64>,
    cursor: Option<Uuid>,
    rebuilding: bool,
    rebuild_after: Option<Uuid>,
}
/// Only Device advances this checkpoint. Source transactions append canonical facts.
pub(crate) async fn advance(
    c: &mut PgConnection,
    tenant: TenantId,
    candidate: &AssetCut,
) -> Result<Vec<Uuid>> {
    initialize(c, tenant).await?;
    let t = tenant.to_string();
    let InputWindow { from_cut: from, to_cut: to, event_after: after, page_through: through, cursor, rebuilding, rebuild_after } =
        sqlx::query_as::<_, InputWindow>("SELECT from_cut,to_cut,event_after,page_through,cursor,rebuilding,rebuild_after FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE")
        .bind(&t).fetch_one(&mut *c).await?;
    let to = to.unwrap_or_else(|| candidate.to_json());
    let cut = AssetCut::from_json(to.clone()).map_err(|_| Error::Storage)?;
    let through = match through {
        Some(value) => Some(value),
        None => sqlx::query_scalar("WITH cut_3 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($3::jsonb)), cut_4 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($4::jsonb)) SELECT max(revision) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM cut_3),false) AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM cut_4),false) ORDER BY revision LIMIT 64) page")
            .bind(&t).bind(after).bind(&to).bind(&from).fetch_one(&mut *c).await?,
    };
    let rebuild = rebuilding || sqlx::query_scalar::<_,bool>("WITH cut_4 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($4::jsonb)), cut_5 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($5::jsonb)) SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM cut_4),false) AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM cut_5),false) AND identity->>'device' IS NULL AND fields && ARRAY['device.serial_number','device.hardware_uuid','device.manufacturer']::text[])")
        .bind(&t).bind(after).bind(through).bind(&to).bind(&from).fetch_one(&mut *c).await?;
    if through.is_none() && !rebuild {
        finish_window(c, tenant, to).await?;
        return Ok(vec![]);
    }
    sqlx::query(
        "UPDATE mdm_devices.checkpoints SET to_cut=$2,page_through=$3 WHERE tenant_id=$1::uuid",
    )
    .bind(&t)
    .bind(&to)
    .bind(through)
    .execute(&mut *c)
    .await?;
    let ids: Vec<Uuid> = if rebuild {
        sqlx::query_scalar(r#"SELECT DISTINCT device FROM mdm_access.asset_authority_history WHERE tenant_id=$1::uuid AND kind='device' AND mdm.asset_visible($2::jsonb,revision) AND ($3::uuid IS NULL OR device>$3) ORDER BY device LIMIT $4"#)
            .bind(&t).bind(&to).bind(rebuild_after).bind((PAGE+1) as i64).fetch_all(&mut *c).await?
    } else {
        sqlx::query_scalar(r#"WITH cut_4 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($4::jsonb)), cut_5 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($5::jsonb)), changed AS (SELECT DISTINCT (a.identity->>'device')::uuid device FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND a.revision>$2 AND a.revision<=$3 AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM cut_4),false) AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM cut_5),false)) SELECT device FROM changed WHERE device IS NOT NULL AND ($6::uuid IS NULL OR device>$6) ORDER BY device LIMIT $7"#)
            .bind(&t).bind(after).bind(through).bind(&to).bind(&from).bind(cursor).bind((PAGE+1) as i64).fetch_all(&mut *c).await?
    };
    let ids = ids
        .into_iter()
        .map(rss_mdm_agent_wire::DeviceId::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Storage)?;
    let more = ids.len() > PAGE;
    let selected = &ids[..ids.len().min(PAGE)];
    let work = project(c, tenant, &cut, selected).await?;
    if rebuild && !more {
        // A full rebuild covers the entire frozen cut, including all remaining event pages.
        finish_window(c, tenant, to).await?;
    } else {
        sqlx::query("UPDATE mdm_devices.checkpoints SET event_after=CASE WHEN $4 THEN event_after ELSE $2 END,page_through=CASE WHEN $4 THEN $2 END,cursor=CASE WHEN NOT $5 THEN $3 END,rebuild_after=CASE WHEN $5 THEN $3 END,rebuilding=$4 AND $5 WHERE tenant_id=$1::uuid")
            .bind(&t).bind(through.unwrap_or(after)).bind(more.then(||selected[PAGE-1].into_uuid())).bind(more).bind(rebuild).execute(c).await?;
    }
    Ok(work)
}
async fn finish_window(
    c: &mut PgConnection,
    tenant: TenantId,
    to: serde_json::Value,
) -> Result<()> {
    sqlx::query("UPDATE mdm_devices.checkpoints SET from_cut=$2,to_cut=NULL,event_after=0,page_through=NULL,cursor=NULL,rebuild_after=NULL,rebuilding=false WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string()).bind(to).execute(&mut *c).await?;
    seal(c, tenant).await
}
/// Object publication order is local to Device; it does not order asset commits.
pub(crate) async fn seal(c: &mut PgConnection, tenant: TenantId) -> Result<()> {
    let id = Uuid::new_v4();
    sqlx::query("WITH sealed AS (UPDATE mdm_devices.checkpoints SET object_revision=object_revision+1,current_cut=$2 WHERE tenant_id=$1::uuid AND NOT rebuilding AND to_cut IS NULL AND from_cut IS NOT NULL RETURNING tenant_id,from_cut,object_revision) INSERT INTO mdm_devices.object_cuts(tenant_id,id,asset_cut,through) SELECT tenant_id,$2,from_cut,object_revision FROM sealed")
        .bind(tenant.to_string()).bind(id).execute(c).await?;
    Ok(())
}
async fn publish(
    c: &mut PgConnection,
    tenant: TenantId,
    key: &ObjectRef,
    input: Option<DeviceObject>,
    force: bool,
) -> Result<()> {
    initialize(c, tenant).await?;
    let t = tenant.to_string();
    let old:Option<(Option<serde_json::Value>,Vec<Uuid>)>=sqlx::query_as("SELECT v.input,v.devices FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object_kind,object_id,revision) WHERE h.tenant_id=$1::uuid AND (h.object_kind,h.object_id)=($2,$3)").bind(&t).bind(key.kind()).bind(key.uuid()).fetch_optional(&mut *c).await?;
    let devices = input
        .as_ref()
        .map(|o| {
            o.members
                .iter()
                .map(|m| m.device)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let doc = input
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Storage)?;
    let identity_changed = old.as_ref().map(|o| &o.0) != Some(&doc);
    if !force && !identity_changed || old.is_none() && doc.is_none() {
        return Ok(());
    }
    let kind = if identity_changed {
        rss_mdm_inventory_service::objects::ObjectChangeKind::IdentityChanged
    } else {
        rss_mdm_inventory_service::objects::ObjectChangeKind::AssetInvalidated
    };
    let revision:i64=sqlx::query_scalar("UPDATE mdm_devices.checkpoints SET object_revision=object_revision+1 WHERE tenant_id=$1::uuid RETURNING object_revision").bind(&t).fetch_one(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_versions(tenant_id,object_kind,object_id,revision,input,devices) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(&t).bind(key.kind()).bind(key.uuid()).bind(revision).bind(doc).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_changes(tenant_id,revision,object_kind,object_id,old_devices,new_devices,kind) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)").bind(&t).bind(revision).bind(key.kind()).bind(key.uuid()).bind(old.map(|o|o.1).unwrap_or_default()).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(kind.as_str()).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_heads(tenant_id,object_kind,object_id,revision) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,object_kind,object_id) DO UPDATE SET revision=excluded.revision").bind(t).bind(key.kind()).bind(key.uuid()).bind(revision).execute(c).await?;
    Ok(())
}
async fn publish_endpoint(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &rss_mdm_agent_wire::DeviceId,
    force: bool,
) -> Result<()> {
    let occupied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released)").bind(tenant.to_string()).bind(device.into_uuid()).fetch_one(&mut *c).await?;
    let members:Vec<serde_json::Value>=sqlx::query_scalar("SELECT input FROM mdm_devices.endpoint_identities WHERE tenant_id=$1::uuid AND device=$2 ORDER BY channel").bind(tenant.to_string()).bind(device.into_uuid()).fetch_all(&mut *c).await?;
    let members = members
        .into_iter()
        .map(|m| serde_json::from_value(m).map_err(|_| Error::Storage))
        .collect::<Result<Vec<_>>>()?;
    let object = ObjectRef::Endpoint(device.to_owned());
    let input = (!occupied && !members.is_empty()).then_some(DeviceObject {
        object,
        association_version: None,
        verified: true,
        members,
    });
    publish(c, tenant, &object, input, force).await
}
/// Call after the owner has changed the association and its members in the original transaction.
pub(crate) async fn association(
    c: &mut PgConnection,
    tenant: TenantId,
    a: &Association,
) -> Result<()> {
    let object = ObjectRef::Association(a.id);
    let input = (a.state != State::Revoked).then(|| DeviceObject {
        object,
        association_version: Some(a.version),
        verified: a.state == State::Confirmed,
        members: a.members.clone(),
    });
    publish(c, tenant, &object, input, false).await?;
    for m in &a.members {
        publish_endpoint(c, tenant, &m.device, false).await?;
    }
    seal(c, tenant).await
}
pub(crate) async fn work_pending(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT requested>completed FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).fetch_optional(c).await?.unwrap_or(false))
}
#[derive(sqlx::FromRow)]
struct AssociationWork {
    kind: String,
    value: Option<String>,
    device: Option<Uuid>,
    requested: i64,
    completed: i64,
    watermark: i64,
    cursor: Option<Uuid>,
}
pub(crate) async fn key_page(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<(Option<(rss_mdm_agent_wire::DeviceId, i64)>, Vec<Uuid>)>> {
    let t = tenant.to_string();
    let row:Option<AssociationWork>=sqlx::query_as("SELECT kind,value,device,requested,completed,watermark,cursor FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE SKIP LOCKED")
        .bind(&t).bind(id).fetch_optional(&mut *c).await?;
    let Some(AssociationWork {
        kind,
        value,
        device,
        requested,
        completed,
        watermark: window,
        cursor,
    }) = row
    else {
        return Ok(None);
    };
    if requested == completed {
        return Ok(Some((None, vec![])));
    }
    let window = if window == completed {
        requested
    } else {
        window
    };
    if kind == "device" {
        let device = rss_mdm_agent_wire::DeviceId::try_from(device.ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        return Ok(Some((Some((device, window)), vec![])));
    }
    let devices:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT device FROM mdm_devices.identity_keys WHERE tenant_id=$1::uuid AND kind=$2 AND value=$3 AND ($4::uuid IS NULL OR device>$4) ORDER BY device LIMIT 65")
        .bind(&t).bind(kind).bind(value.ok_or(Error::Storage)?).bind(cursor).fetch_all(&mut *c).await?;
    let mut work = Vec::new();
    for device in devices.iter().take(PAGE) {
        work.push(
            request(
                c,
                tenant,
                AssociationKey::Device(
                    rss_mdm_agent_wire::DeviceId::try_from(*device).map_err(|_| Error::Storage)?,
                ),
            )
            .await?,
        );
    }
    let more = devices.len() > PAGE;
    sqlx::query("UPDATE mdm_devices.association_work SET watermark=$3,completed=CASE WHEN $4 THEN completed ELSE $3 END,cursor=$5 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(t).bind(id).bind(window).bind(more).bind(more.then(||devices[PAGE-1])).execute(c).await?;
    Ok(Some((None, work)))
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
