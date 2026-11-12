//! Device owner freezes relation identities and validates actual endpoint authority.
//! ref: kube-rs kube-runtime/src/reflector/store.rs@1be7f0d96c3b211680b173c1fc83aa6ad4adba34
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_inventory_service::objects::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub enum ActivityPair {
    Unpaired,
    Pending,
    Paired(DeviceObject),
}

#[derive(sqlx::FromRow)]
struct ChangeRow {
    kind: String,
    revision: i64,
    object_kind: i16,
    object_id: Uuid,
    old_devices: Vec<Uuid>,
    new_devices: Vec<Uuid>,
}

pub struct PlanningObjects;
impl PlanningObjects {
    /// Current verified paired object for a device-bound authentication ceremony. The input
    /// projection is read from a complete snapshot and revalidated by this owner.
    pub async fn paired_in(
        c: &mut PgConnection,
        tenant: TenantId,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<DeviceObject, sqlx::Error> {
        match Self::activity_pair_in(c, tenant, device).await? {
            ActivityPair::Paired(object) => Ok(object),
            ActivityPair::Unpaired | ActivityPair::Pending => {
                Err(storage("paired device unavailable"))
            }
        }
    }
    /// Distinguish a verified absence from an unavailable projection and a storage error.
    pub async fn activity_pair_in(
        c: &mut PgConnection,
        tenant: TenantId,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<ActivityPair, sqlx::Error> {
        let associations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released AND a.state<>'revoked'")
            .bind(tenant.to_string()).bind(device.into_uuid()).fetch_one(&mut *c).await?;
        if associations == 0 {
            return Ok(ActivityPair::Unpaired);
        }
        if associations != 1 {
            return Err(storage("ambiguous association"));
        }
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_versions v JOIN mdm_devices.object_heads h USING(tenant_id,object_kind,object_id,revision) WHERE v.tenant_id=$1::uuid AND v.devices @> ARRAY[$2::uuid] AND v.object_kind=1 AND v.input IS NOT NULL LIMIT 2")
            .bind(tenant.to_string()).bind(device.into_uuid()).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            return Ok(ActivityPair::Pending);
        }
        if rows.len() != 1 {
            return Err(storage("ambiguous association"));
        }
        let input: DeviceObject = serde_json::from_value(
            rows.into_iter()
                .next()
                .ok_or_else(|| storage("paired device unavailable"))?,
        )
        .map_err(storage)?;
        if input.members.len() != 2
            || snapshots::validate(c, tenant, &input, rss_mdm_inventory::Channel::Agent)
                .await?
                .is_none()
            || snapshots::validate(c, tenant, &input, rss_mdm_inventory::Channel::Mdm)
                .await?
                .is_none()
        {
            return Ok(ActivityPair::Pending);
        }
        Ok(ActivityPair::Paired(input))
    }
}
mod snapshots;
fn storage<E>(_: E) -> sqlx::Error {
    sqlx::Error::Protocol("device input unavailable".into())
}
impl ObjectReader for PlanningObjects {
    fn changes<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Pending<'a, Vec<ObjectChange>> {
        Box::pin(async move {
            if !(1..=1000).contains(&limit) || after < 0 || through < after {
                return Err(storage("change window"));
            }
            let rows:Vec<ChangeRow>=sqlx::query_as("SELECT revision,object_kind,object_id,old_devices,new_devices,kind FROM mdm_devices.object_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT $4")
                .bind(tenant.to_string()).bind(after).bind(through).bind(limit as i64).fetch_all(c).await?;
            rows.into_iter()
                .map(|row| {
                    Ok(ObjectChange {
                        kind: match row.kind.as_str() {
                            "asset_invalidated" => ObjectChangeKind::AssetInvalidated,
                            "identity_changed" => ObjectChangeKind::IdentityChanged,
                            _ => return Err(storage("object change kind")),
                        },
                        position: row.revision,
                        object: ObjectRef::from_parts(row.object_kind, row.object_id)
                            .map_err(storage)?,
                        old_devices: row
                            .old_devices
                            .into_iter()
                            .map(rss_mdm_agent_wire::DeviceId::try_from)
                            .collect::<Result<_, _>>()
                            .map_err(storage)?,
                        new_devices: row
                            .new_devices
                            .into_iter()
                            .map(rss_mdm_agent_wire::DeviceId::try_from)
                            .collect::<Result<_, _>>()
                            .map_err(storage)?,
                    })
                })
                .collect()
        })
    }
    fn change_head<'a>(&'a self, c: &'a mut PgConnection, tenant: TenantId) -> Pending<'a, i64> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT s.through FROM mdm_devices.checkpoints p JOIN mdm_devices.object_cuts s ON(s.tenant_id,s.id)=(p.tenant_id,p.current_cut) WHERE p.tenant_id=$1::uuid),0)").bind(tenant.to_string()).fetch_one(c).await
        })
    }
    fn changed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        from: Uuid,
        to: Uuid,
    ) -> Pending<'a, Vec<ObjectRef>> {
        Box::pin(async move {
            let rows:Vec<(i16,Uuid)>=sqlx::query_as("SELECT DISTINCT x.object_kind,x.object_id FROM mdm_devices.object_changes x JOIN mdm_devices.object_cuts a ON a.tenant_id=x.tenant_id AND a.id=$2 JOIN mdm_devices.object_cuts b ON b.tenant_id=x.tenant_id AND b.id=$3 WHERE x.tenant_id=$1::uuid AND x.revision>a.through AND x.revision<=b.through ORDER BY x.object_kind,x.object_id LIMIT 1001")
                .bind(tenant.to_string()).bind(from).bind(to).fetch_all(c).await?;
            if rows.len() > 1000 {
                return Err(storage("object delta window exceeded"));
            }
            rows.into_iter()
                .map(|(kind, id)| ObjectRef::from_parts(kind, id).map_err(storage))
                .collect()
        })
    }
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Vec<rss_mdm_agent_wire::DeviceId>> {
        Box::pin(async move {
            let mut devices: Vec<rss_mdm_agent_wire::DeviceId>=sqlx::query_scalar("SELECT peer.device FROM mdm_devices.members anchor JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(anchor.tenant_id,anchor.association_id) JOIN mdm_devices.members peer ON(peer.tenant_id,peer.association_id)=(a.tenant_id,a.id) WHERE anchor.tenant_id=$1::uuid AND anchor.device=$2 AND NOT anchor.released AND NOT peer.released AND a.state<>'revoked' ORDER BY peer.device LIMIT 3").bind(tenant.to_string()).bind(device.into_uuid()).fetch_all(c).await.and_then(crate::device_ids)?;
            if devices.len() > 2 {
                return Err(storage("association effect boundary"));
            }
            devices.push(device.to_owned());
            devices.sort();
            devices.dedup();
            Ok(devices)
        })
    }

    fn memberships<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: rss_request_context::TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> rss_mdm_inventory_service::objects::Pending<
        'a,
        rss_mdm_inventory_service::objects::MembershipObjects,
    > {
        Box::pin(snapshots::memberships(c, tenant, device))
    }

    fn memberships_at<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        device: &'a rss_mdm_agent_wire::DeviceId,
        channel: rss_mdm_inventory::Channel,
        max_bytes: usize,
    ) -> Pending<'a, Option<(Vec<DeviceObject>, usize)>> {
        Box::pin(snapshots::memberships_at(
            c, tenant, snapshot, device, channel, max_bytes,
        ))
    }

    fn relation_revision<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
    ) -> Pending<'a, u64> {
        Box::pin(async move {
            let revision: i64 = sqlx::query_scalar("SELECT coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)")
                .bind(tenant.to_string()).fetch_one(c).await?;
            u64::try_from(revision).map_err(|_| storage("invalid relation revision"))
        })
    }

    fn capture<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: Option<Uuid>,
    ) -> Pending<'a, ObjectSnapshot> {
        Box::pin(snapshots::capture(c, tenant, after))
    }
    fn complete<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, bool> {
        Box::pin(snapshots::complete(c, tenant, snapshot))
    }
    fn lookup<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        object: &'a ObjectRef,
        max_bytes: usize,
    ) -> Pending<'a, Option<(DeviceObject, usize)>> {
        Box::pin(snapshots::lookup(c, tenant, snapshot, object, max_bytes))
    }
    fn endpoint<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, DeviceObject> {
        Box::pin(snapshots::endpoint(c, tenant, device))
    }
    fn endpoint_at<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        cut: &'a rss_mdm_inventory::AssetCut,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, DeviceObject> {
        Box::pin(snapshots::endpoint_at(c, tenant, cut, device))
    }
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        input: &'a DeviceObject,
        channel: rss_mdm_inventory::Channel,
    ) -> Pending<'a, Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>>
    {
        Box::pin(snapshots::validate(c, tenant, input, channel))
    }
    fn page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        after: Option<ObjectRef>,
        limit: usize,
        selected: Option<Vec<ObjectRef>>,
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(snapshots::page(c, tenant, snapshot, after, limit, selected))
    }
}

/// Normalize source objects before keyset pagination; source SQL is owner-authored and binds tenant/run/source indices.
pub fn complete_source_objects_sql(source_facts: &'static str) -> String {
    format!(
        "SELECT DISTINCT ON(object_kind,object_id) input,unknown FROM (SELECT m.input,m.unknown,CASE WHEN a.id IS NOT NULL OR m.input->'object'->>'kind'='association' THEN 1::smallint ELSE 0::smallint END AS object_kind,coalesce(a.id,(m.input->'object'->>'id')::uuid) AS object_id FROM ({}) m LEFT JOIN mdm_devices.members d ON d.tenant_id=m.tenant_id AND m.input->'object'->>'kind'='endpoint' AND d.device=(m.input->'object'->>'id')::uuid AND NOT d.released LEFT JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(d.tenant_id,d.association_id) AND a.state<>'revoked') objects WHERE ($4::smallint IS NULL OR (object_kind,object_id)>($4,$5::uuid)) ORDER BY object_kind,object_id,unknown LIMIT $6",
        source_facts
    )
}
