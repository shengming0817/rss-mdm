//! Device owner freezes relation identities and validates actual endpoint authority.
//! ref: kube-rs kube-runtime/src/reflector/store.rs@1be7f0d96c3b211680b173c1fc83aa6ad4adba34
use rss_mdm_inventory_service::objects::ObjectRef;
use rss_mdm_inventory_service::objects::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub enum ActivityPair {
    Unpaired,
    Pending,
    Paired(DeviceObject),
}

pub struct PlanningObjects;
impl PlanningObjects {
    /// Current verified paired object for a device-bound authentication ceremony. The input
    /// projection is read from a complete snapshot and revalidated by this owner.
    pub async fn paired_in(
        c: &mut PgConnection,
        tenant: TenantId,
        device: &str,
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
        device: &str,
    ) -> Result<ActivityPair, sqlx::Error> {
        let associations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released AND a.state<>'revoked'")
            .bind(tenant.to_string()).bind(device).fetch_one(&mut *c).await?;
        if associations == 0 {
            return Ok(ActivityPair::Unpaired);
        }
        if associations != 1 {
            return Err(storage("ambiguous association"));
        }
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_versions v JOIN mdm_devices.object_heads h USING(tenant_id,object,revision) WHERE v.tenant_id=$1::uuid AND v.devices @> ARRAY[$2::text] AND v.object LIKE 'association:%' AND v.input IS NOT NULL LIMIT 2")
            .bind(tenant.to_string()).bind(device).fetch_all(&mut *c).await?;
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
            let rows:Vec<(i64,String,Vec<String>,Vec<String>)>=sqlx::query_as("SELECT revision,object,old_devices,new_devices FROM mdm_devices.object_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT $4")
                .bind(tenant.to_string()).bind(after).bind(through).bind(limit as i64).fetch_all(c).await?;
            Ok(rows
                .into_iter()
                .map(
                    |(position, object, old_devices, new_devices)| ObjectChange {
                        position,
                        object,
                        old_devices,
                        new_devices,
                    },
                )
                .collect())
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
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move {
            let rows:Vec<String>=sqlx::query_scalar("SELECT DISTINCT x.object FROM mdm_devices.object_changes x JOIN mdm_devices.object_cuts a ON a.tenant_id=x.tenant_id AND a.id=$2 JOIN mdm_devices.object_cuts b ON b.tenant_id=x.tenant_id AND b.id=$3 WHERE x.tenant_id=$1::uuid AND x.revision>a.through AND x.revision<=b.through ORDER BY x.object LIMIT 1001")
                .bind(tenant.to_string()).bind(from).bind(to).fetch_all(c).await?;
            if rows.len() > 1000 {
                return Err(storage("object delta window exceeded"));
            }
            Ok(rows)
        })
    }
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move {
            let mut devices:Vec<String>=sqlx::query_scalar("SELECT peer.device FROM mdm_devices.members anchor JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(anchor.tenant_id,anchor.association_id) JOIN mdm_devices.members peer ON(peer.tenant_id,peer.association_id)=(a.tenant_id,a.id) WHERE anchor.tenant_id=$1::uuid AND anchor.device=$2 AND NOT anchor.released AND NOT peer.released AND a.state<>'revoked' ORDER BY peer.device LIMIT 3").bind(tenant.to_string()).bind(device).fetch_all(c).await?;
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
        device: &'a str,
    ) -> rss_mdm_inventory_service::objects::Pending<
        'a,
        rss_mdm_inventory_service::objects::MembershipObjects,
    > {
        Box::pin(snapshots::memberships(c, tenant, device))
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
    ) -> Pending<'a, DeviceObject> {
        Box::pin(snapshots::lookup(c, tenant, snapshot, object))
    }
    fn endpoint<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, DeviceObject> {
        Box::pin(snapshots::endpoint(c, tenant, device))
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
        after: Option<String>,
        limit: usize,
        selected: Option<Vec<String>>,
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(snapshots::page(c, tenant, snapshot, after, limit, selected))
    }
}
