//! Device owner freezes relation identities and validates actual endpoint authority.
//! ref: kube-rs kube-runtime/src/reflector/store.rs@1be7f0d96c3b211680b173c1fc83aa6ad4adba34
use rss_mdm_inventory_service::objects::ObjectRef;
use rss_mdm_inventory_service::objects::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub struct PlanningObjects {
    audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
}
impl PlanningObjects {
    pub fn new(audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { audit }
    }

    /// Current verified paired object for a device-bound authentication ceremony. The input
    /// projection is read from a complete snapshot and revalidated by this owner.
    pub async fn paired_in(
        c: &mut PgConnection,
        tenant: TenantId,
        device: &str,
    ) -> Result<DeviceObject, sqlx::Error> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar("WITH current AS (SELECT s.id FROM mdm_devices.input_snapshots s JOIN mdm_devices.checkpoints k USING(tenant_id) WHERE s.tenant_id=$1::uuid AND s.watermark>=k.identity_watermark AND s.relation_revision=k.relation_revision AND s.phase='sealed' ORDER BY s.watermark DESC LIMIT 1) SELECT o.input FROM mdm_devices.input_objects o JOIN current s ON s.id=o.snapshot WHERE o.tenant_id=$1::uuid AND o.devices @> ARRAY[$2::text] AND o.object LIKE 'association:%' LIMIT 2")
            .bind(tenant.to_string()).bind(device).fetch_all(&mut *c).await?;
        if rows.len() != 1 {
            return Err(storage("paired device unavailable"));
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
            return Err(storage("paired device unavailable"));
        }
        Ok(input)
    }
}
mod snapshots;
fn storage<E>(_: E) -> sqlx::Error {
    sqlx::Error::Protocol("device input unavailable".into())
}
impl ObjectReader for PlanningObjects {
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

    fn relation_revision<'a>(&'a self, tenant: TenantId) -> Pending<'a, u64> {
        Box::pin(async move {
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(
                std::time::Duration::from_secs(5),
            );
            self.audit.read(tenant, &budget.control(), tenant, |tenant, tx| Box::pin(async move {
                let tenant = tenant.to_string();
                let revision: i64 = tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query_scalar("SELECT coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)")
                        .bind(tenant).fetch_one(c).await
                })).await?;
                u64::try_from(revision).map_err(|_| crate::Error::Storage)
            })).await.fold(Ok, |e| Err(storage(crate::model::transaction_error(e))), |e| Err(storage(crate::model::transaction_error(e))), |_| Err(storage("read rollback")), |_| Err(storage("read unknown")), |e| Err(storage(crate::model::transaction_error(e))))
        })
    }

    fn freeze<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
    ) -> Pending<'a, ObjectSnapshot> {
        Box::pin(snapshots::begin(c, tenant))
    }
    fn advance<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, SnapshotProgress> {
        Box::pin(snapshots::advance(c, tenant, snapshot))
    }
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, bool> {
        Box::pin(snapshots::current(c, tenant, snapshot))
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
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(snapshots::page(c, tenant, snapshot, after, limit))
    }
}
