//! Device owner freezes relation identities under the original asset/Audit fence.
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
    /// projection is read under the same watermark fence and revalidated by this owner.
    pub async fn paired_in(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        device: &str,
    ) -> Result<DeviceObject, sqlx::Error> {
        rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
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
            || self
                .validate(c, tenant, &input, rss_mdm_inventory::Channel::Agent)
                .await?
                .is_none()
            || self
                .validate(c, tenant, &input, rss_mdm_inventory::Channel::Mdm)
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
            rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
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

    fn changes<'a>(
        &'a self,
        tenant: TenantId,
        after: u64,
        through: Option<u64>,
    ) -> Pending<'a, ChangeWindow> {
        Box::pin(async move {
            use rss_mdm_audit_integration::budget::AuditBudget;
            let budget = AuditBudget::new(std::time::Duration::from_secs(5));
            self.audit
                .read(
                    tenant,
                    &budget.control(),
                    (after, through),
                    |(after, through), tx| {
                        Box::pin(async move {
                            let limit = rss_audit_postgres::ReadLimit::new(64, 8388608)
                                .map_err(|_| crate::Error::Storage)?;
                            let through = if let Some(through) = through {
                                *through
                            } else {
                                let head = tx
                                    .read_page(
                                        rss_audit_postgres::Cursor::start(tenant),
                                        rss_audit_postgres::ReadLimit::new(1, 131072)
                                            .map_err(|_| crate::Error::Storage)?,
                                    )
                                    .await
                                    .map_err(|e| crate::Error::Audit(e.into()))?;
                                head.next()
                                    .and_then(|c| c.continuation())
                                    .map(|(_, through)| through)
                                    .or_else(|| head.records().last().map(|r| r.position()))
                                    .unwrap_or(*after)
                            };
                            if through == *after {
                                return Ok::<_, crate::Error>(ChangeWindow {
                                    after: *after,
                                    through: None,
                                    changed: false,
                                });
                            }
                            let cursor = if *after == 0 {
                                rss_audit_postgres::Cursor::start(tenant)
                            } else {
                                rss_audit_postgres::Cursor::resume(tenant, *after, through)
                                    .map_err(|_| crate::Error::Storage)?
                            };
                            let page = tx
                                .read_page(cursor, limit)
                                .await
                                .map_err(|e| crate::Error::Audit(e.into()))?;
                            let mut changed = false;
                            for record in page.records() {
                                let decoded = rss_audit_core::decode_untrusted(
                                    record.prepared().canonical_bytes(),
                                )
                                .map_err(|_| crate::Error::Storage)?;
                                let event = decoded.event();
                                if event.identity().source().source_id().as_str() == "mdm.business"
                                    && [
                                        "device_association_confirm",
                                        "device_association_revoke",
                                        "device_association_automatic",
                                    ]
                                    .contains(&event.facts().action().as_str())
                                {
                                    changed = true;
                                }
                            }
                            Ok(ChangeWindow {
                                after: page
                                    .records()
                                    .last()
                                    .map(|r| r.position())
                                    .unwrap_or(*after),
                                through: page
                                    .next()
                                    .and_then(|c| c.continuation())
                                    .map(|(_, through)| through),
                                changed,
                            })
                        })
                    },
                )
                .await
                .fold(
                    Ok,
                    |e| Err(storage(crate::model::transaction_error(e))),
                    |e| Err(storage(crate::model::transaction_error(e))),
                    |_| Err(sqlx::Error::Protocol("audit read rollback".into())),
                    |_| Err(sqlx::Error::Protocol("audit read unknown".into())),
                    |e| Err(storage(crate::model::transaction_error(e))),
                )
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
