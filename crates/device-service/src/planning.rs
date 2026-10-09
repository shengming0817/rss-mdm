//! Device owner freezes relation identities under the original asset/Audit fence.
//! ref: kube-rs kube-runtime/src/reflector/store.rs@1be7f0d96c3b211680b173c1fc83aa6ad4adba34
use crate::{identity, model::State};
use rss_mdm_inventory_service::objects::ObjectRef;
use rss_mdm_inventory_service::objects::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;
pub struct PlanningObjects {
    audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
}
impl PlanningObjects {
    pub fn new(audit: std::sync::Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { audit }
    }
}
fn storage(_: crate::Error) -> sqlx::Error {
    sqlx::Error::Protocol("device input unavailable".into())
}
async fn objects(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<(i64, Vec<DeviceObject>), sqlx::Error> {
    let world = identity::world(c, tenant).await.map_err(storage)?;
    let mut endpoints: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for e in &world.endpoints {
        endpoints
            .entry(e.member.device.clone())
            .or_default()
            .push(e.member.clone());
    }
    let mut after = String::new();
    loop {
        let ids = rss_mdm_registration_service::device::endpoints::page_in(
            c,
            &tenant.to_string(),
            &after,
            250,
        )
        .await
        .map_err(|_| sqlx::Error::Protocol("device input unavailable".into()))?;
        if ids.is_empty() {
            break;
        }
        after = ids
            .last()
            .ok_or_else(|| sqlx::Error::Protocol("device input invariant".into()))?
            .clone();
        for id in ids {
            endpoints.entry(id).or_default();
        }
    }
    let mut result = Vec::new();
    for a in &world.associations {
        if a.state == State::Revoked {
            continue;
        }
        let effective = world.effective(a.clone());
        // A continuity decision has to be persisted by the owner before new generations can execute.
        let verified = effective.state == State::Confirmed
            && a.members
                .iter()
                .all(|m| world.current(m).is_some_and(|e| e.member == *m));
        for m in &a.members {
            endpoints.remove(&m.device);
        }
        result.push(DeviceObject {
            object: ObjectRef::Association(a.id),
            association_version: Some(a.version),
            verified,
            members: a.members.clone(),
        });
    }
    for (id, members) in endpoints {
        result.push(DeviceObject {
            object: ObjectRef::Endpoint(id),
            association_version: None,
            verified: true,
            members,
        });
    }
    result.sort_by_key(|o| o.object.key());
    if result.len() > 1_000_000 {
        return Err(sqlx::Error::Protocol("device input capacity".into()));
    }
    Ok((world.watermark, result))
}
fn version(objects: &[DeviceObject]) -> Result<String, sqlx::Error> {
    use sha2::Digest;
    let bytes = serde_json::to_vec(objects)
        .map_err(|_| sqlx::Error::Protocol("device input encoding".into()))?;
    Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
}
impl ObjectReader for PlanningObjects {
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
                    |v| Ok(v.into_value()),
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
        Box::pin(async move {
            let (watermark, objects) = objects(c, tenant).await?;
            let version = version(&objects)?;
            let existing:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_devices.input_snapshots WHERE tenant_id=$1::uuid AND watermark=$2 AND version=$3").bind(tenant.to_string()).bind(watermark).bind(&version).fetch_optional(&mut *c).await?;
            if let Some(id) = existing {
                return Ok(ObjectSnapshot {
                    id,
                    watermark,
                    version,
                });
            }
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO mdm_devices.input_snapshots(tenant_id,id,watermark,version) VALUES($1::uuid,$2,$3,$4)").bind(tenant.to_string()).bind(id).bind(watermark).bind(&version).execute(&mut *c).await?;
            let mut after = String::new();
            loop {
                let ids = rss_mdm_registration_service::device::endpoints::page_in(
                    c,
                    &tenant.to_string(),
                    &after,
                    250,
                )
                .await
                .map_err(|_| sqlx::Error::Protocol("endpoint snapshot unavailable".into()))?;
                if ids.is_empty() {
                    break;
                }
                after = ids.last().unwrap().clone();
                for endpoint in ids {
                    let mut members = Vec::new();
                    for channel in [
                        rss_mdm_inventory::Channel::Mdm,
                        rss_mdm_inventory::Channel::Agent,
                    ] {
                        if let Some(member) =
                            rss_mdm_registration_service::device::endpoints::current_in(
                                c,
                                &tenant.to_string(),
                                &endpoint,
                                channel,
                            )
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("endpoint snapshot unavailable".into())
                            })?
                        {
                            members.push(member);
                        }
                    }
                    let input = DeviceObject {
                        object: ObjectRef::Endpoint(endpoint.clone()),
                        association_version: None,
                        verified: true,
                        members,
                    };
                    sqlx::query("INSERT INTO mdm_devices.input_objects(tenant_id,snapshot,object,input) VALUES($1::uuid,$2,$3,$4)").bind(tenant.to_string()).bind(id).bind(format!("source-endpoint:{endpoint}")).bind(serde_json::to_value(input).map_err(|_|sqlx::Error::Protocol("endpoint snapshot encoding".into()))?).execute(&mut *c).await?;
                }
            }
            for page in objects.chunks(250) {
                let keys: Vec<_> = page.iter().map(|o| o.object.key()).collect();
                let docs: Vec<_> = page
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| sqlx::Error::Protocol("device input encoding".into()))?;
                sqlx::query("INSERT INTO mdm_devices.input_objects(tenant_id,snapshot,object,input) SELECT $1::uuid,$2,k,d FROM unnest($3::text[],$4::jsonb[]) p(k,d) ON CONFLICT DO NOTHING")
                .bind(tenant.to_string()).bind(id).bind(keys).bind(docs).execute(&mut *c).await?;
            }
            Ok(ObjectSnapshot {
                id,
                watermark,
                version,
            })
        })
    }
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let (watermark, objects) = objects(c, tenant).await?;
            Ok(watermark == snapshot.watermark && version(&objects)? == snapshot.version)
        })
    }
    fn page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        after: Option<String>,
        limit: usize,
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(async move {
            if !(1..=1000).contains(&limit) {
                return Err(sqlx::Error::Protocol("device input page budget".into()));
            }
            let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT input FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 AND (object LIKE 'endpoint:%' OR object LIKE 'association:%') AND object>coalesce($3,'') COLLATE \"C\" ORDER BY object COLLATE \"C\" LIMIT $4")
            .bind(tenant.to_string()).bind(snapshot).bind(after).bind(limit as i64).fetch_all(c).await?;
            rows.into_iter()
                .map(|v| {
                    serde_json::from_value(v)
                        .map_err(|_| sqlx::Error::Protocol("device input decoding".into()))
                })
                .collect()
        })
    }
}
