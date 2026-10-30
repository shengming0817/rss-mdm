use super::*;
pub(super) fn permission(kind: EventType) -> Permission {
    match kind {
        EventType::Registered | EventType::Retired | EventType::Test => Permission::InventoryRead,
        EventType::PolicyTerminal => Permission::OperationRead,
        EventType::ComplianceChanged => Permission::ComplianceRead,
        EventType::DeviceAccessChanged => Permission::AccountWrite,
    }
}
pub(super) fn settings(proof: &AuthorizedPrincipal, settings: &Settings) -> Result<(), HttpError> {
    for permission in settings
        .event_types
        .iter()
        .map(|kind| permission(*kind))
        .collect::<std::collections::BTreeSet<_>>()
    {
        match &settings.selection {
            Selection::Devices { ids } => {
                for device in ids {
                    proof.require(permission, Some(device))?;
                }
            }
            _ => proof.require_all_devices(permission)?,
        }
    }
    if matches!(settings.selection, Selection::Groups { .. }) {
        proof.require(Permission::GroupRead, None)?;
    }
    Ok(())
}
pub(super) fn read(proof: &AuthorizedPrincipal, event: &Event) -> Result<(), HttpError> {
    if proof.tenant_id() != event.tenant_id.to_string() {
        return Err(HttpError::Forbidden);
    }
    proof.require(permission(event.event_type), Some(&event.device_id))?;
    Ok(())
}
pub(super) struct Host {
    pub tenant: Uuid,
    pub policies: config::Policies,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub clock: Arc<dyn crate::clock::Clock>,
}
impl webhooks::fanout::Eligibility for Host {
    fn eligible<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        s: &'a Subscription,
        event: &'a Event,
    ) -> futures::future::BoxFuture<'a, Result<bool, webhooks::Error>> {
        Box::pin(async move {
            if event.tenant_id != self.tenant {
                return Ok(false);
            }
            match &s.settings.selection {
                Selection::AllDevices => Ok(true),
                Selection::Devices { ids } => Ok(ids.contains(&event.device_id)),
                Selection::Groups { ids } => {
                    // Current published endpoint membership is owned by Group; unknown/stale groups deny.
                    Ok(sqlx::query_scalar::<_,bool>(r#"SELECT EXISTS(SELECT 1 FROM mdm_group.groups g JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set) WHERE g.tenant_id=$1 AND g.id=ANY($2) AND NOT g.deleted AND g.asset_context='endpoint' AND b.phase='published' AND g.rule_version IS NOT DISTINCT FROM b.rule_version AND (SELECT m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=g.tenant_id AND m.group_id=g.id AND m.object_id=$3 AND m.revision<=g.calculation_revision AND r.phase='published' ORDER BY m.revision DESC LIMIT 1)=true)"#).bind(self.tenant).bind(ids).bind(&event.device_id).fetch_one(c).await?)
                }
            }
        })
    }
    fn compliance_page<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        source: &'a events::CompliancePublication,
        after: Option<String>,
    ) -> futures::future::BoxFuture<'a, Result<webhooks::fanout::ChangePage, webhooks::Error>> {
        Box::pin(async move {
            if source.tenant != self.tenant {
                return Err(webhooks::Error::Denied);
            }
            let tenant =
                TenantId::parse(&self.tenant.to_string()).map_err(|_| webhooks::Error::Invalid)?;
            let mut rows =
                rss_mdm_compliance_postgres::webhook_changes::<rss_mdm_inventory::AssetCut>(
                    c,
                    tenant,
                    source.run,
                    source.previous,
                    after,
                    webhooks::PAGE + 1,
                )
                .await?;
            let more = rows.len() > webhooks::PAGE as usize;
            rows.truncate(webhooks::PAGE as usize);
            let next = if more {
                rows.last().map(|(device, _)| device.clone())
            } else {
                None
            };
            let events = rows
                .into_iter()
                .map(|(device, a)| {
                    Ok(Event {
                        event_id: events::identity(source.run, &format!("compliance:{device}")),
                        event_type: EventType::ComplianceChanged,
                        version: 1,
                        occurred_at: source.occurred_at,
                        tenant_id: source.tenant,
                        device_id: device,
                        data: EventData::Compliance {
                            rule_id: a.rule_id,
                            rule_version: a.rule_version,
                            run_id: source.run,
                            status: serde_json::from_value(serde_json::to_value(a.status)?)
                                .map_err(|_| webhooks::Error::Invalid)?,
                            reason: serde_json::from_value(serde_json::to_value(a.reason)?)
                                .map_err(|_| webhooks::Error::Invalid)?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, webhooks::Error>>()?;
            Ok((events, next))
        })
    }
}
