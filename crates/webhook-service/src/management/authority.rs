use super::*;
pub(super) fn permission(kind: EventType) -> Permission {
    match kind {
        EventType::Registered | EventType::Retired | EventType::Test => Permission::InventoryRead,
        EventType::PolicyTerminal => Permission::OperationRead,
        EventType::ComplianceChanged => Permission::ComplianceRead,
        EventType::DeviceAccessChanged => Permission::AccountWrite,
    }
}
pub(super) fn settings(proof: &AuthorizedPrincipal, settings: &Settings) -> Result<(), Error> {
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
pub(super) fn read(proof: &AuthorizedPrincipal, event: &Event) -> Result<(), Error> {
    if proof.tenant_id() != event.tenant_id.to_string() {
        return Err(Error::Denied);
    }
    proof.require(permission(event.event_type), Some(&event.device_id))?;
    Ok(())
}
pub(super) struct Host {
    pub tenant: Uuid,
    pub policies: crate::network::Policies,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub clock: Arc<dyn Clock>,
    pub sources: Arc<dyn Sources>,
}
impl webhooks::fanout::Eligibility for Host {
    fn eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        s: &'a Subscription,
        event: &'a Event,
    ) -> futures::future::BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            if event.tenant_id != self.tenant {
                return Ok(false);
            }
            match &s.settings.selection {
                Selection::AllDevices => Ok(true),
                Selection::Devices { ids } => Ok(ids.contains(&event.device_id)),
                Selection::Groups { ids } => {
                    self.sources
                        .group_member(
                            c,
                            TenantId::parse(&self.tenant.to_string())
                                .map_err(|_| Error::Invalid)?,
                            ids,
                            &event.device_id,
                        )
                        .await
                }
            }
        })
    }
    fn compliance_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a events::CompliancePublication,
        after: Option<String>,
    ) -> futures::future::BoxFuture<'a, Result<webhooks::fanout::ChangePage, Error>> {
        self.sources.compliance_page(c, source, after)
    }
}
