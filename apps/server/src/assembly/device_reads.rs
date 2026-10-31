//! Device detail joins owner capabilities inside one authorization snapshot.
use rss_mdm_authorization_service::{Permission as Required, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, enrollment::directory::*};
use std::sync::Arc;
pub(crate) struct Devices {
    pub tasks: Arc<super::task_reads::Reads>,
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub windows: bool,
    pub apple: bool,
}
impl DeviceReads for Devices {
    fn detail<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        device: &'a str,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, DeviceDetail> {
        Box::pin(async move {
            self.tasks
                .snapshot(proof, (self, proof, device), |ctx, c, grant, _| {
                    Box::pin(async move {
                        let (s, p, device) = *ctx;
                        grant.require(p, Required::InventoryRead, Some(device))?;
                        let mut item = s.devices.directory_device_on(c, device).await?;
                        let present = s
                            .assets
                            .directory_presence_on(c, &[device.to_owned()])
                            .await
                            .map_err(|_| {
                                Error::Unavailable(rss_mdm_management_http::Failure::Database)
                            })?;
                        item.inventory_available = Some(present.contains(device));
                        let mut capabilities: Vec<_> = s
                            .tasks
                            .execution
                            .directory_capabilities_on(c, p, grant, device, s.windows, s.apple)
                            .await
                            .map_err(super::task_reads::history::execution_fault)?
                            .into_iter()
                            .map(execution_capability)
                            .collect();
                        capabilities.extend(
                            s.tasks
                                .software
                                .directory_capabilities_on(c, p, grant, device, s.windows, s.apple)
                                .await
                                .map_err(super::task_reads::software_fault)?
                                .into_iter()
                                .map(software_capability),
                        );
                        Ok(DeviceDetail { item, capabilities })
                    })
                })
                .await
        })
    }
}
fn execution_capability(v: rss_mdm_execution_service::queries::records::Capability) -> Capability {
    use rss_mdm_execution_service::queries::records as o;
    fn reason(v: o::CapabilityReason) -> CapabilityReason {
        match v {
            o::CapabilityReason::ProductNotConfigured => CapabilityReason::ProductNotConfigured,
            o::CapabilityReason::NotRegistered => CapabilityReason::NotRegistered,
            o::CapabilityReason::CapabilityUnknown => CapabilityReason::CapabilityUnknown,
            o::CapabilityReason::CapabilityNotSupported => CapabilityReason::CapabilityNotSupported,
            o::CapabilityReason::PermissionDenied => CapabilityReason::PermissionDenied,
        }
    }
    fn support(v: o::Support) -> Support {
        Support {
            state: match v.state {
                o::SupportState::Supported => SupportState::Supported,
                o::SupportState::Unsupported => SupportState::Unsupported,
                o::SupportState::Blocked => SupportState::Blocked,
                o::SupportState::Unknown => SupportState::Unknown,
                o::SupportState::Ready => SupportState::Ready,
            },
            reason: v.reason.map(reason),
        }
    }
    Capability {
        action: v.action,
        channel: v.channel,
        product_support: support(v.product_support),
        device_prerequisite: support(v.device_prerequisite),
        permission: Permission {
            allowed: v.permission.allowed,
            reason: v.permission.reason.map(reason),
        },
    }
}
fn software_capability(
    v: rss_mdm_software_service::deployment::queries::records::Capability,
) -> Capability {
    use rss_mdm_software_service::deployment::queries::records as o;
    fn reason(v: o::CapabilityReason) -> CapabilityReason {
        match v {
            o::CapabilityReason::ProductNotConfigured => CapabilityReason::ProductNotConfigured,
            o::CapabilityReason::NotRegistered => CapabilityReason::NotRegistered,
            o::CapabilityReason::CapabilityUnknown => CapabilityReason::CapabilityUnknown,
            o::CapabilityReason::CapabilityNotSupported => CapabilityReason::CapabilityNotSupported,
            o::CapabilityReason::PermissionDenied => CapabilityReason::PermissionDenied,
        }
    }
    fn support(v: o::Support) -> Support {
        Support {
            state: match v.state {
                o::SupportState::Supported => SupportState::Supported,
                o::SupportState::Unsupported => SupportState::Unsupported,
                o::SupportState::Blocked => SupportState::Blocked,
                o::SupportState::Unknown => SupportState::Unknown,
                o::SupportState::Ready => SupportState::Ready,
            },
            reason: v.reason.map(reason),
        }
    }
    Capability {
        action: v.action,
        channel: v.channel,
        product_support: support(v.product_support),
        device_prerequisite: support(v.device_prerequisite),
        permission: Permission {
            allowed: v.permission.allowed,
            reason: v.permission.reason.map(reason),
        },
    }
}
