//! Device detail joins owner capabilities inside one authorization snapshot.
use rss_mdm_authorization_service::{Permission as Required, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, enrollment::directory::*};
use std::sync::Arc;
pub(crate) struct Devices {
    pub tasks: Arc<super::task_reads::Reads>,
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub windows: bool,
    pub apple: bool,
}
impl DeviceReads for Devices {
    fn detail<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a str,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, DeviceDetail> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            self.tasks
                .snapshot(request, (self, proof, device), |ctx, c, grant, _| {
                    Box::pin(async move {
                        let (s, p, device) = *ctx;
                        grant.require(p, Required::InventoryRead, Some(device))?;
                        let mut item = s.devices.directory_device_on(c, device).await?;
                        let present = rss_mdm_inventory_service::assets::directory_presence_on(
                            c,
                            s.tasks.tenant,
                            &[device.to_owned()],
                        )
                        .await
                        .map_err(|_| {
                            Error::Unavailable(rss_mdm_management_http::Failure::Database)
                        })?;
                        item.inventory_available = Some(present.contains(device));
                        let mut capabilities = s
                            .directory_capabilities_on(c, p, grant, device, s.windows, s.apple)
                            .await?;
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

use rss_mdm_device_service::control::agent_facts::Store;
use serde_json::{Value, json};
impl Devices {
    pub async fn directory_capabilities_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        current: &rss_mdm_authorization_service::Snapshot,
        device: &str,
        windows: bool,
        apple: bool,
    ) -> Result<Vec<Capability>, Error> {
        use rss_mdm_registration_service::device::endpoints;
        let tenant = self.tasks.tenant.to_string();
        let agent = endpoints::current_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            device,
            rss_mdm_inventory::Channel::Agent,
        )
        .await?;
        let mdm = endpoints::current_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            device,
            rss_mdm_inventory::Channel::Mdm,
        )
        .await?
        .is_some();
        let binding = if let Some(registration) = &agent {
            super::agent_facts::AgentFacts
                .binding(c, tenant, registration.registration_id)
                .await?
        } else {
            None
        };
        let supported = agent_support(self.tasks.signing_enabled, self.tasks.content_available);
        let result = [
            capability(
                current,
                proof,
                device,
                ("script", Required::ScriptExecute, "agent", supported),
                agent_prerequisite(
                    agent.is_some(),
                    binding
                        .as_ref()
                        .map(rss_mdm_device_service::control::agent_facts::Binding::script),
                ),
            ),
            capability(
                current,
                proof,
                device,
                (
                    "configuration",
                    Required::ConfigurationWrite,
                    "mdm",
                    windows || apple,
                ),
                if mdm {
                    ("unknown", Some("capability_unknown"))
                } else {
                    ("blocked", Some("not_registered"))
                },
            ),
        ];
        serde_json::from_value(json!(result))
            .map_err(|_| Error::Unavailable(rss_mdm_management_http::Failure::CommandInvariant))
    }
}

fn agent_prerequisite(
    registered: bool,
    reported: Option<bool>,
) -> (&'static str, Option<&'static str>) {
    match (registered, reported) {
        (false, _) => ("blocked", Some("not_registered")),
        (true, None) => ("unknown", Some("capability_unknown")),
        (true, Some(false)) => ("unsupported", Some("capability_not_supported")),
        (true, Some(true)) => ("ready", None),
    }
}
fn capability(
    current: &rss_mdm_authorization_service::Snapshot,
    proof: &AuthorizedPrincipal,
    device: &str,
    spec: (&str, Required, &str, bool),
    prerequisite: (&str, Option<&str>),
) -> Value {
    let (action, permission, channel, supported) = spec;
    let allowed = current.require(proof, permission, Some(device)).is_ok();
    json!({"action":action,"channel":channel,
        "productSupport":{"state":if supported{"supported"}else{"unsupported"},"reason":if supported{None}else{Some("product_not_configured")}},
        "devicePrerequisite":{"state":prerequisite.0,"reason":prerequisite.1},
        "permission":{"allowed":allowed,"reason":if allowed{None}else{Some("permission_denied")}}})
}

fn agent_support(signed: bool, content: bool) -> bool {
    signed && content
}
