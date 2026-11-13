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
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> rss_mdm_management_http::execution::task_reads::Pending<'a, DeviceDetail> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            self.tasks
                .snapshot_registered(
                    request,
                    (self, proof, device),
                    |ctx, c, grant, _, registration| {
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
                            let mdm = rss_mdm_registration_service::device::endpoints::current_in(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                p.tenant_id(),
                                device,
                                rss_mdm_inventory::Channel::Mdm,
                            )
                            .await?;
                            *registration = Some((device.to_owned(), mdm.clone()));
                            let mut capabilities = s
                                .directory_capabilities_on(c, p, grant, device, mdm.is_some())
                                .await?;
                            capabilities.extend(
                                s.control_capabilities_on(c, p, grant, device, mdm.as_ref())
                                    .await?,
                            );
                            capabilities.extend(
                                s.tasks
                                    .software
                                    .directory_capabilities_on(
                                        c, p, grant, device, s.windows, s.apple,
                                    )
                                    .await
                                    .map_err(super::task_reads::software_fault)?
                                    .into_iter()
                                    .map(software_capability),
                            );
                            Ok(DeviceDetail { item, capabilities })
                        })
                    },
                )
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
impl Devices {
    pub async fn directory_capabilities_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        current: &rss_mdm_authorization_service::Snapshot,
        device: &rss_mdm_agent_wire::DeviceId,
        mdm: bool,
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
        let binding = if let Some(registration) = &agent {
            super::agent_facts::AgentFacts
                .binding(c, tenant, registration.device)
                .await?
        } else {
            None
        };
        let supported = agent_support(self.tasks.signing_enabled, self.tasks.content_available);
        let result = vec![
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
            )?,
            capability(
                current,
                proof,
                device,
                (
                    "configuration",
                    Required::ConfigurationWrite,
                    "mdm",
                    self.windows || self.apple,
                ),
                if mdm {
                    support(
                        SupportState::Unknown,
                        Some(CapabilityReason::CapabilityUnknown),
                    )
                } else {
                    support(SupportState::Blocked, Some(CapabilityReason::NotRegistered))
                },
            )?,
        ];
        Ok(result)
    }
}

fn support(state: SupportState, reason: Option<CapabilityReason>) -> Support {
    Support { state, reason }
}
fn agent_prerequisite(registered: bool, reported: Option<bool>) -> Support {
    match (registered, reported) {
        (false, _) => support(SupportState::Blocked, Some(CapabilityReason::NotRegistered)),
        (true, None) => support(
            SupportState::Unknown,
            Some(CapabilityReason::CapabilityUnknown),
        ),
        (true, Some(false)) => support(
            SupportState::Unsupported,
            Some(CapabilityReason::CapabilityNotSupported),
        ),
        (true, Some(true)) => support(SupportState::Ready, None),
    }
}
fn capability(
    current: &rss_mdm_authorization_service::Snapshot,
    proof: &AuthorizedPrincipal,
    device: &rss_mdm_agent_wire::DeviceId,
    spec: (&str, Required, &str, bool),
    prerequisite: Support,
) -> Result<Capability, Error> {
    let (action, permission, channel, supported) = spec;
    let allowed = match current.require(proof, permission, Some(device)) {
        Ok(()) => true,
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => false,
        Err(e) => return Err(rss_mdm_authorization_service::Error::from(e).into()),
    };
    Ok(Capability {
        action: action.into(),
        channel: channel.into(),
        product_support: support(
            if supported {
                SupportState::Supported
            } else {
                SupportState::Unsupported
            },
            (!supported).then_some(CapabilityReason::ProductNotConfigured),
        ),
        device_prerequisite: prerequisite,
        permission: Permission {
            allowed,
            reason: (!allowed).then_some(CapabilityReason::PermissionDenied),
        },
    })
}
fn agent_support(signed: bool, content: bool) -> bool {
    signed && content
}

impl Devices {
    async fn control_capabilities_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &rss_mdm_authorization_service::Snapshot,
        device: &rss_mdm_agent_wire::DeviceId,
        registration: Option<&rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    ) -> Result<Vec<Capability>, Error> {
        use rss_mdm_device_service::control::device_control::{self, Applicability, Check, Kind};
        use rss_mdm_inventory::ReportSource;
        let kinds = [Kind::Restart, Kind::Lock, Kind::Wipe];
        let (source, states) = if let Some(registration) = registration {
            let source = device_control::source_on(c, self.tasks.tenant, &registration.device)
                .await
                .map_err(super::task_reads::history::execution_fault)?;
            if let Some(source) = source {
                let checks = kinds.map(|action| Check {
                    device: registration.device,

                    source,
                    action,
                });
                let states = self
                    .tasks
                    .execution
                    .control_applicability_on(c, &checks)
                    .await
                    .map_err(super::task_reads::history::execution_fault)?;
                (Some(source), states)
            } else {
                (None, Vec::new())
            }
        } else {
            // No current registration is a lifecycle block; no platform facts are queried.
            (None, Vec::new())
        };
        kinds
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                let product = match (source, kind) {
                    (_, Kind::Lock) => self.apple && self.tasks.recovery_enabled,
                    (Some(ReportSource::MdmApple), _) => self.apple,
                    (Some(ReportSource::MdmWindows), _) => self.windows,
                    (None, _) => self.apple || self.windows,
                    (Some(ReportSource::AgentBuiltin), _) => false,
                };
                let prerequisite = if registration.is_none() {
                    support(SupportState::Blocked, Some(CapabilityReason::NotRegistered))
                } else if source.is_none() {
                    support(
                        SupportState::Blocked,
                        Some(CapabilityReason::CapabilityUnknown),
                    )
                } else {
                    match states.get(index).ok_or(Error::Unavailable(
                        rss_mdm_management_http::Failure::CommandInvariant,
                    ))? {
                        Applicability::Supported => support(SupportState::Supported, None),
                        Applicability::Unsupported => support(
                            SupportState::Unsupported,
                            Some(CapabilityReason::CapabilityNotSupported),
                        ),
                        Applicability::Unknown => support(
                            SupportState::Unknown,
                            Some(CapabilityReason::CapabilityUnknown),
                        ),
                    }
                };
                let action = match kind {
                    Kind::Restart => "restart",
                    Kind::Lock => "lock",
                    Kind::Wipe => "wipe",
                };
                capability(
                    grant,
                    proof,
                    device,
                    (action, kind.permission(), "mdm", product),
                    prerequisite,
                )
            })
            .collect()
    }
}
