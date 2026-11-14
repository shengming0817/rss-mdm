//! Local preparation facts, projected through the existing runtime diagnostics owner.
//! Domain authorities continue to own materials, revocation and request admission.
use std::sync::{Arc, OnceLock, RwLock};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelName {
    Apple,
    Windows,
    Agent,
    WindowsPush,
    AgentBootstrap,
    Signing,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelState {
    Disabled,
    Waiting,
    Ready,
    Degraded,
}
#[derive(Clone, Copy)]
pub(crate) enum Reason {
    NotSelected,
    Unreadable,
    Invalid,
}
#[derive(Clone)]
pub(crate) struct Assembly {
    pub name: ChannelName,
    pub state: ChannelState,
    pub reason: Option<Reason>,
    pub mounted: bool,
}

pub(crate) struct Channels {
    endpoints: rss_mdm_management_http::enrollment::channels::PublicEndpoints,
    values: RwLock<Vec<Assembly>>,
    agent: OnceLock<Arc<crate::agent_pki::AgentPki>>,
    protection: Arc<rss_mdm_native_protection::Protector>,
}
impl Channels {
    pub(crate) fn new(
        config: &crate::config::Config,
        protection: Arc<rss_mdm_native_protection::Protector>,
    ) -> Self {
        let windows = config.native_protocols.windows.as_ref();
        let apple = config.native_protocols.apple.is_some();
        let agent = matches!(config.agent_pki, crate::agent_pki::Config::StepCa { .. });
        let bootstrap = matches!(
            &config.agent_pki,
            crate::agent_pki::Config::StepCa {
                bootstrap: Some(_),
                ..
            }
        );
        Self {
            endpoints: rss_mdm_management_http::enrollment::channels::PublicEndpoints {
                console: config.product_origin.clone(),
                agent: match &config.agent_pki {
                    crate::agent_pki::Config::StepCa {
                        endpoint,
                        additional_origins,
                        ..
                    } => std::iter::once(endpoint.origin.clone())
                        .chain(additional_origins.iter().cloned())
                        .collect(),
                    crate::agent_pki::Config::Disabled {} => vec![],
                },
                windows_enrollment: windows.map(|w| w.enrollment.origin.clone()),
                windows_management: windows
                    .map(|w| {
                        std::iter::once(w.management.origin.clone())
                            .chain(w.additional_management.iter().map(|e| e.origin.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
                apple_management: config
                    .native_protocols
                    .apple
                    .as_ref()
                    .map(|a| a.management.origin.clone()),
            },
            values: RwLock::new(
                [
                    (ChannelName::Apple, apple),
                    (ChannelName::Windows, windows.is_some()),
                    (ChannelName::Agent, agent),
                    (ChannelName::WindowsPush, windows.is_some()),
                    (ChannelName::AgentBootstrap, bootstrap),
                    (ChannelName::Signing, true),
                ]
                .into_iter()
                .map(|(name, enabled)| Assembly {
                    name,
                    state: if enabled {
                        ChannelState::Waiting
                    } else {
                        ChannelState::Disabled
                    },
                    reason: enabled.then_some(Reason::NotSelected),
                    mounted: false,
                })
                .collect(),
            ),
            agent: OnceLock::new(),
            protection,
        }
    }
    pub(crate) fn endpoints(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> rss_mdm_management_http::enrollment::channels::PublicEndpoints {
        let mut endpoints = self.endpoints.clone();
        endpoints.console = format!("{}/tenants/{tenant}", endpoints.console);
        endpoints
    }
    pub(crate) fn set(
        &self,
        name: ChannelName,
        state: ChannelState,
        reason: Option<Reason>,
    ) -> Result<(), crate::Error> {
        let mut values = self
            .values
            .write()
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
        let value = values
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or(crate::Error::Malformed)?;
        if value.state == ChannelState::Disabled {
            return Ok(());
        }
        value.state = state;
        value.reason = reason;
        Ok(())
    }
    pub(crate) fn mounted(&self, name: ChannelName) -> Result<(), crate::Error> {
        let mut values = self
            .values
            .write()
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
        let value = values
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or(crate::Error::Malformed)?;
        value.mounted = true;
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> Vec<Assembly> {
        match self.values.read() {
            Ok(values) => values.clone(),
            Err(_) => vec![], // reason: a poisoned local observation cannot assert any capability ready.
        }
    }
    pub(crate) fn installation(
        &self,
        agent: Arc<crate::agent_pki::AgentPki>,
    ) -> Result<(), crate::Error> {
        self.agent.set(agent).map_err(|_| crate::Error::Conflict)
    }
    /// Only errors classified at a material boundary may enter this path.
    pub(crate) fn material<T>(
        &self,
        name: ChannelName,
        result: Result<T, crate::Error>,
    ) -> Result<Option<T>, crate::Error> {
        match result {
            Ok(value) => {
                self.set(name, ChannelState::Ready, None)?;
                Ok(Some(value))
            }
            Err(crate::Error::Configuration(issue)) => {
                use crate::ConfigIssue as C;
                let reason = match issue {
                    C::FileAccess => Reason::Unreadable,
                    C::AgentPki
                    | C::SecretContents
                    | C::SecretEncoding
                    | C::EnrollmentCa
                    | C::NativeTls
                    | C::ProtocolKey
                    | C::AppleScep
                    | C::AppleApns
                    | C::AppleProfileSigner
                    | C::AppleChallengeWebhook
                    | C::AppleNotifyWebhook
                    | C::FileShape
                    | C::FileSize => Reason::Invalid,
                    _ => return Err(crate::Error::Configuration(issue)),
                };
                self.set(name, ChannelState::Degraded, Some(reason))?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

impl rss_mdm_software_service::installation::inputs::Admission for Channels {
    fn ready_signing_revision<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        now: i64,
    ) -> futures::future::BoxFuture<'a, rss_mdm_software_service::catalog::Result<Option<u64>>>
    {
        Box::pin(async move {
            use rss_mdm_software_service::catalog::Error;
            let Some(agent) = self.agent.get() else {
                return Ok(None);
            };
            if agent.bootstrap.is_none()
                || !self
                    .snapshot()
                    .iter()
                    .any(|s| s.name == ChannelName::Agent && s.mounted)
            {
                return Ok(None);
            }
            if !agent
                .issuance_ready_on(c, binding, now)
                .await
                .map_err(|_| Error::Dependency)?
            {
                return Ok(None);
            }
            let bootstrap = rss_mdm_pki_service::registry::trust_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                binding.tenant(),
                rss_mdm_agent_wire::pki::Purpose::AgentBootstrap,
            )
            .await
            .map_err(|_| Error::Dependency)?;
            rss_mdm_device_trust::DeviceTrust::new(
                bootstrap,
                rss_mdm_agent_wire::pki::Purpose::AgentBootstrap,
                now,
            )
            .map_err(|_| Error::Dependency)?;
            let trust = match rss_mdm_task_trust::trust::current(
                rss_mdm_install_support::StorageProfile::Mdm,
                rss_mdm_task_trust::Use::AgentTask,
                c,
                binding.tenant(),
            )
            .await
            {
                Ok(trust) => trust,
                Err(rss_mdm_task_trust::Error::NotFound) => return Ok(None),
                Err(_) => return Err(Error::Dependency),
            };
            rss_mdm_task_trust::trust::load(
                rss_mdm_install_support::StorageProfile::Mdm,
                rss_mdm_task_trust::Use::AgentTask,
                c,
                binding.tenant(),
                trust.revision,
                &self.protection,
            )
            .await
            .map_err(|_| Error::Dependency)?;
            Ok(Some(trust.revision))
        })
    }
}
