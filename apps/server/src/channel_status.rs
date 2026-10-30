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
    MaterialNotSelected,
    MaterialUnreadable,
    MaterialInvalid,
    TrustConflict,
    MaterialRevoked,
    MaterialVersionMismatch,
    CertificateExpired,
    DependencyUnavailable,
}
#[derive(Clone, Default)]
pub(crate) struct LoadedMaterials {
    pub trust: Option<i64>,
    pub apns: Option<i64>,
    pub profile: Option<i64>,
    pub wns: Option<i64>,
    pub signing: Option<i64>,
}
#[derive(Clone)]
pub(crate) struct Assembly {
    pub name: ChannelName,
    pub state: ChannelState,
    pub reason: Option<Reason>,
    pub mounted: bool,
    pub materials: LoadedMaterials,
}

pub(crate) struct Channels {
    endpoints: rss_mdm_management_http::enrollment::channels::PublicEndpoints,
    values: RwLock<Vec<Assembly>>,
    installation: OnceLock<(
        Arc<crate::agent_pki::AgentPki>,
        Arc<rss_mdm_pki_service::registry::Registry>,
    )>,
}
impl Channels {
    pub(crate) fn new(config: &crate::config::Config) -> Self {
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
                    (
                        ChannelName::WindowsPush,
                        windows.is_some_and(|w| w.push.is_some()),
                    ),
                    (ChannelName::AgentBootstrap, bootstrap),
                    (ChannelName::Signing, config.task_signing.is_some()),
                ]
                .into_iter()
                .map(|(name, enabled)| Assembly {
                    name,
                    state: if enabled {
                        ChannelState::Waiting
                    } else {
                        ChannelState::Disabled
                    },
                    reason: enabled.then_some(Reason::MaterialNotSelected),
                    mounted: false,
                    materials: Default::default(),
                })
                .collect(),
            ),
            installation: OnceLock::new(),
        }
    }
    pub(crate) fn endpoints(
        &self,
    ) -> rss_mdm_management_http::enrollment::channels::PublicEndpoints {
        self.endpoints.clone()
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
    pub(crate) fn loaded(
        &self,
        name: ChannelName,
        materials: LoadedMaterials,
    ) -> Result<(), crate::Error> {
        let mut values = self
            .values
            .write()
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
        let value = values
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or(crate::Error::Malformed)?;
        value.materials.trust = materials.trust.or(value.materials.trust);
        value.materials.apns = materials.apns.or(value.materials.apns);
        value.materials.profile = materials.profile.or(value.materials.profile);
        value.materials.wns = materials.wns.or(value.materials.wns);
        value.materials.signing = materials.signing.or(value.materials.signing);
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
        pki: Arc<rss_mdm_pki_service::registry::Registry>,
    ) -> Result<(), crate::Error> {
        self.installation
            .set((agent, pki))
            .map_err(|_| crate::Error::Conflict)
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
                    C::FileAccess => Reason::MaterialUnreadable,
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
                    | C::FileSize => Reason::MaterialInvalid,
                    _ => return Err(crate::Error::Configuration(issue)),
                };
                self.set(name, ChannelState::Degraded, Some(reason))?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

impl rss_mdm_execution_service::AgentInstallationAdmission for Channels {
    fn ready_signing_revision(&self, now: i64) -> Option<u64> {
        use rss_mdm_agent_wire::pki::Purpose;
        let (agent, pki) = self.installation.get()?;
        let revision = {
            let states = self.values.read().ok()?;
            let ready = [
                ChannelName::Agent,
                ChannelName::AgentBootstrap,
                ChannelName::Signing,
            ]
            .into_iter()
            .all(|name| {
                states.iter().any(|s| {
                    s.name == name
                        && s.state == ChannelState::Ready
                        && (name != ChannelName::Agent || s.mounted)
                })
            });
            if !ready {
                return None;
            }
            states
                .iter()
                .find(|s| s.name == ChannelName::Signing)
                .and_then(|s| s.materials.signing)
                .and_then(|revision| u64::try_from(revision).ok())?
        };
        // Release the local facts lock before consulting the actual authorities.
        let ready = agent.bootstrap.is_some()
            && agent.issuance_ready(now)
            && [Purpose::Agent, Purpose::AgentBootstrap]
                .into_iter()
                .all(|purpose| {
                    pki.trust(purpose)
                        .ok()
                        .and_then(|trust| {
                            rss_mdm_device_trust::DeviceTrust::new(trust, purpose, now).ok()
                        })
                        .is_some()
                });
        ready.then_some(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_materials_without_final_assembly_cannot_admit_installation() {
        use rss_mdm_execution_service::AgentInstallationAdmission;
        let channels = Channels {
            endpoints: rss_mdm_management_http::enrollment::channels::PublicEndpoints {
                console: "https://mdm.example.test".into(),
                agent: vec![],
                windows_enrollment: None,
                windows_management: vec![],
                apple_management: None,
            },
            values: RwLock::new(
                [
                    ChannelName::Agent,
                    ChannelName::AgentBootstrap,
                    ChannelName::Signing,
                ]
                .into_iter()
                .map(|name| Assembly {
                    name,
                    state: ChannelState::Ready,
                    reason: None,
                    mounted: true,
                    materials: LoadedMaterials {
                        signing: Some(1),
                        ..Default::default()
                    },
                })
                .collect(),
            ),
            installation: OnceLock::new(),
        };
        assert_eq!(channels.ready_signing_revision(1_800_000_000), None);
    }
}
