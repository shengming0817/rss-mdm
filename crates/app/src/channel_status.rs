//! Local preparation facts, projected through the existing runtime diagnostics owner.
//! Domain authorities continue to own materials, revocation and request admission.
use rss_mdm_management_http::runtime_diagnostics::{
    ChannelName, ChannelState, ChannelStatus, Reason,
};
use std::sync::{Arc, OnceLock, RwLock};

pub(crate) struct Channels {
    values: RwLock<Vec<ChannelStatus>>,
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
                .map(|(name, enabled)| ChannelStatus {
                    name,
                    state: if enabled {
                        ChannelState::Waiting
                    } else {
                        ChannelState::Disabled
                    },
                    reasons: if enabled {
                        vec![Reason::MaterialNotSelected]
                    } else {
                        vec![]
                    },
                    listening: false,
                    loaded_materials: Default::default(),
                })
                .collect(),
            ),
            installation: OnceLock::new(),
        }
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
        value.reasons = reason.into_iter().collect();
        Ok(())
    }
    pub(crate) fn listening(&self, name: ChannelName) -> Result<(), crate::Error> {
        let mut values = self
            .values
            .write()
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
        let value = values
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or(crate::Error::Malformed)?;
        value.listening = true;
        Ok(())
    }
    pub(crate) fn loaded(
        &self,
        name: ChannelName,
        materials: impl IntoIterator<Item = (String, i64)>,
    ) -> Result<(), crate::Error> {
        let mut values = self
            .values
            .write()
            .map_err(|_| crate::Error::Unavailable(crate::Failure::CommandInvariant))?;
        let value = values
            .iter_mut()
            .find(|v| v.name == name)
            .ok_or(crate::Error::Malformed)?;
        value.loaded_materials = materials.into_iter().collect();
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> Vec<ChannelStatus> {
        match self.values.read() {
            Ok(values) => {
                let mut values = values.clone();
                project_dependents(&mut values);
                values
            }
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
        let Some((agent, pki)) = self.installation.get() else {
            return None;
        };
        let states = self.snapshot();
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
                    && (name != ChannelName::Agent || s.listening)
            })
        }) && agent.bootstrap.is_some()
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
        if !ready {
            return None;
        }
        states
            .iter()
            .find(|s| s.name == ChannelName::Signing)
            .and_then(|s| s.loaded_materials.get("signing"))
            .and_then(|revision| u64::try_from(*revision).ok())
    }
}

/// A prepared material is not an available capability when its transport owner is closed.
pub(crate) fn project_dependents(values: &mut [ChannelStatus]) {
    for (child, parent) in [
        (ChannelName::WindowsPush, ChannelName::Windows),
        (ChannelName::AgentBootstrap, ChannelName::Agent),
    ] {
        let failed = values
            .iter()
            .find(|v| v.name == parent)
            .filter(|v| v.state != ChannelState::Ready || !v.listening)
            .map(|v| v.reasons.clone());
        if let Some(reasons) = failed {
            if let Some(value) = values
                .iter_mut()
                .find(|v| v.name == child && v.state == ChannelState::Ready)
            {
                value.state = ChannelState::Degraded;
                value.reasons = if reasons.is_empty() {
                    vec![Reason::ListenerUnavailable]
                } else {
                    reasons
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_materials_without_final_assembly_cannot_admit_installation() {
        use rss_mdm_execution_service::AgentInstallationAdmission;
        let channels = Channels {
            values: RwLock::new(
                [
                    ChannelName::Agent,
                    ChannelName::AgentBootstrap,
                    ChannelName::Signing,
                ]
                .into_iter()
                .map(|name| ChannelStatus {
                    name,
                    state: ChannelState::Ready,
                    reasons: vec![],
                    listening: true,
                    loaded_materials: [("signing".into(), 1)].into(),
                })
                .collect(),
            ),
            installation: OnceLock::new(),
        };
        assert_eq!(channels.ready_signing_revision(1_800_000_000), None);
    }
    #[test]
    fn closed_parent_prevents_ready_bootstrap_and_preserves_loaded_material_identity() {
        let mut values = vec![
            ChannelStatus {
                name: ChannelName::Agent,
                state: ChannelState::Degraded,
                reasons: vec![Reason::ListenerUnavailable],
                listening: false,
                loaded_materials: Default::default(),
            },
            ChannelStatus {
                name: ChannelName::AgentBootstrap,
                state: ChannelState::Ready,
                reasons: vec![],
                listening: false,
                loaded_materials: [("bootstrap".into(), 4)].into(),
            },
        ];
        project_dependents(&mut values);
        assert_eq!(values[1].state, ChannelState::Degraded);
        assert!(matches!(
            values[1].reasons.as_slice(),
            [Reason::ListenerUnavailable]
        ));
        assert_eq!(values[1].loaded_materials["bootstrap"], 4);
    }
}
