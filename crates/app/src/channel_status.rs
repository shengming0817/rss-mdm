//! Local preparation facts, projected through the existing runtime diagnostics owner.
//! Domain authorities continue to own materials, revocation and request admission.
use rss_mdm_management_http::runtime_diagnostics::{
    ChannelName, ChannelState, ChannelStatus, Reason,
};
use std::sync::RwLock;

pub(crate) struct Channels(RwLock<Vec<ChannelStatus>>);
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
        Self(RwLock::new(
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
        ))
    }
    pub(crate) fn set(
        &self,
        name: ChannelName,
        state: ChannelState,
        reason: Option<Reason>,
    ) -> Result<(), crate::Error> {
        let mut values = self
            .0
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
            .0
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
            .0
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
        match self.0.read() {
            Ok(values) => values.clone(),
            Err(_) => vec![], // reason: a poisoned local observation cannot assert any capability ready.
        }
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
