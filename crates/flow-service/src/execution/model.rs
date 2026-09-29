use crate::Error;
use rss_device_command::StateDigest;
use rss_mdm_inventory::FieldKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Model,
    OsVersion,
}
impl Field {
    pub fn key(self) -> FieldKey {
        match self {
            Self::Model => FieldKey::Model,
            Self::OsVersion => FieldKey::OsVersion,
        }
    }
    pub fn digest(self, value: &str) -> Result<StateDigest, Error> {
        if !self.key().validate(value) {
            return Err(Error::Malformed);
        }
        // Field and encoding identity are part of the semantic state. Values are exact UTF-8.
        let bytes = serde_json::to_vec(&("mdm.state-verify/v1", self.key().as_str(), value))
            .map_err(|_| Error::Malformed)?;
        Ok(StateDigest::from_bytes(Sha256::digest(bytes).into()))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Task {
    AgentInstall {
        package: Box<crate::planning::policies::agent_install::Package>,
    },
    ProfileInstall {
        enabled: bool,
    },
    ProfileRemove {
        profile: Uuid,
    },
    StateVerify {
        field: Field,
        expected_value: String,
    },
    Firewall {
        enabled: bool,
        os_version: String,
        edition: u32,
    },
}
impl Task {
    pub fn source(&self) -> rss_mdm_inventory::ReportSource {
        match self {
            Self::AgentInstall { package } => match package.identity.platform() {
                rss_mdm_policy::Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
                rss_mdm_policy::Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
            },
            Self::ProfileInstall { .. } | Self::ProfileRemove { .. } => {
                rss_mdm_inventory::ReportSource::MdmApple
            }
            _ => rss_mdm_inventory::ReportSource::MdmWindows,
        }
    }

    pub fn permission(&self) -> crate::authorization::Permission {
        match self {
            Self::AgentInstall { .. } => crate::authorization::Permission::SoftwareDeploy,
            Self::StateVerify { .. } => crate::authorization::Permission::StateVerify,
            Self::ProfileInstall { .. } | Self::ProfileRemove { .. } | Self::Firewall { .. } => {
                crate::authorization::Permission::FirewallWrite
            }
        }
    }
    pub fn digest(&self) -> Result<StateDigest, Error> {
        match self {
            Self::AgentInstall { package } => {
                package.identity.validate()?;
                Ok(StateDigest::from_bytes(
                    Sha256::digest(
                        serde_json::to_vec(&("mdm.agent-install/v1", package))
                            .map_err(|_| Error::Malformed)?,
                    )
                    .into(),
                ))
            }
            Self::ProfileInstall { .. } | Self::ProfileRemove { .. } => Err(Error::Malformed),
            Self::StateVerify {
                field,
                expected_value,
            } => field.digest(expected_value),
            Self::Firewall {
                enabled,
                os_version,
                edition,
                ..
            } => {
                use rss_mdm_windows_mdm::configuration::{Firewall, Platform};
                let compiled = Firewall::compile(
                    *enabled,
                    &Platform::new(os_version, *edition).map_err(|_| Error::Malformed)?,
                )
                .map_err(|_| Error::Malformed)?;
                Ok(StateDigest::from_bytes(
                    Sha256::digest(compiled.identity()).into(),
                ))
            }
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub operation_id: Uuid,
    pub task: Task,
    pub deadline: i64,
}
impl Create {
    pub fn profile_target(&self) -> Option<(Uuid, bool)> {
        match self.task {
            Task::ProfileInstall { .. } => Some((self.operation_id, true)),
            Task::ProfileRemove { profile } => Some((profile, false)),
            _ => None,
        }
    }
    pub fn digest(&self, tenant: &str, device: &str) -> Result<StateDigest, Error> {
        match self.profile_target() {
            Some((profile, present)) => {
                Ok(crate::execution::apple_profile_digest::presence_digest(
                    &rss_mdm_apple_mdm::profile::identifier(tenant, device),
                    profile,
                    present,
                ))
            }
            None => self.task.digest(),
        }
    }

    pub fn validate(&self, now: i64) -> Result<(), Error> {
        if self.operation_id.is_nil()
            || self.deadline <= now
            || self.deadline.checked_mul(1_000_000).is_none()
        {
            return Err(Error::Malformed);
        }
        match self.profile_target() {
            Some((profile, _)) if profile.is_nil() => return Err(Error::Malformed),
            Some(_) => {}
            None => {
                self.task.digest()?;
            }
        }
        Ok(())
    }
}
/// Canonical dispatch payload; the fixed schema and golden consumer guard this wire.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchV2 {
    pub device: String,
    pub request: Create,
    pub generation: i64,
    pub epoch: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub request_id: Uuid,
    pub expected_revision: i64,
}

#[cfg(test)]
#[path = "../../tests/execution/model_unit.rs"]
mod tests;

/// Native exchange phases; database values are decoded fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptPhase {
    Prepare,
    Execute,
    Observe,
}
impl AttemptPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Execute => "execute",
            Self::Observe => "observe",
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "prepare" => Ok(Self::Prepare),
            "execute" => Ok(Self::Execute),
            "observe" => Ok(Self::Observe),
            _ => Err(Error::Unavailable(crate::Failure::CommandInvariant)),
        }
    }
}
#[cfg(test)]
#[path = "../../tests/execution/model_phase_unit.rs"]
mod phase_tests;
