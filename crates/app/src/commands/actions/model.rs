use super::schedule::Schedule;
use crate::Error;
use rss_mdm_agent_wire as wire;
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Platform {
    Windows,
    Macos,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Create {
    pub operation_id: Uuid,
    pub resource: String,
    pub version: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub variant: String,
    pub parameters: Value,
    pub devices: Vec<String>,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
impl Create {
    pub fn validate(&self, now: i64) -> Result<(), Error> {
        if self.operation_id.is_nil()
            || self.devices.is_empty()
            || self.devices.len() > 256
            || self.devices.iter().collect::<BTreeSet<_>>().len() != self.devices.len()
            || self.schedule.until <= now
            || !(60..=604800).contains(&self.run_lifetime_seconds)
        {
            return Err(Error::Malformed);
        }
        for id in [&self.resource, &self.version, &self.variant] {
            r::Id::new(id).map_err(|_| Error::Malformed)?;
        }
        for device in &self.devices {
            rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
        }
        self.schedule.validate()
    }
    pub fn variant<'a>(&self, version: &'a r::Version) -> Result<&'a r::Variant, Error> {
        version
            .resolve(
                match self.platform {
                    Platform::Windows => r::Platform::Windows,
                    Platform::Macos => r::Platform::MacOS,
                },
                match self.architecture {
                    Architecture::X86_64 => r::Architecture::X86_64,
                    Architecture::Aarch64 => r::Architecture::Aarch64,
                },
                &r::Id::new(&self.variant).map_err(|_| Error::Malformed)?,
            )
            .map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Target {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Frozen {
    pub input: Create,
    pub definition: r::ScriptDefinition,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
impl Frozen {
    pub fn artifact(&self) -> Result<r::Artifact, Error> {
        r::Artifact::new(
            r::Id::new(&self.artifact_reference).map_err(|_| Error::Malformed)?,
            self.content.length,
            r::Digest::from_bytes(self.content.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
    pub fn task(
        &self,
        tenant: Uuid,
        target: &Target,
        run: Uuid,
        attempt: Uuid,
        permit: wire::TaskPermit,
        expiry: i64,
    ) -> Result<wire::TaskPayload, Error> {
        let spec = self.definition.spec();
        let mut positional = BTreeMap::new();
        let mut arguments = Vec::new();
        let mut environment = BTreeMap::new();
        for (name, binding) in &spec.bindings {
            let value = self.input.parameters.get(name).ok_or(Error::Malformed)?;
            let literal = match value {
                Value::String(v) => v.clone(),
                Value::Bool(_) | Value::Number(_) => value.to_string(),
                _ => return Err(Error::Malformed),
            };
            match binding {
                r::ParameterBinding::Positional { index } => {
                    positional.insert(*index, literal);
                }
                r::ParameterBinding::Named { name } => {
                    arguments.push(format!("-{name}"));
                    arguments.push(literal);
                }
                r::ParameterBinding::Environment { name } => {
                    environment.insert(name.clone(), literal);
                }
            }
        }
        arguments.extend(positional.into_values());
        wire::TaskSpec {
            wire_version: wire::WIRE_VERSION,
            tenant_id: tenant,
            device_id: target.device.clone(),
            platform: match self.input.platform {
                Platform::Windows => wire::TaskPlatform::Windows,
                Platform::Macos => wire::TaskPlatform::Macos,
            },
            architecture: match self.input.architecture {
                Architecture::X86_64 => wire::TaskArchitecture::X86_64,
                Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
            },
            registration_id: target.registration,
            generation: target.generation.try_into().map_err(|_| Error::Malformed)?,
            task_id: run,
            attempt_id: attempt,
            permit,
            expires_at: expiry,
            resource_digest: self.resource_digest,
            content: self.content.clone(),
            profile: match spec.profile {
                r::ScriptProfile::PowerShell7 => wire::ExecutorProfile::PowerShell7,
                r::ScriptProfile::PosixSh => wire::ExecutorProfile::PosixSh,
                r::ScriptProfile::Bash => wire::ExecutorProfile::Bash,
                r::ScriptProfile::OsqueryInfoV1 => wire::ExecutorProfile::OsqueryInfoV1,
            },
            run_as: match spec.run_as {
                r::RunAs::System => wire::ExecutionIdentity::System,
                r::RunAs::LoggedInUser => wire::ExecutionIdentity::LoggedInUser,
            },
            arguments,
            environment,
            timeout_seconds: spec.timeout_seconds,
            output_bytes: spec.output_bytes,
            max_rows: spec.max_rows,
        }
        .try_into()
        .map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Change {
    pub operation_id: Uuid,
}
