use super::model::Target;
use crate::Error;
use crate::planning::action_contract::*;
use rss_mdm_agent_wire as wire;
use rss_mdm_resource as r;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
impl FrozenAction {
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
                r::ScriptProfile::Osquery => wire::ExecutorProfile::Osquery,
            },
            sql: spec
                .sql
                .as_ref()
                .map(|sql| sql.render(&self.input.parameters, u32::from(spec.max_rows)))
                .transpose()
                .map_err(|_| Error::Malformed)?,
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
