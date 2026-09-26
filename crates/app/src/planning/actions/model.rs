use crate::Error;
use crate::planning::action_schedule::Schedule;
use rss_mdm_agent_wire as wire;
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::planning::action_contract::{Architecture, Platform};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopeRef {
    pub id: Uuid,
    pub resolution_revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Targets {
    Devices { devices: Vec<String> },
    Scope { reference: ScopeRef },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Create {
    pub operation_id: Uuid,
    pub resource: String,
    pub version: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub variant: String,
    pub parameters: Value,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub targets: Targets,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateInput {
    pub operation_id: Uuid,
    pub resource: String,
    pub version: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub variant: String,
    pub parameters: Value,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub devices: Option<Vec<String>>,
    pub scope_ref: Option<ScopeRef>,
}
impl TryFrom<CreateInput> for Create {
    type Error = Error;
    fn try_from(input: CreateInput) -> Result<Self, Error> {
        let targets = match (input.devices, input.scope_ref) {
            (Some(devices), None) => Targets::Devices { devices },
            (None, Some(reference))
                if !reference.id.is_nil()
                    && reference.resolution_revision > 0
                    && reference.resolution_revision <= i64::MAX as u64 =>
            {
                Targets::Scope { reference }
            }
            _ => return Err(Error::Malformed),
        };
        Ok(Self {
            operation_id: input.operation_id,
            resource: input.resource,
            version: input.version,
            platform: input.platform,
            architecture: input.architecture,
            variant: input.variant,
            parameters: input.parameters,
            schedule: input.schedule,
            run_lifetime_seconds: input.run_lifetime_seconds,
            targets,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrozenTargets {
    pub devices: Vec<String>,
    pub scope: Option<ScopeSnapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopeSnapshot {
    pub id: Uuid,
    pub resolution: Uuid,
    pub resolution_revision: u64,
    pub definition_revision: u64,
    pub sources: Value,
    pub fingerprint: String,
}
impl Create {
    pub fn validate(&self) -> Result<(), Error> {
        if self.operation_id.is_nil() || !(60..=604800).contains(&self.run_lifetime_seconds) {
            return Err(Error::Malformed);
        }
        for id in [&self.resource, &self.version, &self.variant] {
            r::Id::new(id).map_err(|_| Error::Malformed)?;
        }
        if let Targets::Devices { devices } = &self.targets {
            validate_devices(devices)?;
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
pub(crate) struct Frozen {
    pub targets: FrozenTargets,
    pub input: Create,
    pub definition: r::ScriptDefinition,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Change {
    pub operation_id: Uuid,
}

pub(crate) fn validate_devices(devices: &[String]) -> Result<(), Error> {
    use crate::planning::error::ActionRejection;
    if devices.is_empty() {
        return Err(ActionRejection::TargetsEmpty.into());
    }
    if devices.len() > 256 {
        return Err(ActionRejection::TargetsLimit.into());
    }
    if devices.iter().collect::<BTreeSet<_>>().len() != devices.len() {
        return Err(Error::Malformed);
    }
    for device in devices {
        rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
    }
    Ok(())
}

#[cfg(test)]
mod target_tests {
    use super::*;
    fn request() -> Value {
        serde_json::json!({
            "operationId":Uuid::new_v4(),"resource":"script","version":"v1",
            "platform":"windows","architecture":"x86_64","variant":"default",
            "parameters":{},"devices":["device-a"],
            "schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":2000000000,"misfire":"skip","jitterSeconds":0},
            "runLifetimeSeconds":300
        })
    }
    #[test]
    fn action_target_input_has_exactly_one_selector() {
        let explicit = request();
        let decode = |v: Value| {
            serde_json::from_value::<CreateInput>(v)
                .map_err(|_| Error::Malformed)
                .and_then(Create::try_from)
        };
        assert!(decode(explicit.clone()).is_ok());
        let mut scope = explicit.clone();
        scope.as_object_mut().unwrap().remove("devices");
        scope["scopeRef"] = serde_json::json!({"id":Uuid::new_v4(),"resolutionRevision":1});
        assert!(matches!(
            decode(scope.clone()).unwrap().targets,
            Targets::Scope { .. }
        ));
        scope["devices"] = serde_json::json!(["device-a"]);
        assert!(decode(scope).is_err());
        let mut neither = explicit;
        neither.as_object_mut().unwrap().remove("devices");
        assert!(decode(neither).is_err());
    }
    #[test]
    fn frozen_target_budget_is_not_silent_truncation() {
        assert!(validate_devices(&[]).is_err());
        assert!(validate_devices(&vec!["duplicate".into(); 2]).is_err());
        let mut devices: Vec<_> = (0..256).map(|i| format!("device-{i}")).collect();
        assert!(validate_devices(&devices).is_ok());
        devices.push("overflow".into());
        assert!(validate_devices(&devices).is_err());
    }
}
