use crate::Error;
use rss_device_command::StateDigest;
use rss_mdm_inventory::FieldKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Field {
    Model,
    OsVersion,
}
impl Field {
    pub(super) fn key(self) -> FieldKey {
        match self {
            Self::Model => FieldKey::Model,
            Self::OsVersion => FieldKey::OsVersion,
        }
    }
    pub(super) fn digest(self, value: &str) -> Result<StateDigest, Error> {
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
pub(crate) enum Task {
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
        plan: Uuid,
        policy: String,
        version: u64,
        os_version: String,
        edition: u32,
    },
}
impl Task {
    pub(crate) fn source(&self) -> rss_mdm_inventory::ReportSource {
        match self {
            Self::ProfileInstall { .. } | Self::ProfileRemove { .. } => {
                rss_mdm_inventory::ReportSource::MdmApple
            }
            _ => rss_mdm_inventory::ReportSource::MdmWindows,
        }
    }

    pub(crate) fn permission(&self) -> crate::authorization::Permission {
        match self {
            Self::StateVerify { .. } => crate::authorization::Permission::StateVerify,
            Self::ProfileInstall { .. } | Self::ProfileRemove { .. } | Self::Firewall { .. } => {
                crate::authorization::Permission::FirewallWrite
            }
        }
    }
    pub(super) fn digest(&self) -> Result<StateDigest, Error> {
        match self {
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
pub(super) struct Create {
    pub operation_id: Uuid,
    pub task: Task,
    pub deadline: i64,
}
impl Create {
    pub(super) fn profile_target(&self) -> Option<(Uuid, bool)> {
        match self.task {
            Task::ProfileInstall { .. } => Some((self.operation_id, true)),
            Task::ProfileRemove { profile } => Some((profile, false)),
            _ => None,
        }
    }
    pub(super) fn digest(&self, tenant: &str, device: &str) -> Result<StateDigest, Error> {
        match self.profile_target() {
            Some((profile, present)) => Ok(crate::apple::profile::presence_digest(
                &crate::apple::profile::identifier(tenant, device),
                profile,
                present,
            )),
            None => self.task.digest(),
        }
    }

    pub(super) fn validate(&self, now: i64) -> Result<(), Error> {
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
pub(super) struct DispatchV2 {
    pub device: String,
    pub request: Create,
    pub generation: i64,
    pub epoch: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Change {
    pub request_id: Uuid,
    pub expected_revision: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_identity_is_field_bound_and_never_normalizes_observation() {
        assert_ne!(
            Field::Model.digest("v1").unwrap(),
            Field::OsVersion.digest("v1").unwrap()
        );
        assert_ne!(
            Field::Model.digest("v1").unwrap(),
            Field::Model.digest(" v1").unwrap()
        );
        for value in ["", "  ", "bad\nvalue"] {
            assert!(Field::Model.digest(value).is_err());
        }
    }
    #[test]
    fn command_contract_rejects_expiry_overflow_unknown_fields_and_nil_keys() {
        let mut request = Create {
            operation_id: Uuid::new_v4(),
            task: Task::StateVerify {
                field: Field::Model,
                expected_value: "Model".into(),
            },
            deadline: 100,
        };
        assert!(request.validate(99).is_ok());
        assert!(request.validate(100).is_err());
        request.deadline = i64::MAX;
        assert!(request.validate(1).is_err());
        request.deadline = 100;
        request.operation_id = Uuid::nil();
        assert!(request.validate(1).is_err());
        let mut value = serde_json::to_value(request).unwrap();
        value["tenant"] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<Create>(value).is_err());
    }
    #[test]
    fn old_requests_and_direct_write_fields_do_not_have_fallbacks() {
        let old = serde_json::json!({"operationId":Uuid::new_v4(),"field":"model","expectedValue":"x","deadline":100});
        assert!(serde_json::from_value::<Create>(old).is_err());
        let task = serde_json::json!({"kind":"firewall","enabled":true,"plan":Uuid::new_v4(),"policy":"x","version":1,"osVersion":"10.0.19045.0","edition":48,"uri":"arbitrary"});
        assert!(serde_json::from_value::<Task>(task).is_err());
        let verify = Task::StateVerify {
            field: Field::Model,
            expected_value: "x".into(),
        };
        assert_eq!(
            verify.permission(),
            crate::authorization::Permission::StateVerify
        );
    }
    #[test]
    fn profile_presence_digest_binds_target_version_device_and_desired_state() {
        let mut request = Create {
            operation_id: Uuid::new_v4(),
            task: Task::ProfileInstall { enabled: true },
            deadline: 100,
        };
        let present = request.digest("tenant", "mac").unwrap();
        assert_ne!(present, request.digest("other", "mac").unwrap());
        assert_ne!(present, request.digest("tenant", "other").unwrap());
        request.task = Task::ProfileRemove {
            profile: request.operation_id,
        };
        assert_ne!(present, request.digest("tenant", "mac").unwrap());
        assert_eq!(
            request.task.source(),
            rss_mdm_inventory::ReportSource::MdmApple
        );
        request.task = Task::ProfileRemove {
            profile: Uuid::nil(),
        };
        assert!(request.validate(1).is_err());
    }
    #[test]
    fn dispatch_wire_matches_schema_and_independent_consumer() {
        let validator = jsonschema::validator_for(
            &serde_json::from_str(include_str!("dispatch-v2.json")).unwrap(),
        )
        .unwrap();
        let id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        for task in [
            Task::StateVerify {
                field: Field::Model,
                expected_value: "Surface".into(),
            },
            Task::Firewall {
                enabled: false,
                plan: id,
                policy: "domain".into(),
                version: 1,
                os_version: "10.0.19045.0".into(),
                edition: 48,
            },
        ] {
            let expected_task = match &task {
                Task::StateVerify { .. } => {
                    serde_json::json!({"kind":"state_verify","field":"model","expectedValue":"Surface"})
                }
                _ => {
                    serde_json::json!({"kind":"firewall","enabled":false,"plan":id,"policy":"domain","version":1,"osVersion":"10.0.19045.0","edition":48})
                }
            };
            let dto = DispatchV2 {
                device: "device-1".into(),
                request: Create {
                    operation_id: id,
                    task,
                    deadline: 100,
                },
                generation: 2,
                epoch: 3,
            };
            let wire = serde_json::to_value(&dto).unwrap();
            assert_eq!(
                wire,
                serde_json::json!({"device":"device-1","request":{"operationId":id,"task":expected_task,"deadline":100},"generation":2,"epoch":3})
            );
            assert!(validator.is_valid(&wire));
            assert!(serde_json::from_value::<DispatchV2>(wire.clone()).is_ok());
            let mut invalid = wire.clone();
            invalid["request"]["task"]["unknown"] = true.into();
            assert!(!validator.is_valid(&invalid));
            let mut invalid = wire;
            invalid.as_object_mut().unwrap().remove("epoch");
            assert!(!validator.is_valid(&invalid));
        }
    }
}

/// Native exchange phases; database values are decoded fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttemptPhase {
    Execute,
    Observe,
}
impl AttemptPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Observe => "observe",
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "execute" => Ok(Self::Execute),
            "observe" => Ok(Self::Observe),
            _ => Err(Error::Unavailable(crate::Failure::CommandInvariant)),
        }
    }
}
#[cfg(test)]
mod phase_tests {
    use super::*;
    #[test]
    fn phase_storage_roundtrip_rejects_unknown() {
        for phase in [AttemptPhase::Execute, AttemptPhase::Observe] {
            assert_eq!(AttemptPhase::parse(phase.as_str()).unwrap(), phase);
        }
        assert!(AttemptPhase::parse("retry").is_err());
    }
}
