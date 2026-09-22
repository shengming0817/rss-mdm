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
    pub(crate) fn permission(&self) -> crate::authorization::Permission {
        match self {
            Self::StateVerify { .. } => crate::authorization::Permission::StateVerify,
            Self::Firewall { .. } => crate::authorization::Permission::FirewallWrite,
        }
    }
    pub(super) fn digest(&self) -> Result<StateDigest, Error> {
        match self {
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
    pub(super) fn validate(&self, now: i64) -> Result<(), Error> {
        if self.operation_id.is_nil()
            || self.deadline <= now
            || self.deadline.checked_mul(1_000_000).is_none()
        {
            return Err(Error::Malformed);
        }
        self.task.digest()?;
        Ok(())
    }
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
}
