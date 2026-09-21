use crate::Error;
use rss_device_command::StateDigest;
use rss_mdm_inventory::FieldKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Field {
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
    pub(super) fn index(self) -> usize {
        match self {
            Self::Model => 0,
            Self::OsVersion => 1,
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
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Create {
    pub operation_id: Uuid,
    pub field: Field,
    pub expected_value: String,
    /// Absolute Unix seconds. Conversion to RSS microseconds is checked.
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
        self.field.digest(&self.expected_value)?;
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
            field: Field::Model,
            expected_value: "Model".into(),
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
}
