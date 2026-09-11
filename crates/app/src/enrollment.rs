//! Enrollment is the single lifecycle owner; the grant retains immutable authorization origin.
pub(crate) mod read;
pub(crate) mod store;
use crate::{Error, sessions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Create {
    pub device_id: String,
    pub password: Password,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Resume {
    pub password: Password,
}
/// Deliberately has no Debug or Serialize implementation.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct Password(Zeroizing<String>);
impl Password {
    pub(crate) fn new(value: String) -> Result<Self, Error> {
        if !sessions::valid(&value) {
            return Err(Error::Malformed);
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub(crate) fn digest(&self, tenant: &str, device: &str) -> Result<String, Error> {
        if !sessions::valid(&self.0) {
            return Err(Error::Malformed);
        }
        Ok(digest(&(
            "mdm.enrollment.password.v1",
            tenant,
            device,
            self.0.as_str(),
        )))
    }
}
pub(crate) fn digest(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("closed operation"))
    )
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Receipt {
    pub operation_id: Uuid,
    pub enrollment_id: Uuid,
    pub status: String,
    pub expires_at: i64,
    #[serde(rename = "registrationId")]
    pub registration: Option<Uuid>,
}
/// All fields originate in PG, never in device claims.
pub(crate) struct Authorization {
    pub id: Uuid,
    pub device: String,
    pub actor: String,
    pub client: String,
    pub session_ref: Uuid,
    pub version: i64,
    pub expected_generation: i64,
    pub operation: Uuid,
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_is_canonical_256_bits_and_domain_separated() {
        let password = Password::new(sessions::random()).unwrap();
        assert_ne!(
            password.digest("tenant-a", "device").unwrap(),
            password.digest("tenant-b", "device").unwrap()
        );
        assert_ne!(
            password.digest("tenant-a", "device").unwrap(),
            password.digest("tenant-a", "other").unwrap()
        );
        for bad in [
            String::new(),
            "a".repeat(42),
            "a".repeat(44),
            "a".repeat(43),
        ] {
            assert!(Password::new(bad).is_err());
        }
        assert!(
            serde_json::from_str::<Create>(
                r#"{"deviceId":"d","password":"bad","expectedGeneration":0}"#
            )
            .is_err()
        );
    }
}
