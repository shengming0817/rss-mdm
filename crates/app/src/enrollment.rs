//! Product enrollment admission, not device identity or a bearer-token protocol.
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Command {
    Issue { device_id: String },
    Consume { device_id: String, grant_id: Uuid },
    Revoke { device_id: String, grant_id: Uuid },
}
impl Command {
    pub fn device(&self) -> &str {
        match self {
            Self::Issue { device_id }
            | Self::Consume { device_id, .. }
            | Self::Revoke { device_id, .. } => device_id,
        }
    }
    pub fn action(&self) -> &'static str {
        match self {
            Self::Issue { .. } => "grant_issue",
            Self::Consume { .. } => "registration_accept",
            Self::Revoke { .. } => "grant_revoke",
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        rss_observation::Id::new(self.device()).map_err(|_| Error::Malformed)?;
        if matches!(self, Self::Consume { grant_id, .. } | Self::Revoke { grant_id, .. } if grant_id.is_nil())
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("closed command"))
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct Receipt {
    pub operation_id: Uuid,
    pub grant_id: Uuid,
    pub request_id: Option<Uuid>,
    pub status: String,
    pub expires_at: i64,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_identity_covers_kind_target_and_grant() {
        let id = Uuid::new_v4();
        let consume = Command::Consume {
            device_id: "device".into(),
            grant_id: id,
        };
        assert_ne!(
            consume.digest(),
            Command::Revoke {
                device_id: "device".into(),
                grant_id: id
            }
            .digest()
        );
        assert_ne!(
            consume.digest(),
            Command::Consume {
                device_id: "other".into(),
                grant_id: id
            }
            .digest()
        );
        assert!(
            Command::Issue {
                device_id: "".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            Command::Consume {
                device_id: "device".into(),
                grant_id: Uuid::nil()
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_str::<Command>(
                r#"{"operation":"issue","device_id":"device","tenant":"other"}"#
            )
            .is_err()
        );
    }
}
