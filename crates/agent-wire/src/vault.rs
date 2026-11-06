//! User-owned Vault synchronization, current V1. No enterprise recovery authority.
//! Recovery material is 32 random client bytes; HKDF-SHA256 with independent
//! `rss-vault-v1/recovery-signing` and `rss-vault-v1/root-wrapping` info domains
//! derives an Ed25519 seed and AES-256-GCM wrapping key. Neither reaches the server.
//! Clients retain only the unwrapped Vault root and their independent device key.
use crate::runtime::WireError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// Maximum encoded record, including its AEAD nonce and tag.
pub const RECORD_BYTES: usize = 24_000;
/// Maximum atomic mutation batch.
pub const BATCH_ITEMS: usize = 4;
/// Canonical unpadded base64url public material, signatures and ciphertext.
pub fn bytes(value: &str, min: usize, max: usize) -> Result<Vec<u8>, WireError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    if value.len() > max.saturating_mul(2) {
        return Err(WireError::InvalidValue);
    }
    let b = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WireError::InvalidValue)?;
    if b.len() < min || b.len() > max || URL_SAFE_NO_PAD.encode(&b) != value {
        return Err(WireError::InvalidValue);
    }
    Ok(b)
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Device {
    /// Id.
    pub id: Uuid,
    /// Public key.
    pub public_key: String,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Mutation {
    /// Id.
    pub id: Uuid,
    /// Expected revision.
    pub expected_revision: i64,
    /// Ciphertext.
    pub ciphertext: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Current Vault protocol value.
pub enum Action {
    /// Initialize operation or result.
    Initialize {
        /// Vault.
        vault: Uuid,
        /// Recovery key.
        recovery_key: String,
        /// Root envelope.
        root_envelope: String,
        /// Device.
        device: Device,
    },
    /// Join operation or result.
    Join {
        /// Device.
        device: Device,
    },
    /// Remove operation or result.
    Remove {
        /// Device.
        device: Uuid,
    },
    /// Write operation or result.
    Write {
        /// Items.
        items: Vec<Mutation>,
    },
    /// Read operation or result.
    Read {
        /// After.
        after: i64,
        /// Cursor.
        cursor: Option<String>,
    },
    /// Devices operation or result.
    Devices,
    /// Operation operation or result.
    Operation {
        /// Operation.
        operation: Uuid,
    },
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Prepare {
    /// Operation.
    pub operation: Uuid,
    /// Device.
    pub device: Uuid,
    /// Action.
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Challenge {
    /// Installation.
    pub installation: Uuid,
    /// Tenant.
    pub tenant: Uuid,
    /// Instance.
    pub instance: Uuid,
    /// Principal.
    pub principal: Uuid,
    /// Incarnation.
    pub incarnation: Uuid,
    /// Vault.
    pub vault: Uuid,
    /// Nonce.
    pub nonce: Uuid,
    /// Expires at.
    pub expires_at: i64,
    /// Request.
    pub request: Prepare,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Execute {
    /// Challenge.
    pub challenge: Challenge,
    /// Signature.
    pub signature: String,
    /// Recovery signature.
    pub recovery_signature: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Entry {
    /// Id.
    pub id: Uuid,
    /// Revision.
    pub revision: i64,
    /// Ciphertext.
    pub ciphertext: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current Vault protocol value.
pub struct Receipt {
    /// Operation.
    pub operation: Uuid,
    /// Incarnation.
    pub incarnation: Uuid,
    /// Revision.
    pub revision: i64,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Current Vault protocol value.
pub enum Response {
    /// Receipt operation or result.
    Receipt {
        /// Receipt.
        receipt: Receipt,
    },
    /// Changes operation or result.
    Changes {
        /// Revision.
        revision: i64,
        /// Entries.
        entries: Vec<Entry>,
        /// Next cursor.
        next_cursor: Option<String>,
        /// Root envelope.
        root_envelope: String,
    },
    /// Devices operation or result.
    Devices {
        /// Devices.
        devices: Vec<Device>,
    },
}
impl Prepare {
    /// Reject malformed or unbounded requests before reserving a challenge.
    pub fn validate(&self) -> Result<(), WireError> {
        let bad = || WireError::InvalidValue;
        if self.operation.is_nil() || self.device.is_nil() {
            return Err(bad());
        }
        match &self.action {
            Action::Initialize {
                vault,
                recovery_key,
                root_envelope,
                device,
            } => {
                if vault.is_nil() {
                    return Err(bad());
                }
                bytes(recovery_key, 32, 32)?;
                bytes(root_envelope, 28, 4096)?;
                if device.id != self.device {
                    return Err(bad());
                }
                bytes(&device.public_key, 32, 32)?;
            }
            Action::Join { device } => {
                if device.id != self.device {
                    return Err(bad());
                }
                bytes(&device.public_key, 32, 32)?;
            }
            Action::Remove { device } | Action::Operation { operation: device } => {
                if device.is_nil() {
                    return Err(bad());
                }
            }
            Action::Write { items } => {
                if items.is_empty() || items.len() > BATCH_ITEMS {
                    return Err(bad());
                }
                let mut ids = std::collections::BTreeSet::new();
                for i in items {
                    if i.id.is_nil() || i.expected_revision < 0 || !ids.insert(i.id) {
                        return Err(bad());
                    }
                    if let Some(c) = &i.ciphertext {
                        bytes(c, 28, RECORD_BYTES)?;
                    } else if i.expected_revision == 0 {
                        return Err(bad());
                    }
                }
            }
            Action::Read { after, cursor } => {
                if *after < 0 || cursor.as_ref().is_some_and(|v| v.len() > 4096) {
                    return Err(bad());
                }
            }
            Action::Devices => {}
        }
        Ok(())
    }
}
impl Challenge {
    /// Single canonical signing payload; signatures never cover caller-selected JSON keys.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.request.validate()?;
        if [
            self.installation,
            self.tenant,
            self.instance,
            self.principal,
            self.incarnation,
            self.vault,
            self.nonce,
        ]
        .iter()
        .any(Uuid::is_nil)
            || self.expires_at <= 0
        {
            return Err(WireError::InvalidValue);
        }
        serde_json::to_vec(&("rss-vault-sync.v1", self)).map_err(|_| WireError::InvalidValue)
    }
}

/// Derived schema fingerprint.
pub const SCHEMA_FINGERPRINT: &str =
    "10129b30433a43d46807fb4117f9e7c21011a1fa272e014821c8b117a6280be4";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_batches_and_canonical_proofs() {
        let r = Prepare {
            operation: Uuid::new_v4(),
            device: Uuid::new_v4(),
            action: Action::Write { items: vec![] },
        };
        assert!(r.validate().is_err());
        assert!(bytes("!!!!", 32, 32).is_err());
        let mut h = Challenge {
            installation: Uuid::new_v4(),
            tenant: Uuid::new_v4(),
            instance: Uuid::new_v4(),
            principal: Uuid::new_v4(),
            incarnation: Uuid::new_v4(),
            vault: Uuid::new_v4(),
            nonce: Uuid::new_v4(),
            expires_at: 99,
            request: Prepare {
                action: Action::Devices,
                ..r
            },
        };
        let original = h.signing_bytes().unwrap();
        h.incarnation = Uuid::new_v4();
        assert_ne!(original, h.signing_bytes().unwrap());
        let mut json = serde_json::to_value(h).unwrap();
        json["unknown"] = true.into();
        assert!(serde_json::from_value::<Challenge>(json).is_err());
    }
}
