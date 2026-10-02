//! Task signing authority, independently configured from artifact storage.
use crate::{ConfigIssue, Error};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::{SignedTask, TaskPayload};
use std::collections::BTreeMap;
pub struct Signer {
    key_id: String,
    key: Ed25519KeyPair,
}
fn bad() -> Error {
    Error::Configuration(ConfigIssue::TaskSigning)
}
impl Signer {
    pub fn from_bytes(
        private: &[u8],
        key_id: &str,
        trusted_keys: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        if trusted_keys.is_empty()
            || trusted_keys.len() > 16
            || trusted_keys.iter().any(|(id, key)| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(key)
                        .map_or(true, |bytes| bytes.len() != 32)
            })
            || key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad());
        }
        if private.len() > 4096 {
            return Err(bad());
        }
        let key = Ed25519KeyPair::from_pkcs8(private).map_err(|_| bad())?;
        let expected = trusted_keys.get(key_id).ok_or_else(bad)?;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected)
            .map_err(|_| bad())?;
        if expected != key.public_key().as_ref() {
            return Err(bad());
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
        })
    }
    pub fn sign(&self, payload: TaskPayload) -> Result<SignedTask, Error> {
        let bytes = payload
            .signing_bytes(&self.key_id)
            .map_err(|_| Error::Malformed)?;
        Ok(SignedTask {
            payload,
            key_id: self.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.sign(&bytes).as_ref()),
        })
    }
}
