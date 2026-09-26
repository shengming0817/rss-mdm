//! Task signing authority, independently configured from artifact storage.
use crate::{ConfigIssue, Error};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::{SignedTask, TaskPayload};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub private_key_file: PathBuf,
    pub key_id: String,
    pub trusted_keys: BTreeMap<String, String>,
}
pub(crate) struct Signer {
    key_id: String,
    key: Ed25519KeyPair,
}
fn bad() -> Error {
    Error::Configuration(ConfigIssue::Execution)
}
impl Signer {
    pub(crate) fn open(config: &Config) -> Result<Self, Error> {
        if config.trusted_keys.is_empty()
            || config.trusted_keys.len() > 16
            || config.trusted_keys.iter().any(|(id, key)| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(key)
                        .map_or(true, |bytes| bytes.len() != 32)
            })
            || config.key_id.is_empty()
            || config.key_id.len() > 128
            || !config
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad());
        }
        let private = crate::config::read(&config.private_key_file, 4096, true)?;
        let key = Ed25519KeyPair::from_pkcs8(&private).map_err(|_| bad())?;
        let expected = config.trusted_keys.get(&config.key_id).ok_or_else(bad)?;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected)
            .map_err(|_| bad())?;
        if expected != key.public_key().as_ref() {
            return Err(bad());
        }
        Ok(Self {
            key_id: config.key_id.clone(),
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
