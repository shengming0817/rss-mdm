use crate::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub context: Value,
    pub offset: usize,
}
pub(crate) fn digest(v: &impl Serialize) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).map_err(|_| Error::Storage)?)
    ))
}
impl Associations {
    pub(crate) fn encode(&self, context: Value, offset: usize) -> Result<String> {
        let mut bytes =
            serde_json::to_vec(&Cursor { context, offset }).map_err(|_| Error::Storage)?;
        bytes.extend(ring::hmac::sign(&self.key, &bytes).as_ref());
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
    pub(crate) fn decode(&self, value: &str) -> Result<Cursor> {
        if value.len() > 16384 {
            return Err(Error::Malformed);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Error::Malformed)?;
        if bytes.len() < 32 {
            return Err(Error::Malformed);
        }
        let (body, mac) = bytes.split_at(bytes.len() - 32);
        ring::hmac::verify(&self.key, body, mac).map_err(|_| Error::Malformed)?;
        serde_json::from_slice(body).map_err(|_| Error::Malformed)
    }
}
