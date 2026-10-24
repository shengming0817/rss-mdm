//! Authenticated, purpose-separated continuations. Context is supplied by the live authority owner.
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_contract::PageCursor;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"rss-mdm/query-cursor/v1\0";
pub fn fingerprint<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| Error::Invalid)?)
    ))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload<T> {
    version: u8,
    context: String,
    position: T,
}
#[derive(Clone)]
pub struct CursorCodec(ring::hmac::Key);
impl CursorCodec {
    pub fn from_key(key: ring::hmac::Key) -> Self {
        Self(key)
    }
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(Error::Invalid);
        }
        Ok(Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret)))
    }
    pub fn encode<T: Serialize>(&self, context: &str, position: &T) -> Result<PageCursor> {
        let payload = Payload {
            version: 1,
            context: context.to_owned(),
            position,
        };
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(&payload).map_err(|_| Error::Invalid)?);
        let tag = ring::hmac::sign(&self.0, &bytes);
        bytes.extend(tag.as_ref());
        PageCursor::parse(&URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| Error::Budget)
    }
    pub fn decode<T: DeserializeOwned>(&self, token: &PageCursor, context: &str) -> Result<T> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_str())
            .map_err(|_| Error::Invalid)?;
        let split = bytes
            .len()
            .checked_sub(32)
            .ok_or(Error::CursorInvalidated)?;
        let (payload, tag) = bytes.split_at(split);
        ring::hmac::verify(&self.0, payload, tag).map_err(|_| Error::CursorInvalidated)?;
        let payload = payload
            .strip_prefix(DOMAIN)
            .ok_or(Error::CursorInvalidated)?;
        let data: Payload<T> =
            serde_json::from_slice(payload).map_err(|_| Error::CursorInvalidated)?;
        if data.version != 1 || data.context != context {
            return Err(Error::CursorInvalidated);
        }
        Ok(data.position)
    }
}
