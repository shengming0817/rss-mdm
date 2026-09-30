use crate::{Error, Query};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub tenant: String,
    pub instance: String,
    pub family: String,
    pub query: Query,
    pub generation: uuid::Uuid,
    pub through: i64,
    pub after_at: i64,
    pub after_position: i64,
}
pub(crate) fn encode(key: &ring::hmac::Key, cursor: &Cursor) -> Result<String, Error> {
    let mut bytes = serde_json::to_vec(cursor).map_err(|_| Error::Integrity)?;
    bytes.extend(ring::hmac::sign(key, &bytes).as_ref());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(crate) fn decode(key: &ring::hmac::Key, token: &str) -> Result<Cursor, Error> {
    if token.len() > 4096 {
        return Err(Error::Malformed);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::Malformed)?;
    if bytes.len() <= 32 {
        return Err(Error::Malformed);
    }
    let (payload, signature) = bytes.split_at(bytes.len() - 32);
    ring::hmac::verify(key, payload, signature).map_err(|_| Error::Conflict)?;
    serde_json::from_slice(payload).map_err(|_| Error::Conflict)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_rejects_tampering_and_preserves_binding() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[3; 32]);
        let c = Cursor {
            tenant: "tenant".into(),
            instance: "instance".into(),
            family: "device".into(),
            query: Query {
                device: Some("device".into()),
                ..Default::default()
            },
            generation: uuid::Uuid::new_v4(),
            through: 10,
            after_at: 50,
            after_position: 9,
        };
        let token = encode(&key, &c).unwrap();
        let restored = decode(&key, &token).unwrap();
        assert_eq!(restored.query, c.query);
        assert_eq!(restored.through, 10);
        let mut bytes = URL_SAFE_NO_PAD.decode(token).unwrap();
        bytes[2] ^= 1;
        assert!(matches!(
            decode(&key, &URL_SAFE_NO_PAD.encode(bytes)),
            Err(Error::Conflict)
        ));
        assert!(
            decode(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[4; 32]),
                &encode(&key, &c).unwrap()
            )
            .is_err()
        );
    }
}
