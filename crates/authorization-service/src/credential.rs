//! Request-local credentials are never durable authorization evidence.
use crate::Error;
use rss_identity_core::session::{BearerSecret, SessionSecret};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub enum RequestCredential {
    Cookie(SessionSecret),
    Bearer(BearerSecret),
    ApiKey(ApiKeySecret),
}
impl RequestCredential {
    pub fn duplicate(&self) -> Result<Self, Error> {
        Ok(match self {
            Self::Cookie(value) => Self::Cookie(
                SessionSecret::parse(value.expose().into()).map_err(|_| Error::Unauthorized)?,
            ),
            Self::Bearer(value) => Self::Bearer(
                BearerSecret::parse(value.expose().into()).map_err(|_| Error::Unauthorized)?,
            ),
            Self::ApiKey(value) => Self::ApiKey(ApiKeySecret::parse(value.expose().into())?),
        })
    }
}

/// Public key ID is a locator; only possession of the random secret authenticates it.
pub struct ApiKeySecret {
    id: Uuid,
    value: Zeroizing<String>,
}
impl ApiKeySecret {
    pub fn parse(value: String) -> Result<Self, Error> {
        let value = Zeroizing::new(value);
        let (id, secret) = value.split_once('.').ok_or(Error::Unauthorized)?;
        let parsed = Uuid::parse_str(id).map_err(|_| Error::Unauthorized)?;
        if parsed.is_nil()
            || parsed.to_string() != id
            || secret.len() != 64
            || !secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Unauthorized);
        }
        Ok(Self { id: parsed, value })
    }
    pub(crate) fn generate(id: Uuid) -> Result<Self, Error> {
        use rand::RngCore;
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| Error::Storage)?;
        let mut value = Zeroizing::new(format!("{id}."));
        use std::fmt::Write;
        for byte in bytes.iter() {
            write!(&mut *value, "{byte:02x}").map_err(|_| Error::Storage)?;
        }
        Ok(Self { id, value })
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn expose(&self) -> &str {
        &self.value
    }
    pub(crate) fn digest(&self, instance: &str, tenant: &str) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"rss-mdm/api-key/v1\0");
        digest.update(instance.as_bytes());
        digest.update([0]);
        digest.update(tenant.as_bytes());
        digest.update([0]);
        digest.update(self.value.as_bytes());
        digest.finalize().to_vec()
    }
}
impl std::fmt::Debug for ApiKeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKeySecret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_secret_is_strict_redacted_and_tenant_bound() {
        let id = Uuid::new_v4();
        let secret = ApiKeySecret::generate(id).unwrap();
        assert_eq!(
            ApiKeySecret::parse(secret.expose().into()).unwrap().id(),
            id
        );
        assert!(!format!("{secret:?}").contains(secret.expose()));
        assert_ne!(
            secret.digest("instance", "tenant-a"),
            secret.digest("instance", "tenant-b")
        );
        assert_ne!(
            secret.digest("instance-a", "tenant"),
            secret.digest("instance-b", "tenant")
        );
        for invalid in [
            format!("{}.{}", Uuid::nil(), "a".repeat(64)),
            format!("{id}.{}", "A".repeat(64)),
            format!("{id}.{}", "a".repeat(63)),
            format!(" {}", secret.expose()),
            format!("{}.extra", secret.expose()),
        ] {
            assert!(ApiKeySecret::parse(invalid).is_err());
        }
    }
}
