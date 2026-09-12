//! Registration-bound encryption; no protocol secret is stored as plaintext.
use crate::{ConfigIssue, Error, Failure, config, sessions};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub(super) struct Secrets {
    pub client_password: Zeroizing<String>,
    pub server_password: Zeroizing<String>,
    pub server_nonce: [u8; 32],
}
impl Secrets {
    pub(super) fn generate() -> Result<Self, Error> {
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        Ok(Self {
            client_password: Zeroizing::new(sessions::random()),
            server_password: Zeroizing::new(sessions::random()),
            server_nonce: nonce,
        })
    }
}
pub(super) struct Protection {
    key: aead::LessSafeKey,
    pub id: String,
}
impl Protection {
    pub(super) fn load(path: &Path) -> Result<Self, Error> {
        let key = config::read(path, 32, true)?;
        let id = crate::enrollment::digest(&("mdm.protocol.key.v1", key.as_slice()));
        Ok(Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &key)
                    .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?,
            ),
            id,
        })
    }
    fn aad(tenant: &str, request: Uuid) -> Vec<u8> {
        serde_json::to_vec(&("mdm.protocol.secrets.v1", tenant, request)).expect("closed AAD")
    }
    pub(super) fn seal(
        &self,
        tenant: &str,
        request: Uuid,
        secrets: &Secrets,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(secrets).map_err(|_| Error::Unavailable(Failure::Protocol))?,
        );
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(Self::aad(tenant, request)),
                &mut *bytes,
            )
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        Ok([nonce.as_slice(), bytes.as_slice()].concat())
    }
    pub(super) fn open(
        &self,
        tenant: &str,
        request: Uuid,
        sealed: &[u8],
    ) -> Result<Secrets, Error> {
        if !(28..=4096).contains(&sealed.len()) {
            return Err(Error::Unavailable(Failure::Protocol));
        }
        let nonce = aead::Nonce::try_assume_unique_for_key(&sealed[..12])
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let mut bytes = Zeroizing::new(sealed[12..].to_vec());
        let plain = self
            .key
            .open_in_place(
                nonce,
                aead::Aad::from(Self::aad(tenant, request)),
                &mut bytes,
            )
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        serde_json::from_slice(plain).map_err(|_| Error::Unavailable(Failure::Protocol))
    }
}
/// OMA DM 1.2.1 security §5.3.1.2: nonce contributes raw octets, not its XML base64.
pub(super) fn digest(name: &str, password: &str, nonce: &[u8]) -> String {
    let credentials = Zeroizing::new(format!("{name}:{password}"));
    let inner = Zeroizing::new(STANDARD.encode(Md5::digest(credentials.as_bytes())));
    let mut hash = Md5::new();
    hash.update(inner.as_bytes());
    hash.update(b":");
    hash.update(nonce);
    STANDARD.encode(hash.finalize())
}
