//! Registration-bound encryption; no protocol secret is stored as plaintext.
use crate::{ConfigIssue, Error, Failure, enrollment};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use ring::rand::{SecureRandom, SystemRandom};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub struct Secrets {
    pub client_password: Zeroizing<String>,
    pub server_password: Zeroizing<String>,
    pub server_nonce: [u8; 32],
}
impl Secrets {
    pub fn generate() -> Result<Self, Error> {
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        Ok(Self {
            client_password: Zeroizing::new(enrollment::random()),
            server_password: Zeroizing::new(enrollment::random()),
            server_nonce: nonce,
        })
    }
}
pub struct Protection {
    protector: Protector,
    pub id: String,
}
impl Protection {
    pub fn from_bytes(key: &[u8]) -> Result<Self, Error> {
        let protector =
            Protector::new(key).map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?;
        Ok(Self {
            id: protector.id().to_owned(),
            protector,
        })
    }
    fn aad(tenant: &str, request: Uuid) -> Result<DerivedAad, Error> {
        let tenant = rss_request_context::TenantId::parse(tenant)
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        ProtectionContext::new(
            tenant,
            &request.to_string(),
            "windows.registration-secrets",
            1,
        )
        .map(|context| context.derive())
        .map_err(|_| Error::Unavailable(Failure::Protocol))
    }
    pub fn seal(&self, tenant: &str, request: Uuid, secrets: &Secrets) -> Result<Vec<u8>, Error> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(secrets).map_err(|_| Error::Unavailable(Failure::Protocol))?,
        );
        self.protector
            .seal_bytes(&bytes, &Self::aad(tenant, request)?)
            .map_err(|_| Error::Unavailable(Failure::Protocol))
    }
    pub fn open(&self, tenant: &str, request: Uuid, sealed: &[u8]) -> Result<Secrets, Error> {
        if sealed.len() > 8192 {
            return Err(Error::Unavailable(Failure::Protocol));
        }
        let plain = self
            .protector
            .open_bytes(sealed, &Self::aad(tenant, request)?)
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        serde_json::from_slice(plain.expose()).map_err(|_| Error::Unavailable(Failure::Protocol))
    }
}
/// OMA DM 1.2.1 security §5.3.1.2: nonce contributes raw octets, not its XML base64.
pub fn digest(name: &str, password: &str, nonce: &[u8]) -> String {
    let credentials = Zeroizing::new(format!("{name}:{password}"));
    let inner = Zeroizing::new(STANDARD.encode(Md5::digest(credentials.as_bytes())));
    let mut hash = Md5::new();
    hash.update(inner.as_bytes());
    hash.update(b":");
    hash.update(nonce);
    STANDARD.encode(hash.finalize())
}

pub(crate) fn native_aad(
    tenant: rss_request_context::TenantId,
    purpose: &str,
    identity: &impl Serialize,
) -> Result<DerivedAad, Error> {
    let owner = serde_json::to_string(identity).map_err(|_| Error::Malformed)?;
    ProtectionContext::new(tenant, &owner, purpose, 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Malformed)
}
pub(crate) fn collection_aad(
    scope: &rss_observation::Scope,
    id: Uuid,
) -> Result<DerivedAad, Error> {
    native_aad(
        scope.tenant(),
        "windows.collection.request",
        &(scope.registration().as_str(), scope.epoch().as_str(), id),
    )
}
