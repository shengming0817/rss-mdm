//! Registration-bound encryption; no protocol secret is stored as plaintext.
use crate::{Error, Failure, enrollment};
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
    protector: std::sync::Arc<Protector>,
}
impl Protection {
    pub fn new(protector: std::sync::Arc<Protector>) -> Self {
        Self { protector }
    }
    pub(crate) fn aad(tenant: &str, request: Uuid) -> Result<DerivedAad, Error> {
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
    rss_mdm_execution_service::native::collection_aad(scope, id).map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotating_encryption_preserves_original_registration_identity_and_secrets() {
        let first = std::sync::Arc::new(Protector::new(&[1; 32]).unwrap());
        let second = std::sync::Arc::new(
            Protector::with_fingerprint(&[2; 32], &[&[1; 32]], &[1; 32]).unwrap(),
        );
        let poll = rss_mdm_windows_mdm::provisioning::Poll {
            interval_for_first_set_of_retries: 15,
            number_of_first_retries: 10,
            interval_for_second_set_of_retries: 0,
            number_of_second_retries: 0,
            interval_for_remaining_scheduled_retries: 1440,
            number_of_remaining_scheduled_retries: 0,
            poll_on_login: false,
            all_users_poll_on_first_login: false,
        };
        let identity = |p: &Protector| {
            crate::protocol_identity(
                "https://enroll.example",
                "https://manage.example",
                "RSS-MDM",
                p,
                &poll,
            )
            .unwrap()
        };
        assert_eq!(identity(&first), identity(&second));
        assert_eq!(
            identity(&first),
            enrollment::digest(&(
                "mdm.windows.profile.v1",
                &poll,
                "https://enroll.example",
                "https://manage.example",
                "RSS-MDM",
                first.id()
            ))
        );
        let tenant = Uuid::new_v4().to_string();
        let request = Uuid::new_v4();
        let secrets = Secrets::generate().unwrap();
        let before = Protection::new(first.clone())
            .seal(&tenant, request, &secrets)
            .unwrap();
        let after = second
            .rewrap_bytes(&before, &Protection::aad(&tenant, request).unwrap())
            .unwrap();
        let reader = Protection::new(second);
        for bytes in [&before, &after] {
            let actual = reader.open(&tenant, request, bytes).unwrap();
            assert_eq!(*actual.client_password, *secrets.client_password);
            assert_eq!(*actual.server_password, *secrets.server_password);
            assert_eq!(actual.server_nonce, secrets.server_nonce);
            assert!(reader.open(&tenant, Uuid::new_v4(), bytes).is_err());
        }
        assert!(
            Protection::new(first)
                .open(&tenant, request, &after)
                .is_err()
        );
    }
}
