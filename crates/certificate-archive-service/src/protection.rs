//! Password wrapping is separate from immutable material versions.
//! ref: argon2 0.5.3 src/lib.rs; ring 0.17.14 src/aead/less_safe_key.rs.
use crate::{Clock, Error, UNLOCK_SECONDS};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::rand::{SecureRandom, SystemRandom};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const KDF: &str = "argon2id-v19-m65536-t3-p1";
pub(crate) type Key = Arc<Zeroizing<[u8; 32]>>;
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| Error::Storage)?;
    Ok(value)
}
pub(crate) fn password(value: &str) -> Result<(), Error> {
    if value.chars().count() < 12 || value.len() > 1024 || value.contains('\0') {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
pub(crate) fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    self::password(password)?;
    if salt.len() != 16 {
        return Err(Error::Integrity);
    }
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Integrity)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Integrity)?;
    Ok(key)
}
pub(crate) fn aad(tenant: &str, owner: &str, purpose: &str) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Integrity)?,
        owner,
        purpose,
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Integrity)
}
pub(crate) fn key_aad(tenant: &str, generation: i64) -> Result<DerivedAad, Error> {
    aad(
        tenant,
        &generation.to_string(),
        "certificate-archive.key/v1",
    )
}
pub(crate) fn material_aad(
    tenant: &str,
    entry: uuid::Uuid,
    version: i64,
) -> Result<DerivedAad, Error> {
    aad(
        tenant,
        &format!("{entry}/{version}"),
        "certificate-archive.bundle/v1",
    )
}
pub(crate) fn protector(key: &[u8]) -> Result<Protector, Error> {
    Protector::new(key).map_err(|_| Error::Integrity)
}
pub(crate) fn wrap(
    tenant: &str,
    generation: i64,
    kek: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    protector(kek)?
        .seal_bytes(key, &key_aad(tenant, generation)?)
        .map_err(|_| Error::Integrity)
}
pub(crate) fn unwrap(
    tenant: &str,
    generation: i64,
    kek: &[u8],
    sealed: &[u8],
) -> Result<Key, Error> {
    let opened = protector(kek)?
        .open_bytes(sealed, &key_aad(tenant, generation)?)
        .map_err(|_| Error::Password)?;
    let bytes: [u8; 32] = opened.expose().try_into().map_err(|_| Error::Integrity)?;
    Ok(Arc::new(Zeroizing::new(bytes)))
}
#[derive(Hash, Eq, PartialEq)]
struct Session {
    tenant: String,
    instance: String,
    principal: String,
    session: String,
}
fn session(proof: &AuthorizedPrincipal) -> Session {
    Session {
        tenant: proof.tenant_id().into(),
        instance: proof.instance_id().into(),
        principal: proof.principal_id().into(),
        session: proof.session_id(),
    }
}
struct Unlock {
    generation: i64,
    key: Key,
    until: Instant,
    display_until: i64,
}
#[derive(Default)]
pub(crate) struct Cache {
    values: Mutex<HashMap<Session, Unlock>>,
}
impl Cache {
    pub fn put(
        &self,
        proof: &AuthorizedPrincipal,
        generation: i64,
        key: Key,
        clock: &dyn Clock,
    ) -> Result<i64, Error> {
        let now = clock.now();
        let display_until = clock
            .unix_seconds()?
            .checked_add(UNLOCK_SECONDS as i64)
            .ok_or(Error::Integrity)?;
        let mut values = self.values.lock().map_err(|_| Error::Storage)?;
        values.retain(|_, v| v.until > now);
        let session = session(proof);
        if values.len() >= 128 && !values.contains_key(&session) {
            return Err(Error::Limited);
        }
        values.insert(
            session,
            Unlock {
                generation,
                key,
                until: now + Duration::from_secs(UNLOCK_SECONDS),
                display_until,
            },
        );
        Ok(display_until)
    }
    pub fn get(
        &self,
        proof: &AuthorizedPrincipal,
        generation: i64,
        clock: &dyn Clock,
    ) -> Result<(Key, i64), Error> {
        proof.check_live()?;
        let mut values = self.values.lock().map_err(|_| Error::Storage)?;
        let identity = session(proof);
        if values
            .get(&identity)
            .is_some_and(|v| v.until <= clock.now() || v.generation != generation)
        {
            values.remove(&identity);
        }
        let value = values.get(&identity).ok_or(Error::Locked)?;
        Ok((value.key.clone(), value.display_until))
    }
    pub fn lock(&self, proof: &AuthorizedPrincipal) -> Result<(), Error> {
        self.values
            .lock()
            .map_err(|_| Error::Storage)?
            .remove(&session(proof));
        Ok(())
    }
    pub fn invalidate(&self, tenant: &str) -> Result<(), Error> {
        self.values
            .lock()
            .map_err(|_| Error::Storage)?
            .retain(|s, _| s.tenant != tenant);
        Ok(())
    }
    pub fn purge(&self, clock: &dyn Clock) -> Result<(), Error> {
        self.values
            .lock()
            .map_err(|_| Error::Storage)?
            .retain(|_, v| v.until > clock.now());
        Ok(())
    }
    pub fn clear(&self) -> Result<(), Error> {
        self.values.lock().map_err(|_| Error::Storage)?.clear();
        Ok(())
    }
}
