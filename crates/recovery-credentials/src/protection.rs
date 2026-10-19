use crate::{Coordinates, Error};
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    x509::X509,
};
use rss_mdm_native_protection::{Plaintext, ProtectionContext, Protector};
use rss_request_context::TenantId;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// One product configuration shared by execution, ingress and management readers.
pub struct Protection {
    pub keys: std::sync::Arc<KeyRing>,
    active_recipient: String,
    recipients: BTreeMap<String, Recipient>,
}
impl Protection {
    pub fn new(
        keys: KeyRing,
        active_recipient: String,
        recipients: Vec<Recipient>,
    ) -> Result<Self, Error> {
        if recipients.is_empty() || recipients.len() > 32 {
            return Err(Error::Configuration);
        }
        let mut values = BTreeMap::new();
        for recipient in recipients {
            if values
                .insert(recipient.id().to_owned(), recipient)
                .is_some()
            {
                return Err(Error::Configuration);
            }
        }
        if !values.contains_key(&active_recipient) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            keys: std::sync::Arc::new(keys),
            active_recipient,
            recipients: values,
        })
    }
    pub fn active_recipient(&self) -> &Recipient {
        &self.recipients[&self.active_recipient]
    }
    pub fn recipient(&self, id: &str) -> Result<&Recipient, Error> {
        self.recipients.get(id).ok_or(Error::Integrity)
    }
}

/// Explicit write key and retained decrypt keys; no fallback key or plaintext mode.
pub struct KeyRing {
    active: String,
    keys: BTreeMap<String, Protector>,
}
impl KeyRing {
    pub fn new(active: String, keys: Vec<(String, Zeroizing<Vec<u8>>)>) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > 32 {
            return Err(Error::Configuration);
        }
        let mut result = BTreeMap::new();
        let mut identities = std::collections::BTreeSet::new();
        for (name, key) in keys {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Error::Configuration);
            }
            let protector = Protector::new(&key).map_err(|_| Error::Configuration)?;
            if !identities.insert(protector.id().to_owned())
                || result.insert(name, protector).is_some()
            {
                return Err(Error::Configuration);
            }
        }
        if !result.contains_key(&active) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            active,
            keys: result,
        })
    }
    pub fn active(&self) -> &str {
        &self.active
    }
    pub fn identity(&self, name: &str) -> Result<&str, Error> {
        self.keys
            .get(name)
            .map(Protector::id)
            .ok_or(Error::Integrity)
    }
    pub fn seal(&self, coordinates: &Coordinates, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        coordinates.binding.subject.validate_secret(bytes)?;
        self.keys[&self.active]
            .seal_bytes(bytes, &aad(coordinates)?)
            .map_err(|_| Error::Integrity)
    }
    pub fn open(
        &self,
        key: &str,
        coordinates: &Coordinates,
        bytes: &[u8],
    ) -> Result<Plaintext, Error> {
        self.keys
            .get(key)
            .ok_or(Error::Integrity)?
            .open_bytes(bytes, &aad(coordinates)?)
            .map_err(|_| Error::Integrity)
    }
    /// Comparison remains bound to the material's original key across storage re-encryption.
    pub fn fingerprint(
        &self,
        key: &str,
        coordinates: &Coordinates,
        bytes: &[u8],
    ) -> Result<[u8; 32], Error> {
        self.keys
            .get(key)
            .ok_or(Error::Integrity)?
            .mac(bytes, &aad(coordinates)?)
            .map_err(|_| Error::Integrity)
    }
}
fn aad(c: &Coordinates) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    c.validate()?;
    let owner = serde_json::to_string(c).map_err(|_| Error::Malformed)?;
    ProtectionContext::new(
        TenantId::parse(&c.tenant.to_string()).map_err(|_| Error::Malformed)?,
        &owner,
        "recovery-credential/material",
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Malformed)
}

/// A dedicated escrow recipient; private keys never enter protocol DTOs.
pub struct Recipient {
    certificate: X509,
    key: PKey<Private>,
    id: String,
}
impl Recipient {
    pub fn from_pem(certificate: &[u8], key: &[u8]) -> Result<Self, Error> {
        let certificate = X509::from_pem(certificate).map_err(|_| Error::Configuration)?;
        let key = PKey::private_key_from_pem(key).map_err(|_| Error::Configuration)?;
        let public = certificate.public_key().map_err(|_| Error::Configuration)?;
        if !public.public_eq(&key) || key.rsa().is_err() || key.bits() < 2048 {
            return Err(Error::Configuration);
        }
        let digest = certificate
            .digest(openssl::hash::MessageDigest::sha256())
            .map_err(|_| Error::Configuration)?;
        let id = digest.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            certificate,
            key,
            id,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    /// New deliveries need a currently valid recipient; historical decrypts retain the original key.
    pub fn require_current(&self, now: i64) -> Result<(), Error> {
        let at = openssl::asn1::Asn1Time::from_unix(now).map_err(|_| Error::Configuration)?;
        if self.certificate.not_before() > at.as_ref()
            || self.certificate.not_after() <= at.as_ref()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        self.key.public_key_to_der().map_err(|_| Error::Integrity)
    }
    /// RSA-OAEP-SHA256 wraps only a random AES key; GCM authenticates the exact execution context.
    pub fn open_envelope(
        &self,
        wrapped: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if wrapped.len() != self.key.size()
            || !(17..=4112).contains(&ciphertext.len())
            || aad.len() > 16384
        {
            return Err(Error::Integrity);
        }
        let mut decrypt =
            openssl::encrypt::Decrypter::new(&self.key).map_err(|_| Error::Integrity)?;
        decrypt
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .map_err(|_| Error::Integrity)?;
        decrypt
            .set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
            .map_err(|_| Error::Integrity)?;
        decrypt
            .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
            .map_err(|_| Error::Integrity)?;
        let mut key = Zeroizing::new(vec![0; self.key.size()]);
        let size = decrypt
            .decrypt(wrapped, &mut key)
            .map_err(|_| Error::Integrity)?;
        if size != 32 {
            return Err(Error::Integrity);
        }
        let cipher = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key[..32])
                .map_err(|_| Error::Integrity)?,
        );
        let mut data = Zeroizing::new(ciphertext.to_vec());
        let length = cipher
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                &mut data,
            )
            .map_err(|_| Error::Integrity)?
            .len();
        data.truncate(length);
        Ok(data)
    }
    pub fn certificate_der(&self) -> Result<Vec<u8>, Error> {
        self.certificate.to_der().map_err(|_| Error::Integrity)
    }
    /// CMS decrypt requires the configured recipient certificate, never unchecked private-key decrypt.
    pub fn decrypt(
        &self,
        expected_recipient: &str,
        cms: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if expected_recipient != self.id || cms.is_empty() || cms.len() > 65536 {
            return Err(Error::Integrity);
        }
        let message = CmsContentInfo::from_der(cms).map_err(|_| Error::Integrity)?;
        let value = Zeroizing::new(
            message
                .decrypt(&self.key, &self.certificate)
                .map_err(|_| Error::Integrity)?,
        );
        if value.is_empty() || value.len() > 16384 {
            return Err(Error::Integrity);
        }
        Ok(value)
    }
}
