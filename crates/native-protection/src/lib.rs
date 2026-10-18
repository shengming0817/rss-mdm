//! Product native storage protection; permission and trusted coordinates remain with each owner.
//! ref: rss-data-protection c83978d src/aead.rs; ring 0.17.14 src/aead/less_safe_key.rs.
use ring::{
    aead, hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, ENVELOPE_VERSION, EncryptionMode,
};
pub use rss_data_protection::{DerivedAad, Plaintext, ProtectionContext};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 32 * 1024 * 1024;
// Product wire, RSS envelope version, AES256-GCM/randomized, key derivation version.
const MAGIC: &[u8; 8] = b"MDMNP\x02\x01\x01";
const PREFIX: usize = MAGIC.len() + 32 + 12;
const TAG: usize = 16;
#[derive(Debug, thiserror::Error)]
#[error("native data protection failed")]
pub struct Error;

/// One exact key; its derived identity remains stable across protection-key rotation.
struct Key {
    cipher: aead::LessSafeKey,
    mac_key: hmac::Key,
    identity: [u8; 32],
    id: String,
}
/// Bounded native protection key ring. Owners supply trusted keys and authenticated coordinates.
/// Only the active key creates ciphertext. Historical keys are retained for exact-ID reads;
/// this type does not discover keys, authorize retirement, or rewrite stored business records.
pub struct Protector {
    active: Key,
    fingerprint: Key,
    historical: std::collections::BTreeMap<[u8; 32], Key>,
}
impl Protector {
    /// Construct protection for one explicitly supplied key.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Self::with_history(key, &[])
    }
    /// Install an active key and at most fifteen distinct historical keys.
    /// Duplicate identities are rejected, including a repeated active key.
    pub fn with_history(active: &[u8], historical: &[&[u8]]) -> Result<Self, Error> {
        Self::with_fingerprint(active, historical, active)
    }
    /// 比较身份独立于密文写钥。历史请求和设备材料的稳定标识不随重加密改变。
    /// 指纹材料仍被历史记录使用时不能退出；它不隐式加入解密钥集合。
    pub fn with_fingerprint(
        active: &[u8],
        historical: &[&[u8]],
        fingerprint: &[u8],
    ) -> Result<Self, Error> {
        if historical.len() > 15 {
            return Err(Error);
        }
        let active = Key::new(active)?;
        let mut keys = std::collections::BTreeMap::new();
        for bytes in historical {
            let key = Key::new(bytes)?;
            if key.identity == active.identity || keys.insert(key.identity, key).is_some() {
                return Err(Error);
            }
        }
        Ok(Self {
            active,
            fingerprint: Key::new(fingerprint)?,
            historical: keys,
        })
    }
    /// Exact identity used for new writes.
    pub fn id(&self) -> &str {
        self.active.id()
    }
    pub fn fingerprint_id(&self) -> &str {
        self.fingerprint.id()
    }
    /// 仅用于有界重加密批次筛选；调用者仍须以领域 AAD 验证完整密文。
    pub fn ciphertext_prefix(&self) -> Vec<u8> {
        [MAGIC.as_slice(), self.active.identity.as_slice()].concat()
    }
    /// Seal under the active key without changing the existing authenticated envelope format.
    pub fn seal_bytes(&self, plain: &[u8], aad: &DerivedAad) -> Result<Vec<u8>, Error> {
        self.active.seal_bytes(plain, aad)
    }
    fn key_for_bytes(&self, sealed: &[u8]) -> Result<&Key, Error> {
        if !(PREFIX + TAG..=PREFIX + MAX_BYTES + TAG).contains(&sealed.len())
            || &sealed[..MAGIC.len()] != MAGIC
        {
            return Err(Error);
        }
        let identity: [u8; 32] = sealed[MAGIC.len()..MAGIC.len() + 32]
            .try_into()
            .map_err(|_| Error)?;
        if identity == self.active.identity {
            Ok(&self.active)
        } else {
            self.historical.get(&identity).ok_or(Error)
        }
    }
    /// Select exactly the envelope's key identity, then authenticate trusted owner coordinates.
    pub fn open_bytes(&self, sealed: &[u8], aad: &DerivedAad) -> Result<Plaintext, Error> {
        self.key_for_bytes(sealed)?.open_bytes(sealed, aad)
    }
    /// Rewrap a verified envelope under the active key. Active ciphertext is returned unchanged,
    /// making a resumed batch safe to repeat. The business owner commits the result atomically.
    pub fn rewrap_bytes(&self, sealed: &[u8], aad: &DerivedAad) -> Result<Vec<u8>, Error> {
        let key = self.key_for_bytes(sealed)?;
        let plain = key.open_bytes(sealed, aad)?;
        if key.identity == self.active.identity {
            Ok(sealed.to_vec())
        } else {
            self.active.seal_bytes(plain.expose(), aad)
        }
    }
    /// 指纹使用独立的稳定比较钥，持久摘要记录 fingerprint_id。
    pub fn mac(&self, plain: &[u8], aad: &DerivedAad) -> Result<[u8; 32], Error> {
        self.fingerprint.mac(plain, aad)
    }
    /// 校验稳定比较钥的指纹；已有带 key ID 的操作使用 verify_mac_with_key。
    pub fn verify_mac(&self, plain: &[u8], aad: &DerivedAad, tag: &[u8]) -> Result<(), Error> {
        self.fingerprint.verify_mac(plain, aad, tag)
    }
    /// Verify a durable request fingerprint against its exact recorded key, without trial decryption.
    pub fn verify_mac_with_key(
        &self,
        id: &str,
        plain: &[u8],
        aad: &DerivedAad,
        tag: &[u8],
    ) -> Result<(), Error> {
        if id == self.fingerprint.id() {
            self.fingerprint.verify_mac(plain, aad, tag)
        } else {
            self.key_for_id(id)?.verify_mac(plain, aad, tag)
        }
    }
    fn key_for_id(&self, id: &str) -> Result<&Key, Error> {
        if id == self.active.id() {
            return Ok(&self.active);
        }
        self.historical
            .values()
            .find(|key| key.id() == id)
            .ok_or(Error)
    }
}
impl Aead for Protector {
    fn seal(&self, plain: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        self.active.seal(plain, aad)
    }
    fn open(
        &self,
        envelope: &CiphertextEnvelope,
        aad: &DerivedAad,
    ) -> Result<Plaintext, AeadError> {
        self.key_for_id(envelope.kid())
            .map_err(|_| AeadError::Open)?
            .open(envelope, aad)
    }
}

struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}
impl Key {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error);
        }
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"rss-mdm/native-protection/v1").extract(key);
        let derive = |label: &[u8]| -> Result<Zeroizing<[u8; 32]>, Error> {
            let mut bytes = Zeroizing::new([0; 32]);
            prk.expand(&[label], KeyLength)
                .map_err(|_| Error)?
                .fill(bytes.as_mut())
                .map_err(|_| Error)?;
            Ok(bytes)
        };
        let encryption = derive(b"aes256-gcm")?;
        let mac = derive(b"native-content-hmac-sha256")?;
        let identity = *derive(b"key-identity")?;
        Ok(Self {
            cipher: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, encryption.as_ref())
                    .map_err(|_| Error)?,
            ),
            mac_key: hmac::Key::new(hmac::HMAC_SHA256, mac.as_ref()),
            id: identity.iter().map(|v| format!("{v:02x}")).collect(),
            identity,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Canonical authenticated native bytes. Replays reuse this exact envelope.
    pub fn seal_bytes(&self, plain: &[u8], aad: &DerivedAad) -> Result<Vec<u8>, Error> {
        let envelope = self.seal(plain, aad).map_err(|_| Error)?;
        let mut bytes = Vec::with_capacity(PREFIX + envelope.ciphertext().len() + TAG);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.identity);
        bytes.extend_from_slice(envelope.nonce());
        bytes.extend_from_slice(envelope.ciphertext());
        bytes.extend_from_slice(envelope.tag());
        Ok(bytes)
    }
    /// Coordinates come from the authorized owner, never from the stored envelope.
    pub fn open_bytes(&self, sealed: &[u8], aad: &DerivedAad) -> Result<Plaintext, Error> {
        if !(PREFIX + TAG..=PREFIX + MAX_BYTES + TAG).contains(&sealed.len())
            || &sealed[..MAGIC.len()] != MAGIC
            || sealed[MAGIC.len()..MAGIC.len() + 32] != self.identity
        {
            return Err(Error);
        }
        let tag_start = sealed.len() - TAG;
        let envelope = CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            &self.id,
            1,
            sealed[MAGIC.len() + 32..PREFIX].to_vec(),
            sealed[PREFIX..tag_start].to_vec(),
            sealed[tag_start..].to_vec(),
            aad.coordinates().clone(),
        )
        .map_err(|_| Error)?;
        self.open(&envelope, aad).map_err(|_| Error)
    }
    /// Verify a bounded domain-bound MAC using the cryptographic provider's constant-time comparison.
    pub fn verify_mac(&self, plain: &[u8], aad: &DerivedAad, tag: &[u8]) -> Result<(), Error> {
        if plain.len() > MAX_BYTES {
            return Err(Error);
        }
        let coordinates = aad.as_canonical_bytes();
        let mut bytes = Zeroizing::new(Vec::with_capacity(16 + coordinates.len() + plain.len()));
        bytes.extend_from_slice(&(coordinates.len() as u64).to_be_bytes());
        bytes.extend_from_slice(coordinates);
        bytes.extend_from_slice(&(plain.len() as u64).to_be_bytes());
        bytes.extend_from_slice(plain);
        hmac::verify(&self.mac_key, &bytes, tag).map_err(|_| Error)
    }
    /// Stable, keyed comparison for secret-bearing canonical input and protocol replay.
    pub fn mac(&self, plain: &[u8], aad: &DerivedAad) -> Result<[u8; 32], Error> {
        if plain.len() > MAX_BYTES {
            return Err(Error);
        }
        let mut context = hmac::Context::with_key(&self.mac_key);
        let coordinates = aad.as_canonical_bytes();
        context.update(&(coordinates.len() as u64).to_be_bytes());
        context.update(coordinates);
        context.update(&(plain.len() as u64).to_be_bytes());
        context.update(plain);
        context.sign().as_ref().try_into().map_err(|_| Error)
    }
}
impl Aead for Key {
    fn seal(&self, plaintext: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        if plaintext.len() > MAX_BYTES {
            return Err(AeadError::Seal);
        }
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AeadError::Seal)?;
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        let tag = self
            .cipher
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                ciphertext.as_mut(),
            )
            .map_err(|_| AeadError::Seal)?;
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            &self.id,
            1,
            nonce.to_vec(),
            ciphertext.to_vec(),
            tag.as_ref().to_vec(),
            aad.coordinates().clone(),
        )
        .map_err(|_| AeadError::Seal)
    }
    fn open(
        &self,
        envelope: &CiphertextEnvelope,
        aad: &DerivedAad,
    ) -> Result<Plaintext, AeadError> {
        if envelope.version() != ENVELOPE_VERSION
            || envelope.alg() != CipherAlg::Aes256Gcm
            || envelope.mode() != EncryptionMode::Randomized
            || envelope.key_version() != 1
            || envelope.kid() != self.id
            || envelope.aad() != aad.coordinates()
            || envelope.nonce().len() != 12
            || envelope.tag().len() != TAG
            || envelope.ciphertext().len() > MAX_BYTES
        {
            return Err(AeadError::Open);
        }
        let nonce = aead::Nonce::try_assume_unique_for_key(envelope.nonce())
            .map_err(|_| AeadError::Open)?;
        let mut bytes = Zeroizing::new(envelope.ciphertext().to_vec());
        bytes.extend_from_slice(envelope.tag());
        let plaintext = self
            .cipher
            .open_in_place(
                nonce,
                aead::Aad::from(aad.as_canonical_bytes()),
                bytes.as_mut(),
            )
            .map_err(|_| AeadError::Open)?;
        Ok(Plaintext::new(plaintext.to_vec()))
    }
}
