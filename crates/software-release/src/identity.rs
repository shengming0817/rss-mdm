use crate::Error;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};

pub(crate) fn checked_name(value: String) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/+@".contains(&b))
        || value
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::InvalidIdentity);
    }
    Ok(value)
}
macro_rules! identities {
    ($($name:ident),+) => { $(
        /// A role-specific tenant key; construction is not authentication.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name { tenant: TenantId, value: String }
        impl $name {
            pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, Error> {
                Ok(Self { tenant, value: checked_name(value.into())? })
            }
            pub fn tenant(&self) -> TenantId { self.tenant }
            pub fn value(&self) -> &str { &self.value }
        }
    )+ };
}
identities!(CandidateId, ActorId, RequestId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Digest([u8; 32]);
impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidDigest);
        }
        let mut result = [0; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::InvalidDigest)?;
        }
        Ok(Self(result))
    }
}
/// Stable publication identity, independent of request, retry count and clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationId(pub(crate) Digest);
impl PublicationId {
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
    pub const fn digest(self) -> Digest {
        self.0
    }
}

pub(crate) struct Encoding(Sha256);
impl Encoding {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut e = Self(Sha256::new());
        e.bytes(domain);
        e
    }
    pub(crate) fn number(&mut self, n: u64) {
        self.0.update(n.to_be_bytes());
    }
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.number(bytes.len() as u64);
        self.0.update(bytes);
    }
    pub(crate) fn object(&mut self, tenant: TenantId, value: &str) {
        self.0.update(tenant.octets());
        self.bytes(value.as_bytes());
    }
    pub(crate) fn digest(&mut self, digest: Digest) {
        self.0.update(digest.0);
    }
    pub(crate) fn finish(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}
