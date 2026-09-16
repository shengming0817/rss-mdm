use crate::Error;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};

pub(crate) fn checked_name(value: String) -> Result<String, Error> {
    validate_name(&value)?;
    Ok(value)
}
pub(crate) fn validate_name(value: &str) -> Result<(), Error> {
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
    Ok(())
}
macro_rules! identities {
    ($($name:ident),+) => { $(
        /// A role-specific tenant key; construction is not authentication.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name { tenant: TenantId, value: String }
        impl $name {
            /// Creates a tenant-scoped reference, without authenticating its owner.
            ///
            /// # Errors
            /// Returns [`Error::InvalidIdentity`] unless the value is 1–128 ASCII
            /// letters, digits or `._-/+@`, without empty, `.` or `..` path segments.
            pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, Error> {
                Ok(Self { tenant, value: checked_name(value.into())? })
            }
            /// Returns the canonical tenant that scopes this reference.
            pub fn tenant(&self) -> TenantId { self.tenant }
            /// Returns the exact validated reference; no normalization is performed.
            pub fn value(&self) -> &str { &self.value }
        }
    )+ };
}
identities!(CandidateId, RequestId);
/// Opaque tenant-scoped principal identity, including product-attested structured subjects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorId {
    tenant: TenantId,
    value: String,
}
impl ActorId {
    /// Accept 1–2048 UTF-8 bytes without controls; this is not authentication.
    pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self { tenant, value })
    }
    /// Owning tenant.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Exact opaque identity.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// SHA-256 bytes supplied by the caller or computed from canonical inputs.
/// A digest binds bytes; it does not authenticate their origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Digest([u8; 32]);
impl Digest {
    /// Wraps an existing SHA-256 value without verifying the corresponding content.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Returns the raw 32-byte digest used by the canonical encoding.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
    /// Hashes exactly these bytes, without a domain prefix or normalization.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    /// Parses exactly 64 ASCII hexadecimal characters, accepting either case.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDigest`] for any other representation.
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
    /// Reconstructs a stored identity; this does not validate an approval or backend fact.
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
    /// Returns the canonical identity digest for storage or comparison.
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
