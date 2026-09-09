use crate::PolicyError;
use rss_request_context::TenantId;
use std::{cmp::Ordering, fmt};

#[derive(Clone, Eq, PartialEq)]
struct Key {
    tenant: TenantId,
    value: String,
}
impl Key {
    fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(PolicyError::InvalidKey);
        }
        Ok(Self { tenant, value })
    }
}
impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), &self.value).cmp(&(other.tenant.octets(), &other.value))
    }
}
impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("tenant", &self.tenant.to_string())
            .field("value", &self.value)
            .finish()
    }
}

macro_rules! identities {
    ($($name:ident),+ $(,)?) => { $(
        /// Tenant-scoped role identity. Construction is not authentication evidence.
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(Key);
        impl $name {
            pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, PolicyError> { Key::new(tenant, value).map(Self) }
            pub fn tenant(&self) -> TenantId { self.0.tenant }
            pub fn value(&self) -> &str { &self.0.value }
        }
    )+ };
}
identities!(DeviceId, PolicyId, PayloadId, TargetSnapshotId, RequestId);
