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
identities!(PolicyId, PayloadId, TargetSnapshotId, RequestId);

/// The original product device identity: 1–256 UTF-8 bytes, without controls.
/// Tenant and value are preserved exactly; construction does not prove authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(Key);
impl DeviceId {
    /// Validate the product identity without normalization or surrogate keys.
    pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(PolicyError::InvalidKey);
        }
        Ok(Self(Key { tenant, value }))
    }
    /// Owning tenant.
    pub fn tenant(&self) -> TenantId {
        self.0.tenant
    }
    /// Exact device identifier.
    pub fn value(&self) -> &str {
        &self.0.value
    }
}

#[cfg(test)]
mod device_identity_tests {
    use super::*;
    #[test]
    fn device_identity_preserves_product_keys_without_aliases() {
        let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
        for value in ["设备/原始 标识".to_owned(), "x".repeat(256)] {
            assert_eq!(DeviceId::new(tenant, &value).unwrap().value(), value);
        }
        for value in [String::new(), "x".repeat(257), "device\n".into()] {
            assert!(DeviceId::new(tenant, value).is_err());
        }
        assert!(PolicyId::new(tenant, "设备").is_err());
    }
}
