use crate::ScopeError;
use rss_request_context::TenantId;
use std::{cmp::Ordering, fmt};

#[derive(Clone, Eq, PartialEq)]
struct Key {
    tenant: TenantId,
    value: String,
}
impl Key {
    fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ScopeError::InvalidKey);
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
        /// Tenant-scoped identity. Construction is not authentication evidence.
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(Key);
        impl $name {
            /// Validate 1–128 ASCII letters, digits, dots, underscores or hyphens.
            /// Invalid text returns [`ScopeError::InvalidKey`]; no authority is verified.
            pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, ScopeError> { Key::new(tenant, value).map(Self) }
            /// Return the tenant bound to this identity.
            pub fn tenant(&self) -> TenantId { self.0.tenant }
            /// Borrow the exact validated identifier, without normalization.
            pub fn value(&self) -> &str { &self.0.value }
        }
    )+ };
}
identities!(GroupId);

/// A tenant-scoped calculation object. Kind and UUID are both part of its identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedObjectId {
    tenant: TenantId,
    object: rss_mdm_agent_wire::ObjectRef,
}
impl ScopedObjectId {
    /// Bind a valid object to its tenant; this does not establish authorization.
    pub fn new(tenant: TenantId, object: rss_mdm_agent_wire::ObjectRef) -> Result<Self, ScopeError> {
        if object.uuid().is_nil() { return Err(ScopeError::InvalidKey); }
        Ok(Self { tenant, object })
    }
    /// Owning tenant.
    pub fn tenant(&self) -> TenantId { self.tenant }
    /// Exact object kind and UUID.
    pub fn object(&self) -> rss_mdm_agent_wire::ObjectRef { self.object }
}
impl Ord for ScopedObjectId {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), self.object).cmp(&(other.tenant.octets(), other.object))
    }
}
impl PartialOrd for ScopedObjectId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
