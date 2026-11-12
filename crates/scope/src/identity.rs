use crate::ScopeError;
use rss_request_context::TenantId;
use std::cmp::Ordering;

/// Tenant-scoped group source identity. Construction is not authentication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupId {
    tenant: TenantId,
    value: uuid::Uuid,
}
impl GroupId {
    /// Bind a nonzero group UUID to its tenant.
    pub fn new(tenant: TenantId, value: uuid::Uuid) -> Result<Self, ScopeError> {
        if value.is_nil() {
            return Err(ScopeError::InvalidKey);
        }
        Ok(Self { tenant, value })
    }
    /// Owning tenant.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Exact group UUID.
    pub fn value(&self) -> uuid::Uuid {
        self.value
    }
}
impl Ord for GroupId {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), self.value).cmp(&(other.tenant.octets(), other.value))
    }
}
impl PartialOrd for GroupId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A tenant-scoped calculation object. Kind and UUID are both part of its identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedObjectId {
    tenant: TenantId,
    object: rss_mdm_agent_wire::ObjectRef,
}
impl ScopedObjectId {
    /// Bind a valid object to its tenant; this does not establish authorization.
    pub fn new(
        tenant: TenantId,
        object: rss_mdm_agent_wire::ObjectRef,
    ) -> Result<Self, ScopeError> {
        if object.uuid().is_nil() {
            return Err(ScopeError::InvalidKey);
        }
        Ok(Self { tenant, object })
    }
    /// Owning tenant.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Exact object kind and UUID.
    pub fn object(&self) -> rss_mdm_agent_wire::ObjectRef {
        self.object
    }
}
impl Ord for ScopedObjectId {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), self.object).cmp(&(other.tenant.octets(), other.object))
    }
}
impl PartialOrd for ScopedObjectId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
