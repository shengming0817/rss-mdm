use rss_contract::Timepoint;
use rss_request_context::TenantId;
use std::{cmp::Ordering, fmt, num::NonZeroU64};

/// Scope-owned opaque device/object identity. This is not authorization evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectKey {
    tenant: TenantId,
    value: String,
}
impl ObjectKey {
    pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, ScopeError> {
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
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn value(&self) -> &str {
        &self.value
    }
}
impl Ord for ObjectKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), &self.value).cmp(&(other.tenant.octets(), &other.value))
    }
}
impl PartialOrd for ObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectKey")
            .field("tenant", &self.tenant.to_string())
            .field("value", &self.value)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceKind {
    Direct,
    Group,
}
/// Exact source snapshot used for both computation and historical explanation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceRef {
    object: ObjectKey,
    kind: SourceKind,
    version: NonZeroU64,
    resolved_at: Timepoint,
}
impl SourceRef {
    pub fn new(
        object: ObjectKey,
        kind: SourceKind,
        version: u64,
        resolved_at: Timepoint,
    ) -> Result<Self, ScopeError> {
        Ok(Self {
            object,
            kind,
            version: NonZeroU64::new(version).ok_or(ScopeError::InvalidVersion)?,
            resolved_at,
        })
    }
    pub fn object(&self) -> &ObjectKey {
        &self.object
    }
    pub fn kind(&self) -> SourceKind {
        self.kind
    }
    pub fn version(&self) -> u64 {
        self.version.get()
    }
    pub fn resolved_at(&self) -> Timepoint {
        self.resolved_at
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    Complete(Vec<ObjectKey>),
    Incomplete,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSource {
    pub source: SourceRef,
    pub resolution: Resolution,
}
/// `Restricted([])` is configured-empty, never unrestricted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Limitations {
    Unrestricted,
    Restricted(Vec<ResolvedSource>),
}
#[derive(Clone)]
pub struct ScopeInput {
    pub tenant: TenantId,
    pub targets: Vec<ResolvedSource>,
    pub limitations: Limitations,
    pub exclusions: Vec<ResolvedSource>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusionReason {
    MissingLimitationMatch,
    ExplicitExclusion,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberExplanation {
    pub object: ObjectKey,
    pub targets: Vec<SourceRef>,
    pub limitations: Vec<SourceRef>,
    pub exclusions: Vec<SourceRef>,
    pub reasons: Vec<ExclusionReason>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeResolution {
    /// None means unrestricted; Some([]) means configured-empty. Includes sources
    /// that did not match, so MissingLimitationMatch remains explainable.
    pub limitation_sources: Option<Vec<SourceRef>>,
    pub members: Vec<ObjectKey>,
    pub explanations: Vec<MemberExplanation>,
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ScopeError {
    #[error("invalid object key")]
    InvalidKey,
    #[error("version must be nonzero")]
    InvalidVersion,
    #[error("scope contains a foreign tenant")]
    TenantMismatch,
    #[error("source snapshot is incomplete")]
    IncompleteSource(SourceRef),
    #[error("source resolution failed")]
    SourceFailed(SourceRef),
    #[error("source snapshot contents conflict")]
    ConflictingSource(SourceRef),
    #[error("direct source must contain exactly its object")]
    InvalidDirectSource(SourceRef),
}
