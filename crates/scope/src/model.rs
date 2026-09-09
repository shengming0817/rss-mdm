use crate::{DeviceId, GroupId};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use std::num::NonZeroU64;

/// Source roles cannot be confused with device members at the API boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceId {
    Direct(DeviceId),
    Group(GroupId),
}
impl SourceId {
    pub fn tenant(&self) -> TenantId {
        match self {
            Self::Direct(id) => id.tenant(),
            Self::Group(id) => id.tenant(),
        }
    }
}
/// Exact source snapshot used for both computation and historical explanation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceRef {
    id: SourceId,
    version: NonZeroU64,
    resolved_at: Timepoint,
}
impl SourceRef {
    pub fn new(id: SourceId, version: u64, resolved_at: Timepoint) -> Result<Self, ScopeError> {
        Ok(Self {
            id,
            version: NonZeroU64::new(version).ok_or(ScopeError::InvalidVersion)?,
            resolved_at,
        })
    }
    pub fn id(&self) -> &SourceId {
        &self.id
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
    Complete(Vec<DeviceId>),
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
    pub object: DeviceId,
    pub targets: Vec<SourceRef>,
    pub limitations: Vec<SourceRef>,
    pub exclusions: Vec<SourceRef>,
    pub reasons: Vec<ExclusionReason>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeResolution {
    pub target_sources: Vec<SourceRef>,
    pub exclusion_sources: Vec<SourceRef>,
    /// None means unrestricted; Some([]) means configured-empty. Includes sources
    /// that did not match, so MissingLimitationMatch remains explainable.
    pub limitation_sources: Option<Vec<SourceRef>>,
    pub members: Vec<DeviceId>,
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
