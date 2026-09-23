use crate::{DeviceId, GroupId};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use std::num::NonZeroU64;

/// Source roles cannot be confused with device members at the API boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceId {
    /// A direct device source; its complete resolution must contain exactly that device.
    Direct(DeviceId),
    /// A caller-expanded group snapshot, which may legitimately have no members.
    Group(GroupId),
}
impl SourceId {
    /// Return the source identity's tenant without resolving its members.
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
    /// Bind a source to a nonzero snapshot version and explicit resolution time.
    /// Zero returns [`ScopeError::InvalidVersion`]; no source read or freshness check occurs.
    pub fn new(id: SourceId, version: u64, resolved_at: Timepoint) -> Result<Self, ScopeError> {
        Ok(Self {
            id,
            version: NonZeroU64::new(version).ok_or(ScopeError::InvalidVersion)?,
            resolved_at,
        })
    }
    /// Borrow the role-specific source identity.
    pub fn id(&self) -> &SourceId {
        &self.id
    }
    /// Return the positive source snapshot version.
    pub fn version(&self) -> u64 {
        self.version.get()
    }
    /// Return the caller-attested source resolution time.
    pub fn resolved_at(&self) -> Timepoint {
        self.resolved_at
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Reason a targeted device is absent from the resolved membership set.
pub enum ExclusionReason {
    /// No configured limitation source includes the target.
    MissingLimitationMatch,
    /// At least one exclusion source includes the target.
    ExplicitExclusion,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Deterministic source matches and exclusions for one targeted device.
pub struct MemberExplanation {
    /// Targeted device, whether retained or excluded.
    pub object: DeviceId,
    /// Sorted unique target source references that include the device.
    pub targets: Vec<SourceRef>,
    /// Sorted unique limitation references that include the device.
    pub limitations: Vec<SourceRef>,
    /// Sorted unique exclusion references that include the device.
    pub exclusions: Vec<SourceRef>,
    /// Applicable exclusion reasons; empty exactly when this target is retained.
    pub reasons: Vec<ExclusionReason>,
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
/// Source validation failure; [`crate::resolve_device`] returns no partial membership set.
pub enum ScopeError {
    #[error("too many source memberships in a device input")]
    /// One device references more than the bounded target/limitation/exclusion set.
    SourceLimit,
    #[error("invalid object key")]
    /// A role or device identity violates its constructor's length/character rules.
    InvalidKey,
    #[error("version must be nonzero")]
    /// A source snapshot version is zero.
    InvalidVersion,
    #[error("scope contains a foreign tenant")]
    /// A source belongs to a different tenant than the scope.
    SourceTenantMismatch {
        /// Exact source reference whose resolution was rejected.
        source_ref: SourceRef,
        /// Tenant required by the scope input.
        expected: TenantId,
    },
    #[error("source snapshot is incomplete")]
    /// A source reports only partial membership.
    IncompleteSource(SourceRef),
    #[error("source resolution failed")]
    /// A source reports a resolution failure.
    SourceFailed(SourceRef),
    #[error("source snapshot contents conflict")]
    /// Repeated source identity/version pairs contain different canonical member sets.
    ConflictingSource(SourceRef),
    #[error("direct source must contain exactly its object")]
    /// A direct source does not resolve to exactly its referenced device.
    InvalidDirectSource(SourceRef),
}
