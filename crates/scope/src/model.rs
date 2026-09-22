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
#[derive(Clone, Debug, Eq, PartialEq)]
/// Caller-supplied source resolution; only complete sources may enter a result.
pub enum Resolution {
    /// The full member set, including an empty group; completeness is caller-attested.
    Complete(Vec<DeviceId>),
    /// The source could be resolved only partially; the whole computation must fail.
    Incomplete,
    /// Source resolution failed; never interpreted as an empty source.
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// One source snapshot and the caller's resolution outcome.
pub struct ResolvedSource {
    /// Exact source identity/version/time used for provenance.
    pub source: SourceRef,
    /// Complete members or a failure condition that prevents resolution.
    pub resolution: Resolution,
}
/// `Restricted([])` is configured-empty, never unrestricted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Limitations {
    /// No limitation intersection is applied to targets.
    Unrestricted,
    /// Intersect targets with this source union; an empty list permits no members.
    Restricted(Vec<ResolvedSource>),
}
#[derive(Clone)]
/// Resolved target union, optional limitation intersection and exclusion subtraction.
/// All inputs must share the tenant; authorization and group expansion belong to the caller.
pub struct ScopeInput {
    /// Tenant required on every source and member.
    pub tenant: TenantId,
    /// Source union from which candidate members and explanations are formed.
    pub targets: Vec<ResolvedSource>,
    /// Optional intersection constraint, distinguishing absent from configured-empty.
    pub limitations: Limitations,
    /// Source union subtracted after limitation matching.
    pub exclusions: Vec<ResolvedSource>,
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
#[derive(Clone, Debug, Eq, PartialEq)]
/// Complete in-memory set decision with source provenance; not a persisted membership receipt.
pub struct ScopeResolution {
    /// Sorted unique target references, including sources with no matches.
    pub target_sources: Vec<SourceRef>,
    /// Sorted unique exclusion references, including sources with no matches.
    pub exclusion_sources: Vec<SourceRef>,
    /// None means unrestricted; Some([]) means configured-empty. Includes sources
    /// that did not match, so MissingLimitationMatch remains explainable.
    pub limitation_sources: Option<Vec<SourceRef>>,
    /// Sorted unique target devices retained after intersection and subtraction.
    pub members: Vec<DeviceId>,
    /// One explanation per unique targeted device, ordered by device identity.
    pub explanations: Vec<MemberExplanation>,
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
/// Source validation failure; [`crate::resolve`] returns no partial membership set.
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
    #[error("source member belongs to a foreign tenant")]
    /// A resolved member belongs to a different tenant than the scope.
    MemberTenantMismatch {
        /// Exact source reference whose resolution was rejected.
        source_ref: Box<SourceRef>,
        /// Foreign member that caused rejection.
        member: DeviceId,
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
