//! Deterministic scope algebra over caller-resolved, complete tenant snapshots.
//! Storage, source authorization and group expansion belong to the caller.
//! Group references cannot become device members through an accidental argument swap:
//! ```compile_fail
//! use rss_mdm_scope::{GroupId, Resolution};
//! fn wrong_role(group: GroupId) { let _ = Resolution::Complete(vec![group]); }
//! ```
//! ```compile_fail
//! use rss_mdm_scope::{GroupId, SourceId};
//! fn wrong_role(group: GroupId) { let _ = SourceId::Direct(group); }
//! ```
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]

mod identity;
pub use identity::{DeviceId, GroupId};
mod model;
pub use model::*;
/// Canonical types required to construct this core's public inputs.
pub use rss_contract::Timepoint;
pub use rss_request_context::TenantId;
use std::collections::{BTreeMap, BTreeSet};

/// Resolve atomically: an invalid source never yields a partial member set.
pub fn resolve(input: &ScopeInput) -> Result<ScopeResolution, ScopeError> {
    let limits = match &input.limitations {
        Limitations::Unrestricted => &[][..],
        Limitations::Restricted(sources) => sources.as_slice(),
    };
    let mut snapshots = BTreeMap::new();
    for source in input.targets.iter().chain(limits).chain(&input.exclusions) {
        validate_source(input.tenant, source, &mut snapshots)?;
    }
    let targets = index(&input.targets, &snapshots);
    let limitations = index(limits, &snapshots);
    let exclusions = index(&input.exclusions, &snapshots);
    let mut members = Vec::new();
    let mut explanations = Vec::new();
    for (object, hits) in targets {
        let limit_hits = limitations.get(&object).cloned().unwrap_or_default();
        let excluded = exclusions.get(&object).cloned().unwrap_or_default();
        let mut reasons = Vec::new();
        if matches!(input.limitations, Limitations::Restricted(_)) && limit_hits.is_empty() {
            reasons.push(ExclusionReason::MissingLimitationMatch);
        }
        if !excluded.is_empty() {
            reasons.push(ExclusionReason::ExplicitExclusion);
        }
        if reasons.is_empty() {
            members.push(object.clone());
        }
        explanations.push(MemberExplanation {
            object,
            targets: hits.into_iter().collect(),
            limitations: limit_hits.into_iter().collect(),
            exclusions: excluded.into_iter().collect(),
            reasons,
        });
    }
    Ok(ScopeResolution {
        target_sources: references(&input.targets),
        limitation_sources: match &input.limitations {
            Limitations::Unrestricted => None,
            Limitations::Restricted(_) => Some(references(limits)),
        },
        exclusion_sources: references(&input.exclusions),
        members,
        explanations,
    })
}
fn references(sources: &[ResolvedSource]) -> Vec<SourceRef> {
    sources
        .iter()
        .map(|s| s.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

type Snapshots = BTreeMap<(SourceId, u64), BTreeSet<DeviceId>>;
fn source_identity(source: &SourceRef) -> (SourceId, u64) {
    (source.id().clone(), source.version())
}
fn validate_source(
    tenant: rss_request_context::TenantId,
    input: &ResolvedSource,
    snapshots: &mut Snapshots,
) -> Result<(), ScopeError> {
    if input.source.id().tenant() != tenant {
        return Err(ScopeError::SourceTenantMismatch {
            source_ref: input.source.clone(),
            expected: tenant,
        });
    }
    let members = match &input.resolution {
        Resolution::Complete(members) => members,
        Resolution::Incomplete => return Err(ScopeError::IncompleteSource(input.source.clone())),
        Resolution::Failed => return Err(ScopeError::SourceFailed(input.source.clone())),
    };
    if let Some(member) = members.iter().find(|m| m.tenant() != tenant) {
        return Err(ScopeError::MemberTenantMismatch {
            source_ref: Box::new(input.source.clone()),
            member: member.clone(),
            expected: tenant,
        });
    }
    let members: BTreeSet<_> = members.iter().cloned().collect();
    if let SourceId::Direct(device) = input.source.id()
        && members != BTreeSet::from([device.clone()])
    {
        return Err(ScopeError::InvalidDirectSource(input.source.clone()));
    }
    if snapshots
        .get(&source_identity(&input.source))
        .is_some_and(|previous| previous != &members)
    {
        return Err(ScopeError::ConflictingSource(input.source.clone()));
    }
    snapshots.insert(source_identity(&input.source), members);
    Ok(())
}

fn index(
    sources: &[ResolvedSource],
    snapshots: &Snapshots,
) -> BTreeMap<DeviceId, BTreeSet<SourceRef>> {
    let mut index: BTreeMap<DeviceId, BTreeSet<SourceRef>> = BTreeMap::new();
    for source in sources {
        // Only validated snapshots reach this private helper.
        if let Some(members) = snapshots.get(&source_identity(&source.source)) {
            for member in members {
                index
                    .entry(member.clone())
                    .or_default()
                    .insert(source.source.clone());
            }
        }
    }
    index
}
