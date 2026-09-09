//! Deterministic scope algebra over caller-resolved, complete tenant snapshots.
//! Storage, source authorization and group expansion belong to the caller.
#![forbid(unsafe_code)]
#![warn(clippy::cognitive_complexity)]

mod model;
pub use model::*;
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
        limitation_sources: match &input.limitations {
            Limitations::Unrestricted => None,
            Limitations::Restricted(_) => Some(
                limits
                    .iter()
                    .map(|s| s.source.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            ),
        },
        members,
        explanations,
    })
}

type Snapshots = BTreeMap<(ObjectKey, SourceKind, u64), BTreeSet<ObjectKey>>;
fn source_identity(source: &SourceRef) -> (ObjectKey, SourceKind, u64) {
    (source.object().clone(), source.kind(), source.version())
}
fn validate_source(
    tenant: rss_request_context::TenantId,
    input: &ResolvedSource,
    snapshots: &mut Snapshots,
) -> Result<(), ScopeError> {
    if input.source.object().tenant() != tenant {
        return Err(ScopeError::TenantMismatch);
    }
    let members = match &input.resolution {
        Resolution::Complete(members) => members,
        Resolution::Incomplete => return Err(ScopeError::IncompleteSource(input.source.clone())),
        Resolution::Failed => return Err(ScopeError::SourceFailed(input.source.clone())),
    };
    if members.iter().any(|m| m.tenant() != tenant) {
        return Err(ScopeError::TenantMismatch);
    }
    let members: BTreeSet<_> = members.iter().cloned().collect();
    if input.source.kind() == SourceKind::Direct
        && members != BTreeSet::from([input.source.object().clone()])
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
) -> BTreeMap<ObjectKey, BTreeSet<SourceRef>> {
    let mut index: BTreeMap<ObjectKey, BTreeSet<SourceRef>> = BTreeMap::new();
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
