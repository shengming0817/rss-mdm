use crate::*;

/// One lookup in an immutable, sealed source set; authorization belongs to the host.
#[derive(Clone, Debug)]
pub struct SourceMembership {
    /// Exact source identity/version/time.
    pub source: SourceRef,
    /// Some(false) is confirmed absence; None is unresolved and rejects the result.
    pub contains: Option<bool>,
}
/// A single-device slice of the scope algebra. No collection of devices is needed.
pub struct DeviceInput {
    /// Tenant-scoped device being considered.
    pub device: DeviceId,
    /// All target sources, including confirmed nonmatches.
    pub targets: Vec<SourceMembership>,
    /// None is unrestricted; Some([]) deliberately allows no devices.
    pub limitations: Option<Vec<SourceMembership>>,
    /// All exclusion sources, including confirmed nonmatches.
    pub exclusions: Vec<SourceMembership>,
}

/// Resolve one device using the same algebra and explanation as complete-set resolution.
/// Every supplied source is checked, including sources that do not match the device.
/// The caller enumerates candidates from sealed target sets and owns page completeness.
pub fn resolve_device(input: &DeviceInput) -> Result<Option<MemberExplanation>, ScopeError> {
    let limits = input.limitations.as_deref().unwrap_or_default();
    if input
        .targets
        .len()
        .saturating_add(limits.len())
        .saturating_add(input.exclusions.len())
        > 3000
    {
        return Err(ScopeError::SourceLimit);
    }
    let mut seen = BTreeMap::new();
    for membership in input.targets.iter().chain(limits).chain(&input.exclusions) {
        let source = &membership.source;
        if source.id().tenant() != input.device.tenant() {
            return Err(ScopeError::SourceTenantMismatch {
                source_ref: source.clone(),
                expected: input.device.tenant(),
            });
        }
        let contains = membership
            .contains
            .ok_or_else(|| ScopeError::IncompleteSource(source.clone()))?;
        if let SourceId::Direct(id) = source.id()
            && contains != (id == &input.device)
        {
            return Err(ScopeError::InvalidDirectSource(source.clone()));
        }
        if seen
            .insert((source.id(), source.version()), contains)
            .is_some_and(|old| old != contains)
        {
            return Err(ScopeError::ConflictingSource(source.clone()));
        }
    }
    if seen.len() > 1000 {
        return Err(ScopeError::SourceLimit);
    }
    let matching = |sources: &[SourceMembership]| {
        sources
            .iter()
            .filter(|s| s.contains == Some(true))
            .map(|s| s.source.clone())
            .collect::<BTreeSet<_>>()
    };
    let targets = matching(&input.targets);
    if targets.is_empty() {
        return Ok(None);
    }
    Ok(Some(explanation(
        input.device.clone(),
        targets,
        matching(limits),
        matching(&input.exclusions),
        input.limitations.is_some(),
    )))
}

pub(crate) fn explanation(
    object: DeviceId,
    targets: BTreeSet<SourceRef>,
    limitations: BTreeSet<SourceRef>,
    exclusions: BTreeSet<SourceRef>,
    restricted: bool,
) -> MemberExplanation {
    let mut reasons = Vec::new();
    if restricted && limitations.is_empty() {
        reasons.push(ExclusionReason::MissingLimitationMatch);
    }
    if !exclusions.is_empty() {
        reasons.push(ExclusionReason::ExplicitExclusion);
    }
    MemberExplanation {
        object,
        targets: targets.into_iter().collect(),
        limitations: limitations.into_iter().collect(),
        exclusions: exclusions.into_iter().collect(),
        reasons,
    }
}
