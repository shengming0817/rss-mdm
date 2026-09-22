use rss_contract::Timepoint;
use rss_mdm_scope::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
fn other() -> TenantId {
    TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap()
}
fn device() -> DeviceId {
    DeviceId::new(tenant(), "device").unwrap()
}
fn source(name: &str, contains: bool) -> SourceMembership {
    SourceMembership {
        source: SourceRef::new(
            SourceId::Group(GroupId::new(tenant(), name).unwrap()),
            1,
            Timepoint::try_from(1).unwrap(),
        )
        .unwrap(),
        contains: Membership::Known(contains),
    }
}
fn input() -> DeviceInput {
    DeviceInput {
        device: device(),
        targets: vec![source("targets", true)],
        limitations: None,
        exclusions: vec![],
    }
}
#[test]
fn finite_membership_truth_table_and_key_boundaries() {
    for target in [false, true] {
        for restricted in [false, true] {
            for limit in [false, true] {
                for excluded in [false, true] {
                    let i = DeviceInput {
                        device: device(),
                        targets: vec![source("target", target)],
                        limitations: restricted.then(|| vec![source("limit", limit)]),
                        exclusions: vec![source("exclude", excluded)],
                    };
                    let decision = resolve_device(&i).unwrap();
                    assert_eq!(decision.is_some(), target);
                    assert_eq!(
                        decision.as_ref().is_some_and(|d| d.reasons.is_empty()),
                        target && (!restricted || limit) && !excluded
                    );
                    if let Some(d) = decision {
                        assert_eq!(
                            d.reasons.contains(&ExclusionReason::MissingLimitationMatch),
                            restricted && !limit
                        );
                        assert_eq!(
                            d.reasons.contains(&ExclusionReason::ExplicitExclusion),
                            excluded
                        );
                    }
                }
            }
        }
    }
    assert!(GroupId::new(tenant(), "").is_err());
    assert!(DeviceId::new(tenant(), "x".repeat(257)).is_err());
    assert!(DeviceId::new(tenant(), "x".repeat(256)).is_ok());
    assert!(
        SourceRef::new(
            SourceId::Direct(device()),
            0,
            Timepoint::try_from(1).unwrap()
        )
        .is_err()
    );
}
#[test]
fn unconfigured_and_configured_empty_are_different() {
    let mut i = input();
    assert!(resolve_device(&i).unwrap().unwrap().reasons.is_empty());
    i.limitations = Some(vec![]);
    assert_eq!(
        resolve_device(&i).unwrap().unwrap().reasons,
        vec![ExclusionReason::MissingLimitationMatch]
    );
    i.targets.clear();
    assert!(resolve_device(&i).unwrap().is_none());
}
#[test]
fn formula_explanations_and_permutations() {
    let mut i = input();
    i.targets.extend([
        source("z", true),
        source("a", true),
        source("targets", true),
        source("nonmatch", false),
    ]);
    i.limitations = Some(vec![source("limit", true)]);
    i.exclusions = vec![source("exclude", true)];
    let expected = resolve_device(&i).unwrap().unwrap();
    assert_eq!(expected.object, device());
    assert_eq!(expected.targets.len(), 3);
    assert_eq!(expected.limitations.len(), 1);
    assert_eq!(expected.exclusions.len(), 1);
    i.targets.reverse();
    assert_eq!(resolve_device(&i).unwrap().unwrap(), expected);
}
#[test]
fn incomplete_failure_and_cross_tenant_are_not_empty_sets() {
    for state in [Membership::Incomplete, Membership::Failed] {
        for role in 0..3 {
            let mut i = input();
            let mut invalid = source("bad", false);
            invalid.contains = state;
            match role {
                0 => i.targets.push(invalid),
                1 => i.limitations = Some(vec![invalid]),
                _ => i.exclusions.push(invalid),
            }
            let error = resolve_device(&i).unwrap_err();
            assert!(matches!(
                (state, error),
                (Membership::Incomplete, ScopeError::IncompleteSource(_))
                    | (Membership::Failed, ScopeError::SourceFailed(_))
            ));
        }
    }
}
#[test]
fn foreign_sources_are_located_in_every_scope_role() {
    for role in 0..3 {
        let foreign = SourceRef::new(
            SourceId::Group(GroupId::new(other(), "foreign").unwrap()),
            1,
            Timepoint::try_from(1).unwrap(),
        )
        .unwrap();
        let invalid = SourceMembership {
            source: foreign.clone(),
            contains: Membership::Known(false),
        };
        let mut i = input();
        match role {
            0 => i.targets.push(invalid),
            1 => i.limitations = Some(vec![invalid]),
            _ => i.exclusions.push(invalid),
        }
        assert_eq!(
            resolve_device(&i),
            Err(ScopeError::SourceTenantMismatch {
                source_ref: foreign,
                expected: tenant()
            })
        );
    }
    let mut i = input();
    i.device = DeviceId::new(other(), "device").unwrap();
    assert!(
        matches!(resolve_device(&i),Err(ScopeError::SourceTenantMismatch{expected,..}) if expected==other())
    );
}
#[test]
fn invalid_sources_rejected_even_when_no_target_can_match() {
    let mut i = input();
    i.targets.clear();
    let mut invalid = source("bad", false);
    invalid.contains = Membership::Incomplete;
    i.exclusions.push(invalid);
    assert!(matches!(
        resolve_device(&i),
        Err(ScopeError::IncompleteSource(_))
    ));
}
#[test]
fn direct_group_dedup_empty_targets_and_conflicting_snapshot() {
    let mut i = input();
    i.targets.push(source("targets", false));
    assert!(matches!(
        resolve_device(&i),
        Err(ScopeError::ConflictingSource(_))
    ));
    i = input();
    let direct = SourceRef::new(
        SourceId::Direct(device()),
        1,
        Timepoint::try_from(1).unwrap(),
    )
    .unwrap();
    i.targets = vec![SourceMembership {
        source: direct.clone(),
        contains: Membership::Known(false),
    }];
    assert_eq!(
        resolve_device(&i),
        Err(ScopeError::InvalidDirectSource(direct))
    );
    i.targets[0].contains = Membership::Known(true);
    assert!(resolve_device(&i).unwrap().unwrap().reasons.is_empty());
    i.device = DeviceId::new(tenant(), "another").unwrap();
    assert!(matches!(
        resolve_device(&i),
        Err(ScopeError::InvalidDirectSource(_))
    ));
    i.targets[0].contains = Membership::Known(false);
    assert!(resolve_device(&i).unwrap().is_none());
}
#[test]
fn source_version_cannot_change_contents_with_a_different_resolution_time() {
    let mut i = input();
    let mut repeat = source("targets", false);
    repeat.source = SourceRef::new(
        repeat.source.id().clone(),
        1,
        Timepoint::try_from(2).unwrap(),
    )
    .unwrap();
    i.targets.push(repeat);
    assert!(matches!(
        resolve_device(&i),
        Err(ScopeError::ConflictingSource(_))
    ));
    i.targets[1].contains = Membership::Known(true);
    assert_eq!(resolve_device(&i).unwrap().unwrap().targets.len(), 2);
}
#[test]
fn source_and_role_budgets_are_bounded() {
    let mut i = input();
    i.targets = (0..1000).map(|n| source(&format!("g{n}"), true)).collect();
    assert_eq!(resolve_device(&i).unwrap().unwrap().targets.len(), 1000);
    i.targets.push(source("overflow", false));
    assert_eq!(resolve_device(&i), Err(ScopeError::SourceLimit));
    i.targets = vec![source("same", true); 3001];
    assert_eq!(resolve_device(&i), Err(ScopeError::SourceLimit));
}
