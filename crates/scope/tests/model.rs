use rss_contract::Timepoint;
use rss_mdm_scope::*;
use rss_request_context::TenantId;

fn tenant() -> TenantId {
    TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap()
}
fn key(s: &str) -> DeviceId {
    DeviceId::new(tenant(), s).unwrap()
}
fn source(id: &str, members: &[&str]) -> ResolvedSource {
    ResolvedSource {
        source: SourceRef::new(
            SourceId::Group(GroupId::new(tenant(), id).unwrap()),
            1,
            Timepoint::try_from(10).unwrap(),
        )
        .unwrap(),
        resolution: Resolution::Complete(members.iter().map(|s| key(s)).collect()),
    }
}
fn input() -> ScopeInput {
    ScopeInput {
        tenant: tenant(),
        targets: vec![source("a", &["d2", "d1", "d1"])],
        limitations: Limitations::Unrestricted,
        exclusions: vec![],
    }
}
#[test]
fn device_resolution_matches_set_algebra_without_materializing_universe() {
    let mut full = input();
    full.limitations = Limitations::Restricted(vec![source("limit", &["d1"])]);
    full.exclusions = vec![source("exclude", &["d2"])];
    let expected = resolve(&full).unwrap();
    for id in ["d1", "d2", "absent"] {
        let device = key(id);
        let hits = |sources: &[ResolvedSource]| {
            sources
                .iter()
                .map(|s| {
                    let Resolution::Complete(members) = &s.resolution else {
                        unreachable!()
                    };
                    SourceMembership {
                        source: s.source.clone(),
                        contains: Some(members.contains(&device)),
                    }
                })
                .collect::<Vec<_>>()
        };
        let Limitations::Restricted(limits) = &full.limitations else {
            unreachable!()
        };
        let mut page = DeviceInput {
            device: device.clone(),
            targets: hits(&full.targets),
            limitations: Some(hits(limits)),
            exclusions: hits(&full.exclusions),
        };
        assert_eq!(
            resolve_device(&page).unwrap(),
            expected
                .explanations
                .iter()
                .find(|e| e.object == device)
                .cloned()
        );
        page.targets[0].contains = None;
        assert!(matches!(
            resolve_device(&page),
            Err(ScopeError::IncompleteSource(_))
        ));
    }
}
#[test]
fn unconfigured_and_configured_empty_are_different() {
    let mut i = input();
    assert_eq!(resolve(&i).unwrap().members, vec![key("d1"), key("d2")]);
    i.limitations = Limitations::Restricted(vec![]);
    let result = resolve(&i).unwrap();
    assert!(result.members.is_empty());
    assert!(
        result
            .explanations
            .iter()
            .all(|e| e.reasons.contains(&ExclusionReason::MissingLimitationMatch))
    );
    i.limitations = Limitations::Restricted(vec![source("empty", &[])]);
    assert!(resolve(&i).unwrap().members.is_empty());
}
#[test]
fn formula_explanations_and_permutations() {
    let mut i = input();
    i.targets.push(source("b", &["d3", "d2"]));
    i.limitations = Limitations::Restricted(vec![source("l1", &["d1"]), source("l2", &["d2"])]);
    i.exclusions = vec![source("x", &["d2", "d3"])];
    let result = resolve(&i).unwrap();
    assert_eq!(result.members, vec![key("d1")]);
    assert_eq!(result.explanations.len(), 3);
    assert_eq!(result.limitation_sources.as_ref().unwrap().len(), 2);
    assert_eq!(result.explanations[1].targets.len(), 2);
    assert_eq!(
        result.explanations[2].reasons,
        vec![
            ExclusionReason::MissingLimitationMatch,
            ExclusionReason::ExplicitExclusion
        ]
    );
    i.targets.reverse();
    if let Resolution::Complete(m) = &mut i.targets[1].resolution {
        m.reverse();
    }
    assert_eq!(result, resolve(&i).unwrap());
}
#[test]
fn incomplete_failure_and_cross_tenant_are_not_empty_sets() {
    let mut i = input();
    i.targets[0].resolution = Resolution::Incomplete;
    assert!(matches!(resolve(&i), Err(ScopeError::IncompleteSource(_))));
    i.targets[0].resolution = Resolution::Failed;
    assert!(matches!(resolve(&i), Err(ScopeError::SourceFailed(_))));
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    i.targets[0].resolution = Resolution::Complete(vec![DeviceId::new(other, "d1").unwrap()]);
    assert!(matches!(
        resolve(&i),
        Err(ScopeError::MemberTenantMismatch { .. })
    ));
}
#[test]
fn direct_group_dedup_empty_targets_and_conflicting_snapshot() {
    let mut i = input();
    let direct = ResolvedSource {
        source: SourceRef::new(
            SourceId::Direct(key("d1")),
            1,
            Timepoint::try_from(10).unwrap(),
        )
        .unwrap(),
        resolution: Resolution::Complete(vec![key("d1")]),
    };
    i.targets.push(direct.clone());
    i.targets.push(direct);
    let r = resolve(&i).unwrap();
    assert_eq!(r.members.len(), 2);
    assert_eq!(r.explanations[0].targets.len(), 2);
    i.exclusions.push(source("a", &["different"]));
    assert!(matches!(resolve(&i), Err(ScopeError::ConflictingSource(_))));
    i = input();
    i.targets.clear();
    assert!(resolve(&i).unwrap().members.is_empty());
}

#[test]
fn source_version_cannot_change_contents_with_a_different_resolution_time() {
    let mut i = input();
    let mut conflict = source("a", &["other"]);
    conflict.source = SourceRef::new(
        SourceId::Group(GroupId::new(tenant(), "a").unwrap()),
        1,
        Timepoint::try_from(11).unwrap(),
    )
    .unwrap();
    i.exclusions.push(conflict);
    assert!(matches!(resolve(&i), Err(ScopeError::ConflictingSource(_))));
}
#[test]
fn invalid_sources_rejected_even_when_no_target_can_match() {
    let mut i = input();
    i.targets.clear();
    let mut bad = source("group", &[]);
    bad.resolution = Resolution::Incomplete;
    i.exclusions.push(bad);
    assert!(matches!(resolve(&i), Err(ScopeError::IncompleteSource(_))));
    let mut i = input();
    i.targets[0].source = SourceRef::new(
        SourceId::Direct(key("a")),
        1,
        Timepoint::try_from(10).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        resolve(&i),
        Err(ScopeError::InvalidDirectSource(_))
    ));
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    i.targets[0].source = SourceRef::new(
        SourceId::Group(GroupId::new(other, "a").unwrap()),
        1,
        Timepoint::try_from(10).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        resolve(&i),
        Err(ScopeError::SourceTenantMismatch { .. })
    ));
}
#[test]
fn finite_membership_truth_table_and_key_boundaries() {
    for target in [false, true] {
        for limited in [false, true] {
            for limit in [false, true] {
                for exclude in [false, true] {
                    let m = |present| if present { vec!["d1"] } else { vec![] };
                    let i = ScopeInput {
                        tenant: tenant(),
                        targets: vec![source("t", &m(target))],
                        limitations: if limited {
                            Limitations::Restricted(vec![source("l", &m(limit))])
                        } else {
                            Limitations::Unrestricted
                        },
                        exclusions: vec![source("e", &m(exclude))],
                    };
                    assert_eq!(
                        !resolve(&i).unwrap().members.is_empty(),
                        target && (!limited || limit) && !exclude
                    );
                }
            }
        }
    }
    for bad in ["", "\0", "\n"] {
        assert!(DeviceId::new(tenant(), bad).is_err());
    }
    assert!(DeviceId::new(tenant(), "a".repeat(256)).is_ok());
    assert!(DeviceId::new(tenant(), "a".repeat(257)).is_err());
    assert!(
        SourceRef::new(
            SourceId::Group(GroupId::new(tenant(), "a").unwrap()),
            0,
            Timepoint::try_from(0).unwrap()
        )
        .is_err()
    );
}

#[test]
fn explanations_preserve_empty_targets_and_nonmatching_exclusion_sources() {
    let empty = source("empty-target", &[]);
    let excluded = source("unrelated-exclusion", &["other"]);
    let i = ScopeInput {
        tenant: tenant(),
        targets: vec![empty.clone(), empty.clone()],
        limitations: Limitations::Unrestricted,
        exclusions: vec![excluded.clone()],
    };
    let r = resolve(&i).unwrap();
    assert!(r.members.is_empty());
    assert!(r.explanations.is_empty());
    assert_eq!(r.target_sources, vec![empty.source]);
    assert_eq!(r.exclusion_sources, vec![excluded.source]);
}

#[test]
fn tenant_errors_distinguish_source_and_member_locations() {
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    for role in 0..3 {
        let mut errors = Vec::new();
        for (source_name, member_name) in [("a", "foreign1"), ("b", "foreign1"), ("b", "foreign2")]
        {
            let mut bad = source(source_name, &[]);
            bad.resolution = Resolution::Complete(vec![DeviceId::new(other, member_name).unwrap()]);
            let mut i = input();
            let expected = ScopeError::MemberTenantMismatch {
                source_ref: Box::new(bad.source.clone()),
                member: DeviceId::new(other, member_name).unwrap(),
                expected: tenant(),
            };
            match role {
                0 => i.targets.push(bad),
                1 => i.limitations = Limitations::Restricted(vec![bad]),
                _ => i.exclusions.push(bad),
            }
            let error = resolve(&i).unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(
                error.to_string(),
                "source member belongs to a foreign tenant"
            );
            errors.push(error);
        }
        assert_ne!(errors[0], errors[1], "source identity is required");
        assert_ne!(errors[1], errors[2], "member identity is required");
    }
}

#[test]
fn foreign_sources_are_located_in_every_scope_role() {
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    for role in 0..3 {
        let source_ref = SourceRef::new(
            SourceId::Group(GroupId::new(other, "foreign").unwrap()),
            2,
            Timepoint::try_from(10).unwrap(),
        )
        .unwrap();
        let bad = ResolvedSource {
            source: source_ref.clone(),
            resolution: Resolution::Complete(vec![]),
        };
        let mut i = input();
        match role {
            0 => i.targets.push(bad),
            1 => i.limitations = Limitations::Restricted(vec![bad]),
            _ => i.exclusions.push(bad),
        }
        let error = resolve(&i).unwrap_err();
        assert_eq!(
            error,
            ScopeError::SourceTenantMismatch {
                source_ref,
                expected: tenant()
            }
        );
        assert_eq!(error.to_string(), "scope contains a foreign tenant");
    }
}
