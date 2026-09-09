use rss_contract::Timepoint;
use rss_mdm_scope::*;
use rss_request_context::TenantId;

fn tenant() -> TenantId {
    TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap()
}
fn key(s: &str) -> ObjectKey {
    ObjectKey::new(tenant(), s).unwrap()
}
fn source(id: &str, members: &[&str]) -> ResolvedSource {
    ResolvedSource {
        source: SourceRef::new(
            key(id),
            SourceKind::Group,
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
    i.targets[0].resolution = Resolution::Complete(vec![ObjectKey::new(other, "d1").unwrap()]);
    assert!(matches!(resolve(&i), Err(ScopeError::TenantMismatch)));
}
#[test]
fn direct_group_dedup_empty_targets_and_conflicting_snapshot() {
    let mut i = input();
    let direct = ResolvedSource {
        source: SourceRef::new(
            key("d1"),
            SourceKind::Direct,
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
        key("a"),
        SourceKind::Group,
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
        key("a"),
        SourceKind::Direct,
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
        ObjectKey::new(other, "a").unwrap(),
        SourceKind::Group,
        1,
        Timepoint::try_from(10).unwrap(),
    )
    .unwrap();
    assert!(matches!(resolve(&i), Err(ScopeError::TenantMismatch)));
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
    for bad in ["", "has space", "../path", "\n"] {
        assert!(ObjectKey::new(tenant(), bad).is_err());
    }
    assert!(ObjectKey::new(tenant(), "a".repeat(128)).is_ok());
    assert!(ObjectKey::new(tenant(), "a".repeat(129)).is_err());
    assert!(
        SourceRef::new(
            key("a"),
            SourceKind::Group,
            0,
            Timepoint::try_from(0).unwrap()
        )
        .is_err()
    );
}
