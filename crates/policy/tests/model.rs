use rss_contract::Timepoint;
use rss_mdm_policy::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap()
}
fn key(s: &str) -> ObjectKey {
    ObjectKey::new(tenant(), s).unwrap()
}
fn version(n: u64) -> Version {
    Version::new(
        key("policy"),
        n,
        PayloadRef::new(key("payload"), n, [n as u8; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap()
}
fn active(n: u64) -> Policy {
    Policy::draft(key("policy"))
        .transition(0, Transition::Activate(version(n)))
        .unwrap()
}
fn targets(m: &[&str]) -> TargetSnapshot {
    TargetSnapshot::new(key("targets"), 1, true, m.iter().map(|s| key(s)).collect()).unwrap()
}
fn record(n: u64, progress: Progress) -> ExecutionRecord {
    ExecutionRecord::new(version(n), key("d1"), progress, Effect::Unverified).unwrap()
}
fn compute(p: &Policy, t: &TargetSnapshot, f: &[ExecutionRecord]) -> Result<Plan, PolicyError> {
    reconcile(PlanInput {
        policy: p,
        targets: t,
        executions: f,
        request: key("request"),
        as_of: Timepoint::try_from(10).unwrap(),
    })
}
#[test]
fn lifecycle_and_revision_conflicts() {
    let p = active(1);
    assert!(matches!(
        p.transition(0, Transition::Pause),
        Err(PolicyError::RevisionConflict)
    ));
    let paused = p.transition(1, Transition::Pause).unwrap();
    assert_eq!(paused.status(), Status::Paused);
    let resumed = paused.transition(2, Transition::Resume).unwrap();
    let archived = resumed.transition(3, Transition::Archive).unwrap();
    assert!(matches!(
        archived.transition(4, Transition::Resume),
        Err(PolicyError::InvalidTransition)
    ));
    assert!(matches!(
        p.transition(1, Transition::Activate(version(1))),
        Err(PolicyError::StaleVersion)
    ));
}
#[test]
fn stable_add_retain_and_supersede() {
    let p = active(2);
    let t = targets(&["d2", "d1", "d1"]);
    let first = compute(&p, &t, &[]).unwrap();
    assert_eq!(first, compute(&p, &t, &[]).unwrap());
    assert_eq!(
        first.id(),
        compute(&p, &targets(&["d1", "d2"]), &[]).unwrap().id()
    );
    assert!(first.intents().iter().all(|i| matches!(i, Intent::Add(_))));
    let old = record(1, Progress::Succeeded);
    let plan = compute(&p, &t, &[old]).unwrap();
    assert!(
        plan.intents()
            .iter()
            .any(|i| matches!(i, Intent::Supersede { .. }))
    );
    let current = record(2, Progress::Unknown);
    let plan = compute(&p, &t, &[current]).unwrap();
    assert!(plan.intents().iter().any(
        |i| matches!(i,Intent::Retain{execution,..} if execution.progress()==Progress::Unknown)
    ));
}
#[test]
fn pause_resume_preserve_identity_and_exit_does_not_claim_rollback() {
    let p = active(1);
    let t = targets(&["d1"]);
    let facts = vec![record(1, Progress::Planned)];
    let paused = p.transition(1, Transition::Pause).unwrap();
    let plan = compute(&paused, &t, &facts).unwrap();
    assert!(!plan.scheduling_open());
    assert!(
        plan.intents()
            .iter()
            .all(|i| matches!(i, Intent::Retain { .. }))
    );
    let resumed = paused.transition(2, Transition::Resume).unwrap();
    let resumed_plan = compute(&resumed, &t, &facts).unwrap();
    assert!(resumed_plan.scheduling_open());
    assert!(
        resumed_plan
            .intents()
            .iter()
            .all(|i| matches!(i, Intent::Retain { .. }))
    );
    let exit = compute(&p, &targets(&[]), &facts).unwrap();
    assert!(
        matches!(&exit.intents()[0],Intent::Cancel{execution,..} if execution.progress()==Progress::Planned && execution.effect()==Effect::Unverified)
    );
}
#[test]
fn incomplete_targets_contradictions_and_stale_expectations_fail_closed() {
    let p = active(1);
    let incomplete = TargetSnapshot::new(key("targets"), 1, false, vec![]).unwrap();
    assert!(matches!(
        compute(&p, &incomplete, &[]),
        Err(PolicyError::IncompleteTargets)
    ));
    let t = targets(&["d1"]);
    assert!(matches!(
        compute(
            &p,
            &t,
            &[record(1, Progress::Planned), record(1, Progress::Succeeded)]
        ),
        Err(PolicyError::ConflictingExecution)
    ));
    assert!(matches!(
        compute(&p, &t, &[record(2, Progress::Succeeded)]),
        Err(PolicyError::StaleVersion)
    ));
}

#[test]
fn every_progress_and_effect_is_retained_without_inventing_success_or_retry() {
    let p = active(1);
    let t = targets(&["d1"]);
    for progress in [
        Progress::Planned,
        Progress::Running,
        Progress::Unknown,
        Progress::Succeeded,
        Progress::Failed,
        Progress::Cancelled,
    ] {
        for effect in [
            Effect::Unverified,
            Effect::Unknown,
            Effect::VerifiedPresent,
            Effect::VerifiedAbsent,
        ] {
            let fact = ExecutionRecord::new(version(1), key("d1"), progress, effect).unwrap();
            let r = compute(&p, &t, &[fact.clone(), fact.clone()]).unwrap();
            assert_eq!(
                r.intents(),
                &[Intent::Retain {
                    execution: fact,
                    reason: RetainReason::Current
                }]
            );
        }
    }
}
#[test]
fn supersede_cancels_old_outstanding_and_never_rewrites_old_facts() {
    let p = active(2);
    let t = targets(&["d1"]);
    let old = record(1, Progress::Unknown);
    let r = compute(&p, &t, std::slice::from_ref(&old)).unwrap();
    assert!(r.intents().iter().any(|i|matches!(i,Intent::Supersede {replacement,previous} if replacement.key().version()==2 && previous==&vec![old.key()])));
    assert!(r.intents().iter().any(|i|matches!(i,Intent::Cancel {execution,reason:CancelReason::Superseded} if execution==&old)));
    let current = record(2, Progress::Succeeded);
    let r = compute(&p, &t, &[old.clone(), current.clone()]).unwrap();
    assert!(
        !r.intents()
            .iter()
            .any(|i| matches!(i, Intent::Add(_) | Intent::Supersede { .. }))
    );
    assert!(
        r.intents()
            .iter()
            .any(|i| matches!(i,Intent::Cancel{execution,..} if execution==&old))
    );
    assert_eq!(r.id(), compute(&p, &t, &[current, old]).unwrap().id());
}
#[test]
fn plan_identity_excludes_request_clock_but_covers_decisions_and_preconditions() {
    let p = active(1);
    let t = targets(&["d1"]);
    let a = compute(&p, &t, &[]).unwrap();
    let b = reconcile(PlanInput {
        policy: &p,
        targets: &t,
        executions: &[],
        request: key("another"),
        as_of: Timepoint::try_from(20).unwrap(),
    })
    .unwrap();
    assert_eq!(a.id(), b.id());
    assert_eq!(a.intents(), b.intents());
    assert_ne!(a.request(), b.request());
    assert_ne!(a.id(), compute(&p, &targets(&["d2"]), &[]).unwrap().id());
    assert_ne!(
        a.id(),
        compute(
            &p,
            &TargetSnapshot::new(key("targets"), 2, true, vec![key("d1")]).unwrap(),
            &[]
        )
        .unwrap()
        .id()
    );
    assert_ne!(
        a.id(),
        compute(&p, &t, &[record(1, Progress::Planned)])
            .unwrap()
            .id()
    );
    assert_eq!(a.expected_revision(), p.revision());
    assert_eq!(a.target_revision(), 1);
    let desired = match &a.intents()[0] {
        Intent::Add(d) => d.key().clone(),
        _ => panic!("expected Add"),
    };
    assert_eq!(desired, record(1, Progress::Planned).key());
    assert_eq!(desired.action(), Action::Apply);
    // Length-delimited object strings must not alias each other.
    assert_ne!(
        compute(&p, &targets(&["ab", "c"]), &[]).unwrap().id(),
        compute(&p, &targets(&["a", "bc"]), &[]).unwrap().id()
    );
}
#[test]
fn archive_and_reentry_preserve_terminal_evidence() {
    let p = active(1);
    let archived = p.transition(1, Transition::Archive).unwrap();
    let outstanding = record(1, Progress::Running);
    let r = compute(
        &archived,
        &targets(&["d1"]),
        std::slice::from_ref(&outstanding),
    )
    .unwrap();
    assert!(!r.scheduling_open());
    assert_eq!(
        r.intents(),
        &[Intent::Cancel {
            execution: outstanding,
            reason: CancelReason::Archived
        }]
    );
    let finished = ExecutionRecord::new(
        version(1),
        key("d1"),
        Progress::Cancelled,
        Effect::VerifiedPresent,
    )
    .unwrap();
    let r = compute(&p, &targets(&["d1"]), std::slice::from_ref(&finished)).unwrap();
    assert_eq!(
        r.intents(),
        &[Intent::Retain {
            execution: finished,
            reason: RetainReason::Current
        }]
    );
    let empty = compute(&Policy::draft(key("policy")), &targets(&["d1"]), &[]).unwrap();
    assert!(!empty.scheduling_open());
    assert!(empty.intents().is_empty());
}
#[test]
fn immutable_version_and_payload_conflicts_are_rejected() {
    let p = active(1);
    let changed = Version::new(
        key("policy"),
        1,
        PayloadRef::new(key("payload"), 1, [9; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    assert_eq!(
        p.transition(1, Transition::Activate(changed.clone()))
            .unwrap_err(),
        PolicyError::VersionConflict
    );
    let bad = ExecutionRecord::new(changed, key("d1"), Progress::Planned, Effect::Unknown).unwrap();
    assert_eq!(
        compute(&p, &targets(&["d1"]), &[bad]).unwrap_err(),
        PolicyError::VersionConflict
    );
    let reused_payload = Version::new(
        key("policy"),
        2,
        PayloadRef::new(key("payload"), 1, [9; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    assert_eq!(
        p.transition(1, Transition::Activate(reused_payload.clone()))
            .unwrap_err(),
        PolicyError::PayloadConflict
    );
    let p = Policy::restore(key("policy"), 2, Status::Active, Some(reused_payload)).unwrap();
    assert_eq!(
        compute(&p, &targets(&["d1"]), &[record(1, Progress::Planned)]).unwrap_err(),
        PolicyError::PayloadConflict
    );
}
#[test]
fn all_lifecycle_edges_and_restore_guards() {
    for state in [
        Status::Draft,
        Status::Active,
        Status::Paused,
        Status::Archived,
    ] {
        let p = if state == Status::Draft {
            Policy::draft(key("policy"))
        } else {
            Policy::restore(key("policy"), 1, state, Some(version(1))).unwrap()
        };
        for (op, expected) in [
            (Transition::Pause, state == Status::Active),
            (Transition::Resume, state == Status::Paused),
            (
                Transition::Archive,
                matches!(state, Status::Active | Status::Paused),
            ),
            (Transition::Activate(version(2)), state != Status::Archived),
        ] {
            assert_eq!(p.transition(p.revision(), op).is_ok(), expected);
        }
    }
    assert!(Policy::restore(key("policy"), 1, Status::Draft, None).is_err());
    assert!(Policy::restore(key("policy"), 0, Status::Active, Some(version(1))).is_err());
    assert!(Policy::restore(key("policy"), 1, Status::Active, None).is_err());
    let p = Policy::restore(key("policy"), u64::MAX, Status::Active, Some(version(1))).unwrap();
    assert_eq!(
        p.transition(u64::MAX, Transition::Pause).unwrap_err(),
        PolicyError::RevisionOverflow
    );
}
#[test]
fn tenant_policy_and_value_boundaries() {
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let foreign = ObjectKey::new(other, "d1").unwrap();
    assert!(
        ExecutionRecord::new(
            version(1),
            foreign.clone(),
            Progress::Planned,
            Effect::Unknown
        )
        .is_err()
    );
    assert!(TargetSnapshot::new(key("t"), 1, true, vec![foreign.clone()]).is_err());
    let foreign_targets =
        TargetSnapshot::new(foreign.clone(), 1, true, vec![foreign.clone()]).unwrap();
    assert_eq!(
        compute(&active(1), &foreign_targets, &[]).unwrap_err(),
        PolicyError::TenantMismatch
    );
    let p = active(1);
    let t = targets(&["d1"]);
    assert_eq!(
        reconcile(PlanInput {
            policy: &p,
            targets: &t,
            executions: &[],
            request: foreign,
            as_of: Timepoint::try_from(10).unwrap()
        })
        .unwrap_err(),
        PolicyError::TenantMismatch
    );
    let wrong = Version::new(
        key("other-policy"),
        1,
        version(1).payload().clone(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    assert_eq!(
        p.transition(1, Transition::Activate(wrong.clone()))
            .unwrap_err(),
        PolicyError::PolicyMismatch
    );
    assert_eq!(
        compute(
            &p,
            &t,
            &[ExecutionRecord::new(wrong, key("d1"), Progress::Planned, Effect::Unknown).unwrap()]
        )
        .unwrap_err(),
        PolicyError::PolicyMismatch
    );
    assert!(ObjectKey::new(tenant(), "bad/url").is_err());
    assert!(ObjectKey::new(tenant(), "a".repeat(129)).is_err());
    assert!(
        Version::new(
            key("policy"),
            0,
            version(1).payload().clone(),
            RemovalRule::CancelOutstandingRetainEffects
        )
        .is_err()
    );
    assert!(PayloadRef::new(key("payload"), 0, [1; 32]).is_err());
}
