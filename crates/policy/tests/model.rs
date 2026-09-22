use rss_contract::Timepoint;
use rss_mdm_policy::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap()
}
fn key(s: &str) -> DeviceId {
    DeviceId::new(tenant(), s).unwrap()
}
fn version(n: u64) -> Version {
    Version::new(
        PolicyId::new(tenant(), "policy").unwrap(),
        n,
        PayloadRef::new(
            PayloadId::new(tenant(), "payload").unwrap(),
            n,
            [n as u8; 32],
        )
        .unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap()
}
fn active(n: u64) -> Policy {
    Policy::draft(PolicyId::new(tenant(), "policy").unwrap())
        .transition(0, Transition::Activate(version(n)))
        .unwrap()
}
fn targets(m: &[&str]) -> TargetSnapshot {
    TargetSnapshot::new(
        TargetSnapshotId::new(tenant(), "targets").unwrap(),
        1,
        SnapshotCompleteness::Complete,
        m.iter().map(|s| key(s)).collect(),
    )
    .unwrap()
}
fn record(n: u64, progress: Progress) -> ExecutionRecord {
    ExecutionRecord::new(version(n), key("d1"), progress, Effect::Unverified).unwrap()
}
fn compute(p: &Policy, t: &TargetSnapshot, f: &[ExecutionRecord]) -> Result<Plan, PolicyError> {
    reconcile(PlanInput {
        policy: p,
        targets: t,
        executions: f,
        request: RequestId::new(tenant(), "request").unwrap(),
        as_of: Timepoint::try_from(10).unwrap(),
    })
}
#[test]
fn streamed_decisions_preserve_lifecycle_and_do_not_require_history_vectors() {
    let policy = active(2);
    let prior = record(1, Progress::Running);
    let current = record(2, Progress::Unknown);
    assert!(matches!(
        desired_for_device(&policy, &key("d1"), true, ExecutionPresence::Previous).unwrap(),
        Some(DesiredIntent::Supersede(_))
    ));
    assert!(
        desired_for_device(&policy, &key("d1"), true, ExecutionPresence::Current)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        classify_record(&policy, true, &prior).unwrap(),
        Intent::Cancel {
            reason: CancelReason::Superseded,
            ..
        }
    ));
    assert!(matches!(
        classify_record(&policy, true, &current).unwrap(),
        Intent::Retain {
            reason: RetainReason::Current,
            ..
        }
    ));
    let paused = policy
        .transition(policy.revision(), Transition::Pause)
        .unwrap();
    assert!(
        desired_for_device(&paused, &key("d1"), true, ExecutionPresence::Absent)
            .unwrap()
            .is_none()
    );
    let archived = policy
        .transition(policy.revision(), Transition::Archive)
        .unwrap();
    assert!(matches!(
        classify_record(&archived, true, &current).unwrap(),
        Intent::Cancel {
            reason: CancelReason::Archived,
            ..
        }
    ));
}
#[test]
fn streamed_plan_identity_survives_page_boundaries_and_restart() {
    let policy = active(2);
    let mut targets = TargetDigest::empty(tenant());
    for id in ["a", "b", "c"] {
        targets.push(&key(id)).unwrap();
    }
    let mut restored = TargetDigest::empty(tenant());
    restored.push(&key("a")).unwrap();
    restored = TargetDigest::restore(tenant(), restored.state(), restored.count());
    for id in ["b", "c"] {
        restored.push(&key(id)).unwrap();
    }
    assert_eq!(targets.state(), restored.state());
    let mut executions = ExecutionDigest::empty(policy.key().clone());
    executions.push(&record(1, Progress::Running)).unwrap();
    let id = TargetSnapshotId::new(tenant(), "frozen").unwrap();
    let first = stream_plan_id(&policy, &id, 1, &targets, &executions).unwrap();
    assert_eq!(
        first,
        stream_plan_id(&policy, &id, 1, &restored, &executions).unwrap()
    );
    executions.push(&record(2, Progress::Unknown)).unwrap();
    assert_ne!(
        first,
        stream_plan_id(&policy, &id, 1, &restored, &executions).unwrap()
    );
    assert_ne!(
        first,
        stream_plan_id(
            &policy,
            &id,
            2,
            &restored,
            &ExecutionDigest::empty(policy.key().clone())
        )
        .unwrap()
    );
}
#[test]
fn lifecycle_and_revision_conflicts() {
    let p = active(1);
    assert!(matches!(
        p.transition(0, Transition::Pause),
        Err(PolicyError::RevisionConflict { .. })
    ));
    let paused = p.transition(1, Transition::Pause).unwrap();
    assert_eq!(paused.status(), Status::Paused);
    let resumed = paused.transition(2, Transition::Resume).unwrap();
    let archived = resumed.transition(3, Transition::Archive).unwrap();
    assert!(matches!(
        archived.transition(4, Transition::Resume),
        Err(PolicyError::InvalidTransition { .. })
    ));
    assert!(matches!(
        p.transition(1, Transition::Activate(version(1))),
        Err(PolicyError::StaleVersion { .. })
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
    assert!(matches!(
        TargetSnapshot::new(
            TargetSnapshotId::new(tenant(), "targets").unwrap(),
            1,
            SnapshotCompleteness::Incomplete,
            vec![]
        ),
        Err(PolicyError::IncompleteTargets)
    ));
    let t = targets(&["d1"]);
    assert!(matches!(
        compute(
            &p,
            &t,
            &[record(1, Progress::Planned), record(1, Progress::Succeeded)]
        ),
        Err(PolicyError::ConflictingExecution { .. })
    ));
    assert!(matches!(
        compute(&p, &t, &[record(2, Progress::Succeeded)]),
        Err(PolicyError::InvalidExecution {
            reason: ExecutionFailure::FutureVersion { .. },
            ..
        })
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
        request: RequestId::new(tenant(), "another").unwrap(),
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
            &TargetSnapshot::new(
                TargetSnapshotId::new(tenant(), "targets").unwrap(),
                2,
                SnapshotCompleteness::Complete,
                vec![key("d1")]
            )
            .unwrap(),
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
    let empty = compute(
        &Policy::draft(PolicyId::new(tenant(), "policy").unwrap()),
        &targets(&["d1"]),
        &[],
    )
    .unwrap();
    assert!(!empty.scheduling_open());
    assert!(empty.intents().is_empty());
}
#[test]
fn immutable_version_and_payload_conflicts_are_rejected() {
    let p = active(1);
    let changed = Version::new(
        PolicyId::new(tenant(), "policy").unwrap(),
        1,
        PayloadRef::new(PayloadId::new(tenant(), "payload").unwrap(), 1, [9; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    assert_eq!(
        p.transition(1, Transition::Activate(changed.clone()))
            .unwrap_err(),
        PolicyError::VersionConflict { version: 1 }
    );
    let bad = ExecutionRecord::new(changed, key("d1"), Progress::Planned, Effect::Unknown).unwrap();
    assert_eq!(
        compute(&p, &targets(&["d1"]), std::slice::from_ref(&bad)).unwrap_err(),
        PolicyError::InvalidExecution {
            execution: Box::new(bad.key()),
            reason: ExecutionFailure::VersionConflict
        }
    );
    let reused_payload = Version::new(
        PolicyId::new(tenant(), "policy").unwrap(),
        2,
        PayloadRef::new(PayloadId::new(tenant(), "payload").unwrap(), 1, [9; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    assert_eq!(
        p.transition(1, Transition::Activate(reused_payload.clone()))
            .unwrap_err(),
        PolicyError::PayloadConflict {
            object: PayloadId::new(tenant(), "payload").unwrap(),
            revision: 1
        }
    );
    let p = Policy::restore(
        PolicyId::new(tenant(), "policy").unwrap(),
        2,
        Status::Active,
        Some(reused_payload),
    )
    .unwrap();
    assert_eq!(
        compute(&p, &targets(&["d1"]), &[record(1, Progress::Planned)]).unwrap_err(),
        PolicyError::InvalidExecution {
            execution: Box::new(record(1, Progress::Planned).key()),
            reason: ExecutionFailure::PayloadConflict {
                object: PayloadId::new(tenant(), "payload").unwrap(),
                revision: 1
            }
        }
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
            Policy::draft(PolicyId::new(tenant(), "policy").unwrap())
        } else {
            Policy::restore(
                PolicyId::new(tenant(), "policy").unwrap(),
                1,
                state,
                Some(version(1)),
            )
            .unwrap()
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
    assert!(
        Policy::restore(
            PolicyId::new(tenant(), "policy").unwrap(),
            1,
            Status::Draft,
            None
        )
        .is_err()
    );
    assert!(
        Policy::restore(
            PolicyId::new(tenant(), "policy").unwrap(),
            0,
            Status::Active,
            Some(version(1))
        )
        .is_err()
    );
    assert!(
        Policy::restore(
            PolicyId::new(tenant(), "policy").unwrap(),
            1,
            Status::Active,
            None
        )
        .is_err()
    );
    let p = Policy::restore(
        PolicyId::new(tenant(), "policy").unwrap(),
        u64::MAX,
        Status::Active,
        Some(version(1)),
    )
    .unwrap();
    assert_eq!(
        p.transition(u64::MAX, Transition::Pause).unwrap_err(),
        PolicyError::RevisionOverflow
    );
}
#[test]
fn tenant_policy_and_value_boundaries() {
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let foreign = DeviceId::new(other, "d1").unwrap();
    assert!(
        ExecutionRecord::new(
            version(1),
            foreign.clone(),
            Progress::Planned,
            Effect::Unknown
        )
        .is_err()
    );
    assert!(
        TargetSnapshot::new(
            TargetSnapshotId::new(tenant(), "t").unwrap(),
            1,
            SnapshotCompleteness::Complete,
            vec![foreign.clone()]
        )
        .is_err()
    );
    let foreign_targets = TargetSnapshot::new(
        TargetSnapshotId::new(other, "targets").unwrap(),
        1,
        SnapshotCompleteness::Complete,
        vec![foreign.clone()],
    )
    .unwrap();
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
            request: RequestId::new(other, "request").unwrap(),
            as_of: Timepoint::try_from(10).unwrap()
        })
        .unwrap_err(),
        PolicyError::TenantMismatch
    );
    let wrong = Version::new(
        PolicyId::new(tenant(), "other-policy").unwrap(),
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
            &[
                ExecutionRecord::new(wrong.clone(), key("d1"), Progress::Planned, Effect::Unknown)
                    .unwrap()
            ]
        )
        .unwrap_err(),
        PolicyError::InvalidExecution {
            execution: Box::new(
                ExecutionRecord::new(wrong, key("d1"), Progress::Planned, Effect::Unknown)
                    .unwrap()
                    .key()
            ),
            reason: ExecutionFailure::PolicyMismatch
        }
    );
    assert_eq!(
        DeviceId::new(tenant(), "device/原始 ID").unwrap().value(),
        "device/原始 ID"
    );
    assert!(DeviceId::new(tenant(), "a".repeat(257)).is_err());
    assert!(
        Version::new(
            PolicyId::new(tenant(), "policy").unwrap(),
            0,
            version(1).payload().clone(),
            RemovalRule::CancelOutstandingRetainEffects
        )
        .is_err()
    );
    assert!(PayloadRef::new(PayloadId::new(tenant(), "payload").unwrap(), 0, [1; 32]).is_err());
}

#[test]
fn terminal_evidence_is_historical_after_archive_exit_and_supersession() {
    let p = active(1);
    let archived = p.transition(1, Transition::Archive).unwrap();
    let scenarios = [
        (archived, targets(&["d1"])),
        (p.clone(), targets(&[])),
        (active(2), targets(&["d1"])),
    ];
    for progress in [Progress::Succeeded, Progress::Failed, Progress::Cancelled] {
        let terminal =
            ExecutionRecord::new(version(1), key("d1"), progress, Effect::VerifiedPresent).unwrap();
        for (policy, targets) in &scenarios {
            let plan = compute(policy, targets, std::slice::from_ref(&terminal)).unwrap();
            assert!(plan.intents().contains(&Intent::Retain {
                execution: terminal.clone(),
                reason: RetainReason::Historical
            }));
            assert!(!plan.intents().iter().any(
                |i| matches!(i,Intent::Cancel{execution,..} if execution.key()==terminal.key())
            ));
        }
    }
    let planned = record(1, Progress::Planned);
    let exited = compute(&p, &targets(&[]), std::slice::from_ref(&planned)).unwrap();
    assert_eq!(
        exited.intents(),
        &[Intent::Cancel {
            execution: planned,
            reason: CancelReason::ScopeExit
        }]
    );
}

#[test]
fn activating_then_pausing_still_cancels_superseded_executions() {
    let policy = active(1)
        .transition(1, Transition::Activate(version(2)))
        .unwrap()
        .transition(2, Transition::Pause)
        .unwrap();
    let old = record(1, Progress::Running);
    let plan = compute(&policy, &targets(&["d1"]), std::slice::from_ref(&old)).unwrap();
    assert!(!plan.scheduling_open());
    assert_eq!(
        plan.intents(),
        &[Intent::Cancel {
            execution: old,
            reason: CancelReason::Superseded
        }]
    );
}

#[test]
fn conflict_errors_identify_the_failed_precondition_or_record() {
    let p = active(1);
    assert_eq!(
        p.transition(0, Transition::Pause).unwrap_err(),
        PolicyError::RevisionConflict {
            expected: 0,
            actual: 1
        }
    );
    assert_eq!(
        p.transition(1, Transition::Resume).unwrap_err(),
        PolicyError::InvalidTransition {
            status: Status::Active,
            operation: TransitionKind::Resume
        }
    );
    assert_eq!(
        p.transition(1, Transition::Activate(version(1)))
            .unwrap_err(),
        PolicyError::StaleVersion {
            requested: 1,
            latest: 1
        }
    );
    let t = targets(&["d1"]);
    let old = record(1, Progress::Planned);
    assert_eq!(
        compute(&p, &t, &[old.clone(), record(1, Progress::Succeeded)]).unwrap_err(),
        PolicyError::ConflictingExecution {
            execution: old.key()
        }
    );
    assert_eq!(
        compute(&p, &t, &[record(2, Progress::Planned)]).unwrap_err(),
        PolicyError::InvalidExecution {
            execution: Box::new(record(2, Progress::Planned).key()),
            reason: ExecutionFailure::FutureVersion { latest: 1 }
        }
    );
    assert_eq!(
        Policy::restore(
            PolicyId::new(tenant(), "policy").unwrap(),
            7,
            Status::Draft,
            None
        )
        .unwrap_err(),
        PolicyError::InvalidSnapshot {
            status: Status::Draft,
            revision: 7
        }
    );
}

#[test]
fn execution_errors_distinguish_bad_records_and_version_direction() {
    let p = active(1);
    let t = targets(&["d1"]);
    let mut errors = Vec::new();
    for device in ["bad1", "bad2"] {
        let wrong = Version::new(
            PolicyId::new(tenant(), "other-policy").unwrap(),
            1,
            version(1).payload().clone(),
            RemovalRule::CancelOutstandingRetainEffects,
        )
        .unwrap();
        let bad =
            ExecutionRecord::new(wrong, key(device), Progress::Planned, Effect::Unknown).unwrap();
        errors.push(compute(&p, &t, &[record(1, Progress::Planned), bad]).unwrap_err());
    }
    assert_ne!(errors[0], errors[1], "execution identity is required");
    let future = compute(&p, &t, &[record(2, Progress::Planned)]).unwrap_err();
    let stale = p
        .transition(1, Transition::Activate(version(1)))
        .unwrap_err();
    assert_ne!(
        future.to_string(),
        stale.to_string(),
        "future facts are not version rollback"
    );
}

#[test]
fn batch_execution_errors_preserve_identity_and_closed_reason() {
    let p = active(3);
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let foreign_version = Version::new(
        PolicyId::new(other, "policy").unwrap(),
        1,
        PayloadRef::new(PayloadId::new(other, "payload").unwrap(), 1, [1; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let foreign = ExecutionRecord::new(
        foreign_version,
        DeviceId::new(other, "foreign").unwrap(),
        Progress::Running,
        Effect::Unknown,
    )
    .unwrap();
    let mismatch = Version::new(
        PolicyId::new(tenant(), "other-policy").unwrap(),
        1,
        version(1).payload().clone(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let mismatch =
        ExecutionRecord::new(mismatch, key("bad"), Progress::Running, Effect::Unknown).unwrap();
    for (bad, reason) in [
        (foreign, ExecutionFailure::TenantMismatch),
        (mismatch, ExecutionFailure::PolicyMismatch),
        (
            record(4, Progress::Running),
            ExecutionFailure::FutureVersion { latest: 3 },
        ),
    ] {
        let valid = record(1, Progress::Planned);
        for records in [vec![valid.clone(), bad.clone()], vec![bad.clone(), valid]] {
            let error = compute(&p, &targets(&["d1"]), &records).unwrap_err();
            assert_eq!(error.to_string(), reason.to_string());
            assert_eq!(
                error,
                PolicyError::InvalidExecution {
                    execution: Box::new(bad.key()),
                    reason: reason.clone()
                }
            );
        }
    }
    let draft = Policy::draft(PolicyId::new(tenant(), "policy").unwrap());
    assert_eq!(
        compute(&draft, &targets(&[]), &[record(1, Progress::Planned)]).unwrap_err(),
        PolicyError::InvalidExecution {
            execution: Box::new(record(1, Progress::Planned).key()),
            reason: ExecutionFailure::FutureVersion { latest: 0 }
        }
    );
}

#[test]
fn plan_v1_fingerprint_covers_each_variable_encoded_field() {
    let p = Policy::restore(
        PolicyId::new(tenant(), "policy").unwrap(),
        7,
        Status::Active,
        Some(version(3)),
    )
    .unwrap();
    let t = targets(&["d1"]);
    let baseline = compute(&p, &t, &[]).unwrap().id();
    for (request, time) in [("another", 10), ("request", 20)] {
        let changed = reconcile(PlanInput {
            policy: &p,
            targets: &t,
            executions: &[],
            request: RequestId::new(tenant(), request).unwrap(),
            as_of: Timepoint::try_from(time).unwrap(),
        })
        .unwrap();
        assert_eq!(baseline, changed.id(), "request/time are provenance only");
    }
    let payload = p.version().unwrap().payload();
    let changed_versions = [
        (
            "version number",
            Version::new(
                p.key().clone(),
                4,
                payload.clone(),
                RemovalRule::CancelOutstandingRetainEffects,
            )
            .unwrap(),
        ),
        (
            "payload object",
            Version::new(
                p.key().clone(),
                3,
                PayloadRef::new(
                    PayloadId::new(tenant(), "other-payload").unwrap(),
                    3,
                    [3; 32],
                )
                .unwrap(),
                RemovalRule::CancelOutstandingRetainEffects,
            )
            .unwrap(),
        ),
        (
            "payload revision",
            Version::new(
                p.key().clone(),
                3,
                PayloadRef::new(payload.object().clone(), 4, [3; 32]).unwrap(),
                RemovalRule::CancelOutstandingRetainEffects,
            )
            .unwrap(),
        ),
        (
            "payload digest",
            Version::new(
                p.key().clone(),
                3,
                PayloadRef::new(payload.object().clone(), 3, [4; 32]).unwrap(),
                RemovalRule::CancelOutstandingRetainEffects,
            )
            .unwrap(),
        ),
    ];
    for (field, v) in changed_versions {
        let changed = Policy::restore(p.key().clone(), 7, Status::Active, Some(v)).unwrap();
        assert_ne!(
            baseline,
            compute(&changed, &t, &[]).unwrap().id(),
            "{field}"
        );
    }
    for (field, revision, status) in [
        ("policy revision", 8, Status::Active),
        ("paused status", 7, Status::Paused),
        ("archived status", 7, Status::Archived),
    ] {
        let changed =
            Policy::restore(p.key().clone(), revision, status, p.version().cloned()).unwrap();
        assert_ne!(
            baseline,
            compute(&changed, &t, &[]).unwrap().id(),
            "{field}"
        );
    }
    let other_policy = PolicyId::new(tenant(), "other-policy").unwrap();
    let v = Version::new(
        other_policy.clone(),
        3,
        payload.clone(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let changed = Policy::restore(other_policy, 7, Status::Active, Some(v)).unwrap();
    assert_ne!(
        baseline,
        compute(&changed, &t, &[]).unwrap().id(),
        "policy identity"
    );
    for (field, name, revision, members) in [
        ("target identity", "other-targets", 1, vec![key("d1")]),
        ("target revision", "targets", 2, vec![key("d1")]),
        ("target member", "targets", 1, vec![key("d2")]),
        ("target count", "targets", 1, vec![key("d1"), key("d2")]),
    ] {
        let changed = TargetSnapshot::new(
            TargetSnapshotId::new(tenant(), name).unwrap(),
            revision,
            SnapshotCompleteness::Complete,
            members,
        )
        .unwrap();
        assert_ne!(
            baseline,
            compute(&p, &changed, &[]).unwrap().id(),
            "{field}"
        );
    }
    let fact = record(1, Progress::Planned);
    let fact_id = compute(&p, &t, std::slice::from_ref(&fact)).unwrap().id();
    assert_ne!(baseline, fact_id, "fact count");
    let v = fact.version();
    for (field, number, payload_name, revision, digest, device) in [
        ("fact version", 2, "payload", 1, [1; 32], "d1"),
        ("fact payload object", 1, "other", 1, [1; 32], "d1"),
        ("fact payload revision", 1, "payload", 2, [1; 32], "d1"),
        ("fact payload digest", 1, "payload", 1, [2; 32], "d1"),
        ("fact device", 1, "payload", 1, [1; 32], "d2"),
    ] {
        let changed = Version::new(
            v.policy().clone(),
            number,
            PayloadRef::new(
                PayloadId::new(tenant(), payload_name).unwrap(),
                revision,
                digest,
            )
            .unwrap(),
            RemovalRule::CancelOutstandingRetainEffects,
        )
        .unwrap();
        let changed =
            ExecutionRecord::new(changed, key(device), Progress::Planned, Effect::Unverified)
                .unwrap();
        assert_ne!(
            fact_id,
            compute(&p, &t, &[changed]).unwrap().id(),
            "{field}"
        );
    }
    let mut progress_ids = Vec::new();
    for progress in [
        Progress::Planned,
        Progress::Running,
        Progress::Unknown,
        Progress::Succeeded,
        Progress::Failed,
        Progress::Cancelled,
    ] {
        let changed =
            ExecutionRecord::new(v.clone(), key("d1"), progress, Effect::Unverified).unwrap();
        let id = compute(&p, &t, &[changed]).unwrap().id();
        assert!(!progress_ids.contains(&id), "progress {progress:?}");
        progress_ids.push(id);
    }
    let mut effect_ids = Vec::new();
    for effect in [
        Effect::Unverified,
        Effect::Unknown,
        Effect::VerifiedPresent,
        Effect::VerifiedAbsent,
    ] {
        let changed =
            ExecutionRecord::new(v.clone(), key("d1"), Progress::Planned, effect).unwrap();
        let id = compute(&p, &t, &[changed]).unwrap().id();
        assert!(!effect_ids.contains(&id), "effect {effect:?}");
        effect_ids.push(id);
    }
    // Tenant fields must change together to remain a valid public input.
    let other = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let policy_id = PolicyId::new(other, "policy").unwrap();
    let v = Version::new(
        policy_id.clone(),
        3,
        PayloadRef::new(PayloadId::new(other, "payload").unwrap(), 3, [3; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let changed_p = Policy::restore(policy_id, 7, Status::Active, Some(v)).unwrap();
    let changed_t = TargetSnapshot::new(
        TargetSnapshotId::new(other, "targets").unwrap(),
        1,
        SnapshotCompleteness::Complete,
        vec![DeviceId::new(other, "d1").unwrap()],
    )
    .unwrap();
    let changed = reconcile(PlanInput {
        policy: &changed_p,
        targets: &changed_t,
        executions: &[],
        request: RequestId::new(other, "request").unwrap(),
        as_of: Timepoint::try_from(10).unwrap(),
    })
    .unwrap();
    assert_ne!(baseline, changed.id(), "tenant");
}

#[test]
fn plan_v1_fixed_sha256_vectors() {
    // Independently encoded from the documented V1 fields with big-endian u64
    // lengths/numbers and SHA-256. These constants never derive from plan_id.
    // The active vector includes current/historical payloads, ordered members,
    // nonzero progress/effect tags, and the singleton Apply/removal tags.
    let p = Policy::restore(
        PolicyId::new(tenant(), "policy").unwrap(),
        7,
        Status::Active,
        Some(version(3)),
    )
    .unwrap();
    let t = TargetSnapshot::new(
        TargetSnapshotId::new(tenant(), "targets").unwrap(),
        11,
        SnapshotCompleteness::Complete,
        vec![key("d2"), key("d1")],
    )
    .unwrap();
    let fact = ExecutionRecord::new(
        version(1),
        key("d1"),
        Progress::Running,
        Effect::VerifiedPresent,
    )
    .unwrap();
    let hex = |id: PlanId| {
        id.bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(compute(&p, &t, &[fact]).unwrap().id()),
        "05eabf7c7b0d2c0f911bb5b021d70697ff5a7ea7f1a4840c9b21925cb9c163ab"
    );
    // Draft locks the absent-version tag, zero revision and empty sets.
    let draft = Policy::draft(PolicyId::new(tenant(), "policy").unwrap());
    assert_eq!(
        hex(compute(&draft, &targets(&[]), &[]).unwrap().id()),
        "ac19e7eb9c3dcb4c803e41d3fb66dde125deaadbf6761abe57a6e2c44be8e24c"
    );
}
