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
fn record(n: u64, progress: Progress) -> ExecutionRecord {
    ExecutionRecord::new(version(n), key("d1"), progress, Effect::Unverified).unwrap()
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
fn every_progress_effect_and_lifecycle_preserves_execution_evidence() {
    let active = active(2);
    let paused = active
        .transition(active.revision(), Transition::Pause)
        .unwrap();
    let archived = active
        .transition(active.revision(), Transition::Archive)
        .unwrap();
    for policy in [&active, &paused, &archived] {
        for targeted in [true, false] {
            for n in [1, 2] {
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
                        let fact =
                            ExecutionRecord::new(version(n), key("d1"), progress, effect).unwrap();
                        let actual = classify_record(policy, targeted, &fact).unwrap();
                        let cancel = policy.status() == Status::Archived || !targeted || n != 2;
                        match actual {
                            Intent::Cancel { execution, reason } => {
                                assert_eq!(execution, fact);
                                assert!(cancel && !progress.is_terminal());
                                assert_eq!(
                                    reason,
                                    if policy.status() == Status::Archived {
                                        CancelReason::Archived
                                    } else if !targeted {
                                        CancelReason::ScopeExit
                                    } else {
                                        CancelReason::Superseded
                                    }
                                );
                            }
                            Intent::Retain { execution, reason } => {
                                assert_eq!(execution, fact);
                                assert!(!cancel || progress.is_terminal());
                                assert_eq!(
                                    reason,
                                    if cancel {
                                        RetainReason::Historical
                                    } else if policy.status() == Status::Paused {
                                        RetainReason::Paused
                                    } else {
                                        RetainReason::Current
                                    }
                                );
                            }
                        }
                        if n == 2 {
                            assert!(
                                desired_for_device(
                                    policy,
                                    &key("d1"),
                                    targeted,
                                    ExecutionPresence::Current
                                )
                                .unwrap()
                                .is_none()
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn desired_actions_never_admit_executions_and_obey_all_lifecycle_states() {
    let active = active(2);
    let draft = Policy::draft(active.key().clone());
    let paused = active
        .transition(active.revision(), Transition::Pause)
        .unwrap();
    let archived = active
        .transition(active.revision(), Transition::Archive)
        .unwrap();
    for policy in [&draft, &active, &paused, &archived] {
        for targeted in [false, true] {
            for history in [
                ExecutionPresence::Absent,
                ExecutionPresence::Previous,
                ExecutionPresence::Current,
            ] {
                let desired = desired_for_device(policy, &key("d1"), targeted, history).unwrap();
                assert_eq!(
                    desired.is_some(),
                    policy.status() == Status::Active
                        && targeted
                        && history != ExecutionPresence::Current
                );
                if let Some(desired) = desired {
                    let execution = match desired {
                        DesiredIntent::Add(e) => {
                            assert_eq!(history, ExecutionPresence::Absent);
                            e
                        }
                        DesiredIntent::Supersede(e) => {
                            assert_eq!(history, ExecutionPresence::Previous);
                            e
                        }
                    };
                    assert_eq!(execution.key().version(), 2);
                    assert_eq!(execution.key().device(), &key("d1"));
                    assert_eq!(execution.payload(), version(2).payload());
                }
            }
        }
    }
    let foreign = TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    assert_eq!(
        desired_for_device(
            &active,
            &DeviceId::new(foreign, "d1").unwrap(),
            true,
            ExecutionPresence::Absent
        ),
        Err(PolicyError::TenantMismatch)
    );
}
#[test]
fn current_version_payload_and_future_execution_fail_closed() {
    let policy = active(1);
    assert!(matches!(
        classify_record(&policy, true, &record(2, Progress::Running)),
        Err(PolicyError::InvalidExecution {
            reason: ExecutionFailure::FutureVersion { latest: 1 },
            ..
        })
    ));
    let inconsistent = Version::new(
        policy.key().clone(),
        1,
        PayloadRef::new(PayloadId::new(tenant(), "different").unwrap(), 1, [9; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let fact =
        ExecutionRecord::new(inconsistent, key("d1"), Progress::Running, Effect::Unknown).unwrap();
    assert!(matches!(
        classify_record(&policy, true, &fact),
        Err(PolicyError::InvalidExecution {
            reason: ExecutionFailure::VersionConflict,
            ..
        })
    ));
}
#[test]
fn stream_fingerprint_covers_policy_targets_and_execution_fields() {
    let policy = active(1);
    let source = TargetSnapshotId::new(tenant(), "targets").unwrap();
    let digest = |policy: &Policy,
                  source: &TargetSnapshotId,
                  revision: u64,
                  devices: &[&str],
                  facts: &[ExecutionRecord]| {
        let mut targets = TargetDigest::empty(tenant());
        for d in devices {
            targets.push(&key(d)).unwrap();
        }
        let mut executions = ExecutionDigest::empty(policy.key().clone());
        for f in facts {
            executions.push(f).unwrap();
        }
        stream_plan_id(policy, source, revision, &targets, &executions).unwrap()
    };
    let baseline = digest(&policy, &source, 1, &["d1"], &[]);
    assert_ne!(baseline, digest(&policy, &source, 2, &["d1"], &[]));
    assert_ne!(
        baseline,
        digest(
            &policy,
            &TargetSnapshotId::new(tenant(), "other").unwrap(),
            1,
            &["d1"],
            &[]
        )
    );
    assert_ne!(baseline, digest(&policy, &source, 1, &["d2"], &[]));
    assert_ne!(baseline, digest(&policy, &source, 1, &["d1", "d2"], &[]));
    assert_ne!(
        baseline,
        digest(
            &policy
                .transition(policy.revision(), Transition::Pause)
                .unwrap(),
            &source,
            1,
            &["d1"],
            &[]
        )
    );
    let fact = record(1, Progress::Running);
    let recorded = digest(&policy, &source, 1, &["d1"], std::slice::from_ref(&fact));
    assert_ne!(baseline, recorded);
    for (progress, effect) in [
        (Progress::Unknown, Effect::Unverified),
        (Progress::Running, Effect::VerifiedPresent),
    ] {
        let changed = ExecutionRecord::new(version(1), key("d1"), progress, effect).unwrap();
        assert_ne!(recorded, digest(&policy, &source, 1, &["d1"], &[changed]));
    }
    assert_ne!(baseline, digest(&active(2), &source, 1, &["d1"], &[]));
}
