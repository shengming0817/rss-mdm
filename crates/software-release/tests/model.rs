use rss_contract::Timepoint;
use rss_mdm_software_release::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn at(n: u64) -> Timepoint {
    Timepoint::try_from(n as i64).unwrap()
}
fn actor(name: &str) -> ActorId {
    ActorId::new(tenant(), name).unwrap()
}
fn digest(n: u8) -> Digest {
    Digest::from_bytes([n; 32])
}
fn content(n: u8) -> Content {
    Content::new(
        SoftwareIdentity::new(SoftwareIdentityFields {
            source: "private".into(),
            package: "Acme.App".into(),
            version: "1.0".into(),
            platform: "windows".into(),
        })
        .unwrap(),
        digest(1),
        digest(2),
        digest(3),
        vec![
            VariantContent::new(
                "x64",
                "msi",
                vec![Artifact::new("installer", digest(n)).unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn candidate() -> Candidate {
    Candidate::new(
        CandidateId::new(tenant(), "candidate").unwrap(),
        content(4),
        at(1),
    )
}
fn request(c: &Candidate, name: &str, who: &str, operation: Operation) -> Request {
    Request {
        id: RequestId::new(tenant(), name).unwrap(),
        actor: actor(who),
        expected_revision: c.snapshot().revision,
        as_of: at(100),
        operation,
    }
}
fn apply(c: &mut Candidate, name: &str, who: &str, op: Operation) -> (Receipt, Decision) {
    match c.transition(request(c, name, who, op), None).unwrap() {
        Transition::Applied {
            next,
            receipt,
            decision,
        } => {
            *c = *next;
            (receipt, decision)
        }
        Transition::Replayed(_) => panic!("new request"),
    }
}
fn validation(c: &Candidate, ring: Ring) -> Validation {
    Validation {
        candidate: c.snapshot().id.clone(),
        content: c.snapshot().content.digest(),
        ring,
        evidence: evidence(),
        verdict: Verdict::Passed,
    }
}
fn publish_op(c: &Candidate, ring: Ring) -> Operation {
    Operation::Publish {
        validation: validation(c, ring),
        lifecycle: digest(7),
    }
}
fn published_pending(c: &mut Candidate, ring: Ring) -> Publication {
    let op = publish_op(c, ring);
    match apply(
        c,
        &format!("publish-{}", c.snapshot().revision),
        "publisher",
        op,
    )
    .1
    {
        Decision::Publish(p) => *p,
        _ => panic!("publication"),
    }
}
fn record(c: &mut Candidate, p: &Publication, outcome: PublicationResult) -> Decision {
    apply(
        c,
        &format!("record-{}", c.snapshot().revision),
        "service",
        Operation::Record {
            ring: p.binding.validation.ring,
            publication: p.id(),
            attempt: p.attempt,
            outcome,
        },
    )
    .1
}
fn evidence() -> Evidence {
    Evidence {
        actor: actor("backend"),
        digest: digest(9),
        at: at(100),
    }
}

#[test]
fn unknown_requires_reconciliation_and_withdrawal_never_reopens() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    assert!(matches!(
        record(&mut c, &p, PublicationResult::Unknown(evidence())),
        Decision::Reconcile { .. }
    ));
    assert!(
        c.transition(
            request(
                &c,
                "retry",
                "publisher",
                Operation::Retry {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: p.attempt
                }
            ),
            None
        )
        .is_err()
    );
    apply(&mut c, "withdraw", "publisher", Operation::Quarantine);
    record(&mut c, &p, PublicationResult::Applied(evidence()));
    assert_eq!(c.snapshot().disposition, Disposition::Quarantined);
    assert!(c.snapshot().ring_state(Ring::Test).is_published());
    assert!(
        c.transition(
            request(
                &c,
                "reopen",
                "publisher",
                Operation::Publish {
                    validation: p.binding.validation.clone(),
                    lifecycle: p.binding.lifecycle
                }
            ),
            None
        )
        .is_err()
    );
}

#[test]
fn canonical_order_and_input_budgets() {
    let b = content(4);
    let a = Artifact::new("a", digest(1)).unwrap();
    let z = Artifact::new("z", digest(2)).unwrap();
    let create = |items| {
        VariantContent::new("x64", "msi", items).and_then(|v| {
            Content::new(
                b.software().clone(),
                b.description(),
                b.source_snapshot(),
                b.manifest(),
                vec![v],
            )
        })
    };
    assert_eq!(
        create(vec![a.clone(), z.clone()]),
        create(vec![z, a.clone()])
    );
    assert_eq!(create(vec![]), Err(Error::InvalidArtifacts));
    assert_eq!(create(vec![a.clone(), a]), Err(Error::InvalidArtifacts));
    assert!(
        create(
            (0..256)
                .map(|n| Artifact::new(n.to_string(), digest(1)).unwrap())
                .collect()
        )
        .is_ok()
    );
    assert_eq!(
        create(
            (0..257)
                .map(|n| Artifact::new(n.to_string(), digest(1)).unwrap())
                .collect()
        ),
        Err(Error::InvalidArtifacts)
    );
    for bad in ["", "\0", "\n"] {
        assert!(ActorId::new(tenant(), bad).is_err());
    }
    assert!(ActorId::new(tenant(), "a".repeat(2048)).is_ok());
    assert!(ActorId::new(tenant(), "a".repeat(2049)).is_err());
    assert!(Digest::parse(&"a".repeat(64)).is_ok());
    assert_eq!(Digest::parse(&"g".repeat(64)), Err(Error::InvalidDigest));
    assert_eq!(Digest::parse(&"a".repeat(63)), Err(Error::InvalidDigest));
}

#[test]
fn same_candidate_input_is_deterministic_and_tenant_separated() {
    let mut a = candidate();
    let mut b = candidate();
    let pa = published_pending(&mut a, Ring::Test);
    let pb = published_pending(&mut b, Ring::Test);
    assert_eq!(a, b);
    assert_eq!(pa.id(), pb.id());
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let mut different = pa.binding.clone();
    different.validation.candidate = CandidateId::new(foreign, "candidate").unwrap();
    assert_ne!(different.publication_id(), pa.id());
}

#[test]
fn new_request_does_not_duplicate_an_outstanding_publication() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    let (_, decision) = apply(
        &mut c,
        "another-request",
        "publisher",
        Operation::Publish {
            validation: p.binding.validation.clone(),
            lifecycle: p.binding.lifecycle,
        },
    );
    assert_eq!(
        decision,
        Decision::Reconcile {
            publication: p.id(),
            attempt: 1
        }
    );
    assert_eq!(
        c.transition(
            request(&c, "replace", "publisher", Operation::Replace(content(5))),
            None
        ),
        Err(Error::ContentFrozen)
    );
}

#[test]
fn only_confirmed_not_applied_allows_same_identity_retry() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    record(&mut c, &p, PublicationResult::NotApplied(evidence()));
    let Decision::Publish(retry) = apply(
        &mut c,
        "retry",
        "publisher",
        Operation::Retry {
            ring: Ring::Test,
            publication: p.id(),
            attempt: p.attempt,
        },
    )
    .1
    else {
        panic!("retry")
    };
    assert_eq!(retry.id(), p.id());
    assert_eq!(retry.attempt, 2);
    assert_eq!(
        c.transition(
            request(
                &c,
                "late",
                "service",
                Operation::Record {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: 1,
                    outcome: PublicationResult::Applied(evidence())
                }
            ),
            None
        ),
        Err(Error::IdentityMismatch)
    );
    record(&mut c, &retry, PublicationResult::Applied(evidence()));
    assert_eq!(
        c.transition(
            request(
                &c,
                "contradiction",
                "service",
                Operation::Record {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: 2,
                    outcome: PublicationResult::NotApplied(evidence())
                }
            ),
            None
        ),
        Err(Error::ResultConflict)
    );
}

#[test]
fn receipt_replay_checks_all_original_inputs_and_cannot_rewind() {
    let mut c = candidate();
    let req = request(&c, "withdraw", "operator", Operation::Quarantine);
    let (receipt, _) = apply(&mut c, "withdraw", "operator", Operation::Quarantine);
    assert_eq!(
        receipt.fingerprint,
        Digest::parse("f2b56d1bcc70d1776a0ec50c6b5334b0e00c02c5206afde818ddd4342bde0a09").unwrap()
    );
    for changed in [
        Request {
            actor: actor("other"),
            ..req.clone()
        },
        Request {
            as_of: at(101),
            ..req.clone()
        },
        Request {
            expected_revision: 1,
            ..req.clone()
        },
        Request {
            operation: Operation::Deprecate,
            ..req.clone()
        },
    ] {
        assert_eq!(
            c.transition(changed, Some(&receipt)),
            Err(Error::RequestConflict)
        );
    }
    for changed in [
        Receipt {
            revision: receipt.revision + 1,
            ..receipt.clone()
        },
        Receipt {
            at: at(99),
            ..receipt.clone()
        },
        Receipt {
            before_revision: 5,
            ..receipt.clone()
        },
    ] {
        assert_eq!(
            c.transition(req.clone(), Some(&changed)),
            Err(Error::InvalidSnapshot)
        );
    }
    assert_eq!(
        c.transition(req.clone(), None),
        Err(Error::RevisionConflict {
            expected: 0,
            actual: 1
        })
    );
    assert!(matches!(
        c.transition(req, Some(&receipt)).unwrap(),
        Transition::Replayed(_)
    ));
}

#[test]
fn tenant_identity_and_time_are_checked_at_each_boundary() {
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let c = candidate();
    let mut req = request(&c, "foreign", "operator", Operation::Quarantine);
    req.id = RequestId::new(foreign, "foreign").unwrap();
    assert_eq!(c.transition(req, None), Err(Error::TenantMismatch));
    let mut req = request(&c, "foreign", "operator", Operation::Quarantine);
    req.actor = ActorId::new(foreign, "operator").unwrap();
    assert_eq!(c.transition(req, None), Err(Error::TenantMismatch));
    let mut req = request(&c, "past", "operator", Operation::Quarantine);
    req.as_of = at(0);
    assert_eq!(c.transition(req, None), Err(Error::InvalidTime));
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    let mut e = evidence();
    e.actor = ActorId::new(foreign, "backend").unwrap();
    assert_eq!(
        c.transition(
            request(
                &c,
                "foreign",
                "service",
                Operation::Record {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: 1,
                    outcome: PublicationResult::Applied(e)
                }
            ),
            None
        ),
        Err(Error::TenantMismatch)
    );
    for wrong in [
        Operation::Record {
            ring: Ring::Pilot,
            publication: p.id(),
            attempt: 1,
            outcome: PublicationResult::Applied(evidence()),
        },
        Operation::Record {
            ring: Ring::Test,
            publication: PublicationId::from_digest(digest(99)),
            attempt: 1,
            outcome: PublicationResult::Applied(evidence()),
        },
    ] {
        assert_eq!(
            c.transition(request(&c, "wrong", "service", wrong), None),
            Err(Error::IdentityMismatch)
        );
    }
    let mut e = evidence();
    e.at = at(101);
    assert_eq!(
        c.transition(
            request(
                &c,
                "future",
                "service",
                Operation::Record {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: 1,
                    outcome: PublicationResult::Applied(e)
                }
            ),
            None
        ),
        Err(Error::InvalidTime)
    );
}

#[test]
fn restored_snapshots_reject_inconsistent_content_stages_and_evidence() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    record(&mut c, &p, PublicationResult::Applied(evidence()));
    let _ = published_pending(&mut c, Ring::Pilot);
    let base = c.snapshot().clone();
    let mut invalid = Vec::new();
    let mut s = base.clone();
    s.content = content(88);
    invalid.push(s);
    let mut s = base.clone();
    s.revision = 0;
    invalid.push(s);
    let mut s = base.clone();
    s.at = at(1);
    invalid.push(s);
    let mut s = base.clone();
    s.content_at = at(101);
    invalid.push(s);
    let mut s = base.clone();
    s.at = at(101);
    s.content_at = at(101);
    invalid.push(s);
    let mut s = base.clone();
    s.rings[0] = RingState::Candidate;
    invalid.push(s);
    let mut s = base.clone();
    s.rings[0] = RingState::NotStarted;
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.binding.predecessor = None;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.attempt = 0;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.binding.validation.verdict = Verdict::Failed;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.binding.actor = ActorId::new(
            TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap(),
            "foreign",
        )
        .unwrap();
    }
    invalid.push(s);
    for s in invalid {
        assert!(Candidate::restore(s).is_err());
    }
    let restored = Candidate::restore(base).unwrap();
    let RingState::Publication(p) = restored.snapshot().ring_state(Ring::Pilot) else {
        panic!()
    };
    let req = request(
        &restored,
        "after-restart",
        "publisher",
        Operation::Publish {
            validation: p.binding.validation.clone(),
            lifecycle: p.binding.lifecycle,
        },
    );
    assert!(matches!(
        restored.transition(req, None).unwrap(),
        Transition::Applied {
            decision: Decision::Reconcile { .. },
            ..
        }
    ));
}

#[test]
fn checked_revision_and_attempt_overflow_leave_original_unchanged() {
    let mut snapshot = candidate().snapshot().clone();
    snapshot.revision = u64::MAX;
    let c = Candidate::restore(snapshot).unwrap();
    assert_eq!(
        c.transition(
            request(&c, "overflow", "operator", Operation::Quarantine),
            None
        ),
        Err(Error::Overflow)
    );
    assert_eq!(c.snapshot().disposition, Disposition::Active);
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    record(&mut c, &p, PublicationResult::NotApplied(evidence()));
    let mut snapshot = c.snapshot().clone();
    if let RingState::Publication(p) = &mut snapshot.rings[0] {
        p.attempt = u64::MAX;
    }
    let c = Candidate::restore(snapshot).unwrap();
    assert_eq!(
        c.transition(
            request(
                &c,
                "overflow",
                "publisher",
                Operation::Retry {
                    ring: Ring::Test,
                    publication: p.id(),
                    attempt: u64::MAX
                }
            ),
            None
        ),
        Err(Error::Overflow)
    );
}

fn rejects_changed_operation(c: &Candidate, op: Operation, changes: Vec<Operation>, who: &str) {
    let req = request(c, "fingerprint", who, op);
    let Transition::Applied { next, receipt, .. } = c.transition(req.clone(), None).unwrap() else {
        panic!("first execution")
    };
    assert!(matches!(
        next.transition(req.clone(), Some(&receipt)).unwrap(),
        Transition::Replayed(_)
    ));
    for operation in changes {
        assert_eq!(
            next.transition(
                Request {
                    operation,
                    ..req.clone()
                },
                Some(&receipt)
            ),
            Err(Error::RequestConflict)
        );
    }
}

macro_rules! changed_fields {
    ($base:expr; $($($field:ident).+ = $value:expr),+ $(,)?) => {
        vec![$({ let mut changed = $base.clone(); changed.$($field).+ = $value; changed }),+]
    };
}

#[test]
fn request_replay_binds_validation_and_content_fields() {
    let c = candidate();
    rejects_changed_operation(
        &c,
        Operation::Replace(content(5)),
        vec![Operation::Replace(content(6))],
        "publisher",
    );
    let v = Validation {
        candidate: c.snapshot().id.clone(),
        content: c.snapshot().content.digest(),
        ring: Ring::Test,
        evidence: evidence(),
        verdict: Verdict::Passed,
    };
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let changes = changed_fields!(v;
        candidate = CandidateId::new(tenant(), "other").unwrap(),
        candidate = CandidateId::new(foreign, "candidate").unwrap(),
        content = digest(99), ring = Ring::Pilot,
        evidence.actor = actor("other"),
        evidence.actor = ActorId::new(foreign, "backend").unwrap(),
        evidence.digest = digest(99), evidence.at = at(99),
        verdict = Verdict::Failed, verdict = Verdict::Unknown,
    );
    rejects_changed_operation(
        &c,
        Operation::Publish {
            validation: v,
            lifecycle: digest(7),
        },
        changes
            .into_iter()
            .map(|validation| Operation::Publish {
                validation,
                lifecycle: digest(7),
            })
            .collect(),
        "publisher",
    );
}

#[test]
fn request_replay_binds_retry_and_each_external_result_field() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    let record_op = |ring, publication, attempt, outcome| Operation::Record {
        ring,
        publication,
        attempt,
        outcome,
    };
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    for result in [
        PublicationResult::Unknown,
        PublicationResult::NotApplied,
        PublicationResult::Applied,
    ] {
        let e = evidence();
        let mut changes = changed_fields!(e;
            actor = actor("other"), actor = ActorId::new(foreign, "backend").unwrap(),
            digest = digest(99), at = at(99),
        )
        .into_iter()
        .map(|e| record_op(Ring::Test, p.id(), 1, result(e)))
        .collect::<Vec<_>>();
        changes.extend([
            record_op(Ring::Pilot, p.id(), 1, result(e.clone())),
            record_op(
                Ring::Test,
                PublicationId::from_digest(digest(99)),
                1,
                result(e.clone()),
            ),
            record_op(Ring::Test, p.id(), 2, result(e.clone())),
        ]);
        for other in [
            PublicationResult::Unknown(e.clone()),
            PublicationResult::NotApplied(e.clone()),
            PublicationResult::Applied(e.clone()),
        ] {
            if other != result(e.clone()) {
                changes.push(record_op(Ring::Test, p.id(), 1, other));
            }
        }
        rejects_changed_operation(
            &c,
            record_op(Ring::Test, p.id(), 1, result(e)),
            changes,
            "service",
        );
    }
    record(&mut c, &p, PublicationResult::NotApplied(evidence()));
    let retry = |ring, publication, attempt| Operation::Retry {
        ring,
        publication,
        attempt,
    };
    rejects_changed_operation(
        &c,
        retry(Ring::Test, p.id(), 1),
        vec![
            retry(Ring::Pilot, p.id(), 1),
            retry(Ring::Test, PublicationId::from_digest(digest(99)), 1),
            retry(Ring::Test, p.id(), 2),
        ],
        "publisher",
    );
}

#[test]
fn one_publish_has_no_approval_and_each_ring_requires_previous_success() {
    let mut c = candidate();
    for ring in [Ring::Pilot, Ring::Production] {
        assert_eq!(
            c.transition(request(&c, "skip", "operator", publish_op(&c, ring)), None),
            Err(Error::PromotionBlocked)
        );
    }
    let mut previous = None;
    for ring in Ring::ALL {
        let p = published_pending(&mut c, ring);
        assert_eq!(p.binding.predecessor, previous);
        previous = Some(p.id());
        record(&mut c, &p, PublicationResult::Applied(evidence()));
        assert_eq!(Candidate::restore(c.snapshot().clone()).unwrap(), c);
    }
}
#[test]
fn automatic_validation_rejects_failed_unknown_stale_and_future_inputs() {
    let c = candidate();
    let base = validation(&c, Ring::Test);
    let mut changes = vec![];
    for verdict in [Verdict::Failed, Verdict::Unknown] {
        let mut v = base.clone();
        v.verdict = verdict;
        changes.push(v);
    }
    let mut v = base.clone();
    v.content = digest(99);
    changes.push(v);
    let mut v = base.clone();
    v.evidence.at = at(0);
    changes.push(v);
    let mut v = base;
    v.evidence.at = at(101);
    changes.push(v);
    for validation in changes {
        assert!(
            c.transition(
                request(
                    &c,
                    "invalid",
                    "operator",
                    Operation::Publish {
                        validation,
                        lifecycle: digest(7)
                    }
                ),
                None
            )
            .is_err()
        );
    }
}
#[test]
fn publication_identity_excludes_operator_and_observation_but_binds_content_target_and_tenant() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    let mut b = p.binding.clone();
    b.actor = actor("another");
    b.at = at(200);
    b.validation.evidence = evidence();
    b.validation.evidence.digest = digest(99);
    b.lifecycle = digest(98);
    assert_eq!(b.publication_id(), p.id());
    for b in changed_fields!(p.binding; validation.content=digest(99),validation.ring=Ring::Pilot,predecessor=Some(PublicationId::from_digest(digest(1))),validation.candidate=CandidateId::new(tenant(),"new").unwrap())
    {
        assert_ne!(b.publication_id(), p.id());
    }
}
#[test]
fn published_content_is_frozen_and_old_request_replay_never_reopens() {
    let mut c = candidate();
    let op = publish_op(&c, Ring::Test);
    let req = request(&c, "publish", "operator", op.clone());
    let (receipt, _) = apply(&mut c, "publish", "operator", op);
    assert_eq!(
        c.transition(
            request(&c, "replace", "operator", Operation::Replace(content(9))),
            None
        ),
        Err(Error::ContentFrozen)
    );
    apply(&mut c, "close", "operator", Operation::Quarantine);
    assert_eq!(
        c.transition(req, Some(&receipt)).unwrap(),
        Transition::Replayed(receipt)
    );
    assert_eq!(
        c.transition(
            request(&c, "new", "other", publish_op(&c, Ring::Test)),
            None
        ),
        Err(Error::PublicationClosed)
    );
}
#[test]
fn different_operator_can_retry_but_changed_lifecycle_cannot_reuse_pending_publication() {
    let mut c = candidate();
    let p = published_pending(&mut c, Ring::Test);
    let mut op = publish_op(&c, Ring::Test);
    if let Operation::Publish { lifecycle, .. } = &mut op {
        *lifecycle = digest(99);
    }
    assert_eq!(
        c.transition(request(&c, "stale", "other", op), None),
        Err(Error::StaleEvidence)
    );
    record(&mut c, &p, PublicationResult::NotApplied(evidence()));
    let (_, decision) = apply(
        &mut c,
        "retry",
        "another",
        Operation::Retry {
            ring: Ring::Test,
            publication: p.id(),
            attempt: 1,
        },
    );
    let Decision::Publish(next) = decision else {
        panic!()
    };
    assert_eq!(next.id(), p.id());
    assert_eq!(next.attempt, 2);
}
