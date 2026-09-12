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
            architecture: "x64".into(),
            variant: "msi".into(),
        })
        .unwrap(),
        digest(1),
        digest(2),
        digest(3),
        vec![Artifact::new("installer", digest(n)).unwrap()],
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
fn validate(c: &mut Candidate, ring: Ring) {
    let validation = Validation {
        candidate: c.snapshot().id.clone(),
        content: c.snapshot().content.digest(),
        ring,
        evidence: Evidence {
            actor: actor("validator"),
            digest: digest(8),
            at: at(100),
        },
        verdict: Verdict::Passed,
    };
    apply(
        c,
        &format!("validate-{}", c.snapshot().revision),
        "publisher",
        Operation::Validate(validation),
    );
}
fn approve(c: &mut Candidate, ring: Ring) -> Digest {
    apply(
        c,
        &format!("approve-{}", c.snapshot().revision),
        "approver",
        Operation::Approve {
            ring,
            publisher: actor("publisher"),
            policy: ActorPolicy::default(),
        },
    );
    match c.snapshot().ring_state(ring) {
        RingState::Approved(a) => a.digest(),
        _ => panic!("approval"),
    }
}
fn authorized(c: &mut Candidate, ring: Ring) -> Publication {
    validate(c, ring);
    let approval = approve(c, ring);
    match apply(
        c,
        &format!("publish-{}", c.snapshot().revision),
        "publisher",
        Operation::Authorize { ring, approval },
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
            ring: p.approval.validation.ring,
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
fn approval_changes_and_ring_order() {
    let mut c = candidate();
    validate(&mut c, Ring::Test);
    let old = approve(&mut c, Ring::Test);
    apply(
        &mut c,
        "replace",
        "publisher",
        Operation::Replace(content(5)),
    );
    assert_eq!(c.snapshot().ring_state(Ring::Test), &RingState::Candidate);
    assert!(
        c.transition(
            request(
                &c,
                "old",
                "publisher",
                Operation::Authorize {
                    ring: Ring::Test,
                    approval: old
                }
            ),
            None
        )
        .is_err()
    );
    let p = authorized(&mut c, Ring::Test);
    assert!(
        c.transition(
            request(
                &c,
                "skip",
                "approver",
                Operation::Approve {
                    ring: Ring::Production,
                    publisher: actor("publisher"),
                    policy: ActorPolicy::Separate
                }
            ),
            None
        )
        .is_err()
    );
    record(&mut c, &p, PublicationResult::Applied(evidence()));
    let _ = authorized(&mut c, Ring::Pilot);
}
#[test]
fn unknown_requires_reconciliation_and_withdrawal_never_reopens() {
    let mut c = candidate();
    let p = authorized(&mut c, Ring::Test);
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
                Operation::Authorize {
                    ring: Ring::Test,
                    approval: p.approval.digest()
                }
            ),
            None
        )
        .is_err()
    );
}
#[test]
fn replay_cannot_return_old_state_or_publish_decision() {
    let mut c = candidate();
    validate(&mut c, Ring::Test);
    let approval = approve(&mut c, Ring::Test);
    let req = request(
        &c,
        "publish",
        "publisher",
        Operation::Authorize {
            ring: Ring::Test,
            approval,
        },
    );
    let (receipt, _) = apply(&mut c, "publish", "publisher", req.operation.clone());
    apply(&mut c, "withdraw", "publisher", Operation::Quarantine);
    assert_eq!(
        c.transition(req, Some(&receipt)).unwrap(),
        Transition::Replayed(receipt)
    );
}

#[test]
fn all_rings_require_their_own_evidence_and_approval() {
    let mut c = candidate();
    let mut ids = Vec::new();
    for ring in Ring::ALL {
        let approval_without_validation = request(
            &c,
            "premature",
            "approver",
            Operation::Approve {
                ring,
                publisher: actor("publisher"),
                policy: ActorPolicy::Separate,
            },
        );
        assert!(c.transition(approval_without_validation, None).is_err());
        let p = authorized(&mut c, ring);
        if let Some(previous) = ids.last() {
            assert_eq!(p.approval.predecessor, Some(*previous));
        } else {
            assert_eq!(p.approval.predecessor, None);
        }
        ids.push(p.id());
        record(&mut c, &p, PublicationResult::Applied(evidence()));
        assert_eq!(Candidate::restore(c.snapshot().clone()).unwrap(), c);
    }
    assert!(c.snapshot().rings.iter().all(RingState::is_published));
    assert!(ids.windows(2).all(|w| w[0] != w[1]));
}

#[test]
fn actor_policy_is_explicit_and_authorization_requires_the_bound_publisher() {
    let mut c = candidate();
    validate(&mut c, Ring::Test);
    assert_eq!(
        c.transition(
            request(
                &c,
                "self",
                "publisher",
                Operation::Approve {
                    ring: Ring::Test,
                    publisher: actor("publisher"),
                    policy: ActorPolicy::default()
                }
            ),
            None
        ),
        Err(Error::ActorConstraint)
    );
    apply(
        &mut c,
        "explicit-self",
        "publisher",
        Operation::Approve {
            ring: Ring::Test,
            publisher: actor("publisher"),
            policy: ActorPolicy::AllowSameActor,
        },
    );
    let RingState::Approved(approval) = c.snapshot().ring_state(Ring::Test) else {
        panic!("approval")
    };
    assert_eq!(
        c.transition(
            request(
                &c,
                "wrong-publisher",
                "different",
                Operation::Authorize {
                    ring: Ring::Test,
                    approval: approval.digest()
                }
            ),
            None
        ),
        Err(Error::ActorConstraint)
    );
}

#[test]
fn changed_failed_and_unknown_validation_invalidate_approval() {
    for verdict in [Verdict::Passed, Verdict::Failed, Verdict::Unknown] {
        let mut c = candidate();
        validate(&mut c, Ring::Test);
        let old = approve(&mut c, Ring::Test);
        let RingState::Approved(a) = c.snapshot().ring_state(Ring::Test) else {
            panic!()
        };
        let mut changed = a.validation.clone();
        changed.evidence.digest = digest(99);
        changed.verdict = verdict;
        apply(
            &mut c,
            "new-evidence",
            "validator",
            Operation::Validate(changed),
        );
        assert!(!matches!(
            *c.snapshot().ring_state(Ring::Test),
            RingState::Approved(_)
        ));
        assert!(
            c.transition(
                request(
                    &c,
                    "stale",
                    "publisher",
                    Operation::Authorize {
                        ring: Ring::Test,
                        approval: old
                    }
                ),
                None
            )
            .is_err()
        );
        if verdict != Verdict::Passed {
            assert_eq!(
                c.transition(
                    request(
                        &c,
                        "approve-failure",
                        "approver",
                        Operation::Approve {
                            ring: Ring::Test,
                            publisher: actor("publisher"),
                            policy: ActorPolicy::Separate
                        }
                    ),
                    None
                ),
                Err(Error::ValidationRequired)
            );
        }
    }
}

#[test]
fn every_content_component_is_bound_and_replacement_discards_approval() {
    let base = content(4);
    let mut alternatives = vec![
        Content::new(
            base.software().clone(),
            digest(99),
            base.source_snapshot(),
            base.manifest(),
            base.artifacts().to_vec(),
        )
        .unwrap(),
        Content::new(
            base.software().clone(),
            base.description(),
            digest(99),
            base.manifest(),
            base.artifacts().to_vec(),
        )
        .unwrap(),
        Content::new(
            base.software().clone(),
            base.description(),
            base.source_snapshot(),
            digest(99),
            base.artifacts().to_vec(),
        )
        .unwrap(),
        content(99),
        Content::new(
            base.software().clone(),
            base.description(),
            base.source_snapshot(),
            base.manifest(),
            vec![Artifact::new("other-key", digest(4)).unwrap()],
        )
        .unwrap(),
    ];
    for i in 0..6 {
        let mut parts = base.software().fields().clone();
        match i {
            0 => parts.source = "changed".into(),
            1 => parts.package = "changed".into(),
            2 => parts.version = "changed".into(),
            3 => parts.platform = "changed".into(),
            4 => parts.architecture = "changed".into(),
            _ => parts.variant = "changed".into(),
        }
        alternatives.push(
            Content::new(
                SoftwareIdentity::new(parts).unwrap(),
                base.description(),
                base.source_snapshot(),
                base.manifest(),
                base.artifacts().to_vec(),
            )
            .unwrap(),
        );
    }
    for changed in alternatives {
        assert_ne!(base.digest(), changed.digest());
        let mut c = candidate();
        validate(&mut c, Ring::Test);
        let old = approve(&mut c, Ring::Test);
        if changed.software() != base.software() {
            assert_eq!(
                c.transition(
                    request(&c, "replace", "publisher", Operation::Replace(changed)),
                    None
                ),
                Err(Error::ContentConflict)
            );
        } else {
            apply(&mut c, "replace", "publisher", Operation::Replace(changed));
            assert!(
                c.transition(
                    request(
                        &c,
                        "old",
                        "publisher",
                        Operation::Authorize {
                            ring: Ring::Test,
                            approval: old
                        }
                    ),
                    None
                )
                .is_err()
            );
        }
    }
}

#[test]
fn canonical_order_and_input_budgets() {
    let b = content(4);
    let a = Artifact::new("a", digest(1)).unwrap();
    let z = Artifact::new("z", digest(2)).unwrap();
    let create = |items| {
        Content::new(
            b.software().clone(),
            b.description(),
            b.source_snapshot(),
            b.manifest(),
            items,
        )
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
    for bad in ["", "../secret", "a//b", "https://host", "a b", "$secret"] {
        assert!(ActorId::new(tenant(), bad).is_err());
    }
    assert!(ActorId::new(tenant(), "a".repeat(128)).is_ok());
    assert!(ActorId::new(tenant(), "a".repeat(129)).is_err());
    assert!(Digest::parse(&"a".repeat(64)).is_ok());
    assert_eq!(Digest::parse(&"g".repeat(64)), Err(Error::InvalidDigest));
    assert_eq!(Digest::parse(&"a".repeat(63)), Err(Error::InvalidDigest));
}

#[test]
fn same_candidate_input_is_deterministic_and_tenant_separated() {
    let mut a = candidate();
    let mut b = candidate();
    let pa = authorized(&mut a, Ring::Test);
    let pb = authorized(&mut b, Ring::Test);
    assert_eq!(a, b);
    assert_eq!(pa.id(), pb.id());
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let mut different = pa.approval.clone();
    different.validation.candidate = CandidateId::new(foreign, "candidate").unwrap();
    assert_ne!(different.publication_id(), pa.id());
}

#[test]
fn approval_fingerprint_covers_every_authority_input() {
    let mut c = candidate();
    let p = authorized(&mut c, Ring::Test);
    let base = p.approval.clone();
    let mut changes = Vec::new();
    let mut changed = base.clone();
    changed.publisher = actor("new");
    changes.push(changed);
    let mut changed = base.clone();
    changed.approver = actor("new");
    changes.push(changed);
    let mut changed = base.clone();
    changed.policy = ActorPolicy::AllowSameActor;
    changes.push(changed);
    let mut changed = base.clone();
    changed.at = at(101);
    changes.push(changed);
    let mut changed = base.clone();
    changed.predecessor = Some(PublicationId::from_digest(digest(10)));
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.ring = Ring::Pilot;
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.content = digest(10);
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.candidate = CandidateId::new(tenant(), "new").unwrap();
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.evidence.actor = actor("new");
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.evidence.digest = digest(10);
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.evidence.at = at(99);
    changes.push(changed);
    let mut changed = base.clone();
    changed.validation.verdict = Verdict::Unknown;
    changes.push(changed);
    for changed in changes {
        assert_ne!(changed.digest(), base.digest());
        assert_ne!(changed.publication_id(), p.id());
    }
}

#[test]
fn new_request_does_not_duplicate_an_outstanding_publication() {
    let mut c = candidate();
    let p = authorized(&mut c, Ring::Test);
    let (_, decision) = apply(
        &mut c,
        "another-request",
        "publisher",
        Operation::Authorize {
            ring: Ring::Test,
            approval: p.approval.digest(),
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
    let p = authorized(&mut c, Ring::Test);
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
fn withdrawal_and_deprecation_close_all_write_authorizations() {
    for op in [Operation::Quarantine, Operation::Deprecate] {
        let mut c = candidate();
        let p = authorized(&mut c, Ring::Test);
        record(&mut c, &p, PublicationResult::NotApplied(evidence()));
        apply(&mut c, "close", "operator", op);
        for denied in [
            Operation::Authorize {
                ring: Ring::Test,
                approval: p.approval.digest(),
            },
            Operation::Retry {
                ring: Ring::Test,
                publication: p.id(),
                attempt: 1,
            },
            Operation::Approve {
                ring: Ring::Pilot,
                publisher: actor("publisher"),
                policy: ActorPolicy::Separate,
            },
            Operation::Replace(content(5)),
        ] {
            assert_eq!(
                c.transition(request(&c, "denied", "publisher", denied), None),
                Err(Error::PublicationClosed)
            );
        }
        assert_eq!(Candidate::restore(c.snapshot().clone()).unwrap(), c);
    }
}

#[test]
fn receipt_replay_checks_all_original_inputs_and_cannot_rewind() {
    let mut c = candidate();
    let req = request(&c, "withdraw", "operator", Operation::Quarantine);
    let (receipt, _) = apply(&mut c, "withdraw", "operator", Operation::Quarantine);
    assert_eq!(
        receipt.fingerprint,
        Digest::parse("471b7aab510f8b9c9b5f7ce33fb24c24358d7534687330d725d379a208816498").unwrap()
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
    let p = authorized(&mut c, Ring::Test);
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
    let p = authorized(&mut c, Ring::Test);
    record(&mut c, &p, PublicationResult::Applied(evidence()));
    let _ = authorized(&mut c, Ring::Pilot);
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
        p.approval.predecessor = None;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.attempt = 0;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.approval.validation.verdict = Verdict::Failed;
    }
    invalid.push(s);
    let mut s = base.clone();
    if let RingState::Publication(p) = &mut s.rings[1] {
        p.approval.approver = p.approval.publisher.clone();
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
        Operation::Authorize {
            ring: Ring::Pilot,
            approval: p.approval.digest(),
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
    let p = authorized(&mut c, Ring::Test);
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

#[test]
fn canonical_v1_identity_vectors() {
    // Independently encoded using length-prefixed bytes and big-endian u64 values.
    let mut c = candidate();
    assert_eq!(
        c.snapshot().content.digest(),
        Digest::parse("7775bcf4d8e000ffbb627b6caa86ef22c13f7a14cf2178ff0eee8b073b8ce5a0").unwrap()
    );
    let p = authorized(&mut c, Ring::Test);
    assert_eq!(
        p.approval.digest(),
        Digest::parse("bb476bd762cd2f310438641ff9aa6df2b1df8724a899d9a725ecccf6e8762ae3").unwrap()
    );
    assert_eq!(
        p.id().digest(),
        Digest::parse("76877263034156d12bf8f4107d0d9d2fa70d418a7509b7a6529c8c5fadcde772").unwrap()
    );
}

#[test]
fn validation_cannot_predate_candidate_or_current_content() {
    let mut c = candidate();
    let validation = |c: &Candidate, when| Validation {
        candidate: c.snapshot().id.clone(),
        content: c.snapshot().content.digest(),
        ring: Ring::Test,
        evidence: Evidence {
            actor: actor("validator"),
            digest: digest(8),
            at: at(when),
        },
        verdict: Verdict::Passed,
    };
    assert_eq!(
        c.transition(
            request(
                &c,
                "too-early",
                "operator",
                Operation::Validate(validation(&c, 0))
            ),
            None
        ),
        Err(Error::InvalidTime)
    );
    let mut replace = request(&c, "replace", "publisher", Operation::Replace(content(55)));
    replace.as_of = at(200);
    let Transition::Applied { next, .. } = c.transition(replace, None).unwrap() else {
        panic!()
    };
    c = *next;
    let mut validate = request(
        &c,
        "old-verification",
        "operator",
        Operation::Validate(validation(&c, 100)),
    );
    validate.as_of = at(201);
    assert_eq!(c.transition(validate, None), Err(Error::InvalidTime));
    assert_eq!(c.snapshot().content_at, at(200));
    let mut exact = request(
        &c,
        "current-verification",
        "operator",
        Operation::Validate(validation(&c, 200)),
    );
    exact.as_of = at(201);
    let Transition::Applied { next, .. } = c.transition(exact, None).unwrap() else {
        panic!()
    };
    assert_eq!(Candidate::restore(next.snapshot().clone()).unwrap(), *next);
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
        Operation::Validate(v),
        changes.into_iter().map(Operation::Validate).collect(),
        "publisher",
    );
}

#[test]
fn request_replay_binds_approval_and_authorization_fields() {
    let mut c = candidate();
    validate(&mut c, Ring::Test);
    let approve_op = |ring, publisher, policy| Operation::Approve {
        ring,
        publisher,
        policy,
    };
    let foreign = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    rejects_changed_operation(
        &c,
        approve_op(Ring::Test, actor("publisher"), ActorPolicy::Separate),
        vec![
            approve_op(Ring::Pilot, actor("publisher"), ActorPolicy::Separate),
            approve_op(Ring::Test, actor("other"), ActorPolicy::Separate),
            approve_op(
                Ring::Test,
                ActorId::new(foreign, "publisher").unwrap(),
                ActorPolicy::Separate,
            ),
            approve_op(Ring::Test, actor("publisher"), ActorPolicy::AllowSameActor),
        ],
        "approver",
    );
    let approval = approve(&mut c, Ring::Test);
    rejects_changed_operation(
        &c,
        Operation::Authorize {
            ring: Ring::Test,
            approval,
        },
        vec![
            Operation::Authorize {
                ring: Ring::Pilot,
                approval,
            },
            Operation::Authorize {
                ring: Ring::Test,
                approval: digest(99),
            },
        ],
        "publisher",
    );
}

#[test]
fn request_replay_binds_retry_and_each_external_result_field() {
    let mut c = candidate();
    let p = authorized(&mut c, Ring::Test);
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
