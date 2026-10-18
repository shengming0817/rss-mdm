use rss_contract::Timepoint;
use rss_mdm_software_release::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn at(n: i64) -> Timepoint {
    Timepoint::try_from(n).unwrap()
}
fn actor() -> ActorId {
    ActorId::new(tenant(), "operator").unwrap()
}
fn evidence(n: i64) -> Evidence {
    Evidence {
        actor: actor(),
        digest: Digest::from_bytes([9; 32]),
        at: at(n),
    }
}
fn publication(target: &str) -> Publication {
    let content = Content::new(
        SoftwareIdentity::new(SoftwareIdentityFields {
            source: target.into(),
            package: "App".into(),
            version: "2".into(),
            platform: "windows".into(),
        })
        .unwrap(),
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
        Digest::from_bytes([3; 32]),
        vec![
            VariantContent::new(
                "x64",
                "msi",
                vec![Artifact::new("installer", Digest::from_bytes([4; 32])).unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let binding = PublicationBinding {
        publication: PublicationKey::new(tenant(), "record").unwrap(),
        content: content.digest(),
        target: TargetId::new(tenant(), target).unwrap(),
        target_digest: Digest::from_bytes([2; 32]),
        evidence: evidence(1),
        lifecycle: Digest::from_bytes([8; 32]),
        actor: actor(),
        at: at(1),
    };
    Publication::new(content, binding).unwrap()
}
fn request(p: &Publication, key: &str, operation: Operation) -> Request {
    Request {
        id: RequestId::new(tenant(), key).unwrap(),
        actor: actor(),
        expected_revision: p.snapshot().revision,
        as_of: at(10),
        operation,
    }
}
fn apply(p: &mut Publication, key: &str, op: Operation) -> (Receipt, Decision) {
    let r = request(p, key, op);
    let Transition::Applied {
        next,
        receipt,
        decision,
    } = p.transition(r.clone(), None).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        next.transition(r, Some(&receipt)).unwrap(),
        Transition::Replayed(receipt.clone())
    );
    *p = *next;
    (receipt, decision)
}
#[test]
fn direct_acceptance_has_one_immutable_target_and_attempt() {
    let a = publication("internal");
    let b = publication("secondary");
    assert_eq!(a.snapshot().attempt.attempt, 1);
    assert_eq!(a.snapshot().attempt.outcome, PublicationOutcome::Pending);
    assert_ne!(a.snapshot().attempt.id(), b.snapshot().attempt.id());
    let mut withdrawn = a.clone();
    apply(&mut withdrawn, "withdraw", Operation::Withdraw);
    assert!(withdrawn.snapshot().withdrawn);
    assert!(!b.snapshot().withdrawn);
    assert_eq!(a.snapshot().attempt, withdrawn.snapshot().attempt);
}
#[test]
fn unknown_cannot_retry_and_late_attempt_cannot_overwrite() {
    let mut p = publication("internal");
    let id = p.snapshot().attempt.id();
    apply(
        &mut p,
        "unknown",
        Operation::Record {
            publication: id,
            attempt: 1,
            outcome: PublicationResult::Unknown(evidence(10)),
        },
    );
    assert_eq!(
        p.transition(
            request(
                &p,
                "retry",
                Operation::Retry {
                    publication: id,
                    attempt: 1
                }
            ),
            None
        ),
        Err(Error::ReconciliationRequired)
    );
    apply(
        &mut p,
        "failed",
        Operation::Record {
            publication: id,
            attempt: 1,
            outcome: PublicationResult::NotApplied(evidence(10)),
        },
    );
    let (_, d) = apply(
        &mut p,
        "retry",
        Operation::Retry {
            publication: id,
            attempt: 1,
        },
    );
    assert!(matches!(d,Decision::Publish(ref a) if a.attempt==2&&a.id()==id));
    assert_eq!(
        p.transition(
            request(
                &p,
                "late",
                Operation::Record {
                    publication: id,
                    attempt: 1,
                    outcome: PublicationResult::Applied(evidence(10))
                }
            ),
            None
        ),
        Err(Error::IdentityMismatch)
    );
}
#[test]
fn withdrawal_retains_late_truth_without_reopening() {
    let mut p = publication("internal");
    let id = p.snapshot().attempt.id();
    apply(&mut p, "withdraw", Operation::Withdraw);
    apply(
        &mut p,
        "applied",
        Operation::Record {
            publication: id,
            attempt: 1,
            outcome: PublicationResult::Applied(evidence(10)),
        },
    );
    assert!(p.snapshot().withdrawn);
    assert!(matches!(
        p.snapshot().attempt.outcome,
        PublicationOutcome::Reported(PublicationResult::Applied(_))
    ));
    assert_eq!(
        p.transition(
            request(
                &p,
                "retry",
                Operation::Retry {
                    publication: id,
                    attempt: 1
                }
            ),
            None
        ),
        Err(Error::PublicationClosed)
    );
    assert_eq!(
        p.transition(
            request(
                &p,
                "contradict",
                Operation::Record {
                    publication: id,
                    attempt: 1,
                    outcome: PublicationResult::NotApplied(evidence(10))
                }
            ),
            None
        ),
        Err(Error::ResultConflict)
    );
}
#[test]
fn replay_checks_all_original_fields_and_cas() {
    let p = publication("internal");
    let original = request(&p, "close", Operation::Withdraw);
    let Transition::Applied { next, receipt, .. } = p.transition(original.clone(), None).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        next.transition(original.clone(), Some(&receipt)),
        Ok(Transition::Replayed(_))
    ));
    let mut changed = original.clone();
    changed.actor = ActorId::new(tenant(), "other").unwrap();
    assert_eq!(
        next.transition(changed, Some(&receipt)),
        Err(Error::RequestConflict)
    );
    assert!(matches!(
        next.transition(original, None),
        Err(Error::RevisionConflict { .. })
    ));
}
#[test]
fn retry_and_record_replay_fingerprints_cover_every_effect_field() {
    let pending = publication("internal");
    let id = pending.snapshot().attempt.id();
    let record = Operation::Record {
        publication: id,
        attempt: 1,
        outcome: PublicationResult::NotApplied(evidence(10)),
    };
    let mut failed = pending.clone();
    apply(&mut failed, "failure", record.clone());
    for (p, operation) in [
        (pending, record),
        (
            failed,
            Operation::Retry {
                publication: id,
                attempt: 1,
            },
        ),
    ] {
        let original = request(&p, "original", operation);
        let Transition::Applied { next, receipt, .. } =
            p.transition(original.clone(), None).unwrap()
        else {
            panic!()
        };
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.actor = ActorId::new(tenant(), "other").unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.expected_revision += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.as_of = at(11);
        variants.push(changed);
        for field in 0..6 {
            let mut changed = original.clone();
            match &mut changed.operation {
                Operation::Retry {
                    publication,
                    attempt,
                }
                | Operation::Record {
                    publication,
                    attempt,
                    ..
                } => {
                    if field == 0 {
                        *publication = PublicationId::from_digest(Digest::from_bytes([99; 32]));
                    }
                    if field == 1 {
                        *attempt += 1;
                    }
                }
                _ => unreachable!(),
            }
            if field >= 2 {
                let Operation::Record { outcome, .. } = &mut changed.operation else {
                    continue;
                };
                let mut e = evidence(10);
                match field {
                    2 => {
                        *outcome = PublicationResult::Applied(e);
                    }
                    3 => {
                        e.actor = ActorId::new(tenant(), "different-evidence").unwrap();
                        *outcome = PublicationResult::NotApplied(e);
                    }
                    4 => {
                        e.digest = Digest::from_bytes([77; 32]);
                        *outcome = PublicationResult::NotApplied(e);
                    }
                    _ => {
                        e.at = at(9);
                        *outcome = PublicationResult::NotApplied(e);
                    }
                }
            }
            variants.push(changed);
        }
        for changed in variants {
            assert_eq!(
                next.transition(changed, Some(&receipt)),
                Err(Error::RequestConflict)
            );
        }
    }
}
#[test]
fn restore_rejects_identity_time_and_tenant_corruption() {
    let p = publication("internal");
    assert_eq!(Publication::restore(p.snapshot().clone()).unwrap(), p);
    let mut s = p.snapshot().clone();
    s.attempt.binding.content = Digest::from_bytes([7; 32]);
    assert!(Publication::restore(s).is_err());
    let mut s = p.snapshot().clone();
    s.attempt.requested_at = at(2);
    assert!(Publication::restore(s).is_err());
    let mut s = p.snapshot().clone();
    s.attempt.binding.target = TargetId::new(
        TenantId::parse("20000000-0000-0000-0000-000000000002").unwrap(),
        "internal",
    )
    .unwrap();
    assert_eq!(Publication::restore(s), Err(Error::TenantMismatch));
}
