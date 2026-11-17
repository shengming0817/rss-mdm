use rss_mdm_recovery_observation::{Observations, Phase};
use rss_reconcile::{Completion, Error, ErrorKind, Observation, Scope, Stage, Target};
use rss_request_context::TenantId;

fn scope(tenant: u32, domain: &str) -> Scope {
    Scope::new(
        TenantId::parse(&format!("00000000-0000-0000-0000-{tenant:012}")).unwrap(),
        domain,
    )
    .unwrap()
}
fn failed(scope: &Scope, kind: ErrorKind) -> Observation {
    Observation::ScanFailed {
        scope: scope.clone(),
        error: Error::new(kind),
    }
}

#[test]
fn only_confirmed_scan_of_the_exact_scope_clears_its_failure() {
    let a = scope(1, "jobs");
    let b = scope(2, "jobs");
    let other_domain = scope(1, "events");
    let mut state = Observations::default();
    for kind in [
        ErrorKind::Transient,
        ErrorKind::Deadline,
        ErrorKind::CommitUnknown,
    ] {
        // This also represents a timeout that dropped the store future before it returned.
        state.observe(&failed(&a, kind), Some(10));
        state.scan(&b, Ok(()), Some(20));
        state.scan(&other_domain, Ok(()), None);
        state.discovery("jobs", Ok(()), Some(30));
        state.settled(
            &Target::new(a.clone(), "scan").unwrap(),
            Completion::Converged,
        );
        assert_eq!(state.snapshot().scan.unwrap().failure, Some(kind));
        assert!(state.snapshot().failed());
        assert_eq!(state.snapshot().unresolved_attempts, 0);
        state.scan(&a, Ok(()), Some(5)); // A wall clock may move backwards.
        assert_eq!(state.snapshot().recovery, Phase::Healthy);
    }
}

#[test]
fn discovery_domains_scan_and_target_settlement_have_distinct_identities() {
    let a = scope(1, "jobs");
    let target = Target::new(a.clone(), "inputs").unwrap();
    let mut state = Observations::default();
    state.discovery("jobs", Err(ErrorKind::Deadline), Some(2));
    state.discovery("events", Ok(()), Some(9));
    state.scan(&a, Ok(()), Some(10));
    assert_eq!(
        state.snapshot().discovery.unwrap().failure,
        Some(ErrorKind::Deadline)
    );
    state.observe(
        &Observation::AttemptFailed {
            target: target.clone(),
            stage: Stage::Finish,
            error: Error::new(ErrorKind::CommitUnknown),
        },
        Some(11),
    );
    state.discovery("jobs", Ok(()), Some(12));
    assert_eq!(
        state.snapshot().recovery,
        Phase::Failed(ErrorKind::CommitUnknown)
    );
    assert_eq!(
        state.snapshot().latest_failure.unwrap().stage,
        Stage::Finish
    );
    state.settled(&target, Completion::Suspended { failures: 1 });
    assert_eq!(state.snapshot().unresolved_attempts, 1);
    state.settled(
        &target,
        Completion::Reobserve(std::time::Duration::from_secs(1)),
    );
    assert_eq!(state.snapshot().recovery, Phase::Healthy);
}

#[test]
fn relay_rounds_and_epochs_cannot_acknowledge_each_other() {
    let a = scope(1, "jobs");
    let mut state = Observations::default();
    state.relay(&a, 1, Err(ErrorKind::CommitUnknown), None);
    state.relay_round("jobs", Ok(()), None);
    state.relay(&a, 2, Ok(()), None);
    state.discovery("jobs", Ok(()), None);
    assert!(state.snapshot().failed());
    state.relay_round("jobs", Err(ErrorKind::Transient), None);
    state.relay(&a, 1, Ok(()), None);
    assert!(state.snapshot().failed());
    state.relay_round("jobs", Ok(()), None);
    assert!(!state.snapshot().failed());
}

#[test]
fn shared_budget_updates_known_keys_but_never_invents_recovery_after_overflow() {
    let mut state = Observations::default();
    state.discovery("jobs", Err(ErrorKind::Transient), None);
    for n in 1..1000 {
        state.scan(&scope(n, "jobs"), Err(ErrorKind::Deadline), None);
    }
    state.scan(&scope(1, "jobs"), Err(ErrorKind::CommitUnknown), Some(1));
    assert!(!state.snapshot().truncated);
    assert_eq!(
        state.snapshot().scan.unwrap().failure,
        Some(ErrorKind::CommitUnknown)
    );
    state.scan(&scope(1000, "jobs"), Err(ErrorKind::Transient), None);
    state.discovery("jobs", Ok(()), None);
    for n in 1..=1000 {
        state.scan(&scope(n, "jobs"), Ok(()), None);
    }
    assert!(state.snapshot().truncated);
    assert!(state.snapshot().failed());
    assert!(!Observations::default().snapshot().truncated);
}

#[test]
fn input_recovery_clears_the_exact_target_across_all_attempt_stages() {
    let target = Target::new(scope(1, "jobs"), "inputs").unwrap();
    let peer = Target::new(scope(1, "events"), "inputs").unwrap();
    for stage in [Stage::Observe, Stage::Apply, Stage::Renew, Stage::Finish] {
        let mut state = Observations::default();
        for target in [&target, &peer] {
            state.observe(
                &Observation::AttemptFailed {
                    target: target.clone(),
                    stage,
                    error: Error::new(ErrorKind::CommitUnknown),
                },
                None,
            );
        }
        state.inputs(&target, Ok(()), None);
        assert_eq!(state.snapshot().unresolved_attempts, 1);
        assert_eq!(state.snapshot().latest_failure.unwrap().stage, stage);
        state.settled(&peer, Completion::Converged);
        assert_eq!(state.snapshot().recovery, Phase::Healthy);
    }
}
