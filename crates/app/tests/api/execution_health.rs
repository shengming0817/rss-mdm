use super::*;
#[test]
fn execution_failure_dominates_missing_first_round_in_either_branch() {
    use rss_mdm_execution_service::health::{Health as ExecutionHealth, Phase};
    let failure = Phase::Failed(rss_reconcile::ErrorKind::Transient);
    for (recovery, relay) in [
        (failure, Phase::Initializing),
        (Phase::Initializing, failure),
    ] {
        let component = execution_component(ExecutionHealth {
            task: Some(rss_runtime::TaskState::Running),
            stopping: false,
            recovery,
            relay,
        });
        assert!(component.health == Health::Degraded);
        assert!(component.readiness == Readiness::NotReady);
        assert!(
            component
                .reasons
                .iter()
                .any(|r| matches!(r, Reason::DependencyUnavailable))
        );
        assert!(
            component
                .reasons
                .iter()
                .any(|r| matches!(r, Reason::Initializing))
        );
    }
}

#[test]
fn source_bridge_failure_survives_policy_success_until_source_recovers() {
    use rss_mdm_policy_service::worker::{AutomationFailure, RunObservation};
    let source = Some(RunObservation {
        failure: Some(AutomationFailure::SettlementUnknown),
        observed_at: Some(1),
    });
    let policy = Some(RunObservation {
        failure: None,
        observed_at: Some(2),
    });
    for (a, b) in [
        (source, policy),
        (policy, source),
        (source, None),
        (None, source),
    ] {
        assert!(matches!(
            merge_observation(a, b).unwrap().failure,
            Some(AutomationFailure::SettlementUnknown)
        ));
    }
    let recovered = Some(RunObservation {
        failure: None,
        observed_at: Some(3),
    });
    assert!(
        merge_observation(policy, recovered)
            .unwrap()
            .failure
            .is_none()
    );
    assert!(merge_observation(policy, None).is_none());
}
