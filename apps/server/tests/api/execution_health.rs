use super::*;
#[test]
fn every_execution_owner_participates_with_only_its_actual_phases() {
    use rss_mdm_recovery_observation::{Health as OwnerHealth, Phase};
    let healthy = OwnerHealth {
        task: Some(rss_runtime::TaskState::Running),
        stopping: false,
        recovery: Phase::Healthy,
        relay: Some(Phase::Healthy),
        inputs: None,
    };
    let mut owners = vec![healthy.clone(); 9];
    assert!(matches!(
        recovery_component(&owners).readiness,
        Readiness::Ready
    ));
    for index in 0..owners.len() {
        owners[index].recovery = Phase::Failed(rss_reconcile::ErrorKind::CommitUnknown);
        let status = recovery_component(&owners);
        assert!(matches!(status.readiness, Readiness::NotReady));
        assert!(
            status
                .reasons
                .iter()
                .any(|r| matches!(r, Reason::SettlementUnknown))
        );
        owners[index] = healthy.clone();
    }
    owners[4].relay = Some(Phase::Initializing);
    assert!(matches!(
        recovery_component(&owners).readiness,
        Readiness::NotReady
    ));
    owners[4] = healthy;
    assert!(matches!(
        recovery_component(&owners).readiness,
        Readiness::Ready
    ));
}

#[test]
fn owner_failure_survives_another_owner_success_until_recovery() {
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
