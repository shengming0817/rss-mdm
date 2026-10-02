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
