use super::*;
#[test]
fn recovery_reports_each_phase_and_keeps_other_owner_success_separate() {
    use rss_mdm_recovery_observation::{Health as OwnerHealth, Phase};
    let healthy = OwnerHealth {
        task: Some(rss_runtime::TaskState::Running),
        stopping: false,
        recovery: Phase::Healthy,
        scan: Phase::Healthy,
        unresolved_attempts: 0,
        truncated: false,
        relay: Some(Phase::Healthy),
        inputs: None,
    };
    let mut failed = healthy.clone();
    failed.recovery = Phase::Failed(rss_reconcile::ErrorKind::CommitUnknown);
    failed.unresolved_attempts = 1;
    let script = recovery_component(ComponentName::ScriptExecution, &failed);
    let collection = recovery_component(ComponentName::CollectionExecution, &healthy);
    assert!(matches!(script.readiness, Readiness::NotReady));
    assert!(matches!(collection.readiness, Readiness::Ready));
    let value = serde_json::to_value(script).unwrap();
    assert_eq!(value["name"], "script_execution");
    assert_eq!(value["runner"]["unresolvedAttempts"], 1);
    assert_eq!(value["phases"][0]["reason"], "settlement_unknown");
    assert_eq!(value["phases"][1]["state"], "healthy");
    assert_eq!(value["phases"].as_array().unwrap().len(), 2);
    failed.recovery = Phase::Healthy;
    failed.unresolved_attempts = 0;
    assert!(matches!(
        recovery_component(ComponentName::ScriptExecution, &failed).readiness,
        Readiness::Ready
    ));
}

#[test]
fn unknown_counts_and_missing_optional_owners_are_not_zero_or_failed() {
    let mut policy = component(ComponentName::Policy, true);
    apply_queues(&mut policy, Err(HealthFailure::Storage));
    assert!(
        policy
            .queues
            .iter()
            .all(|queue| queue.count.is_none() && queue.truncated.is_none())
    );
    let optional = unmounted(ComponentName::NativeRecoveryCredentials);
    assert!(!optional.mounted);
    assert!(matches!(optional.readiness, Readiness::NotApplicable));
    assert!(matches!(optional.health, Health::NotApplicable));
    let count = queue(QueueName::Pending, Some(1001));
    assert_eq!(count.count, Some(1000));
    assert_eq!(count.truncated, Some(true));
}

#[test]
fn retained_policy_input_failure_revokes_only_its_component() {
    let mut policy = component(ComponentName::Policy, true);
    let group = component(ComponentName::Group, true);
    apply_configuration_input(&mut policy, Ok(true));
    assert!(matches!(policy.readiness, Readiness::NotReady));
    assert!(matches!(group.readiness, Readiness::Ready));
}
