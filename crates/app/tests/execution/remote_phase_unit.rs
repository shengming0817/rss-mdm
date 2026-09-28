use super::*;
#[test]
fn cancellation_deadline_and_unknown_do_not_claim_early_completion() {
    let mut operation = Remote {
        id: Uuid::new_v4(),
        frozen: Frozen::Configuration {
            enabled: true,
            platform: Platform::Macos,
            exit: rss_mdm_policy::Exit::Retain,
            resource_digest: [1; 32],
        },
        deadline: 100,
        cancelled: true,
        staged: false,
        snapshot: remote::Snapshot::Devices {
            devices: Default::default(),
        },
    };
    assert!(matches!(
        phase(true, false, &operation, 99),
        RemotePhase::Cancelling
    ));
    operation.cancelled = false;
    operation.staged = true;
    assert!(matches!(
        phase(true, false, &operation, 101),
        RemotePhase::Expiring
    ));
    assert!(matches!(
        phase(false, true, &operation, 101),
        RemotePhase::Unknown
    ));
    assert!(matches!(
        phase(false, false, &operation, 101),
        RemotePhase::Completed
    ));
}
