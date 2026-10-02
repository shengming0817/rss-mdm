use super::*;
#[test]
fn cancellation_deadline_and_unknown_do_not_claim_early_completion() {
    let id = Uuid::new_v4();
    let key = rss_mdm_native_protection::Protector::new(&[17; 32]).unwrap();
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let mut operation = Remote {
        id,
        frozen: Frozen::Configuration {
            native: crate::configuration::Protected::seal(
                &key,
                tenant,
                crate::configuration::Owner::Remote { operation: id },
                &crate::configuration::Configuration {
                    target: NativeTarget::Device,
                    remove: None,
                    apply: Task::Macos {
                        request: rss_mdm_apple_mdm::native::request::Request::Declarations {
                            declarations: vec![],
                        },
                    },
                },
            )
            .unwrap(),
            grants: Default::default(),
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
