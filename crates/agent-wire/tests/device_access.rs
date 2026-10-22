use rss_mdm_agent_wire::runtime::*;
use uuid::Uuid;

fn task() -> AccessTaskSpec {
    AccessTaskSpec {
        wire_version: 1,
        tenant_id: Uuid::from_u128(1),
        device_id: "endpoint".into(),
        registration_id: Uuid::from_u128(2),
        generation: 1,
        platform: TaskPlatform::Windows,
        architecture: TaskArchitecture::X86_64,
        task_id: Uuid::from_u128(3),
        attempt_id: Uuid::from_u128(4),
        permit: TaskPermit::Start,
        expires_at: 100,
        deadline: 200,
        binding_id: Uuid::from_u128(5),
        instance_id: Uuid::from_u128(8),
        principal_id: Uuid::from_u128(9),
        binding_generation: 1,
        revision: 1,
        definition_digest: [7; 32],
        action: AccessAction::Apply {
            account: AccessAccount::Windows {
                sid: "S-1-5-21-100-200-300-1001".into(),
            },
            configuration: AccessConfiguration {
                self_enrollment: true,
                enabled: true,
                role: None,
            },
        },
        authorization: TaskAuthorization::Policy {
            policy_id: Uuid::from_u128(6),
            policy_version: Uuid::from_u128(7),
        },
    }
}
#[test]
fn access_signature_binds_account_generation_and_configuration() {
    let original = task();
    let bytes = original.signing_bytes("key").unwrap();
    for changed in [
        AccessTaskSpec {
            binding_generation: 2,
            ..original.clone()
        },
        AccessTaskSpec {
            revision: 2,
            ..original.clone()
        },
        AccessTaskSpec {
            registration_id: Uuid::from_u128(20),
            ..original.clone()
        },
        AccessTaskSpec {
            action: AccessAction::Apply {
                account: AccessAccount::Windows {
                    sid: "S-1-5-21-100-200-300-1002".into(),
                },
                configuration: AccessConfiguration {
                    self_enrollment: true,
                    enabled: true,
                    role: Some(AccessRole::Administrator),
                },
            },
            ..original.clone()
        },
    ] {
        assert_ne!(bytes, changed.signing_bytes("key").unwrap());
    }
    assert_ne!(bytes, original.signing_bytes("other-key").unwrap());
    let payload = TaskPayload::DeviceAccess(Box::new(original));
    let decoded: TaskPayload =
        serde_json::from_value(serde_json::to_value(&payload).unwrap()).unwrap();
    assert_eq!(payload, decoded);
}
#[test]
fn invalid_native_identity_and_cross_platform_tasks_are_rejected() {
    for sid in [
        "Administrator",
        "S-1-5-18",
        "S-1-5-21-100-200-300-01001",
        "S-1-5-21-100-200-300-4294967296",
    ] {
        assert!(
            AccessAccount::Windows { sid: sid.into() }
                .validate()
                .is_err()
        );
    }
    let mut value = task();
    value.platform = TaskPlatform::Macos;
    value.architecture = TaskArchitecture::Aarch64;
    assert!(value.validate().is_err());
    value.action = AccessAction::Create {
        name: "../existing".into(),
        configuration: AccessConfiguration {
            self_enrollment: false,
            enabled: true,
            role: None,
        },
    };
    assert!(value.validate().is_err());
    value.action = AccessAction::Create {
        name: "employee".into(),
        configuration: AccessConfiguration {
            self_enrollment: false,
            enabled: true,
            role: None,
        },
    };
    assert!(value.validate().is_ok());
}
#[test]
fn mac_application_requires_its_own_secure_token_observation() {
    let account = AccessAccount::Macos {
        generated_uid: Uuid::from_u128(20),
    };
    let incomplete = AccessEffect::Applied {
        account: account.clone(),
        role: AccessRole::Standard,
        mac: None,
    };
    assert!(incomplete.validate_for(TaskPlatform::Macos).is_err());
    for state in [
        AccessObservation::Absent,
        AccessObservation::Unknown,
        AccessObservation::NeedsAdministrator,
        AccessObservation::Present,
    ] {
        let value = AccessEffect::Applied {
            account: account.clone(),
            role: AccessRole::Standard,
            mac: Some(AccessMacFacts {
                secure_token: state,
                volume_owner: AccessObservation::Unknown,
                filevault_unlock: AccessObservation::Unknown,
            }),
        };
        assert!(value.validate_for(TaskPlatform::Macos).is_ok());
        assert_eq!(value.complete(), state == AccessObservation::Present);
        assert!(value.validate_for(TaskPlatform::Windows).is_err());
    }
    assert!(!AccessEffect::Unknown.complete());
}
