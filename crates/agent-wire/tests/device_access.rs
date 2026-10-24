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
        factor_generation: 1,
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
        windows: Some(AccessWindowsPlan::Initialize {
            recipient: CredentialRecipient {
                key_id: "a".repeat(64),
                public_key: "AQID".into(),
            },
            expected_revision: 0,
        }),
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
    value.windows = None;
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
        windows: None,
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
            windows: None,
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

#[test]
fn device_access_can_register_with_the_canonical_capability_order() {
    use rss_mdm_agent_wire::enroll::RuntimeProfile;
    let profile: RuntimeProfile=serde_json::from_value(serde_json::json!({
        "capabilities":["inventory.collect.v1","task.execute.v1","credentials.windows.v1","device_access.v1"],
        "platform":"windows","architecture":"x86_64",
        "executionContext":{"revision":1,"osVersion":[10,0,22621,0],"userHelper":true,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}
    })).unwrap();
    assert!(profile.validate().is_ok());
    assert!(!supported_capabilities(&[
        Capability::DeviceAccessV1,
        Capability::InventoryCollectionV1
    ]));
    assert!(supported_capabilities(&[
        Capability::InventoryCollectionV1,
        Capability::DeviceAccessV1
    ]));
}

#[test]
fn initialization_aad_fences_every_generation_and_native_account() {
    let original = task();
    let subject = CredentialSubject::RssLogin {
        binding: original.binding_id,
        binding_generation: original.binding_generation,
        sid: "S-1-5-21-100-200-300-1001".into(),
    };
    let aad = original.material_aad(&subject, 0).unwrap();
    let mut next = original.clone();
    next.factor_generation += 1;
    assert_ne!(aad, next.material_aad(&subject, 0).unwrap());
    next = original.clone();
    next.attempt_id = Uuid::from_u128(90);
    assert_ne!(aad, next.material_aad(&subject, 0).unwrap());
    assert!(original.material_aad(&subject, 1).is_err());
    let mut wrong = subject.clone();
    if let CredentialSubject::RssLogin { sid, .. } = &mut wrong {
        *sid = "S-1-5-21-100-200-300-1002".into();
    }
    assert!(original.material_aad(&wrong, 0).is_err());
    let mut missing = original.clone();
    missing.windows = None;
    assert!(missing.validate().is_err());
    missing.action = AccessAction::Unbind {
        account: AccessAccount::Windows {
            sid: "S-1-5-21-100-200-300-1001".into(),
        },
    };
    assert!(missing.validate().is_ok());
}
#[test]
fn escrow_ack_preserves_exact_coordinates_and_rejects_old_shape() {
    let receipt = CredentialReceipt {
        subject: CredentialSubject::RssLogin {
            binding: Uuid::from_u128(5),
            binding_generation: 1,
            sid: "S-1-5-21-100-200-300-1001".into(),
        },
        material: Uuid::from_u128(70),
        version: 2,
    };
    let ack = TaskEventAck::new(None, false).with_credentials(vec![receipt.clone()]);
    let mut json = serde_json::to_value(&ack).unwrap();
    let decoded: TaskEventAck = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(decoded.credentials(), &[receipt]);
    json.as_object_mut().unwrap().remove("credentials");
    assert!(serde_json::from_value::<TaskEventAck>(json).is_err());
}
