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
                authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local,
            },
            configuration: AccessConfiguration {
                mac: Some(Default::default()),
                windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
                    accounts: vec![rss_mdm_agent_wire::runtime::AccessWindowsKind::Local],
                },
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
                    authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local,
                },
                configuration: AccessConfiguration {
                    mac: Some(Default::default()),
                    windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
                        accounts: vec![rss_mdm_agent_wire::runtime::AccessWindowsKind::Local],
                    },
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
            AccessAccount::Windows {
                sid: sid.into(),
                authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local
            }
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
            mac: Some(Default::default()),
            windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
                accounts: vec![rss_mdm_agent_wire::runtime::AccessWindowsKind::Local],
            },
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
            mac: Some(Default::default()),
            windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
                accounts: vec![rss_mdm_agent_wire::runtime::AccessWindowsKind::Local],
            },
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
                password_sync: AccessObservation::Unknown,
                keychain_sync: AccessObservation::Unknown,
                secure_token: state,
                volume_owner: AccessObservation::Unknown,
                filevault_unlock: AccessObservation::Unknown,
            }),
        };
        assert!(value.validate_for(TaskPlatform::Macos).is_ok());
        assert_eq!(
            value.complete(&configuration()),
            state == AccessObservation::Present
        );
        assert!(value.validate_for(TaskPlatform::Windows).is_err());
    }
    assert!(!AccessEffect::Unknown.complete(&configuration()));
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
        disposition: AccessAccountDisposition::Keep,
        account: AccessAccount::Windows {
            sid: "S-1-5-21-100-200-300-1001".into(),
            authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local,
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

#[test]
fn windows_authority_is_explicit_and_bound_to_native_identity() {
    let local = AccessAccount::Windows {
        sid: "S-1-5-21-100-200-300-1001".into(),
        authority: AccessWindowsAuthority::Local,
    };
    let domain = AccessAccount::Windows {
        sid: "S-1-5-21-100-200-300-1001".into(),
        authority: AccessWindowsAuthority::ActiveDirectory {
            domain_sid: "S-1-5-21-100-200-300".into(),
        },
    };
    assert!(local.validate().is_ok());
    assert!(domain.validate().is_ok());
    assert_ne!(local, domain);
    assert!(
        AccessAccount::Windows {
            sid: "S-1-5-21-100-200-300-1001".into(),
            authority: AccessWindowsAuthority::ActiveDirectory {
                domain_sid: "S-1-5-21-900-200-300".into()
            },
        }
        .validate()
        .is_err()
    );
    let cloud = AccessAccount::Windows {
        sid: "S-1-12-1-100-200-300-400".into(),
        authority: AccessWindowsAuthority::Entra {
            tenant_id: Uuid::from_u128(10),
            object_id: Uuid::from_u128(20),
        },
    };
    assert!(cloud.validate().is_ok());
    assert!(
        AccessAccount::Windows {
            sid: "S-1-12-1-100-200-300-400".into(),
            authority: AccessWindowsAuthority::Local,
        }
        .validate()
        .is_err()
    );
    let mut old = serde_json::to_value(local).unwrap();
    old.as_object_mut().unwrap().remove("authority");
    assert!(serde_json::from_value::<AccessAccount>(old).is_err());
}

fn configuration() -> AccessConfiguration {
    AccessConfiguration {
        self_enrollment: true,
        enabled: true,
        role: None,
        mac: Some(Default::default()),
        windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
            accounts: vec![AccessWindowsKind::Local],
        },
    }
}

#[test]
fn unbind_signature_binds_explicit_account_disposition() {
    let mut value = task();
    value.windows = None;
    let account = AccessAccount::Windows {
        sid: "S-1-5-21-100-200-300-1001".into(),
        authority: AccessWindowsAuthority::Local,
    };
    let mut signed = std::collections::BTreeSet::new();
    for disposition in [
        AccessAccountDisposition::Keep,
        AccessAccountDisposition::Disable,
        AccessAccountDisposition::Standard,
    ] {
        value.action = AccessAction::Unbind {
            account: account.clone(),
            disposition,
        };
        assert!(signed.insert(value.signing_bytes("key").unwrap()));
        let receipt = AccessEffect::Unbound { disposition };
        assert!(receipt.validate_for(TaskPlatform::Windows).is_ok());
        assert_eq!(
            serde_json::from_value::<AccessEffect>(serde_json::to_value(&receipt).unwrap())
                .unwrap(),
            receipt
        );
    }
    assert!(
        serde_json::from_value::<AccessEffect>(serde_json::json!({"state":"unbound"})).is_err()
    );
}

#[test]
fn password_application_requires_independent_password_keychain_and_volume_facts() {
    use rss_mdm_agent_wire::platform_sso::{AuthenticationMode, LoginPolicy};
    let mut config = configuration();
    let login = config.mac.as_mut().unwrap();
    login.authentication = AuthenticationMode::Password;
    login.password_provider = Some(Uuid::from_u128(77));
    login.filevault = LoginPolicy::Require;
    login.maintenance_accounts = vec!["maintenance".into()];
    assert!(config.validate().is_ok());
    for missing in 0..5 {
        let effect = AccessEffect::Applied {
            account: AccessAccount::Macos {
                generated_uid: Uuid::from_u128(20),
            },
            role: AccessRole::Standard,
            windows: None,
            mac: Some(AccessMacFacts {
                secure_token: AccessObservation::Present,
                volume_owner: if missing == 3 {
                    AccessObservation::Unknown
                } else {
                    AccessObservation::Present
                },
                password_sync: if missing == 0 {
                    AccessObservation::Unknown
                } else {
                    AccessObservation::Present
                },
                keychain_sync: if missing == 1 {
                    AccessObservation::Unknown
                } else {
                    AccessObservation::Present
                },
                filevault_unlock: if missing == 2 {
                    AccessObservation::Unknown
                } else {
                    AccessObservation::Present
                },
            }),
        };
        assert_eq!(effect.complete(&config), missing == 4);
    }
}

#[test]
fn mac_hardening_requires_password_provider_and_maintenance_path() {
    use rss_mdm_agent_wire::platform_sso::{AuthenticationMode, LoginConfiguration, LoginPolicy};
    let mut login = LoginConfiguration::default();
    assert!(login.validate().is_ok());
    login.login = LoginPolicy::Require;
    assert!(login.validate().is_err());
    login.authentication = AuthenticationMode::Password;
    assert!(login.validate().is_err());
    login.password_provider = Some(Uuid::from_u128(12));
    assert!(login.validate().is_err());
    login.maintenance_accounts = vec!["maintenance".into()];
    assert!(login.validate().is_ok());
    login.offline_grace_seconds = Some(0);
    assert!(login.validate().is_err());
    login.offline_grace_seconds = Some(300);
    assert!(login.validate().is_ok());
    login.login = LoginPolicy::Local;
    assert!(login.validate().is_err());
    login.offline_grace_seconds = None;
    login.unlock = LoginPolicy::Attempt;
    assert!(login.validate().is_ok());
    login.maintenance_accounts.push("maintenance".into());
    assert!(login.validate().is_err());
}

fn hello_task() -> AccessTaskSpec {
    let mut task = task();
    task.action = AccessAction::Apply {
        account: AccessAccount::Windows {
            sid: "S-1-12-1-1-2-3-4".into(),
            authority: AccessWindowsAuthority::Entra {
                tenant_id: Uuid::from_u128(40),
                object_id: Uuid::from_u128(41),
            },
        },
        configuration: AccessConfiguration {
            mac: None,
            windows: AccessWindowsConfiguration::Whfb,
            self_enrollment: true,
            enabled: true,
            role: None,
        },
    };
    task.windows = Some(AccessWindowsPlan::Whfb {
        retire: false,
        previous_key: None,
    });
    task
}
fn hello_facts() -> AccessWhfbFacts {
    AccessWhfbFacts {
        factor_generation: 1,
        tenant_id: Uuid::from_u128(40),
        object_id: Uuid::from_u128(41),
        policy: AccessObservation::Present,
        registration: AccessObservation::Present,
        hardware_key: AccessObservation::Present,
        key_id: Some(Uuid::from_u128(42)),
        observed_at: 101,
    }
}
#[test]
fn hello_plan_has_no_escrow_and_cannot_select_local_accounts_or_rss_provisioning() {
    let mut hello = hello_task();
    hello.validate().unwrap();
    let baseline = hello.signing_bytes("key").unwrap();
    hello.windows = Some(AccessWindowsPlan::Whfb {
        retire: false,
        previous_key: Some(Uuid::from_u128(42)),
    });
    assert_ne!(baseline, hello.signing_bytes("key").unwrap());
    hello.windows = task().windows;
    assert!(hello.validate().is_err());
    let mut hello = hello_task();
    if let AccessAction::Apply { account, .. } = &mut hello.action {
        *account = AccessAccount::Windows {
            sid: "S-1-5-21-1-2-3-4".into(),
            authority: AccessWindowsAuthority::Local,
        };
    }
    assert!(hello.validate().is_err());
    let config = AccessWindowsConfiguration::Whfb;
    assert_eq!(config.accounts(), &[AccessWindowsKind::Entra]);
}
#[test]
fn hello_policy_observation_cannot_substitute_for_registration_or_hardware_proof() {
    let AccessAction::Apply {
        account,
        configuration,
    } = hello_task().action
    else {
        panic!()
    };
    let full = hello_facts();
    let effect = |facts| AccessEffect::Applied {
        account: account.clone(),
        role: AccessRole::Standard,
        mac: None,
        windows: Some(AccessWindowsFacts::Whfb(facts)),
    };
    effect(full.clone())
        .validate_for(TaskPlatform::Windows)
        .unwrap();
    assert!(effect(full.clone()).complete(&configuration));
    for observation in [
        AccessObservation::Absent,
        AccessObservation::Unknown,
        AccessObservation::NeedsAdministrator,
    ] {
        let mut pending = full.clone();
        pending.policy = observation;
        assert!(!effect(pending).complete(&configuration));
        let mut pending = full.clone();
        pending.registration = observation;
        assert!(!effect(pending).complete(&configuration));
        let mut pending = full.clone();
        pending.hardware_key = observation;
        assert!(!effect(pending).complete(&configuration));
    }
    let mut wrong = full.clone();
    wrong.tenant_id = Uuid::from_u128(43);
    assert!(effect(wrong).validate_for(TaskPlatform::Windows).is_err());
    let mut impossible = full;
    impossible.key_id = None;
    assert!(
        effect(impossible)
            .validate_for(TaskPlatform::Windows)
            .is_err()
    );
    assert!(
        effect(hello_facts())
            .validate_for(TaskPlatform::Macos)
            .is_err()
    );
}
#[test]
fn hello_retirement_requires_observed_policy_and_credential_removal() {
    let AccessAction::Apply {
        account,
        mut configuration,
    } = hello_task().action
    else {
        panic!()
    };
    configuration.enabled = false;
    let mut facts = hello_facts();
    facts.policy = AccessObservation::Absent;
    let effect = |facts| AccessEffect::WhfbRetired {
        account: account.clone(),
        disposition: AccessAccountDisposition::Keep,
        facts,
    };
    assert!(!effect(facts.clone()).complete(&configuration));
    facts.registration = AccessObservation::Absent;
    facts.hardware_key = AccessObservation::Absent;
    facts.key_id = None;
    effect(facts.clone())
        .validate_for(TaskPlatform::Windows)
        .unwrap();
    assert!(effect(facts).complete(&configuration));
    assert!(
        !AccessEffect::Unbound {
            disposition: AccessAccountDisposition::Keep
        }
        .complete(&configuration)
    );
    let mut task = hello_task();
    task.action = AccessAction::Unbind {
        account,
        disposition: AccessAccountDisposition::Keep,
    };
    assert!(task.validate().is_err());
    task.windows = Some(AccessWindowsPlan::Whfb {
        retire: true,
        previous_key: None,
    });
    task.validate().unwrap();
}
