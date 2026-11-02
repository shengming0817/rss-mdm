use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_agent_wire::{da, task_trust};
use uuid::Uuid;

#[test]
fn configuration_signature_covers_authority_content_and_delivery() {
    let content=serde_json::from_value(serde_json::json!({"mac":null,"windows":{"kind":"whfb"},"selfEnrollment":false,"enabled":true,"role":null})).unwrap();
    let value = da::Configuration {
        service_id: Uuid::from_u128(1),
        tenant: Uuid::from_u128(2),
        id: Uuid::from_u128(3),
        version: Uuid::from_u128(6),
        operation_id: Uuid::from_u128(7),
        revision: 1,
        trust_revision: 1,
        audience: da::Audience::Tenant,
        delivery: da::DeliveryPermission::Da,
        managed_fields: vec![],
        issued_at: 100,
        expires_at: 200,
        native: da::NativeExpectation::new(&content, vec![], None).unwrap(),
        content,
    };
    let payload = value.payload().unwrap();
    let bytes = da::SignedConfiguration::signing_bytes(&payload, "configuration").unwrap();
    let random = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let signature = key.sign(&bytes);
    use ring::signature::KeyPair;
    let verifier =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key());
    verifier.verify(&bytes, signature.as_ref()).unwrap();
    for (field, new_value) in [
        ("serviceId", serde_json::json!(Uuid::from_u128(4))),
        ("tenant", serde_json::json!(Uuid::from_u128(4))),
        ("id", serde_json::json!(Uuid::from_u128(4))),
        ("revision", serde_json::json!(2)),
        ("trustRevision", serde_json::json!(2)),
        ("version", serde_json::json!(Uuid::from_u128(8))),
        ("operationId", serde_json::json!(Uuid::from_u128(8))),
        (
            "audience",
            serde_json::json!({"kind":"device","device":"one","registration":Uuid::from_u128(5),"generation":1}),
        ),
        ("delivery", serde_json::json!("managed_mandatory")),
        ("issuedAt", serde_json::json!(101)),
        ("expiresAt", serde_json::json!(201)),
    ] {
        let mut altered = serde_json::to_value(&value).unwrap();
        altered[field] = new_value;
        let altered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered).unwrap());
        assert!(
            verifier
                .verify(
                    &da::SignedConfiguration::signing_bytes(&altered, "configuration").unwrap(),
                    signature.as_ref()
                )
                .is_err(),
            "{field}"
        );
    }
    let mut altered = value.clone();
    altered.content.enabled = false;
    assert!(
        verifier
            .verify(
                &da::SignedConfiguration::signing_bytes(
                    &altered.payload().unwrap(),
                    "configuration"
                )
                .unwrap(),
                signature.as_ref()
            )
            .is_err()
    );
    assert!(
        verifier
            .verify(
                &da::SignedConfiguration::signing_bytes(&payload, "other-key").unwrap(),
                signature.as_ref()
            )
            .is_err()
    );
    let mut invalid = value;
    invalid.revision = u64::MAX;
    assert!(invalid.payload().is_err());
    let pretty = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(
                &URL_SAFE_NO_PAD.decode(&payload).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    assert!(
        verifier
            .verify(
                &da::SignedConfiguration::signing_bytes(&pretty, "configuration").unwrap(),
                signature.as_ref()
            )
            .is_err(),
        "reserializing equal JSON changes the signed bytes"
    );
}

#[test]
fn same_public_material_cannot_acknowledge_another_use() {
    let agent = task_trust::Trust {
        version: 1,
        service_id: Uuid::from_u128(1),
        tenant: Uuid::from_u128(2),
        revision: 1,
        keys: vec![task_trust::PublicKey {
            id: "first".into(),
            public_key: URL_SAFE_NO_PAD.encode([3; 32]),
            state: task_trust::KeyState::Active,
        }],
    };
    let da = da::ConfigurationTrust {
        service_id: agent.service_id,
        tenant: agent.tenant,
        revision: agent.revision,
        keys: agent.keys.clone(),
    };
    assert_ne!(
        agent.installation_digest().unwrap(),
        da.installation_digest().unwrap()
    );
}

#[test]
fn native_expectation_binds_public_generator_inputs() {
    let content = rss_mdm_agent_wire::runtime::AccessConfiguration {
        mac: Some(Default::default()),
        windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::Disabled,
        self_enrollment: false,
        enabled: true,
        role: None,
    };
    let native = da::MacNativeInput {
        deployment: rss_mdm_agent_wire::platform_sso::Configuration {
            team_id: "ABCDEFGHIJ".into(),
            extension_id: "example.da.extension".into(),
            application_id: "example.da".into(),
            application_version: "1.0".into(),
            client_id: Uuid::from_u128(10),
        },
        origin: "https://da.example".into(),
    };
    let bindings = vec![
        da::NativeBinding {
            schema: "Configuration".into(),
            identifier: "example.da.profile".into(),
            uuid: Uuid::from_u128(11),
            version: 1,
        },
        da::NativeBinding {
            schema: "mdm/profiles/com.apple.extensiblesso.yaml".into(),
            identifier: "example.da.extension".into(),
            uuid: Uuid::from_u128(12),
            version: 1,
        },
    ];
    let expected =
        da::NativeExpectation::new(&content, bindings.clone(), Some(native.clone())).unwrap();
    let mut changed = native;
    changed.origin = "https://other.example".into();
    assert_ne!(
        expected.digest,
        da::NativeExpectation::new(&content, bindings.clone(), Some(changed))
            .unwrap()
            .digest
    );
    let mut changed = bindings.clone();
    changed[1].uuid = Uuid::from_u128(11);
    assert!(da::NativeExpectation::new(&content, changed, expected.mac.clone()).is_err());
    assert!(da::NativeExpectation::new(&content, bindings, None).is_err());
}
