use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_agent_wire::{da, task_trust};
use uuid::Uuid;

#[test]
fn configuration_signature_covers_authority_content_and_delivery() {
    let value = da::Configuration {
        service_id: Uuid::from_u128(1), tenant: Uuid::from_u128(2), id: Uuid::from_u128(3),
        revision: 1, epoch: 1, audience: da::Audience::Tenant, delivery: da::DeliveryPermission::Da,
        issued_at: 100, expires_at: 200,
        content: serde_json::from_value(serde_json::json!({"mac":null,"windows":{"kind":"whfb"},"selfEnrollment":false,"enabled":true,"role":null})).unwrap(),
    };
    let bytes = value.signing_bytes("configuration").unwrap();
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
        ("epoch", serde_json::json!(2)),
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
        let altered: da::Configuration = serde_json::from_value(altered).unwrap();
        assert!(
            verifier
                .verify(
                    &altered.signing_bytes("configuration").unwrap(),
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
                &altered.signing_bytes("configuration").unwrap(),
                signature.as_ref()
            )
            .is_err()
    );
    assert!(
        verifier
            .verify(
                &value.signing_bytes("other-key").unwrap(),
                signature.as_ref()
            )
            .is_err()
    );
    let mut invalid = value;
    invalid.revision = u64::MAX;
    assert!(invalid.signing_bytes("configuration").is_err());
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
