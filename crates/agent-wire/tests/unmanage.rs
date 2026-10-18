use rss_mdm_agent_wire::runtime::*;
use uuid::Uuid;

fn task() -> UnmanageTaskSpec {
    UnmanageTaskSpec {
        wire_version: WIRE_VERSION,
        tenant_id: Uuid::from_u128(1),
        device_id: "managed-device".into(),
        registration_id: Uuid::from_u128(2),
        generation: 3,
        retirement_id: Uuid::from_u128(4),
        task_id: Uuid::from_u128(5),
        attempt_id: Uuid::from_u128(6),
        permit: TaskPermit::Start,
        expires_at: 100,
        deadline: 200,
        platform: TaskPlatform::Macos,
        architecture: TaskArchitecture::Aarch64,
        authorization: TaskAuthorization::Policy {
            policy_id: Uuid::from_u128(7),
            policy_version: Uuid::from_u128(8),
        },
    }
}
#[test]
fn retirement_signature_binds_installation_authority_and_attempt() {
    let original = task();
    let bytes = original.signing_bytes("key").unwrap();
    assert!(bytes.starts_with(b"rss-mdm-agent-unmanage-v1-ed25519\0"));
    let changes: [fn(&mut UnmanageTaskSpec); 6] = [
        |s| s.registration_id = Uuid::from_u128(9),
        |s| s.generation += 1,
        |s| s.retirement_id = Uuid::from_u128(9),
        |s| s.attempt_id = Uuid::from_u128(9),
        |s| s.permit = TaskPermit::Offer,
        |s| s.expires_at += 1,
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed);
        assert_ne!(bytes, changed.signing_bytes("key").unwrap());
    }
    assert_ne!(bytes, original.signing_bytes("other-key").unwrap());
    let mut invalid = original.clone();
    invalid.generation = 0;
    assert!(invalid.signing_bytes("key").is_err());
    let mut invalid = original.clone();
    invalid.retirement_id = Uuid::nil();
    assert!(invalid.signing_bytes("key").is_err());
    let mut invalid = original.clone();
    invalid.expires_at = 201;
    assert!(invalid.signing_bytes("key").is_err());
    let payload = TaskPayload::Unmanage(Box::new(original));
    let value = serde_json::to_value(&payload).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert_eq!(payload, serde_json::from_value(value).unwrap());
}
