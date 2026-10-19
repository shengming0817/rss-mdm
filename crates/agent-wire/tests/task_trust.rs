use base64::Engine;
use rss_mdm_agent_wire::task_trust::{Acknowledgement, KeyState, PublicKey, Trust};
use uuid::Uuid;
fn trust() -> Trust {
    Trust {
        version: 1,
        origin: "https://agent.example.test".into(),
        tenant: Uuid::from_u128(1),
        revision: 1,
        keys: vec![PublicKey {
            id: "first".into(),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32]),
            state: KeyState::Active,
        }],
    }
}
#[test]
fn trust_is_bound_to_material_authority_and_revision() {
    let old = trust();
    let digest = old.installation_digest().unwrap();
    let mut next = old.clone();
    next.revision = 2;
    next.keys.push(PublicKey {
        id: "second".into(),
        public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2; 32]),
        state: KeyState::Prepared,
    });
    next.validate_successor(&old).unwrap();
    assert_ne!(digest, next.installation_digest().unwrap());
    assert!(old.validate_successor(&next).is_err());
    let mut changed = old.clone();
    changed.keys[0].public_key = next.keys[1].public_key.clone();
    assert!(changed.validate_successor(&old).is_err());
    changed.revision = 2;
    assert!(changed.validate_successor(&old).is_err());
    let mut foreign = next.clone();
    foreign.tenant = Uuid::from_u128(2);
    assert!(foreign.validate_successor(&old).is_err());
    foreign = next.clone();
    foreign.origin = "https://other.example.test".into();
    assert!(foreign.validate_successor(&old).is_err());
    let ack = Acknowledgement {
        operation: Uuid::from_u128(2),
        version: 1,
        registration: Uuid::from_u128(3),
        generation: 1,
        revision: 1,
        digest,
    };
    assert!(ack.matches(&old).unwrap());
    assert!(!ack.matches(&next).unwrap());
}
#[test]
fn ambiguous_keys_and_noncanonical_origins_are_rejected() {
    for origin in [
        "http://agent.example.test",
        "https://agent.example.test/",
        "https://user@agent.example.test",
        "https://agent.example.test/path",
        "https://agent.example.test?x=1",
    ] {
        let mut value = trust();
        value.origin = origin.into();
        assert!(value.validate().is_err());
    }
    let mut value = trust();
    value.keys.push(value.keys[0].clone());
    assert!(value.validate().is_err());
    value.keys[1].id = "second".into();
    value.keys[1].state = KeyState::Prepared;
    assert!(value.validate().is_err()); // Same public material under two identities.
    value.keys[1].public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2; 32]);
    assert!(value.validate().is_ok());
    value.keys.swap(0, 1);
    assert!(value.validate().is_err());
    let mut value = trust();
    value.revision = 0;
    assert!(value.validate().is_err());
}

#[test]
fn activation_cannot_skip_installed_preparation_or_reactivate_verify_only_keys() {
    let initial = trust();
    let mut prepared = initial.clone();
    prepared.revision = 2;
    prepared.keys.push(PublicKey {
        id: "second".into(),
        public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2; 32]),
        state: KeyState::Prepared,
    });
    let mut active = prepared.clone();
    active.revision = 3;
    active.keys[0].state = KeyState::VerifyOnly;
    active.keys[1].state = KeyState::Active;
    assert!(active.validate_successor(&initial).is_err());
    active.validate_successor(&prepared).unwrap();
    let mut rollback = active.clone();
    rollback.revision = 4;
    rollback.keys[0].state = KeyState::Active;
    rollback.keys[1].state = KeyState::VerifyOnly;
    assert!(rollback.validate_successor(&active).is_err());
    let mut retired = active.clone();
    retired.revision = 4;
    retired.keys.remove(0);
    retired.validate_successor(&active).unwrap();
}

#[test]
fn observation_rejects_false_applied_and_unbounded_or_ambiguous_coordinates() {
    use rss_mdm_agent_wire::task_trust::{Observation, ObservationReason, ObservationState};
    let mut value = Observation {
        operation: uuid::Uuid::new_v4(),
        version: 1,
        registration: uuid::Uuid::new_v4(),
        generation: 1,
        sequence: 1,
        target_revision: Some(2),
        target_digest: Some("a".repeat(64)),
        actual_revision: Some(1),
        actual_digest: Some("b".repeat(64)),
        state: ObservationState::Failed,
        reason: Some(ObservationReason::Storage),
        observed_at: 1,
    };
    assert!(value.validate().is_ok());
    value.state = ObservationState::Applied;
    value.reason = None;
    assert!(value.validate().is_err());
    value.actual_revision = value.target_revision;
    value.actual_digest = value.target_digest.clone();
    assert!(value.validate().is_ok());
    value.sequence = u64::MAX;
    assert!(value.validate().is_err());
    value.sequence = 1;
    value.actual_digest = None;
    assert!(value.validate().is_err());
    value.actual_revision = None;
    value.state = ObservationState::Unknown;
    assert!(value.validate().is_err());
    value.reason = Some(ObservationReason::Restart);
    assert!(value.validate().is_ok());
}

#[test]
fn observation_schema_rejects_invalid_coordinates() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/task_trust/observation-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let valid = serde_json::json!({"operation":uuid::Uuid::from_u128(1),"version":1,"registration":uuid::Uuid::from_u128(2),
        "generation":1,"sequence":1,"target_revision":null,"target_digest":null,
        "actual_revision":null,"actual_digest":null,"state":"unknown","reason":"restart","observed_at":1});
    assert!(validator.is_valid(&valid));
    for (field, value) in [
        ("version", serde_json::json!(0)),
        ("generation", serde_json::json!(0)),
        ("sequence", serde_json::json!(u64::MAX)),
        ("target_revision", serde_json::json!(0)),
        ("actual_revision", serde_json::json!(u64::MAX)),
        ("observed_at", serde_json::json!(-1)),
        ("target_digest", serde_json::json!("bad")),
        ("actual_digest", serde_json::json!("A".repeat(64))),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(!validator.is_valid(&invalid), "{field}");
        assert!(
            serde_json::from_value::<rss_mdm_agent_wire::task_trust::Observation>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
