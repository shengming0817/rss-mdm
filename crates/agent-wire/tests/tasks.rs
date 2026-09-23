use rss_mdm_agent_wire::{TaskEvent, TaskEventRequest};
use serde_json::json;
use uuid::Uuid;
#[test]
fn task_events_are_closed_bounded_and_cannot_claim_identity() {
    let value = json!({"wireVersion":2,"operationId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"event":{"kind":"received"}});
    let request: TaskEventRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(request.event(), TaskEvent::Received));
    for mutate in [
        |v: &mut serde_json::Value| {
            v["wireVersion"] = json!(1);
        },
        |v: &mut serde_json::Value| {
            v["tenant"] = json!("attacker");
        },
        |v: &mut serde_json::Value| {
            v["attemptId"] = json!(Uuid::nil());
        },
        |v: &mut serde_json::Value| {
            v["event"] = json!({"kind":"applied"});
        },
    ] {
        let mut bad = value.clone();
        mutate(&mut bad);
        assert!(serde_json::from_value::<TaskEventRequest>(bad).is_err());
    }
}

#[test]
fn signatures_bind_attempt_artifact_and_permission_and_fail_closed() {
    use base64::Engine;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rss_mdm_agent_wire::*;
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let id = Uuid::new_v4();
    let spec = TaskSpec {
        wire_version: 2,
        tenant_id: id,
        device_id: "device".into(),
        platform: TaskPlatform::Macos,
        architecture: TaskArchitecture::Aarch64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        expires_at: 100,
        resource_digest: [1; 32],
        content: TaskContent {
            length: 3,
            sha256: [2; 32],
        },
        profile: ExecutorProfile::PosixSh,
        run_as: ExecutionIdentity::System,
        arguments: vec!["$(touch /bad)".into()],
        environment: Default::default(),
        timeout_seconds: 60,
        output_bytes: 4096,
        max_rows: 1,
    };
    let signature = key.sign(&spec.signing_bytes("test-key").unwrap());
    let signed = SignedTask {
        payload: spec.clone().try_into().unwrap(),
        key_id: "test-key".into(),
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref()),
    };
    let context = TaskVerification {
        key_id: "test-key",
        public_key: key.public_key().as_ref(),
        tenant_id: id,
        device_id: "device",
        platform: TaskPlatform::Macos,
        architecture: TaskArchitecture::Aarch64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        now: 99,
    };
    signed.verify(&context).unwrap();
    for bad in [
        TaskVerification {
            platform: TaskPlatform::Windows,
            ..context
        },
        TaskVerification {
            architecture: TaskArchitecture::X86_64,
            ..context
        },
        TaskVerification {
            tenant_id: Uuid::new_v4(),
            ..context
        },
        TaskVerification {
            registration_id: Uuid::new_v4(),
            ..context
        },
        TaskVerification {
            task_id: Uuid::new_v4(),
            ..context
        },
        TaskVerification {
            permit: TaskPermit::Start,
            ..context
        },
        TaskVerification {
            now: 100,
            ..context
        },
        TaskVerification {
            key_id: "wrong-key",
            ..context
        },
        TaskVerification {
            device_id: "foreign",
            ..context
        },
        TaskVerification {
            generation: 2,
            ..context
        },
    ] {
        assert!(signed.verify(&bad).is_err());
    }
    for mutate in [
        |s: &mut TaskSpec| {
            s.attempt_id = Uuid::new_v4();
        },
        |s: &mut TaskSpec| {
            s.content.sha256 = [3; 32];
        },
        |s: &mut TaskSpec| {
            s.generation = 2;
        },
        |s: &mut TaskSpec| {
            s.permit = TaskPermit::Start;
        },
    ] {
        let mut badspec = spec.clone();
        mutate(&mut badspec);
        let mut bad = signed.clone();
        bad.payload = badspec.try_into().unwrap();
        assert!(bad.verify(&context).is_err());
    }
    let mut bad = serde_json::to_value(signed.payload).unwrap();
    bad["outputBytes"] = json!(0);
    assert!(serde_json::from_value::<TaskPayload>(bad).is_err());
}

#[test]
fn task_response_schemas_and_rust_reject_unknown_major_and_authority() {
    use rss_mdm_agent_wire::{MAX_TASK_CANCELLATIONS, TaskClaimResponse, TaskEventAck};
    let samples = [
        (
            include_str!("../schema/task-claim-response-v2.schema.json"),
            json!({"wireVersion":2,"task":null,"cancellations":[]}),
        ),
        (
            include_str!("../schema/task-event-ack-v2.schema.json"),
            json!({"wireVersion":2,"accepted":true,"permit":null,"cancelRequested":false}),
        ),
    ];
    for (index, (schema, value)) in samples.into_iter().enumerate() {
        let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
        let validator = jsonschema::draft202012::new(&schema).unwrap();
        let rust_valid = |value: serde_json::Value| {
            if index == 0 {
                serde_json::from_value::<TaskClaimResponse>(value).is_ok()
            } else {
                serde_json::from_value::<TaskEventAck>(value).is_ok()
            }
        };
        assert!(validator.is_valid(&value));
        assert!(rust_valid(value.clone()));
        for (name, invalid) in [("wireVersion", json!(1)), ("tenant", json!(Uuid::new_v4()))] {
            let mut bad = value.clone();
            bad[name] = invalid;
            assert!(!validator.is_valid(&bad));
            assert!(!rust_valid(bad));
        }
    }
    let cancellation = json!({"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4()});
    let boundary = json!({
        "wireVersion":2,
        "task":null,
        "cancellations":vec![cancellation.clone(); MAX_TASK_CANCELLATIONS]
    });
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-claim-response-v2.schema.json")).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    assert!(validator.is_valid(&boundary));
    assert!(serde_json::from_value::<TaskClaimResponse>(boundary).is_ok());
    let overflow = json!({
        "wireVersion":2,
        "task":null,
        "cancellations":vec![cancellation; MAX_TASK_CANCELLATIONS + 1]
    });
    assert!(!validator.is_valid(&overflow));
    assert!(serde_json::from_value::<TaskClaimResponse>(overflow).is_err());
}
