use rss_mdm_agent_wire::{TaskEvent, TaskEventRequest};
use serde_json::json;
use uuid::Uuid;
#[test]
fn task_events_are_closed_bounded_and_cannot_claim_identity() {
    let value = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"event":{"kind":"received"}});
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
        wire_version: 4,
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
fn software_task_binds_approved_definition_and_artifacts_without_script_fallback() {
    use base64::Engine;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rss_mdm_agent_wire::*;
    let id = Uuid::new_v4();
    let steps = vec![SoftwareTaskStep {
        action: serde_json::from_value(json!({"package":"acme.editor","version":"2","format":"msi","primary":"installer",
            "install":{"executor":"msi","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},
            "uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"2"},
            "reboot":"report","downgrade":"deny","ownership":"managed_only","bundle":null})).unwrap(),
        artifacts: vec![SoftwareTaskArtifact {
            key: "0/installer".into(),
            length: 20_000_000,
            sha256: [2; 32],
        }],
        export_identity: None,
    }];
    let digest: [u8; 32] =
        ring::digest::digest(&ring::digest::SHA256, &serde_json::to_vec(&steps).unwrap())
            .as_ref()
            .try_into()
            .unwrap();
    let spec = SoftwareTaskSpec {
        wire_version: 4,
        tenant_id: id,
        device_id: "device".into(),
        platform: TaskPlatform::Windows,
        architecture: TaskArchitecture::X86_64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        expires_at: 200,
        steps,
        definition_digest: digest,
        intent: SoftwareTaskIntent::Install,
        start_mode: SoftwareStartMode::Automatic,
    };
    let payload: TaskPayload = spec.clone().try_into().unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-payload-v4.schema.json")).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(&payload).unwrap()));
    for change in [
        |v: &mut serde_json::Value| v["steps"] = json!([]),
        |v: &mut serde_json::Value| v["steps"][0]["artifacts"] = json!([]),
        |v: &mut serde_json::Value| v["steps"][0]["artifacts"][0]["key"] = json!("0/a//b"),
        |v: &mut serde_json::Value| v["steps"][0]["action"]["source"] = json!({}),
        |v: &mut serde_json::Value| v["steps"][0]["action"]["format"] = json!("rpm"),
        |v: &mut serde_json::Value| {
            v["steps"][0]["action"]["install"]["timeoutSeconds"] = json!("never")
        },
        |v: &mut serde_json::Value| v["publicationId"] = json!(null),
    ] {
        let mut bad = serde_json::to_value(&spec).unwrap();
        change(&mut bad);
        assert!(!validator.is_valid(&bad), "schema accepted {bad}");
        assert!(serde_json::from_value::<TaskPayload>(bad).is_err());
    }
    assert!(serde_json::from_value::<TaskSpec>(serde_json::to_value(&payload).unwrap()).is_err());
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let signed = SignedTask {
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(&payload.signing_bytes("key").unwrap()).as_ref()),
        key_id: "key".into(),
        payload,
    };
    let context = TaskVerification {
        key_id: "key",
        public_key: key.public_key().as_ref(),
        tenant_id: id,
        device_id: "device",
        platform: TaskPlatform::Windows,
        architecture: TaskArchitecture::X86_64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        now: 100,
    };
    signed.verify(&context).unwrap();
    let mut altered = spec;
    altered.steps[0].action.package = "other.editor".into();
    altered.definition_digest = ring::digest::digest(
        &ring::digest::SHA256,
        &serde_json::to_vec(&altered.steps).unwrap(),
    )
    .as_ref()
    .try_into()
    .unwrap();
    let mut forged = signed;
    forged.payload = altered.try_into().unwrap();
    assert!(forged.verify(&context).is_err());
}

#[test]
fn software_detection_requires_matching_evidence_shape() {
    use rss_mdm_agent_wire::*;
    let diagnostics = TaskDiagnostics::new(String::new(), String::new(), 1, 1, None).unwrap();
    let mut result = SoftwareTaskResult {
        intent: SoftwareTaskIntent::Install,
        installer_exit_code: Some(0),
        detection: SoftwareDetectionState::Present,
        definition_digest: [1; 32],
        observed_version: Some("1".into()),
        evidence_digest: [2; 32],
        reboot_required: false,
        diagnostics,
    };
    assert!(
        TaskEventRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            TaskEvent::SoftwareResult(result.clone())
        )
        .is_ok()
    );
    result.observed_version = None;
    assert!(
        TaskEventRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            TaskEvent::SoftwareResult(result.clone())
        )
        .is_err()
    );
    result.detection = SoftwareDetectionState::Unknown;
    assert!(
        TaskEventRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            TaskEvent::SoftwareResult(result)
        )
        .is_ok()
    );
}

#[test]
fn task_response_schemas_and_rust_reject_unknown_major_and_authority() {
    use rss_mdm_agent_wire::{MAX_TASK_CANCELLATIONS, TaskClaimResponse, TaskEventAck};
    let samples = [
        (
            include_str!("../schema/task-claim-response-v4.schema.json"),
            json!({"wireVersion":4,"task":null,"cancellations":[]}),
        ),
        (
            include_str!("../schema/task-event-ack-v4.schema.json"),
            json!({"wireVersion":4,"accepted":true,"permit":null,"cancelRequested":false}),
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
        let mut missing_nullable = value.clone();
        missing_nullable
            .as_object_mut()
            .unwrap()
            .remove(if index == 0 { "task" } else { "permit" });
        assert!(!validator.is_valid(&missing_nullable));
        assert!(!rust_valid(missing_nullable));
        for (name, invalid) in [("wireVersion", json!(1)), ("tenant", json!(Uuid::new_v4()))] {
            let mut bad = value.clone();
            bad[name] = invalid;
            assert!(!validator.is_valid(&bad));
            assert!(!rust_valid(bad));
        }
    }
    let cancellation = json!({"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4()});
    let boundary = json!({
        "wireVersion":4,
        "task":null,
        "cancellations":vec![cancellation.clone(); MAX_TASK_CANCELLATIONS]
    });
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-claim-response-v4.schema.json")).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    assert!(validator.is_valid(&boundary));
    assert!(serde_json::from_value::<TaskClaimResponse>(boundary).is_ok());
    let overflow = json!({
        "wireVersion":4,
        "task":null,
        "cancellations":vec![cancellation; MAX_TASK_CANCELLATIONS + 1]
    });
    assert!(!validator.is_valid(&overflow));
    assert!(serde_json::from_value::<TaskClaimResponse>(overflow).is_err());
}

#[test]
fn task_response_producers_can_only_construct_valid_shapes() {
    use rss_mdm_agent_wire::{
        MAX_TASK_CANCELLATIONS, TaskCancellation, TaskClaimResponse, TaskEventAck, WireError,
    };

    let task_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let cancellation = TaskCancellation::new(task_id, attempt_id).unwrap();
    assert_eq!(cancellation.task_id(), task_id);
    assert_eq!(cancellation.attempt_id(), attempt_id);
    assert_eq!(
        TaskCancellation::new(Uuid::nil(), Uuid::new_v4()),
        Err(WireError::InvalidValue)
    );

    let response = TaskClaimResponse::new(None, vec![cancellation; MAX_TASK_CANCELLATIONS])
        .expect("boundary response");
    assert!(response.task().is_none());
    assert_eq!(response.cancellations().len(), MAX_TASK_CANCELLATIONS);
    assert_eq!(serde_json::to_value(&response).unwrap()["wireVersion"], 4);
    assert_eq!(
        TaskClaimResponse::new(
            None,
            vec![
                TaskCancellation::new(Uuid::new_v4(), Uuid::new_v4()).unwrap();
                MAX_TASK_CANCELLATIONS + 1
            ],
        ),
        Err(WireError::InvalidValue)
    );

    let ack = TaskEventAck::new(None, true);
    assert!(ack.permit().is_none());
    assert!(ack.cancel_requested());
    assert_eq!(serde_json::to_value(ack).unwrap()["accepted"], true);
}

#[test]
fn task_results_require_bounded_coherent_diagnostics() {
    use rss_mdm_agent_wire::{OutputQuality, TaskDiagnostics, TaskFailure, TaskResult, WireError};

    let diagnostics = TaskDiagnostics::new("stdout".into(), "stderr".into(), 42, 1, None)
        .expect("bounded diagnostics");
    assert_eq!(diagnostics.stdout(), "stdout");
    assert_eq!(diagnostics.stderr(), "stderr");
    assert_eq!(diagnostics.duration_ms(), 42);
    assert_eq!(diagnostics.executed_at(), 1);
    assert_eq!(diagnostics.failure(), None);
    let result = TaskResult::new(
        Some(0),
        OutputQuality::Complete,
        json!({"version":"1.2"}),
        diagnostics,
    )
    .unwrap();
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.quality(), OutputQuality::Complete);
    assert_eq!(result.output(), &json!({"version":"1.2"}));
    assert!(result.diagnostics().failure().is_none());
    let request =
        TaskEventRequest::new(Uuid::new_v4(), Uuid::new_v4(), TaskEvent::Result(result)).unwrap();
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["event"]["kind"], "result");
    assert_eq!(encoded["event"]["diagnostics"]["durationMs"], 42);
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-event-request-v4.schema.json")).unwrap();
    assert!(
        jsonschema::draft202012::new(&schema)
            .unwrap()
            .is_valid(&encoded)
    );
    assert!(serde_json::from_value::<TaskEventRequest>(encoded).is_ok());

    for field in ["exitCode", "failure"] {
        let mut missing = serde_json::to_value(&request).unwrap();
        if field == "failure" {
            missing["event"]["diagnostics"]
                .as_object_mut()
                .unwrap()
                .remove(field);
        } else {
            missing["event"].as_object_mut().unwrap().remove(field);
        }
        assert!(
            !jsonschema::draft202012::new(&schema)
                .unwrap()
                .is_valid(&missing)
        );
        assert!(serde_json::from_value::<TaskEventRequest>(missing).is_err());
    }

    for invalid in [
        {
            let mut value = serde_json::to_value(&request).unwrap();
            value["event"]["exitCode"] = json!(null);
            value
        },
        {
            let mut value = serde_json::to_value(&request).unwrap();
            value["event"]["quality"] = json!("failed");
            value["event"]["diagnostics"]["failure"] = json!("non_zero_exit");
            value
        },
        {
            let mut value = serde_json::to_value(&request).unwrap();
            value["event"]["quality"] = json!("failed");
            value["event"]["diagnostics"]["failure"] = json!("launch_failed");
            value
        },
    ] {
        assert!(
            !jsonschema::draft202012::new(&schema)
                .unwrap()
                .is_valid(&invalid)
        );
        assert!(serde_json::from_value::<TaskEventRequest>(invalid).is_err());
    }

    assert_eq!(
        TaskDiagnostics::new("x".repeat(16_385), String::new(), 0, 1, None),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskDiagnostics::new(String::new(), "bad\0stderr".into(), 0, 1, None),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskDiagnostics::new(String::new(), String::new(), 604_800_001, 1, None),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskDiagnostics::new(String::new(), String::new(), 0, 0, None),
        Err(WireError::InvalidValue)
    );

    let diagnostics =
        |failure| TaskDiagnostics::new(String::new(), String::new(), 0, 1, failure).unwrap();
    assert_eq!(
        TaskResult::new(None, OutputQuality::Failed, json!(null), diagnostics(None),),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            Some(0),
            OutputQuality::Complete,
            json!(null),
            diagnostics(Some(TaskFailure::CaptureFailed)),
        ),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            None,
            OutputQuality::Truncated,
            json!(null),
            diagnostics(Some(TaskFailure::TimedOut)),
        ),
        Err(WireError::InvalidValue)
    );
    assert!(
        TaskResult::new(
            None,
            OutputQuality::Truncated,
            json!(null),
            diagnostics(Some(TaskFailure::OutputLimit)),
        )
        .is_ok()
    );
    assert_eq!(
        TaskResult::new(
            Some(0),
            OutputQuality::Failed,
            json!(null),
            diagnostics(Some(TaskFailure::NonZeroExit)),
        ),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            Some(1),
            OutputQuality::Failed,
            json!(null),
            diagnostics(Some(TaskFailure::LaunchFailed)),
        ),
        Err(WireError::InvalidValue)
    );

    let expanded = TaskResult::new(
        None,
        OutputQuality::Partial,
        json!("x".repeat(1_048_574)),
        TaskDiagnostics::new("\u{1}".repeat(16_384), "\u{1}".repeat(16_384), 0, 1, None).unwrap(),
    )
    .unwrap();
    assert_eq!(
        TaskEventRequest::new(Uuid::new_v4(), Uuid::new_v4(), TaskEvent::Result(expanded)),
        Err(WireError::InvalidValue)
    );
}
