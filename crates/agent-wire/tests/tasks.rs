mod support;
use rss_mdm_agent_wire::runtime::{TaskEvent, TaskEventRequest};
use serde_json::json;
use uuid::Uuid;
#[test]
fn task_events_are_closed_bounded_and_cannot_claim_identity() {
    let value = json!({"wireVersion":1,"executionContext":{"revision":1,"osVersion":[14,0,0,0],"userHelper":true,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false},"operationId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"event":{"kind":"received"}});
    let request: TaskEventRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(request.event(), TaskEvent::Received));
    for mutate in [
        |v: &mut serde_json::Value| {
            v["wireVersion"] = json!(6);
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
    use rss_mdm_agent_wire::runtime::*;
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let id = Uuid::new_v4();
    let spec = TaskSpec {
        projection: ScriptProjection::None,
        wire_version: 1,
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
        resource: TaskResource {
            id: "r".into(),
            version: "v1".into(),
            variant: "default".into(),
        },
        authorization: TaskAuthorization::Policy {
            policy_id: id,
            policy_version: id,
        },
        parameters: Default::default(),
        deadline: 200,
        content: TaskContent {
            length: 3,
            sha256: [2; 32],
        },
        profile: ExecutorProfile::PosixSh,
        sql_parameters: None,
        run_as: ExecutionIdentity::System,
        execution_target: SoftwareExecutionTarget::Device,
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
    support::verify_signature(&signed, key.public_key().as_ref()).unwrap();
    for mutate in [
        |s: &mut TaskSpec| {
            s.resource.variant = "other".into();
        },
        |s: &mut TaskSpec| {
            s.parameters.insert("name".into(), json!("changed"));
        },
        |s: &mut TaskSpec| {
            s.deadline += 1;
        },
        |s: &mut TaskSpec| {
            s.authorization = TaskAuthorization::Policy {
                policy_id: Uuid::new_v4(),
                policy_version: Uuid::new_v4(),
            };
        },
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
        assert!(support::verify_signature(&bad, key.public_key().as_ref()).is_err());
    }
    let mut bad = serde_json::to_value(signed.payload).unwrap();
    bad["task"]["outputBytes"] = json!(0);
    assert!(serde_json::from_value::<TaskPayload>(bad).is_err());
}

#[test]
fn software_task_binds_approved_definition_and_artifacts_without_script_fallback() {
    use base64::Engine;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rss_mdm_agent_wire::runtime::*;
    let id = Uuid::new_v4();
    let steps = vec![SoftwareTaskStep {
        action: serde_json::from_value(json!({"package":"acme.editor","version":"2","reboot":"report","downgrade":"deny","behavior":{"kind":"msi","installer":"installer","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"2"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[]})).unwrap(),
        artifacts: vec![SoftwareTaskArtifact {
            key: "0/installer".into(),
            length: 20_000_000,
            sha256: [2; 32],
        }],
        export: SoftwareTaskExport::Direct,
        target: SoftwareExecutionTarget::Device,
    }];
    let digest: [u8; 32] =
        ring::digest::digest(&ring::digest::SHA256, &serde_json::to_vec(&steps).unwrap())
            .as_ref()
            .try_into()
            .unwrap();
    let spec = SoftwareTaskSpec {
        authorization: TaskAuthorization::Policy {
            policy_id: Uuid::new_v4(),
            policy_version: Uuid::new_v4(),
        },
        execution_context: rss_mdm_agent_wire::runtime::SoftwareExecutionContext {
            revision: 1,
            os_version: [14, 0, 0, 0],
            user_helper: true,
            system_broker: true,
            interactive_user: None,
            source_credentials: vec![],
            msix_sideload: false,
            msix_unsigned: false,
        },
        wire_version: 1,
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
    let mut self_service = spec.clone();
    self_service.start_mode = SoftwareStartMode::UserInitiated;
    assert!(self_service.validate().is_err());
    self_service.authorization = TaskAuthorization::SelfService {
        request_id: id,
        subject: SelfServiceSubject::Device {},
        source: SelfServiceCaller::Human,
        policy_id: id,
        policy_revision: 1,
        policy_version: id,
        allow_ai: true,
        risk_level: 2,
        confirmed: false,
    };
    assert!(self_service.validate().is_ok());
    self_service.start_mode = SoftwareStartMode::Automatic;
    assert!(self_service.validate().is_err());
    self_service.start_mode = SoftwareStartMode::UserInitiated;
    if let TaskAuthorization::SelfService { risk_level, .. } = &mut self_service.authorization {
        *risk_level = 1;
    }
    assert!(self_service.validate().is_err());
    let payload: TaskPayload = spec.clone().try_into().unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(&payload).unwrap()));
    for change in [
        |v: &mut serde_json::Value| v["steps"] = json!([]),
        |v: &mut serde_json::Value| v["steps"][0]["artifacts"] = json!([]),
        |v: &mut serde_json::Value| v["steps"][0]["artifacts"][0]["key"] = json!("0/a//b"),
        |v: &mut serde_json::Value| v["steps"][0]["action"]["source"] = json!({}),
        |v: &mut serde_json::Value| v["steps"][0]["action"]["behavior"]["kind"] = json!("rpm"),
        |v: &mut serde_json::Value| {
            v["steps"][0]["action"]["behavior"]["install"]["timeoutSeconds"] = json!("never")
        },
        |v: &mut serde_json::Value| v["publicationId"] = json!(null),
        |v: &mut serde_json::Value| v["steps"][0]["action"]["ownership"] = json!("managed_only"),
        |v: &mut serde_json::Value| {
            v["steps"][0]["action"]["ownership"] = json!("allow_user_existing")
        },
        |v: &mut serde_json::Value| v["steps"][0]["action"]["ownership"] = json!(null),
    ] {
        let mut bad = serde_json::to_value(&payload).unwrap();
        change(&mut bad["task"]);
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
    support::verify_signature(&signed, key.public_key().as_ref()).unwrap();
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
    assert!(support::verify_signature(&forged, key.public_key().as_ref()).is_err());
}

#[test]
fn task_response_schemas_and_rust_reject_unknown_major_and_authority() {
    use rss_mdm_agent_wire::runtime::{MAX_TASK_CANCELLATIONS, TaskClaimResponse, TaskEventAck};
    let samples = [
        (
            include_str!("../schema/runtime/task-claim-response-v1.schema.json"),
            json!({"wireVersion":1,"task":null,"cancellations":[]}),
        ),
        (
            include_str!("../schema/runtime/task-event-ack-v1.schema.json"),
            json!({"wireVersion":1,"accepted":true,"permit":null,"cancelRequested":false,"credentials":[]}),
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
        for (name, invalid) in [("wireVersion", json!(6)), ("tenant", json!(Uuid::new_v4()))] {
            let mut bad = value.clone();
            bad[name] = invalid;
            assert!(!validator.is_valid(&bad));
            assert!(!rust_valid(bad));
        }
    }
    let cancellation = json!({"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4()});
    let boundary = json!({
        "wireVersion":1,
        "task":null,
        "cancellations":vec![cancellation.clone(); MAX_TASK_CANCELLATIONS]
    });
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-claim-response-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    assert!(validator.is_valid(&boundary));
    assert!(serde_json::from_value::<TaskClaimResponse>(boundary).is_ok());
    let overflow = json!({
        "wireVersion":1,
        "task":null,
        "cancellations":vec![cancellation; MAX_TASK_CANCELLATIONS + 1]
    });
    assert!(!validator.is_valid(&overflow));
    assert!(serde_json::from_value::<TaskClaimResponse>(overflow).is_err());
}

#[test]
fn task_response_producers_can_only_construct_valid_shapes() {
    use rss_mdm_agent_wire::runtime::{
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
    assert_eq!(serde_json::to_value(&response).unwrap()["wireVersion"], 1);
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
    use rss_mdm_agent_wire::runtime::{
        OutputQuality, TaskDiagnostics, TaskFailure, TaskResult, WireError,
    };

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
        2,
    )
    .unwrap();
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.quality(), OutputQuality::Complete);
    assert_eq!(result.output(), &json!({"version":"1.2"}));
    assert!(result.diagnostics().failure().is_none());
    let request = TaskEventRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        TaskEvent::Result(result),
        rss_mdm_agent_wire::runtime::SoftwareExecutionContext {
            revision: 1,
            os_version: [14, 0, 0, 0],
            user_helper: true,
            system_broker: true,
            interactive_user: None,
            source_credentials: vec![],
            msix_sideload: false,
            msix_unsigned: false,
        },
    )
    .unwrap();
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["event"]["kind"], "result");
    assert_eq!(encoded["event"]["diagnostics"]["durationMs"], 42);
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-event-request-v1.schema.json"
    ))
    .unwrap();
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
        TaskResult::new(
            None,
            OutputQuality::Failed,
            json!(null),
            diagnostics(None),
            2,
        ),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            Some(0),
            OutputQuality::Complete,
            json!(null),
            diagnostics(Some(TaskFailure::CaptureFailed)),
            2,
        ),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            None,
            OutputQuality::Truncated,
            json!(null),
            diagnostics(Some(TaskFailure::TimedOut)),
            2,
        ),
        Err(WireError::InvalidValue)
    );
    assert!(
        TaskResult::new(
            None,
            OutputQuality::Truncated,
            json!(null),
            diagnostics(Some(TaskFailure::OutputLimit)),
            2,
        )
        .is_ok()
    );
    assert_eq!(
        TaskResult::new(
            Some(0),
            OutputQuality::Failed,
            json!(null),
            diagnostics(Some(TaskFailure::NonZeroExit)),
            2,
        ),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        TaskResult::new(
            Some(1),
            OutputQuality::Failed,
            json!(null),
            diagnostics(Some(TaskFailure::LaunchFailed)),
            2,
        ),
        Err(WireError::InvalidValue)
    );

    let expanded = TaskResult::new(
        None,
        OutputQuality::Partial,
        json!("x".repeat(1_048_574)),
        TaskDiagnostics::new("\u{1}".repeat(16_384), "\u{1}".repeat(16_384), 0, 1, None).unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(
        TaskEventRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            TaskEvent::Result(expanded),
            rss_mdm_agent_wire::runtime::SoftwareExecutionContext {
                revision: 1,
                os_version: [14, 0, 0, 0],
                user_helper: true,
                system_broker: true,
                interactive_user: None,
                source_credentials: vec![],
                msix_sideload: false,
                msix_unsigned: false
            }
        ),
        Err(WireError::InvalidValue)
    );
}

#[test]
fn claims_require_current_unique_executor_profiles() {
    use rss_mdm_agent_wire::runtime::TaskClaimRequest;
    let base = json!({"wireVersion":1,"executionContext":{"revision":1,"osVersion":[14,0,0,0],"userHelper":true,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false},"operationId":Uuid::new_v4(),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["osquery"]});
    assert!(serde_json::from_value::<TaskClaimRequest>(base.clone()).is_ok());
    for profiles in [json!([]), json!(["posix_sh", "osquery"])] {
        let mut value = base.clone();
        value["profiles"] = profiles;
        assert!(serde_json::from_value::<TaskClaimRequest>(value).is_ok());
    }
    for profiles in [json!(["osquery", "osquery"]), json!(["arbitrary"])] {
        let mut value = base.clone();
        value["profiles"] = profiles;
        assert!(serde_json::from_value::<TaskClaimRequest>(value).is_err());
    }
    let mut missing = base;
    missing.as_object_mut().unwrap().remove("profiles");
    assert!(serde_json::from_value::<TaskClaimRequest>(missing).is_err());
}

#[test]
fn software_support_is_a_closed_format_scope_context_profile() {
    use rss_mdm_agent_wire::runtime::Capability;
    for name in [
        "software.msi.system.v1",
        "software.exe.user.v1",
        "software.dmg.app.system.v1",
        "software.msix.registration.user.v1",
        "software.msix.provisioning.system.v1",
        "software.brew.bottle.user.v1",
    ] {
        assert!(
            serde_json::from_value::<Capability>(serde_json::json!(name)).is_ok(),
            "{name}"
        );
    }
    assert!(
        serde_json::from_value::<Capability>(serde_json::json!("software.execute.v1")).is_err()
    );
    assert!(
        serde_json::from_value::<Capability>(serde_json::json!("software.msix.generic.v1"))
            .is_err()
    );
}
#[test]
fn self_service_directory_requires_a_closed_subject() {
    use rss_mdm_agent_wire::runtime::*;
    let id = Uuid::new_v4();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/self-service-directory-response-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for subject in [
        json!({"kind":"device"}),
        json!({"kind":"user","user":{"tenantId":id,"instanceId":id,"principalId":id}}),
    ] {
        let value = json!({"items":[{
            "policyId":id,"policyRevision":1,"policyVersion":id,"subject":subject,
            "selfService":{"published":true,"presentation":{"displayName":"Repair","description":"",
                "prerequisites":"","sideEffects":"","category":"Support","keywords":[]},
                "allowAi":true,"riskLevel":2},
            "task":{"kind":"script","resource":{"id":"repair","version":"1","variant":"macos"},
                "runAs":"system","parameterSources":{},"parameterSchema":{"type":"object"}}
        }],"nextCursor":null,"asOf":1});
        assert!(validator.is_valid(&value));
        let decoded: SelfServiceDirectoryResponse = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        let mut missing = value.clone();
        missing["items"][0]
            .as_object_mut()
            .unwrap()
            .remove("subject");
        assert!(!validator.is_valid(&missing));
        assert!(serde_json::from_value::<SelfServiceDirectoryResponse>(missing).is_err());
        for invalid_subject in [
            serde_json::Value::Null,
            json!({"kind":"authenticated_user"}),
            json!({"kind":"user"}),
            json!({"kind":"device","user":{"tenantId":id,"instanceId":id,"principalId":id}}),
        ] {
            let mut invalid = value.clone();
            invalid["items"][0]["subject"] = invalid_subject;
            assert!(!validator.is_valid(&invalid));
            assert!(serde_json::from_value::<SelfServiceDirectoryResponse>(invalid).is_err());
        }
    }
}

#[test]
fn self_service_schemas_follow_owned_dtos_and_reject_model_authority() {
    use rss_mdm_agent_wire::runtime::*;
    fn same<T: schemars::JsonSchema>(published: &str) {
        let generated = serde_json::to_value(schemars::schema_for!(T)).unwrap();
        let mut published: serde_json::Value = serde_json::from_str(published).unwrap();
        published.as_object_mut().unwrap().remove("$id");
        assert_eq!(generated, published);
    }
    same::<TaskAuthorization>(include_str!(
        "../schema/runtime/task-authorization-v1.schema.json"
    ));
    same::<TaskResource>(include_str!(
        "../schema/runtime/task-resource-v1.schema.json"
    ));
    same::<SelfServiceInvoke>(include_str!(
        "../schema/runtime/self-service-invoke-v1.schema.json"
    ));
    same::<SelfServiceDirectory>(include_str!(
        "../schema/runtime/self-service-directory-v1.schema.json"
    ));
    same::<SelfServiceDirectoryResponse>(include_str!(
        "../schema/runtime/self-service-directory-response-v1.schema.json"
    ));
    same::<SelfServiceAccepted>(include_str!(
        "../schema/runtime/self-service-accepted-v1.schema.json"
    ));
    same::<SelfServiceStatus>(include_str!(
        "../schema/runtime/self-service-status-v1.schema.json"
    ));
    for risk in [0, 3, 255] {
        let metadata = json!({"published":true,"presentation":{"displayName":"Repair","description":"","prerequisites":"","sideEffects":"","category":"Support","keywords":[]},"allowAi":true,"riskLevel":risk});
        assert!(serde_json::from_value::<SelfServiceMetadata>(metadata).is_err());
    }
    // Generated types must also be the definitions signed inside TaskSpec.
    let payload: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
    for (name, mut generated) in [
        (
            "TaskAuthorization",
            serde_json::to_value(schemars::schema_for!(TaskAuthorization)).unwrap(),
        ),
        (
            "TaskResource",
            serde_json::to_value(schemars::schema_for!(TaskResource)).unwrap(),
        ),
    ] {
        let root = generated.as_object_mut().unwrap();
        root.remove("$schema");
        root.remove("title");
        if let Some(serde_json::Value::Object(definitions)) = root.remove("$defs") {
            for (name, definition) in definitions {
                assert_eq!(definition, payload["$defs"][&name], "embedded {name}");
            }
        }
        assert_eq!(generated, payload["$defs"][name], "embedded {name}");
    }
    let id = Uuid::new_v4();
    let input = json!({"operationId":id,"policyId":id,"policyRevision":1,"policyVersion":id,"source":"ai","confirmed":true,"parameters":{}});
    for field in [
        "actor",
        "deviceId",
        "registrationId",
        "authorization",
        "grant",
        "parameterSchema",
        "riskLevel",
    ] {
        let mut invalid = input.clone();
        invalid[field] = json!(id);
        assert!(serde_json::from_value::<SelfServiceInvoke>(invalid.clone()).is_err());
        assert!(
            !jsonschema::validator_for(
                &serde_json::from_str::<serde_json::Value>(include_str!(
                    "../schema/runtime/self-service-invoke-v1.schema.json"
                ))
                .unwrap()
            )
            .unwrap()
            .is_valid(&invalid)
        );
    }
    let authorization = |source, allow_ai, risk_level, confirmed| TaskAuthorization::SelfService {
        request_id: id,
        subject: SelfServiceSubject::User {
            user: SelfServiceUser {
                tenant_id: id,
                instance_id: id,
                principal_id: id,
            },
        },
        source,
        policy_id: id,
        policy_revision: 1,
        policy_version: id,
        allow_ai,
        risk_level,
        confirmed,
    };
    assert!(
        authorization(SelfServiceCaller::Ai, true, 1, false)
            .validate(id)
            .is_ok()
    );
    assert!(
        authorization(SelfServiceCaller::Ai, true, 2, false)
            .validate(id)
            .is_err()
    );
    assert!(
        authorization(SelfServiceCaller::Ai, true, 2, true)
            .validate(id)
            .is_ok()
    );
    assert!(
        authorization(SelfServiceCaller::Ai, false, 1, true)
            .validate(id)
            .is_err()
    );
    assert!(
        authorization(SelfServiceCaller::Human, false, 2, false)
            .validate(id)
            .is_ok()
    );
    assert!(
        authorization(SelfServiceCaller::Human, true, 3, true)
            .validate(id)
            .is_err()
    );
    assert!(
        authorization(SelfServiceCaller::Human, true, 1, true)
            .validate(Uuid::new_v4())
            .is_err()
    );
}

#[test]
fn self_service_result_declares_the_persisted_evidence_envelope() {
    use rss_mdm_agent_wire::runtime::ScriptRunResult;
    let schema = serde_json::to_value(schemars::schema_for!(ScriptRunResult)).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = json!({"collectedAt":2,"receivedAt":3,"exitCode":0,"quality":"complete","schemaValid":true,"budgetValid":true,"output":{"resourceDefined":[1,"dynamic",null]},"outputReference":null,"diagnostics":{"stdout":"ok","stderr":"","durationMs":1,"executedAt":1,"failure":null},"trusted":true});
    let parsed: ScriptRunResult = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    assert!(validator.is_valid(&value));
    for field in [
        "collectedAt",
        "receivedAt",
        "exitCode",
        "quality",
        "schemaValid",
        "budgetValid",
        "output",
        "outputReference",
        "diagnostics",
        "trusted",
    ] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ScriptRunResult>(invalid.clone()).is_err(),
            "missing {field}"
        );
        assert!(!validator.is_valid(&invalid), "schema missing {field}");
    }
    for (field, bad) in [
        ("quality", json!("unknown")),
        ("receivedAt", json!("3")),
        ("trusted", json!(1)),
        ("authority", json!("model")),
    ] {
        let mut invalid = value.clone();
        invalid[field] = bad;
        assert!(serde_json::from_value::<ScriptRunResult>(invalid.clone()).is_err());
        assert!(!validator.is_valid(&invalid));
    }
    let mut referenced = value;
    referenced["output"] = serde_json::Value::Null;
    referenced["outputReference"] = json!({"bytes":4097,"sha256":"a".repeat(64)});
    assert!(validator.is_valid(&referenced));
    assert!(serde_json::from_value::<ScriptRunResult>(referenced).is_ok());
}
