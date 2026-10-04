mod support;
use rss_mdm_agent_wire::runtime::{
    BindingProfile, Capability, CollectedValue, ErrorBody, ErrorCode, FailureCode, IntakeStatus,
    ObservationStatus, ProjectionStatus, ReportAck, ReportBody, ReportRequest, ReportSource,
    ReportStatus, SCHEMA_FINGERPRINT, SCHEMA_MANIFEST, Secret, WireError,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn secret() -> String {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
}

#[test]
fn published_schemas_match_wire_rejections() {
    let report_schema: Value = serde_json::from_str(include_str!(
        "../schema/runtime/report-request-v1.schema.json"
    ))
    .unwrap();
    let report_validator = jsonschema::validator_for(&report_schema).unwrap();
    let valid_report = serde_json::to_value(
        ReportRequest::new(
            Uuid::new_v4(),
            1,
            1,
            collection(),
            ReportBody::Snapshot(vec![]),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(report_validator.is_valid(&valid_report));
    for (key, value) in [
        ("wireVersion", json!(4)),
        ("reportId", json!(Uuid::nil())),
        ("sequence", json!(9223372036854775808_u64)),
        ("unknown", json!(true)),
    ] {
        let mut invalid = valid_report.clone();
        invalid[key] = value;
        assert!(!report_validator.is_valid(&invalid));
        assert!(serde_json::from_value::<ReportRequest>(invalid).is_err());
    }
}

#[test]
fn manifest_covers_and_fingerprints_every_public_shape() {
    let manifest: Value = serde_json::from_str(SCHEMA_MANIFEST).unwrap();
    assert_eq!(manifest["wireVersion"], 1);
    assert_eq!(
        manifest["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "BindingProfile",
            "ReportRequest",
            "ReportAck",
            "ReportStatus",
            "ErrorBody",
            "TaskClaimRequest",
            "TaskEventRequest",
            "TaskPayload",
            "SignedTask",
            "TaskClaimResponse",
            "TaskEventAck",
            "TaskAuthorization",
            "TaskResource",
            "SelfServiceInvoke",
            "SelfServiceDirectory",
            "SelfServiceDirectoryResponse",
            "SelfServiceAccepted",
            "SelfServiceStatus",
        ]
    );
    let schemas = [
        include_bytes!("../schema/runtime/binding-profile-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/report-request-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/report-ack-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/report-status-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/error-body-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-claim-request-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-event-request-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-payload-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/signed-task-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-claim-response-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-event-ack-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-authorization-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/task-resource-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/self-service-invoke-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/self-service-directory-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/self-service-directory-response-v1.schema.json")
            .as_slice(),
        include_bytes!("../schema/runtime/self-service-accepted-v1.schema.json").as_slice(),
        include_bytes!("../schema/runtime/self-service-status-v1.schema.json").as_slice(),
    ];
    let mut digest = Sha256::new();
    for schema in schemas {
        digest.update(schema);
    }
    assert_eq!(format!("{:x}", digest.finalize()), SCHEMA_FINGERPRINT);
}

#[test]
fn response_and_error_schemas_match_strict_consumers() {
    let operation = Uuid::new_v4();
    let registration = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let report = Uuid::new_v4();
    let receipt = BindingProfile {
        wire_version: 1,
        operation_id: operation,
        device_id: "device-1".into(),
        registration_id: registration,
        generation: 1,
        source: ReportSource::AgentBuiltin,
        epoch,
        capabilities: vec![Capability::InventoryCollectionV1],
        collections: vec![collection()],
    };
    let ack = ReportAck {
        wire_version: 1,
        report_id: report,
        received_at: 1,
        intake: IntakeStatus::Durable,
    };
    let status = ReportStatus {
        ack: ack.clone(),
        observation: ObservationStatus::Pending,
        projection: ProjectionStatus::Pending,
    };
    let values: [(Value, &str); 4] = [
        (
            serde_json::to_value(receipt).unwrap(),
            include_str!("../schema/runtime/binding-profile-v1.schema.json"),
        ),
        (
            serde_json::to_value(ack).unwrap(),
            include_str!("../schema/runtime/report-ack-v1.schema.json"),
        ),
        (
            serde_json::to_value(status).unwrap(),
            include_str!("../schema/runtime/report-status-v1.schema.json"),
        ),
        (
            serde_json::to_value(ErrorBody {
                code: ErrorCode::OperationUnknown,
            })
            .unwrap(),
            include_str!("../schema/runtime/error-body-v1.schema.json"),
        ),
    ];
    for (value, schema) in values {
        let schema: Value = serde_json::from_str(schema).unwrap();
        assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    }

    let uppercase = json!({
        "wireVersion":1,"reportId":report.to_string().to_uppercase(),
        "receivedAt":1,"intake":"durable"
    });
    let schema: Value =
        serde_json::from_str(include_str!("../schema/runtime/report-ack-v1.schema.json")).unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&uppercase)
    );
    assert!(serde_json::from_value::<ReportAck>(uppercase).is_err());
}

#[test]
fn canonical_secrets_are_exactly_256_bits() {
    assert!(Secret::parse(&secret()).is_ok());
    for invalid in ["", "bad", &"A".repeat(42), &"A".repeat(44)] {
        assert_eq!(Secret::parse(invalid), Err(WireError::InvalidValue));
    }
}

#[test]
fn report_profile_is_closed_bounded_and_canonical() {
    let id = Uuid::new_v4();
    let a = json!({
        "wireVersion": 1,
        "reportId": id,
        "sequence": 7,
        "observedAt": 1_800_000_000,
        "collection": collection(),
        "body": {"kind":"snapshot","values":[
            {"field":"device.os.version","value":{"kind":"value","value":{"kind":"string","value":"15.4"}}},
            {"field":"device.model","value":{"kind":"unsupported"}}
        ]}
    });
    let b = json!({
        "wireVersion": 1,
        "reportId": id,
        "sequence": 7,
        "observedAt": 1_800_000_000,
        "collection": collection(),
        "body": {"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"unsupported"}},
            {"field":"device.os.version","value":{"kind":"value","value":{"kind":"string","value":"15.4"}}}
        ]}
    });
    let a: ReportRequest = serde_json::from_value(a).unwrap();
    let b: ReportRequest = serde_json::from_value(b).unwrap();
    assert_eq!(a.canonical().unwrap(), b.canonical().unwrap());
    assert!(matches!(a.body(), ReportBody::Snapshot(_)));
    assert_eq!(
        a.values()[0].field,
        rss_mdm_agent_wire::runtime::FieldKey::parse("device.model").unwrap()
    );
    assert_eq!(a.values()[0].value, CollectedValue::Unsupported);

    let duplicate = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"collection":collection(),
        "body":{"kind":"partial","values":[
            {"field":"device.model","value":{"kind":"value","value":{"kind":"string","value":"A"}}},
            {"field":"device.model","value":{"kind":"value","value":{"kind":"string","value":"B"}}}
        ]}
    });
    assert!(serde_json::from_value::<ReportRequest>(duplicate).is_err());
    let delta = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"collection":collection(),
        "body":{"kind":"delta","values":[]}
    });
    assert!(serde_json::from_value::<ReportRequest>(delta).is_err());
}

#[test]
fn failed_reports_and_error_codes_are_closed() {
    let request: ReportRequest = serde_json::from_value(json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"collection":collection(),
        "body":{"kind":"failed","code":"temporarilyUnavailable"}
    }))
    .unwrap();
    assert_eq!(
        request.body(),
        &ReportBody::Failed {
            code: FailureCode::TemporarilyUnavailable
        }
    );
    assert_eq!(
        serde_json::to_value(ErrorCode::OperationUnknown).unwrap(),
        "operation_unknown"
    );
    assert!(serde_json::from_value::<ErrorCode>(json!("future_error")).is_err());
}

fn collection() -> rss_mdm_agent_wire::runtime::CollectionDefinition {
    support::collection()
}
