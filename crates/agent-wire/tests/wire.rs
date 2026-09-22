use rss_mdm_agent_wire::{
    Capability, CollectedValue, ErrorBody, ErrorCode, FailureCode, Field, IntakeStatus,
    ObservationStatus, ProjectionStatus, RegistrationReceipt, RegistrationRequest, ReportAck,
    ReportBody, ReportRequest, ReportSource, ReportStatus, SCHEMA_FINGERPRINT, SCHEMA_MANIFEST,
    Secret, WireError,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn secret() -> String {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
}

fn registration() -> Value {
    json!({
        "wireVersion": 1,
        "operationId": Uuid::nil(),
        "enrollmentId": "8cc2fb40-21a1-4390-b4ec-702087c284b5",
        "password": secret(),
        "credential": secret(),
        "capabilities": ["inventory.basic.v1"]
    })
}

#[test]
fn registration_is_strict_and_secrets_are_redacted() {
    let mut value = registration();
    value["operationId"] = json!(Uuid::new_v4());
    let request: RegistrationRequest = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(request.capabilities(), &[Capability::InventoryBasicV1]);
    assert_eq!(format!("{:?}", request.password()), "[REDACTED]");
    assert_eq!(format!("{:?}", request.credential()), "[REDACTED]");
    assert_eq!(request.password().expose(), secret());

    value["unknown"] = json!(true);
    assert!(serde_json::from_value::<RegistrationRequest>(value).is_err());
    let mut wrong = registration();
    wrong["wireVersion"] = json!(2);
    assert!(serde_json::from_value::<RegistrationRequest>(wrong).is_err());
    let mut unknown = registration();
    unknown["capabilities"] = json!(["inventory.basic.v1", "future"]);
    assert!(serde_json::from_value::<RegistrationRequest>(unknown).is_err());
}

#[test]
fn producers_construct_the_only_supported_shape() {
    let request = RegistrationRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Secret::parse(&secret()).unwrap(),
        Secret::parse(&secret()).unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(request).unwrap()["wireVersion"], 1);
    assert!(matches!(
        RegistrationRequest::new(
            Uuid::nil(),
            Uuid::new_v4(),
            Secret::parse(&secret()).unwrap(),
            Secret::parse(&secret()).unwrap(),
        ),
        Err(WireError::InvalidValue)
    ));
    assert!(ReportRequest::new(Uuid::new_v4(), 1, 1, ReportBody::Snapshot(vec![])).is_ok());
    assert_eq!(
        ReportRequest::new(
            Uuid::new_v4(),
            i64::MAX as u64 + 1,
            1,
            ReportBody::Snapshot(vec![])
        )
        .unwrap_err(),
        WireError::InvalidValue
    );
}

#[test]
fn published_schemas_match_wire_rejections() {
    let registration_schema: Value = serde_json::from_str(include_str!(
        "../schema/registration-request-v1.schema.json"
    ))
    .unwrap();
    let registration_validator = jsonschema::validator_for(&registration_schema).unwrap();
    let report_schema: Value =
        serde_json::from_str(include_str!("../schema/report-request-v1.schema.json")).unwrap();
    let report_validator = jsonschema::validator_for(&report_schema).unwrap();

    let mut valid_registration = registration();
    valid_registration["operationId"] = json!(Uuid::new_v4());
    for invalid in [
        registration(),
        {
            let mut value = valid_registration.clone();
            value["operationId"] = json!("not-a-uuid");
            value
        },
        {
            let mut value = valid_registration.clone();
            value["credential"] = json!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            value
        },
        {
            let mut value = valid_registration.clone();
            value["unknown"] = json!(true);
            value
        },
    ] {
        assert!(!registration_validator.is_valid(&invalid));
        assert!(serde_json::from_value::<RegistrationRequest>(invalid).is_err());
    }
    assert!(registration_validator.is_valid(&valid_registration));
    assert!(serde_json::from_value::<RegistrationRequest>(valid_registration).is_ok());

    for operation in [
        "8CC2FB40-21A1-4390-B4EC-702087C284B5",
        "8cc2fb4021a14390b4ec702087c284b5",
    ] {
        let mut invalid = registration();
        invalid["operationId"] = json!(operation);
        assert!(!registration_validator.is_valid(&invalid));
        assert!(serde_json::from_value::<RegistrationRequest>(invalid).is_err());
    }

    let valid_report = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,
        "body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":"设备型号"}}
        ]}
    });
    for invalid in [
        json!({"wireVersion":1,"reportId":Uuid::nil(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":9223372036854775808_u64,"observedAt":1,"body":{"kind":"snapshot","values":[]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":9223372036854775808_u64,"body":{"kind":"snapshot","values":[]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"partial","values":[
            {"field":"device.model","value":{"kind":"known","value":"A"}},
            {"field":"device.model","value":{"kind":"known","value":"B"}}
        ]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":" \t"}}
        ]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":"bad\u{0007}"}}
        ]}}),
    ] {
        assert!(
            !report_validator.is_valid(&invalid),
            "schema accepted {invalid}"
        );
        assert!(
            serde_json::from_value::<ReportRequest>(invalid.clone()).is_err(),
            "wire accepted {invalid}"
        );
    }
    assert!(report_validator.is_valid(&valid_report));
    assert!(serde_json::from_value::<ReportRequest>(valid_report).is_ok());
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
            "RegistrationRequest",
            "RegistrationReceipt",
            "ReportRequest",
            "ReportAck",
            "ReportStatus",
            "ErrorBody"
        ]
    );
    let schemas = [
        include_bytes!("../schema/registration-request-v1.schema.json").as_slice(),
        include_bytes!("../schema/registration-receipt-v1.schema.json").as_slice(),
        include_bytes!("../schema/report-request-v1.schema.json").as_slice(),
        include_bytes!("../schema/report-ack-v1.schema.json").as_slice(),
        include_bytes!("../schema/report-status-v1.schema.json").as_slice(),
        include_bytes!("../schema/error-body-v1.schema.json").as_slice(),
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
    let receipt = RegistrationReceipt {
        wire_version: 1,
        operation_id: operation,
        device_id: "device-1".into(),
        registration_id: registration,
        generation: 1,
        source: ReportSource::AgentBuiltin,
        epoch,
        capabilities: vec![Capability::InventoryBasicV1],
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
            include_str!("../schema/registration-receipt-v1.schema.json"),
        ),
        (
            serde_json::to_value(ack).unwrap(),
            include_str!("../schema/report-ack-v1.schema.json"),
        ),
        (
            serde_json::to_value(status).unwrap(),
            include_str!("../schema/report-status-v1.schema.json"),
        ),
        (
            serde_json::to_value(ErrorBody {
                code: ErrorCode::OperationUnknown,
            })
            .unwrap(),
            include_str!("../schema/error-body-v1.schema.json"),
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
        serde_json::from_str(include_str!("../schema/report-ack-v1.schema.json")).unwrap();
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
        "body": {"kind":"snapshot","values":[
            {"field":"device.os.version","value":{"kind":"known","value":"15.4"}},
            {"field":"device.model","value":{"kind":"unsupported"}}
        ]}
    });
    let b = json!({
        "wireVersion": 1,
        "reportId": id,
        "sequence": 7,
        "observedAt": 1_800_000_000,
        "body": {"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"unsupported"}},
            {"field":"device.os.version","value":{"kind":"known","value":"15.4"}}
        ]}
    });
    let a: ReportRequest = serde_json::from_value(a).unwrap();
    let b: ReportRequest = serde_json::from_value(b).unwrap();
    assert_eq!(a.canonical().unwrap(), b.canonical().unwrap());
    assert!(matches!(a.body(), ReportBody::Snapshot(_)));
    assert_eq!(a.values()[0].field, Field::Model);
    assert_eq!(a.values()[0].value, CollectedValue::Unsupported);

    let duplicate = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,
        "body":{"kind":"partial","values":[
            {"field":"device.model","value":{"kind":"known","value":"A"}},
            {"field":"device.model","value":{"kind":"known","value":"B"}}
        ]}
    });
    assert!(serde_json::from_value::<ReportRequest>(duplicate).is_err());
    let delta = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,
        "body":{"kind":"delta","values":[]}
    });
    assert!(serde_json::from_value::<ReportRequest>(delta).is_err());
}

#[test]
fn failed_reports_and_error_codes_are_closed() {
    let request: ReportRequest = serde_json::from_value(json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,
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
