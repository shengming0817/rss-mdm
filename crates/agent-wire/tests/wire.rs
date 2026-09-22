use rss_mdm_agent_wire::{
    Capability, CollectedValue, ErrorCode, FailureCode, Field, RegistrationRequest, ReportBody,
    ReportRequest, Secret, WireError,
};
use serde_json::{Value, json};
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

    let valid_report = json!({
        "wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,
        "body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":"设备型号"}}
        ]}
    });
    for invalid in [
        json!({"wireVersion":1,"reportId":Uuid::nil(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[]}}),
        json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":9223372036854775808_u64,"observedAt":1,"body":{"kind":"snapshot","values":[]}}),
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
