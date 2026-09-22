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
