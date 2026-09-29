use super::*;
#[test]
fn state_identity_is_field_bound_and_never_normalizes_observation() {
    assert_ne!(
        Field::Model.digest("v1").unwrap(),
        Field::OsVersion.digest("v1").unwrap()
    );
    assert_ne!(
        Field::Model.digest("v1").unwrap(),
        Field::Model.digest(" v1").unwrap()
    );
    for value in ["", "  ", "bad\nvalue"] {
        assert!(Field::Model.digest(value).is_err());
    }
}
#[test]
fn command_contract_rejects_expiry_overflow_unknown_fields_and_nil_keys() {
    let mut request = Create {
        operation_id: Uuid::new_v4(),
        task: Task::StateVerify {
            field: Field::Model,
            expected_value: "Model".into(),
        },
        deadline: 100,
    };
    assert!(request.validate(99).is_ok());
    assert!(request.validate(100).is_err());
    request.deadline = i64::MAX;
    assert!(request.validate(1).is_err());
    request.deadline = 100;
    request.operation_id = Uuid::nil();
    assert!(request.validate(1).is_err());
    let mut value = serde_json::to_value(request).unwrap();
    value["tenant"] = serde_json::json!("untrusted");
    assert!(serde_json::from_value::<Create>(value).is_err());
}
#[test]
fn old_requests_and_direct_write_fields_do_not_have_fallbacks() {
    let old = serde_json::json!({"operationId":Uuid::new_v4(),"field":"model","expectedValue":"x","deadline":100});
    assert!(serde_json::from_value::<Create>(old).is_err());
    let task = serde_json::json!({"kind":"firewall","enabled":true,"policyVersion":Uuid::new_v4(),"policy":"x","version":1,"osVersion":"10.0.19045.0","edition":48,"uri":"arbitrary"});
    assert!(serde_json::from_value::<Task>(task).is_err());
    let verify = Task::StateVerify {
        field: Field::Model,
        expected_value: "x".into(),
    };
    assert_eq!(
        verify.permission(),
        crate::authorization::Permission::StateVerify
    );
}
#[test]
fn profile_presence_digest_binds_target_version_device_and_desired_state() {
    let mut request = Create {
        operation_id: Uuid::new_v4(),
        task: Task::ProfileInstall { enabled: true },
        deadline: 100,
    };
    let present = request.digest("tenant", "mac").unwrap();
    assert_ne!(present, request.digest("other", "mac").unwrap());
    assert_ne!(present, request.digest("tenant", "other").unwrap());
    request.task = Task::ProfileRemove {
        profile: request.operation_id,
    };
    assert_ne!(present, request.digest("tenant", "mac").unwrap());
    assert_eq!(
        request.task.source(),
        rss_mdm_inventory::ReportSource::MdmApple
    );
    request.task = Task::ProfileRemove {
        profile: Uuid::nil(),
    };
    assert!(request.validate(1).is_err());
}
#[test]
fn dispatch_wire_matches_schema_and_independent_consumer() {
    let validator = jsonschema::validator_for(
        &serde_json::from_str(include_str!("../../src/execution/dispatch-v2.json")).unwrap(),
    )
    .unwrap();
    let id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    for task in [
        Task::StateVerify {
            field: Field::Model,
            expected_value: "Surface".into(),
        },
        Task::Firewall {
            enabled: false,
            os_version: "10.0.19045.0".into(),
            edition: 48,
        },
    ] {
        let expected_task = match &task {
            Task::StateVerify { .. } => {
                serde_json::json!({"kind":"state_verify","field":"model","expectedValue":"Surface"})
            }
            _ => {
                serde_json::json!({"kind":"firewall","enabled":false,"osVersion":"10.0.19045.0","edition":48})
            }
        };
        let dto = DispatchV2 {
            device: "device-1".into(),
            request: Create {
                operation_id: id,
                task,
                deadline: 100,
            },
            generation: 2,
            epoch: 3,
        };
        let wire = serde_json::to_value(&dto).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({"device":"device-1","request":{"operationId":id,"task":expected_task,"deadline":100},"generation":2,"epoch":3})
        );
        assert!(validator.is_valid(&wire));
        assert!(serde_json::from_value::<DispatchV2>(wire.clone()).is_ok());
        let mut invalid = wire.clone();
        invalid["request"]["task"]["unknown"] = true.into();
        assert!(!validator.is_valid(&invalid));
        let mut invalid = wire;
        invalid.as_object_mut().unwrap().remove("epoch");
        assert!(!validator.is_valid(&invalid));
    }
}
