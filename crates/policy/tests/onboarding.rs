use rss_mdm_policy::Definition;
use serde_json::json;
use uuid::Uuid;

#[test]
fn enrollment_action_has_no_fictitious_resource() {
    let value = json!({"scope":Uuid::new_v4(),"action":{
        "kind":"request_mdm_enrollment", "organization":Uuid::new_v4(),
        "runLifetimeSeconds":3600
    }});
    let definition: Definition = serde_json::from_value(value.clone()).unwrap();
    definition.validate().unwrap();
    let mut invalid = value;
    invalid["action"]["resource"] = json!({"id":"fake","version":"v1"});
    assert!(serde_json::from_value::<Definition>(invalid).is_err());
}

#[test]
fn old_split_resource_behavior_contract_is_rejected() {
    let old = json!({"scope":Uuid::new_v4(),"resource":{
        "id":"firewall","version":"v1","platform":"windows",
        "architecture":"x86_64","variant":"default"
    },"behavior":{"kind":"configuration","exit":"retain"}});
    assert!(serde_json::from_value::<Definition>(old).is_err());
}

#[test]
fn onboarding_requires_organization_and_bounded_lifetime() {
    for (organization, lifetime) in [
        (Uuid::nil(), 3600),
        (Uuid::new_v4(), 0),
        (Uuid::new_v4(), 604801),
    ] {
        let value = json!({"scope":Uuid::new_v4(),"action":{
            "kind":"request_mdm_enrollment", "organization":organization,
            "runLifetimeSeconds":lifetime
        }});
        let parsed = serde_json::from_value::<Definition>(value);
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
}

#[test]
fn retirement_is_manual_device_execution_without_resource_or_self_service() {
    use rss_mdm_policy::{Action, ActionKind, AssignmentBehavior, schedule::Trigger};
    let input = json!({"scope":Uuid::new_v4(),"action":{
        "kind":"unmanage_device", "runLifetimeSeconds":3600
    }});
    let definition: Definition = serde_json::from_value(input.clone()).unwrap();
    definition.validate().unwrap();
    let Action::UnmanageDevice { schedule, .. } = &definition.action else {
        panic!("wrong action");
    };
    assert!(matches!(schedule.trigger, Trigger::Manual));
    assert_eq!(definition.action.kind().target_channel(), None);
    assert_eq!(
        definition.action.kind().assignment_behavior(),
        AssignmentBehavior::DeviceLifecycle
    );
    assert!(ActionKind::UnmanageDevice.supports_rerun());
    assert!(definition.action.resource().is_none());
    for (name, value) in [
        ("resource", json!({"id":"fake"})),
        ("channel", json!("agent")),
    ] {
        let mut invalid = input.clone();
        invalid["action"][name] = value;
        assert!(serde_json::from_value::<Definition>(invalid).is_err());
    }
    for lifetime in [0, 59, 604801] {
        let mut invalid = input.clone();
        invalid["action"]["runLifetimeSeconds"] = json!(lifetime);
        let parsed = serde_json::from_value::<Definition>(invalid);
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
}
