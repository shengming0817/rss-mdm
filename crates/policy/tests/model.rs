use rss_mdm_policy::*;
use serde_json::json;
use uuid::Uuid;
#[test]
fn targets_and_enablement_do_not_create_execution_versions() {
    let id = Uuid::new_v4();
    let definition:Definition=serde_json::from_value(json!({"scope":"11111111-1111-1111-1111-111111111111","action": {"resource": {"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"execution","parameters":{},"runLifetimeSeconds":300}})).unwrap();
    let first = Policy::apply(
        id,
        None,
        0,
        &Change::Put {
            definition: Box::new(definition.clone()),
            enabled: true,
        },
        Uuid::new_v4(),
    )
    .unwrap();
    let disabled =
        Policy::apply(id, Some(&first.policy), 1, &Change::Disable, Uuid::new_v4()).unwrap();
    assert_eq!(disabled.policy.version, first.policy.version);
    assert!(!disabled.semantic_changed);
    assert_eq!(disabled.policy.revision, 2);
    let mut expanded = definition;
    expanded.scope = Uuid::new_v4();
    let second = Policy::apply(
        id,
        Some(&disabled.policy),
        2,
        &Change::Put {
            definition: Box::new(expanded),
            enabled: true,
        },
        Uuid::new_v4(),
    )
    .unwrap();
    assert_eq!(second.policy.number, 1);
    assert!(!second.semantic_changed);
    assert!(matches!(
        Policy::apply(
            id,
            Some(&second.policy),
            2,
            &Change::Disable,
            Uuid::new_v4()
        ),
        Err(Error::Conflict)
    ));
}

#[test]
fn invalid_restored_aggregate_cannot_produce_checked_change() {
    let definition:Definition=serde_json::from_value(json!({"scope":Uuid::new_v4(),"action": {"resource": {"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration"}})).unwrap();
    let id = Uuid::new_v4();
    for (revision, number, version) in [
        (0, 0, Uuid::nil()),
        (1, 0, Uuid::new_v4()),
        (1, 1, Uuid::nil()),
        (1, 2, Uuid::new_v4()),
    ] {
        let old = Policy {
            id,
            revision,
            number,
            version,
            enabled: true,
            definition: definition.clone(),
        };
        assert!(matches!(
            Policy::apply(
                id,
                Some(&old),
                revision as u64,
                &Change::Enable,
                Uuid::new_v4()
            ),
            Err(Error::Malformed)
        ));
    }
}
#[test]
fn native_delivery_source_and_ring_are_execution_semantics() {
    let id = uuid::Uuid::new_v4();
    let mut value = serde_json::json!({"scope":id,"action":{"kind":"software","resource":{"kind":"software","id":"acme","version":"1","variants":{"windows_x86_64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","admissionOperation":id,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":id,"opensAt":0}]}}});
    let direct: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    value["action"]["delivery"] =
        serde_json::json!({"kind":"native","source":"enterprise","ring":"test"});
    let test: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    value["action"]["delivery"]["ring"] = serde_json::json!("production");
    let production: rss_mdm_policy::Definition = serde_json::from_value(value.clone()).unwrap();
    assert_ne!(direct.semantic().unwrap(), test.semantic().unwrap());
    assert_ne!(test.semantic().unwrap(), production.semantic().unwrap());
    value["action"].as_object_mut().unwrap().remove("delivery");
    assert!(serde_json::from_value::<rss_mdm_policy::Definition>(value).is_err());
}
