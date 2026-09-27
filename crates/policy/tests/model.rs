use rss_mdm_policy::*;
use serde_json::json;
use uuid::Uuid;
#[test]
fn targets_and_enablement_do_not_create_execution_versions() {
    let id = Uuid::new_v4();
    let definition:Definition=serde_json::from_value(json!({"resource":{"id":"r","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"targets":{"kind":"devices","devices":[]},"behavior":{"kind":"execution","parameters":{},"runLifetimeSeconds":300}})).unwrap();
    let first = Policy::apply(
        id,
        None,
        0,
        &Change::Put {
            definition: definition.clone(),
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
    expanded.targets = Targets::Devices {
        devices: ["device".into()].into(),
    };
    let second = Policy::apply(
        id,
        Some(&disabled.policy),
        2,
        &Change::Put {
            definition: expanded,
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
