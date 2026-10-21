use rss_contract::Timepoint;
use rss_mdm_resource::*;
use rss_request_context::TenantId;
fn id(v: &str) -> Id {
    Id::new(v).unwrap()
}
#[test]
fn snapshot_preserves_states_and_rejects_inconsistent_storage() {
    let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let mut resource = Resource::new(tenant, id("app"), Kind::Script);
    let version = |label: &str| {
        Version::new(
            tenant,
            id("app"),
            id(label),
            Kind::Script,
            vec![Variant::new(
                Platform::Windows,
                Architecture::X86_64,
                id("script"),
                Declaration::Script {
                    artifact: Artifact::new(id("script"), 3, Digest::of(b"abc")).unwrap(),
                    definition: script(),
                },
            )],
        )
        .unwrap()
    };
    let at = Timepoint::try_from(10).unwrap();
    resource.insert(version("v1"), at).unwrap();
    resource.insert(version("v2"), at).unwrap();
    resource.activate(&id("v1"), at).unwrap();
    let version_digest = resource.version(&id("v1")).unwrap().digest();
    resource
        .set_presentation(
            serde_json::json!({"name":"App","vendor":{"help":"support"}})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
    assert_eq!(
        resource.version(&id("v1")).unwrap().digest(),
        version_digest
    );
    let snapshot = resource.snapshot();
    assert_eq!(
        Resource::restore(snapshot.clone()).unwrap().snapshot(),
        snapshot
    );
    let mut bad = snapshot.clone();
    bad.versions[1].state = State::Active;
    assert!(Resource::restore(bad).is_err());
    let mut bad = snapshot.clone();
    bad.changed_at = None;
    assert!(Resource::restore(bad).is_err());
    let mut bad = snapshot.clone();
    bad.versions.push(bad.versions[0].clone());
    assert!(Resource::restore(bad).is_err());
    let mut bad = snapshot;
    bad.key = id("another");
    assert!(Resource::restore(bad).is_err());
}

fn script() -> ScriptDefinition {
    serde_json::from_value(serde_json::json!({"profile":"power_shell7","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object"},"purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1})).unwrap()
}

#[test]
fn presentation_rejects_excess_structure_and_bytes_without_mutating_the_resource() {
    let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let mut resource = Resource::new(tenant, id("app"), Kind::Script);
    let initial = serde_json::json!({"vendor":{"label":"preserved"}})
        .as_object()
        .unwrap()
        .clone();
    resource.set_presentation(initial.clone()).unwrap();
    let mut deep = serde_json::json!("text");
    for _ in 0..17 {
        deep = serde_json::json!([deep]);
    }
    assert!(
        resource
            .set_presentation(
                serde_json::json!({"extra":deep})
                    .as_object()
                    .unwrap()
                    .clone()
            )
            .is_err()
    );
    for value in [
        serde_json::json!({"extra":"x".repeat(65536)}),
        serde_json::json!({"extra":vec![0;4096]}),
    ] {
        assert!(
            resource
                .set_presentation(value.as_object().unwrap().clone())
                .is_err()
        );
    }
    assert_eq!(resource.snapshot().presentation, initial);
}
