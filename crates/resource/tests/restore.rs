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
                    interpreter: id("powershell"),
                    detect: id("exit-code"),
                },
            )],
        )
        .unwrap()
    };
    let at = Timepoint::try_from(10).unwrap();
    resource.insert(version("v1"), at).unwrap();
    resource.insert(version("v2"), at).unwrap();
    resource.activate(&id("v1"), at).unwrap();
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
