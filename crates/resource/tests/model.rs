use rss_contract::Timepoint;
use rss_mdm_resource::*;
use rss_request_context::TenantId;
use std::time::Duration;

fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn now() -> Timepoint {
    Timepoint::try_from_duration(Duration::from_secs(100)).unwrap()
}
fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
fn variant(arch: Architecture, byte: u8) -> Variant {
    let artifact = Artifact::new(id("binary"), 12, Digest::from_bytes([byte; 32])).unwrap();
    Variant::new(
        Platform::Windows,
        arch,
        id("msi"),
        Declaration::Software {
            package: Package::new(id("private"), id("Acme.App"), id("1.2")),
            artifact,
            install: id("msi-install"),
            detect: id("product-code"),
            uninstall: Some(id("msi-remove")),
        },
    )
}
fn version(label: &str, variants: Vec<Variant>) -> Version {
    Version::new(tenant(), id("app"), id(label), Kind::Software, variants).unwrap()
}
#[test]
fn immutable_identity_and_canonical_order() {
    let a = variant(Architecture::X86_64, 1);
    let b = variant(Architecture::Aarch64, 2);
    let v = version("one", vec![a.clone(), b.clone()]);
    assert_eq!(v.digest(), version("one", vec![b, a]).digest());
    let mut r = Resource::new(tenant(), id("app"), Kind::Software);
    assert!(r.insert(v.clone(), now()).unwrap());
    assert!(!r.insert(v, now()).unwrap());
    assert_eq!(
        r.insert(
            version("one", vec![variant(Architecture::X86_64, 3)]),
            now()
        ),
        Err(Error::IdentityConflict)
    );
}
#[test]
fn lifecycle_and_references_are_explicit() {
    let mut r = Resource::new(tenant(), id("app"), Kind::Software);
    r.insert(
        version("one", vec![variant(Architecture::X86_64, 1)]),
        now(),
    )
    .unwrap();
    r.insert(
        version("two", vec![variant(Architecture::Aarch64, 2)]),
        now(),
    )
    .unwrap();
    r.activate(&id("one"), now()).unwrap();
    r.activate(&id("two"), now()).unwrap();
    assert_eq!(r.state(&id("one")).unwrap(), State::Deprecated);
    r.activate(&id("one"), now()).unwrap();
    let refs = References::new(tenant(), id("app"), id("one"), false, 0);
    assert_eq!(
        r.archive(&id("one"), &refs, now()),
        Err(Error::IncompleteReferences)
    );
    let refs = References::new(tenant(), id("app"), id("one"), true, 1);
    assert_eq!(r.archive(&id("one"), &refs, now()), Err(Error::Referenced));
    let refs = References::new(tenant(), id("app"), id("one"), true, 0);
    r.archive(&id("one"), &refs, now()).unwrap();
    assert_eq!(r.activate(&id("one"), now()), Err(Error::InvalidTransition));
}
#[test]
fn exact_selection_and_input_rejection() {
    let v = version("one", vec![variant(Architecture::X86_64, 1)]);
    assert!(
        v.resolve(Platform::Windows, Architecture::X86_64, &id("msi"))
            .is_ok()
    );
    assert_eq!(
        v.resolve(Platform::MacOS, Architecture::X86_64, &id("msi")),
        Err(Error::MissingVariant)
    );
    assert!(
        Version::new(
            tenant(),
            id("app"),
            id("one"),
            Kind::Software,
            vec![
                variant(Architecture::X86_64, 1),
                variant(Architecture::X86_64, 2)
            ]
        )
        .is_err()
    );
    assert!(Id::new("https://host/?token=secret").is_err());
    assert!(Digest::parse("bad").is_err());
}

#[test]
fn all_kinds_are_data_and_boundaries_do_not_mutate_state() {
    for declaration in [
        Declaration::Script {
            artifact: Artifact::new(id("script"), 3, Digest::of(b"abc")).unwrap(),
            interpreter: id("powershell"),
            detect: id("exit-code"),
        },
        Declaration::Configuration {
            artifact: Artifact::new(id("payload"), 3, Digest::of(b"abc")).unwrap(),
            schema: id("profile-v1"),
            apply: id("apply-profile"),
            detect: id("observe-profile"),
            remove: Some(id("remove-profile")),
        },
    ] {
        declaration.artifact().verify(b"abc").unwrap();
        assert_eq!(
            declaration.artifact().verify(b"xyz"),
            Err(Error::InvalidDigest)
        );
        let kind = declaration.kind();
        let v = Version::new(
            tenant(),
            id("item"),
            id("v1"),
            kind,
            vec![Variant::new(
                Platform::MacOS,
                Architecture::Aarch64,
                id("native"),
                declaration,
            )],
        )
        .unwrap();
        let mut r = Resource::new(tenant(), id("item"), kind);
        r.insert(v.clone(), now()).unwrap();
        assert_eq!(r.deprecate(&id("v1"), now()), Err(Error::InvalidTransition));
        r.activate(&id("v1"), now()).unwrap();
        r.deprecate(&id("v1"), now()).unwrap();
        let earlier = Timepoint::try_from_duration(Duration::from_secs(99)).unwrap();
        assert_eq!(r.activate(&id("v1"), earlier), Err(Error::StaleTime));
        let other = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            r.archive(
                &id("v1"),
                &References::new(other, id("item"), id("v1"), true, 0),
                now()
            ),
            Err(Error::TenantMismatch)
        );
        assert_eq!(r.version(&id("v1")).unwrap(), &v);
        let mut foreign = Resource::new(other, id("item"), kind);
        assert_eq!(foreign.insert(v, now()), Err(Error::TenantMismatch));
    }
    let binding = AccessBinding::new(
        tenant(),
        id("source"),
        id("secret-source-reference"),
        id("secret-artifact-reference"),
    );
    assert!(!format!("{binding:?}").contains("secret"));
}
