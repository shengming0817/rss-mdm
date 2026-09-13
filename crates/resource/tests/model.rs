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
    assert_eq!(
        v.digest().bytes(),
        Digest::parse("f820d2058997820f12d037252919197efa5d99377bc5d7a98542a47105e92a2b")
            .unwrap()
            .bytes()
    );
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
}

#[test]
fn v1_digest_goldens_cover_declarations_and_optional_tags() {
    // Fixed vectors computed independently with Python hashlib/struct from the V1 encoding.
    // Domain bytes, UUID octets, big-endian lengths, tags and field order are persistent identity.
    let artifact = Artifact::new(id("payload"), 3, Digest::from_bytes([0xa5; 32])).unwrap();
    for (declaration, expected) in [
        (
            Declaration::Software {
                package: Package::new(id("private"), id("Acme.App"), id("1.2")),
                artifact: artifact.clone(),
                install: id("install"),
                detect: id("detect"),
                uninstall: None,
            },
            "5494e58566811eb82af4b811108d69ec8476d87d4702ef96ad4bfa9822c11aad",
        ),
        (
            Declaration::Software {
                package: Package::new(id("private"), id("Acme.App"), id("1.2")),
                artifact: artifact.clone(),
                install: id("install"),
                detect: id("detect"),
                uninstall: Some(id("remove")),
            },
            "76e813f5dc77d639c68c9c0c9d282cb3e021777ac59313733e7d512282f785cb",
        ),
        (
            Declaration::Configuration {
                artifact: artifact.clone(),
                schema: id("schema"),
                apply: id("apply"),
                detect: id("detect"),
                remove: None,
            },
            "aa852259d17921b4fb2ca529ad8c163e7b746f38b5a15d79fdc263adadbab265",
        ),
        (
            Declaration::Configuration {
                artifact: artifact.clone(),
                schema: id("schema"),
                apply: id("apply"),
                detect: id("detect"),
                remove: Some(id("remove")),
            },
            "22f34d4f621bf28e19abd175570820418fc113cf1070fdef76170f3a3b2c20df",
        ),
        (
            Declaration::Script {
                artifact: artifact.clone(),
                interpreter: id("shell"),
                detect: id("detect"),
            },
            "2e41740dffca1a9e1db83e3d0616b59f8997d5ef368d08505a88fd6911f1f928",
        ),
    ] {
        let version = Version::new(
            tenant(),
            id("item"),
            id("v1"),
            declaration.kind(),
            vec![Variant::new(
                Platform::MacOS,
                Architecture::Aarch64,
                id("native"),
                declaration,
            )],
        )
        .unwrap();
        assert_eq!(
            version.digest().bytes(),
            Digest::parse(expected).unwrap().bytes()
        );
    }
}
