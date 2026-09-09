use rss_mdm_brew_source::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn artifact() -> Artifact {
    Artifact::new("https://files.example/app.tar.gz", [1; 32]).unwrap()
}
fn spec() -> Cask {
    Cask::new(
        PackageKey::new(tenant(), "acme/private", "app").unwrap(),
        "1.2",
        "App",
        "Internal app",
        "https://acme.example/",
        vec![
            (Architecture::Arm64, artifact()),
            (Architecture::Intel, artifact()),
        ],
        CaskArtifact::App("App.app".into()),
    )
    .unwrap()
}
#[test]
fn controlled_cask_and_bottle() {
    let doc = spec().render().unwrap();
    assert_eq!(doc.path(), "Casks/app.rb");
    assert!(
        std::str::from_utf8(doc.bytes())
            .unwrap()
            .contains("on_arm do")
    );
    assert!(
        std::str::from_utf8(doc.bytes())
            .unwrap()
            .contains("app \"App.app\"")
    );
    let f = Formula::new(
        PackageKey::new(tenant(), "acme/private", "tool").unwrap(),
        "1.2",
        "Tool",
        "https://acme.example/",
        artifact(),
        "tool",
        vec![
            Bottle::new(
                BottleTag::Arm64Sonoma,
                "https://files.example/bottles",
                [2; 32],
            )
            .unwrap(),
        ],
        vec![],
    )
    .unwrap();
    let doc = f.render().unwrap();
    assert_eq!(doc.path(), "Formula/tool.rb");
    assert!(
        std::str::from_utf8(doc.bytes())
            .unwrap()
            .contains("arm64_sonoma:")
    );
}
#[test]
fn identities_paths_and_secrets_are_not_templates() {
    assert!(PackageKey::new(tenant(), "acme/private", "../evil").is_err());
    assert!(Artifact::new("https://user:token@files.example/app", [1; 32]).is_err());
    assert!(Artifact::new("https://files.example/app?token=secret", [1; 32]).is_err());
    assert!(
        Cask::new(
            PackageKey::new(tenant(), "acme/private", "app").unwrap(),
            "1",
            "App",
            "desc",
            "https://acme.example/",
            vec![(Architecture::Arm64, artifact())],
            CaskArtifact::App("../x.app".into())
        )
        .is_err()
    );
}

#[test]
fn interpolation_is_literal_and_order_is_canonical() {
    let key = PackageKey::new(tenant(), "acme/private", "app").unwrap();
    let c = |variants| {
        Cask::new(
            key.clone(),
            "1",
            "#{system('bad')} \\\"",
            "description",
            "https://acme.example/",
            variants,
            CaskArtifact::Pkg("App.pkg".into()),
        )
        .unwrap()
        .render()
        .unwrap()
    };
    let one = c(vec![
        (Architecture::Arm64, artifact()),
        (Architecture::Intel, artifact()),
    ]);
    let two = c(vec![
        (Architecture::Intel, artifact()),
        (Architecture::Arm64, artifact()),
    ]);
    assert_eq!(one, two);
    assert!(
        std::str::from_utf8(one.bytes())
            .unwrap()
            .contains("\\#{system('bad')}")
    );
    assert!(
        Cask::new(
            key,
            "1",
            "name",
            "desc",
            "https://acme.example/",
            vec![
                (Architecture::Arm64, artifact()),
                (Architecture::Arm64, artifact())
            ],
            CaskArtifact::App("App.app".into())
        )
        .is_err()
    );
}

#[test]
fn dependency_and_artifact_checks_are_explicit() {
    let other = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let dependency = PackageKey::new(other, "acme/private", "dep").unwrap();
    assert_eq!(
        Formula::new(
            PackageKey::new(tenant(), "acme/private", "tool").unwrap(),
            "1",
            "desc",
            "https://acme.example/",
            artifact(),
            "tool",
            vec![Bottle::new(BottleTag::Sonoma, "https://files.example/", [1; 32]).unwrap()],
            vec![dependency]
        )
        .unwrap_err(),
        Error::TenantMismatch
    );
    assert_eq!(
        artifact().verify(b"different bytes"),
        Err(Error::DigestMismatch)
    );
    let binding = AccessBinding::new(
        tenant(),
        "acme/private",
        "secret-git-reference",
        "secret-download-reference",
    )
    .unwrap();
    assert!(!format!("{binding:?}").contains("secret"));
}
