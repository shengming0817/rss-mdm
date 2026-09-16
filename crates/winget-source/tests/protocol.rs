use rss_mdm_winget_source::*;
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn query() -> Query {
    Query::new(
        tenant(),
        "private",
        "Acme.App",
        "1.2",
        Architecture::X64,
        InstallerType::Msi,
        Scope::Machine,
    )
    .unwrap()
}
#[test]
fn exact_manifest_and_publish_output() {
    let m = parse_manifest(&query(), include_bytes!("fixtures/msi.json")).unwrap();
    assert_eq!(m.package(), "Acme.App");
    assert_eq!(m.version(), "1.2");
    assert_eq!(m.sha256(), [0x11; 32]);
    let complete =
        VersionManifest::from_response(tenant(), "private", include_bytes!("fixtures/msi.json"))
            .unwrap();
    let bytes = complete.bytes();
    let request: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert!(request.get("Data").is_none());
    let envelope = serde_json::json!({"Data":request});
    assert_eq!(
        parse_manifest(&query(), &serde_json::to_vec(&envelope).unwrap()).unwrap(),
        m
    );
    assert_eq!(m.query().architecture(), Architecture::X64);
    assert_eq!(m.query().installer_type(), InstallerType::Msi);
    assert_eq!(m.query().scope(), Scope::Machine);
}
#[test]
fn malformed_unsupported_and_ambiguous_are_not_empty_success() {
    let input = include_str!("fixtures/msi.json");
    assert_eq!(
        parse_manifest(&query(), input.replace("Acme.App", "Other.App").as_bytes()),
        Err(Error::IdentityMismatch)
    );
    assert_eq!(
        parse_manifest(&query(), input.replace("\"msi\"", "\"zip\"").as_bytes()),
        Err(Error::NotFound)
    );
    assert_eq!(
        parse_manifest(
            &query(),
            input
                .replace(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    "bad"
                )
                .as_bytes()
        ),
        Err(Error::InvalidDigest)
    );
    let mut v: serde_json::Value = serde_json::from_str(input).unwrap();
    let installer = v["Data"]["Versions"][0]["Installers"][0].clone();
    v["Data"]["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .push(installer);
    assert_eq!(
        parse_manifest(&query(), &serde_json::to_vec(&v).unwrap()),
        Err(Error::Ambiguous)
    );
}

#[test]
fn official_exe_fixture_preserves_unspecified_scope() {
    let q = Query::new(
        tenant(),
        "private",
        "Foo.Bar",
        "5.0.0",
        Architecture::X64,
        InstallerType::Exe,
        Scope::Unspecified,
    )
    .unwrap();
    let bytes = include_bytes!("fixtures/upstream-exe.json");
    let m = parse_manifest(&q, bytes).unwrap();
    assert_eq!(m.package(), "Foo.Bar");
    let machine = Query::new(
        tenant(),
        "private",
        "Foo.Bar",
        "5.0.0",
        Architecture::X64,
        InstallerType::Exe,
        Scope::Machine,
    )
    .unwrap();
    assert_eq!(parse_manifest(&machine, bytes), Err(Error::NotFound));
    assert_eq!(m.verify_expected_digest([1; 32]), Err(Error::InvalidDigest));
}
#[test]
fn exact_installer_identity_disambiguates_without_first_match() {
    let mut data: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/msi.json")).unwrap();
    data["Data"]["Versions"][0]["Installers"][0]["InstallerIdentifier"] = "first".into();
    let mut second = data["Data"]["Versions"][0]["Installers"][0].clone();
    second["InstallerIdentifier"] = "second".into();
    data["Data"]["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let bytes = serde_json::to_vec(&data).unwrap();
    assert_eq!(parse_manifest(&query(), &bytes), Err(Error::Ambiguous));
    assert!(parse_manifest(&query().with_installer_id("second").unwrap(), &bytes).is_ok());
}

#[test]
fn unrelated_installers_do_not_block_the_exact_candidate() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/msi.json")).unwrap();
    for (field, value) in [
        ("Architecture", "x86"),
        ("InstallerType", "portable"),
        ("Scope", "future-scope"),
        ("InstallerIdentifier", "other"),
    ] {
        for first in [true, false] {
            let mut data = original.clone();
            let installers = data["Data"]["Versions"][0]["Installers"]
                .as_array_mut()
                .unwrap();
            installers[0]["InstallerIdentifier"] = "target".into();
            let mut sibling = installers[0].clone();
            sibling[field] = value.into();
            sibling["UnsupportedBehavior"] = true.into();
            sibling["InstallerUrl"] = "http://untrusted/".into();
            sibling["InstallerSha256"] = "invalid".into();
            installers.insert(if first { 0 } else { 1 }, sibling);
            let q = if field == "InstallerIdentifier" {
                query().with_installer_id("target").unwrap()
            } else {
                query()
            };
            let result = parse_manifest(&q, &serde_json::to_vec(&data).unwrap()).unwrap();
            assert_eq!(result.sha256(), [0x11; 32]);
        }
    }
}

#[test]
fn plaintext_source_is_rejected() {
    for address in ["127.0.0.1", "192.0.2.10"] {
        assert!(
            Source::new(
                tenant(),
                "private",
                "http://source.invalid/",
                vec![address.parse().unwrap()],
                "ref"
            )
            .is_err()
        );
    }
    assert!(
        Source::new(
            tenant(),
            "private",
            "https://source.invalid/",
            vec!["127.0.0.1".parse().unwrap()],
            "ref"
        )
        .is_err()
    );
}

#[test]
fn missing_private_bearer_is_rejected() {
    for bearer in ["", " ", "token with spaces", "token\r\nInjected: value"] {
        assert!(Access::new(tenant(), "private", "ref", bearer).is_err());
    }
    assert!(Access::new(tenant(), "private", "ref", &"a".repeat(8193)).is_err());
}

#[test]
fn selected_candidate_still_rejects_unknown_behavior_and_invalid_artifact() {
    for (field, value, expected) in [
        ("UnsupportedBehavior", "enabled", Error::Unsupported),
        ("InstallerUrl", "http://untrusted/", Error::InvalidInput),
        ("InstallerSha256", "invalid", Error::InvalidDigest),
        ("InstallerIdentifier", "../escape", Error::InvalidInput),
    ] {
        let mut data: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/msi.json")).unwrap();
        data["Data"]["Versions"][0]["Installers"][0][field] = value.into();
        assert_eq!(
            parse_manifest(&query(), &serde_json::to_vec(&data).unwrap()),
            Err(expected)
        );
    }
}
