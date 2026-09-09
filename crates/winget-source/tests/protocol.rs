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
    let bytes = m.publication_metadata().unwrap();
    let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
        Err(Error::Unsupported)
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
