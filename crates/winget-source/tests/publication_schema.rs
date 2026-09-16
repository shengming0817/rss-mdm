use rss_mdm_winget_source::*;
use rss_request_context::TenantId;

#[test]
fn publish_requests_satisfy_fixed_official_schema_not_our_response_parser() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/publish-schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    for (bytes, package, version, kind, scope) in [
        (
            include_bytes!("fixtures/msi.json").as_slice(),
            "Acme.App",
            "1.2",
            InstallerType::Msi,
            Scope::Machine,
        ),
        (
            include_bytes!("fixtures/upstream-exe.json").as_slice(),
            "Foo.Bar",
            "5.0.0",
            InstallerType::Exe,
            Scope::Unspecified,
        ),
    ] {
        let query = Query::new(
            tenant,
            "private",
            package,
            version,
            Architecture::X64,
            kind,
            scope,
        )
        .unwrap();
        parse_manifest(&query, bytes).unwrap();
        let manifest = VersionManifest::from_response(tenant, "private", bytes).unwrap();
        let value: serde_json::Value = serde_json::from_slice(manifest.bytes()).unwrap();
        let errors = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(value.get("Data").is_none());
        // Negative controls: the previous response envelope and missing License must fail.
        assert!(!validator.is_valid(&serde_json::json!({"Data":value.clone()})));
        let mut invalid = value;
        invalid["Versions"][0]["DefaultLocale"]
            .as_object_mut()
            .unwrap()
            .remove("License");
        assert!(!validator.is_valid(&invalid));
    }
}
