use rss_mdm_resource::*;
use rss_request_context::TenantId;
use serde_json::{Value, json};

fn spec() -> Value {
    json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.0+enterprise","format":"msi","primary":"package","artifacts":{"package":{"reference":"app-msi","length":3,"sha256":vec![2;32]}},"install":{"executor":"msi","entry":null,"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.0+enterprise"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":null})
}
fn version(value: Value) -> Result<Version, String> {
    let definition: SoftwareDefinition =
        serde_json::from_value(value).map_err(|e| e.to_string())?;
    Version::new(
        TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
        Id::new("app").unwrap(),
        Id::new("v1").unwrap(),
        Kind::Software,
        vec![Variant::new(
            Platform::Windows,
            Architecture::X86_64,
            Id::new("default").unwrap(),
            Declaration::Software { definition },
        )],
    )
    .map_err(|e| e.to_string())
}
#[test]
fn complete_software_definition_is_frozen_without_external_manifest() {
    let original = version(spec()).unwrap();
    for (pointer, value) in [
        ("/install/runAs", json!("logged_in_user")),
        ("/install/timeoutSeconds", json!(601)),
        ("/install/outputBytes", json!(8192)),
        ("/install/environment", json!({"RSS_PARAM_MODE":"safe"})),
        ("/source/id", json!("another-source")),
        ("/source/sha256", json!(vec![3; 32])),
        ("/package", json!("Acme.Other")),
        ("/version", json!("2+enterprise")),
        ("/downgrade", json!("allow")),
        ("/ownership", json!("allow_user_existing")),
        (
            "/dependencies",
            json!([{"resource":"dependency","version":"v1","sha256":vec![3;32]}]),
        ),
        ("/install/arguments", json!(["/quiet"])),
        ("/source/revision", json!("2")),
        ("/detect/version", json!("2")),
        ("/reboot", json!("forbid")),
        ("/artifacts/package/length", json!(4)),
    ] {
        let mut changed = spec();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(
            original.digest(),
            version(changed).unwrap().digest(),
            "{pointer}"
        );
    }
    let mut resource = Resource::new(original.tenant(), Id::new("app").unwrap(), Kind::Software);
    let at = rss_contract::Timepoint::try_from(100i64).unwrap();
    resource.insert(original.clone(), at).unwrap();
    assert!(!resource.insert(original, at).unwrap());
    let mut changed = spec();
    changed["install"]["arguments"] = json!(["/quiet"]);
    assert_eq!(
        resource.insert(version(changed).unwrap(), at),
        Err(Error::IdentityConflict)
    );
}
#[test]
fn incomplete_or_unbounded_software_is_rejected() {
    for pointer in ["detect", "install", "artifacts", "source"] {
        let mut v = spec();
        v.as_object_mut().unwrap().remove(pointer);
        assert!(version(v).is_err(), "{pointer}");
    }
    for (pointer, value) in [
        ("/install/timeoutSeconds", json!(0)),
        ("/install/environment", json!({"PATH":"evil"})),
        ("/primary", json!("missing")),
        (
            "/dependencies",
            json!([{"resource":"app","version":"v1","sha256":vec![3;32]}]),
        ),
        ("/detect", json!({"kind":"exit_zero"})),
    ] {
        let mut v = spec();
        *v.pointer_mut(pointer).unwrap() = value;
        assert!(version(v).is_err(), "{pointer}");
    }
    let mut v = spec();
    v["installId"] = json!("mutable");
    assert!(version(v).is_err());
}

#[test]
fn software_validation_reports_closed_context_without_input_values() {
    for (pointer, value, category) in [
        ("/source/id", json!("secret-source-value!"), "Source"),
        ("/package", json!(""), "Identity"),
        ("/primary", json!("missing"), "Artifact"),
        (
            "/dependencies",
            json!([{"resource":"..","version":"v1","sha256":vec![3;32]}]),
            "Dependency",
        ),
        ("/format", json!("bundle"), "Bundle"),
        ("/install/timeoutSeconds", json!(0), "Command"),
        (
            "/detect/productCode",
            json!("bad-product-code"),
            "Detection",
        ),
    ] {
        let mut value_spec = spec();
        *value_spec.pointer_mut(pointer).unwrap() = value;
        let parsed: SoftwareSpec = serde_json::from_value(value_spec).unwrap();
        let error = SoftwareDefinition::new(parsed).unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(category), "{pointer}: {diagnostic}");
        assert!(!diagnostic.contains("secret-source-value"));
        assert!(!diagnostic.contains("bad-product-code"));
    }
    let definition = SoftwareDefinition::new(serde_json::from_value(spec()).unwrap()).unwrap();
    assert!(
        definition
            .validate_target(Platform::MacOS, Architecture::X86_64)
            .unwrap_err()
            .to_string()
            .contains("Target")
    );
}
