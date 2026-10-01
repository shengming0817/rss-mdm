use rss_mdm_software_service::{imports::prepare, publication::derive_document};
use rss_request_context::TenantId;
#[path = "support/imports.rs"]
mod fixtures;
#[test]
fn native_document_is_derived_from_complete_frozen_behavior() {
    let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let mut input = fixtures::input();
    input["behavior"]["detect"] = serde_json::json!({"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"});
    let prepared = prepare(
        tenant,
        &fixtures::source(),
        &serde_json::from_value(input).unwrap(),
        &fixtures::documents(),
    )
    .unwrap();
    let document = derive_document(
        &prepared.version,
        &[],
        "https://hosted.example.test/artifacts/",
    )
    .unwrap();
    let json = serde_json::to_value(document).unwrap();
    assert_eq!(
        json["manifest"]["Versions"][0]["Installers"][0]["InstallerSwitches"]["Silent"],
        "/quiet"
    );
    assert_eq!(
        json["manifest"]["Versions"][0]["Installers"][0]["ProductCode"],
        "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
    );
    let mut input = fixtures::input();
    input["behavior"]["layout"]["data.bin"] = serde_json::json!("data");
    input["additionalArtifacts"]["data"] = serde_json::json!({"reference":"data","origin":"https://cdn.example.test/data.bin","length":3,"sha256":vec![2;32]});
    let prepared = prepare(
        tenant,
        &fixtures::source(),
        &serde_json::from_value(input).unwrap(),
        &fixtures::documents(),
    )
    .unwrap();
    assert!(
        derive_document(
            &prepared.version,
            &[],
            "https://hosted.example.test/artifacts/"
        )
        .is_err()
    );
}

#[test]
fn brew_exports_preserve_scope_invocations_and_explicit_removal() {
    use rss_mdm_resource as r;
    use serde_json::json;
    fn version(behavior: serde_json::Value, bottle: bool) -> r::Version {
        let definition:r::SoftwareDefinition=serde_json::from_value(json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"tool","version":"1","provenance":{"kind":"private"},"artifacts":{"package":{"reference":"installer","length":3,"sha256":vec![1;32]},"source":{"reference":"source","length":4,"sha256":vec![2;32]}},"behavior":behavior,"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"export":{"kind":"brew","name":"Tool","description":"Enterprise tool","homepage":"https://acme.example.test/","payload":if bottle{json!({"kind":"bottle","artifact":"package","source":"source","tag":"sonoma","cellar":"any_skip_relocation","revision":0,"rebuild":0,"executable":"bin/tool"})}else{json!({"kind":"cask","path":"Tool.pkg","receipts":["com.acme.tool"]})}}})).unwrap();
        r::Version::new(
            TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
            r::Id::new("tool").unwrap(),
            r::Id::new("1").unwrap(),
            r::Kind::Software,
            vec![r::Variant::new(
                r::Platform::MacOS,
                r::Architecture::X86_64,
                r::Id::new("default").unwrap(),
                r::Declaration::Software { definition },
            )],
        )
        .unwrap()
    }
    let invoke = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let pkg = json!({"kind":"pkg","installer":"package","scope":"system","install":invoke,"upgradeInvocation":invoke,"upgrade":"in_place","uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.acme.tool","version":"1"}});
    let base = "https://hosted.example.test/artifacts/";
    let doc = derive_document(&version(pkg.clone(), false), &[], base).unwrap();
    assert!(matches!(
        doc,
        rss_mdm_software_service::publication::ExportDocument::Brew { .. }
    ));
    for field in ["scope", "arguments", "environment", "upgrade", "removal"] {
        let mut changed = pkg.clone();
        match field {
            "scope" => {
                changed["scope"] = json!("user");
                changed["install"]["runAs"] = json!("logged_in_user");
                changed["upgradeInvocation"]["runAs"] = json!("logged_in_user");
            }
            "arguments" => changed["install"]["arguments"] = json!(["-custom"]),
            "environment" => changed["install"]["environment"] = json!({"RSS_PARAM_X":"1"}),
            "upgrade" => changed["upgradeInvocation"]["arguments"] = json!(["-different"]),
            _ => changed["uninstall"] = json!({"installer":"package","invocation":invoke}),
        }
        assert!(
            derive_document(&version(changed, false), &[], base).is_err(),
            "export changed {field}"
        );
    }
    let mut brew = pkg;
    brew["kind"] = json!("brew");
    brew["scope"] = json!("user");
    brew["install"]["runAs"] = json!("logged_in_user");
    brew["upgradeInvocation"] = brew["install"].clone();
    brew["uninstall"] = json!({"installer":"package","invocation":brew["install"]});
    assert!(derive_document(&version(brew.clone(), true), &[], base).is_ok());
    for field in ["upgrade", "arguments", "removal"] {
        let mut changed = brew.clone();
        match field {
            "upgrade" => changed["upgrade"] = json!("deny"),
            "arguments" => changed["upgradeInvocation"]["arguments"] = json!(["--custom"]),
            _ => changed["uninstall"] = json!(null),
        }
        assert!(
            derive_document(&version(changed, true), &[], base).is_err(),
            "export changed Brew {field}"
        );
    }
}
