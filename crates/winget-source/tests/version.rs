use rss_mdm_winget_source::*;
fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
#[test]
fn complete_manifest_preserves_all_installers_and_canonical_order() {
    let response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/msi.json")).unwrap();
    let mut body = response["Data"].clone();
    body["Versions"][0]
        .as_object_mut()
        .unwrap()
        .remove("Channel");
    let mut arm = body["Versions"][0]["Installers"][0].clone();
    arm["Architecture"] = "arm64".into();
    body["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .push(arm);
    let first =
        VersionManifest::parse(tenant(), "private", &serde_json::to_vec(&body).unwrap()).unwrap();
    assert_eq!(first.installers().len(), 2);
    body["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        first,
        VersionManifest::parse(tenant(), "private", &serde_json::to_vec(&body).unwrap()).unwrap()
    );
    body["Versions"][0]["Installers"][0]["InstallerSwitches"] =
        serde_json::json!({"Silent":"/bad"});
    assert!(
        VersionManifest::parse(tenant(), "private", &serde_json::to_vec(&body).unwrap()).is_err()
    );
}
