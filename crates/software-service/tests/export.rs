use rss_mdm_software_service::{imports::prepare, publication::derive_document};
use rss_request_context::TenantId;
#[path = "imports.rs"]
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
