use rss_mdm_software_service::{
    catalog::SourceDefinition,
    imports::{ImportRequest, prepare},
};
use rss_request_context::TenantId;
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub(crate) fn source() -> SourceDefinition {
    serde_json::from_value(json!({"id":"community","revision":"1","protocol":{"kind":"winget_community","repository":"https://github.com/microsoft/winget-pkgs.git","commit":"3119f00ff5be7f34f85e16158dae2f70d1a2ee04"}})).unwrap()
}
pub(crate) fn input() -> Value {
    let invocation = json!({"runAs":"system","arguments":["/quiet"],"environment":{},"timeoutSeconds":60,"outputBytes":1024,"exitCodes":{"success":[0],"reboot":[]}});
    json!({"asOfUnixSeconds":1700000000,"source":source().snapshot().unwrap(),"resource":"acme","resourceVersion":"1","package":"Acme.App","packageVersion":"1.2","platform":"windows","architecture":"x86_64","variant":"default","selection":{"kind":"winget","installerType":"exe","scope":"machine","installerId":null,"files":["Acme.App.yaml"]},"behavior":{"kind":"exe","installer":"installer","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"layout":{"setup.exe":"installer"},"detect":{"kind":"registry","scope":"system","key":"Software\\Acme\\App","value":"Version","version":"1.2"}},"installerLength":3,"additionalArtifacts":{},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","nativeExport":true})
}
pub(crate) fn documents() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("Acme.App.yaml".into(),b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme\nPackageName: Acme App\nLicense: Proprietary\nShortDescription: Enterprise application\nInstallerType: exe\nScope: machine\nInstallerSwitches:\n  Silent: /quiet\nInstallers:\n  - Architecture: x64\n    InstallerUrl: https://cdn.example.test/app.exe\n    InstallerSha256: '1111111111111111111111111111111111111111111111111111111111111111'\nManifestType: singleton\nManifestVersion: 1.10.0\n".to_vec())])
}
#[test]
fn import_freezes_requested_source_and_original_bytes() {
    let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let request: ImportRequest = serde_json::from_value(input()).unwrap();
    let prepared = prepare(tenant, &source(), &request, &documents()).unwrap();
    assert_eq!(prepared.originals.len(), 1);
    let mut changed = documents();
    changed
        .get_mut("Acme.App.yaml")
        .unwrap()
        .extend_from_slice(b"# source comment\n");
    assert_ne!(
        prepared.version.digest(),
        prepare(tenant, &source(), &request, &changed)
            .unwrap()
            .version
            .digest()
    );
    for path in [
        "/source/sha256",
        "/behavior/install/arguments",
        "/selection/files",
    ] {
        let mut value = input();
        *value.pointer_mut(path).unwrap() = match path {
            "/source/sha256" => json!(vec![0; 32]),
            "/selection/files" => json!(["other.yaml"]),
            _ => json!(["/different"]),
        };
        let request: ImportRequest = serde_json::from_value(value).unwrap();
        assert!(
            prepare(tenant, &source(), &request, &documents()).is_err(),
            "{path}"
        );
    }
}
