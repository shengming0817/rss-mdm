use rss_mdm_software_service::{
    catalog::SourceDefinition,
    imports::{ImportRequest, prepare},
};
use rss_request_context::TenantId;
use serde_json::json;
use std::collections::BTreeMap;
#[path = "support/imports.rs"]
mod fixtures;
use fixtures::{documents, input, source};
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

#[test]
fn brew_source_tag_is_bound_to_resource_architecture_even_without_export() {
    let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let source:SourceDefinition=serde_json::from_value(json!({"id":"brew","revision":"1","protocol":{"kind":"brew_tap","repository":"https://github.com/acme/homebrew-private.git","commit":"1111111111111111111111111111111111111111","tap":"acme/private"}})).unwrap();
    let formula = format!(
        "class App < Formula\n  version \"1.2\"\n  desc \"Controlled tool\"\n  homepage \"https://example.test/\"\n  url \"https://cdn.example.test/app-source.tar.gz\"\n  sha256 \"{}\"\n  bottle do\n    root_url \"https://cdn.example.test/bottles\"\n    sha256 cellar: :any_skip_relocation, arm64_sonoma: \"{}\", sonoma: \"{}\"\n  end\n  def install\n    bin.install \"app\"\n  end\nend\n",
        "11".repeat(32),
        "22".repeat(32),
        "22".repeat(32)
    );
    let cask = format!(
        "cask \"app\" do\n  version \"1.2\"\n  sha256 \"{}\"\n  url \"https://cdn.example.test/app.dmg\"\n  name \"App\"\n  desc \"Controlled application\"\n  homepage \"https://example.test/\"\n  app \"App.app\"\nend\n",
        "22".repeat(32)
    );
    let user = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":1024,"exitCodes":{"success":[0],"reboot":[]}});
    let behavior = json!({"kind":"brew","installer":"installer","scope":"user","install":user,"upgradeInvocation":user,"upgrade":"in_place","uninstall":null,"detect":{"kind":"file","scope":"user","path":"bin/app","version":"1.2","sha256":vec![2;32]}});
    let dmg = json!({"kind":"dmg","image":"installer","volume":"App","scope":"system","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":1024,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"App.app","targetName":"App.app","bundleId":"com.acme.app","version":"1.2","materialSha256":vec![2;32]},"uninstall":true}});
    for native_export in [true, false] {
        for (path, document, behavior) in [
            ("Formula/app.rb", formula.as_str(), behavior.clone()),
            ("Casks/app.rb", cask.as_str(), dmg.clone()),
        ] {
            for arch in ["x86_64", "aarch64"] {
                for tag in ["sonoma", "arm64_sonoma"] {
                    let request=serde_json::from_value(json!({"asOfUnixSeconds":1700000000,"source":source.snapshot().unwrap(),"resource":"app","resourceVersion":"1","package":"app","packageVersion":"1.2","platform":"macos","architecture":arch,"variant":"default","selection":{"kind":"brew","path":path,"bottleTag":tag,"sourceLength":if path.starts_with("Formula"){json!(3)}else{json!(null)}},"behavior":behavior,"installerLength":3,"additionalArtifacts":if path.starts_with("Formula"){json!({"source":{"reference":"source","origin":"https://cdn.example.test/app-source.tar.gz","length":3,"sha256":vec![0x11;32]}})}else{json!({})},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","nativeExport":native_export})).unwrap();
                    let docs = BTreeMap::from([(path.into(), document.as_bytes().to_vec())]);
                    assert_eq!(
                        prepare(tenant, &source, &request, &docs).is_ok(),
                        (arch == "aarch64") == (tag == "arm64_sonoma"),
                        "{path}/{arch}/{tag}/export={native_export}"
                    );
                }
            }
        }
    }
}
