use rss_mdm_software_service::{
    catalog::SourceDefinition,
    imports::{ImportRequest, SourceDocuments, prepare},
};
use rss_request_context::TenantId;
use serde_json::json;
use sha2::{Digest, Sha256};
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
    let dmg = json!({"kind":"dmg","image":"installer","volume":"App","scope":"system","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":1024,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"App.app","targetName":"App.app","bundleId":"com.acme.app","version":"1.2"},"uninstall":true}});
    for native_export in [true, false] {
        for (path, document, behavior) in [
            ("Formula/app.rb", formula.as_str(), behavior.clone()),
            ("Casks/app.rb", cask.as_str(), dmg.clone()),
        ] {
            for arch in ["x86_64", "aarch64"] {
                for tag in ["sonoma", "arm64_sonoma"] {
                    let request=serde_json::from_value(json!({"asOfUnixSeconds":1700000000,"source":source.snapshot().unwrap(),"resource":"app","resourceVersion":"1","package":"app","packageVersion":"1.2","platform":"macos","architecture":arch,"variant":"default","selection":{"kind":"brew","path":path,"bottleTag":tag,"sourceLength":if path.starts_with("Formula"){json!(3)}else{json!(null)}},"behavior":behavior,"installerLength":3,"additionalArtifacts":if path.starts_with("Formula"){json!({"source":{"reference":"source","origin":"https://cdn.example.test/app-source.tar.gz","length":3,"sha256":vec![0x11;32]}})}else{json!({})},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","nativeExport":native_export})).unwrap();
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


#[test]
fn downloaded_source_fixtures_preserve_conversion_and_original_evidence() {
    let tenant = TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let id = "fixture";
    let base = "https://cdn.example.test/";
    let commit = "3119f00ff5be7f34f85e16158dae2f70d1a2ee04";
    let sha = Sha256::digest(b"abc")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut rest: serde_json::Value =
        serde_json::from_str(include_str!("../../winget-source/tests/fixtures/msi.json")).unwrap();
    let document = &mut rest["Data"];
    document["Versions"][0]["PackageVersion"] = json!("1.2");
    document["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    document["Versions"][0]["Installers"][0]["InstallerUrl"] =
        json!(format!("{base}artifacts/x64.msi"));
    document["Versions"][0]["Installers"][0]["InstallerSha256"] = json!(sha);
    let yaml = format!(
        "PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nInstallerType: msi\nScope: machine\nInstallers:\n  - Architecture: x64\n    InstallerUrl: {}artifacts/x64.msi\n    InstallerSha256: '{}'\nManifestType: installer\nManifestVersion: 1.10.0\n",
        base, sha
    );
    let community_documents = [
        ("Acme.App.installer.yaml", yaml.clone().into_bytes()),
        ("Acme.App.locale.en-US.yaml", b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme\nPackageName: Acme Application\nLicense: Proprietary\nShortDescription: Controlled enterprise application\nManifestType: defaultLocale\nManifestVersion: 1.10.0\n".to_vec()),
        ("Acme.App.yaml", b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nDefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.10.0\n".to_vec()),
    ];
    let cask = format!(
        "cask \"app\" do\n  version \"1.2\"\n  sha256 \"{sha}\"\n  url \"{}artifacts/app.dmg\"\n  name \"Application\"\n  desc \"Controlled application\"\n  homepage \"https://example.test/\"\n  app \"App.app\"\nend\n",
        base
    );
    let bottle = format!(
        "class App < Formula\n  version \"1.2\"\n  desc \"Controlled bottle\"\n  homepage \"https://example.test/\"\n  url \"{}artifacts/source.tar.gz\"\n  sha256 \"{sha}\"\n  bottle do\n    root_url \"{}artifacts\"\n    sha256 cellar: :any_skip_relocation, sonoma: \"{sha}\"\n  end\n  def install\n    bin.install \"app\"\n  end\nend\n",
        base, base
    );
    let native = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let msi = json!({"kind":"msi","installer":"installer","scope":"system","install":native,"upgradeInvocation":native,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"}});
    let dmg = json!({"kind":"dmg","image":"installer","volume":"App","scope":"system","invocation":native,"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"App.app","bundleId":"com.acme.app","version":"1.2","targetName":"App.app"},"uninstall":true}});
    let user_invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let brew_behavior = json!({"kind":"brew","installer":"installer","scope":"user","install":user_invocation,"upgradeInvocation":user_invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"file","scope":"user","path":"bin/app","version":"1.2","sha256":<[u8;32]>::from(Sha256::digest(b"abc"))}});
    for (revision, protocol, selection, behavior, platform, package, raw) in [
        (
            "rest",
            json!({"kind":"winget_rest","location":format!("{base}rest/"),"identifier":id}),
            json!({"kind":"winget","installerType":"msi","scope":"machine","installerId":null,"files":["manifest.json"]}),
            msi.clone(),
            "windows",
            "Acme.App",
            serde_json::to_vec(&json!({"Data":document})).unwrap(),
        ),
        (
            "community",
            json!({"kind":"winget_community","repository":"https://github.com/microsoft/winget-pkgs.git","commit":commit}),
            json!({"kind":"winget","installerType":"msi","scope":"machine","installerId":null,"files":["Acme.App.installer.yaml","Acme.App.locale.en-US.yaml","Acme.App.yaml"]}),
            msi,
            "windows",
            "Acme.App",
            yaml.clone().into_bytes(),
        ),
        (
            "brew",
            json!({"kind":"brew_tap","repository":"https://github.com/acme/homebrew-private.git","commit":commit,"tap":"acme/private"}),
            json!({"kind":"brew","path":"Casks/app.rb","bottleTag":"sonoma","sourceLength":null}),
            dmg,
            "macos",
            "app",
            cask.clone().into_bytes(),
        ),
        (
            "bottle",
            json!({"kind":"brew_tap","repository":"https://github.com/acme/homebrew-private.git","commit":commit,"tap":"acme/private"}),
            json!({"kind":"brew","path":"Formula/app.rb","bottleTag":"sonoma","sourceLength":3}),
            brew_behavior,
            "macos",
            "app",
            bottle.clone().into_bytes(),
        ),
    ] {
        let source_id = format!("{id}-{revision}");
        let source: SourceDefinition =
            serde_json::from_value(json!({"id":source_id,"revision":revision,"protocol":protocol}))
                .unwrap();
        let resource = "imported-app";
        let mut request = json!({"asOfUnixSeconds":1700000000,"source":source.snapshot().unwrap(),"resource":resource,"resourceVersion":"v1","package":package,"packageVersion":"1.2","platform":platform,"architecture":"x86_64","variant":"default","selection":selection,"behavior":behavior,"installerLength":3,"additionalArtifacts":{},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","nativeExport":true});
        if revision == "bottle" {
            request["additionalArtifacts"] = json!({"source":{"reference":"source","origin":format!("{base}artifacts/source.tar.gz"),"length":3,"sha256":<[u8;32]>::from(Sha256::digest(b"abc"))}});
        }
        // Start at the existing downloaded-document boundary; no network or application hook.
        let documents: SourceDocuments = match revision {
            "rest" => [("manifest.json".into(), raw.clone())].into(),
            "community" => community_documents
                .clone()
                .into_iter()
                .map(|(path, bytes)| (path.into(), bytes))
                .collect(),
            "brew" => [("Casks/app.rb".into(), raw.clone())].into(),
            "bottle" => [("Formula/app.rb".into(), raw.clone())].into(),
            _ => unreachable!(),
        };
        let input: ImportRequest = serde_json::from_value(request).unwrap();
        let prepared = prepare(tenant, &source, &input, &documents).unwrap();
        let rss_mdm_resource::Declaration::Software { definition } =
            prepared.version.variants()[0].declaration()
        else {
            panic!("{revision}: imported a non-software declaration");
        };
        let definition = serde_json::to_value(definition).unwrap();
        assert_eq!(definition["source"], json!(source.snapshot().unwrap()));
        assert_eq!(definition["provenance"]["kind"], "imported");
        let files = definition["provenance"]["files"].as_array().unwrap();
        assert_eq!(
            files.len(),
            documents.len(),
            "{revision}: complete source evidence"
        );
        assert_eq!(prepared.originals.len(), documents.len());
        for (path, bytes) in &documents {
            let file = files
                .iter()
                .find(|file| file["path"] == *path)
                .expect("missing source document");
            let digest = <[u8; 32]>::from(Sha256::digest(bytes));
            assert_eq!(file["content"]["sha256"], json!(digest));
            assert_eq!(file["content"]["length"], bytes.len());
            assert!(
                prepared
                    .originals
                    .iter()
                    .any(|(artifact, original)| artifact.sha256 == digest && original == bytes),
                "{revision}/{path}: original bytes changed"
            );
        }
        assert_eq!(
            definition["artifacts"]["installer"]["sha256"],
            json!(<[u8; 32]>::from(Sha256::digest(b"abc")))
        );
        assert_eq!(definition["behavior"], json!(input.behavior));
        assert_eq!(
            definition["export"]["kind"],
            if platform == "windows" {
                "winget"
            } else {
                "brew"
            },
            "{revision}: native export disabled or changed protocol"
        );
        if platform == "macos" {
            assert_eq!(
                definition["export"]["payload"]["kind"],
                if revision == "bottle" {
                    "bottle"
                } else {
                    "cask"
                }
            );
        }
    }
}
