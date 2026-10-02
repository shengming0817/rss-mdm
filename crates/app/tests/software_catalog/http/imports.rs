use crate::test_support::software::{Fixture, write};
use crate::test_support::*;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=software.http; real fixed HTTPS source protocols + PG + content"]
async fn exact_rest_community_and_brew_imports_preserve_evidence_and_replay() -> Result<()> {
    // raw.githubusercontent.com is resolved to this owned TLS listener, with the real hostname checked.
    let peer = publication_support::Server::at_port(443).await;
    let id = peer.logical.clone();
    let commit = "3119f00ff5be7f34f85e16158dae2f70d1a2ee04";
    let sha = Sha256::digest(b"abc")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut manifest = peer.winget_document();
    let rss_mdm_software_service::publication::ExportDocument::Winget {
        manifest: ref mut document,
    } = manifest
    else {
        unreachable!()
    };
    document["Versions"][0]["PackageVersion"] = json!("1.2");
    document["Versions"][0]["Installers"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    let yaml = format!(
        "PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme\nPackageName: Acme Application\nLicense: Proprietary\nShortDescription: Controlled enterprise application\nInstallerType: msi\nScope: machine\nInstallers:\n  - Architecture: x64\n    InstallerUrl: {}artifacts/x64.msi\n    InstallerSha256: '{}'\nManifestType: singleton\nManifestVersion: 1.10.0\n",
        peer.base, sha
    );
    let cask = format!(
        "cask \"app\" do\n  version \"1.2\"\n  sha256 \"{sha}\"\n  url \"{}artifacts/app.dmg\"\n  name \"Application\"\n  desc \"Controlled application\"\n  homepage \"https://example.test/\"\n  app \"App.app\"\nend\n",
        peer.base
    );
    let bottle = format!(
        "class App < Formula\n  version \"1.2\"\n  desc \"Controlled bottle\"\n  homepage \"https://example.test/\"\n  url \"{}artifacts/source.tar.gz\"\n  sha256 \"{sha}\"\n  bottle do\n    root_url \"{}artifacts\"\n    sha256 cellar: :any_skip_relocation, sonoma: \"{sha}\"\n  end\n  def install\n    bin.install \"app\"\n  end\nend\n",
        peer.base, peer.base
    );
    {
        let mut state = peer.state.lock().unwrap();
        state.source_documents.insert(
            "/rest/information".into(),
            serde_json::to_vec(
                &json!({"Data":{"SourceIdentifier":id,"ServerSupportedVersions":["1.0.0"]}}),
            )?,
        );
        state.source_documents.insert(
            "/rest/packageManifests/Acme.App?Version=1.2".into(),
            serde_json::to_vec(&json!({"Data":document}))?,
        );
        state.source_documents.insert(
            format!("/microsoft/winget-pkgs/{commit}/manifests/a/Acme/App/1.2/Acme.App.yaml"),
            yaml.clone().into_bytes(),
        );
        state.source_documents.insert(
            format!("/acme/homebrew-private/{commit}/Casks/app.rb"),
            cask.clone().into_bytes(),
        );
    }
    peer.state.lock().unwrap().source_documents.insert(
        format!("/acme/homebrew-private/{commit}/Formula/app.rb"),
        bottle.clone().into_bytes(),
    );
    let mut f = Fixture::with_peer_and_uploads(Some(peer), Some(1)).await?;
    let base = f.peer.as_ref().unwrap().base.clone();
    let native = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let msi = json!({"kind":"msi","installer":"installer","scope":"system","install":native,"upgradeInvocation":native,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"}});
    let dmg = json!({"kind":"dmg","image":"installer","volume":"App","scope":"system","invocation":native,"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"App.app","bundleId":"com.acme.app","version":"1.2","materialSha256":vec![7;32],"targetName":"App.app"},"uninstall":true}});
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
            serde_json::to_vec(&json!({"Data":document}))?,
        ),
        (
            "community",
            json!({"kind":"winget_community","repository":"https://github.com/microsoft/winget-pkgs.git","commit":commit}),
            json!({"kind":"winget","installerType":"msi","scope":"machine","installerId":null,"files":["Acme.App.yaml"]}),
            msi,
            "windows",
            "Acme.App",
            yaml.into_bytes(),
        ),
        (
            "brew",
            json!({"kind":"brew_tap","repository":"https://github.com/acme/homebrew-private.git","commit":commit,"tap":"acme/private"}),
            json!({"kind":"brew","path":"Casks/app.rb","bottleTag":"sonoma","sourceLength":null}),
            dmg,
            "macos",
            "app",
            cask.into_bytes(),
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
        let source_path = format!("/api/v3/software/sources/{source_id}/revisions/{revision}");
        let registered=write(&mut f.user,&f.router,&source_path,0,json!({"action":"register","definition":{"id":source_id,"revision":revision,"protocol":protocol}})).await?;
        write(
            &mut f.user,
            &f.router,
            &source_path,
            1,
            json!({"action":"approve","evidence":["fixed source snapshot review"]}),
        )
        .await?;
        let resource = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let request = json!({"operationId":operation,"expectedRevision":0,"input":{"asOfUnixSeconds":1700000000,"source":registered["snapshot"],"resource":resource,"resourceVersion":"v1","package":package,"packageVersion":"1.2","platform":platform,"architecture":"x86_64","variant":"default","selection":selection,"behavior":behavior,"installerLength":3,"additionalArtifacts":{},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","nativeExport":true}});
        let mut request = request;
        if revision == "bottle" {
            request["input"]["additionalArtifacts"] = json!({"source":{"reference":"source","origin":format!("{base}artifacts/source.tar.gz"),"length":3,"sha256":<[u8;32]>::from(Sha256::digest(b"abc"))}});
        }
        let imported = f
            .user
            .call(
                &f.router,
                Method::POST,
                "/api/v3/software/imports",
                Some(request.clone()),
            )
            .await?;
        ensure!(
            imported.0 == StatusCode::OK,
            "{revision} import: {imported:?}"
        );
        let definition = f
            .user
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v4/resources/{resource}"),
                None,
            )
            .await?;
        let declaration = &definition.1["versions"][0]["variants"][0]["declaration"]["definition"];
        ensure!(
            declaration["provenance"]["kind"] == "imported",
            "source evidence: {definition:?}"
        );
        ensure!(
            declaration["provenance"]["files"][0]["content"]["sha256"]
                == json!(<[u8; 32]>::from(Sha256::digest(&raw))),
            "original bytes changed"
        );
        let content_path = format!(
            "/api/v3/resources/{resource}/content/mirror?version=v1&variant=default&platform={platform}&architecture=x86_64&operation={}",
            Uuid::new_v4()
        );
        let mirrored = f
            .user
            .call(&f.router, Method::POST, &content_path, None)
            .await?;
        ensure!(mirrored.0.is_success(), "mirror: {mirrored:?}");
        if revision == "bottle" {
            let mirror=f.user.call(&f.router,Method::POST,&format!("/api/v3/resources/{resource}/content/mirror?version=v1&variant=default&platform=macos&architecture=x86_64&artifact=source&operation={}",Uuid::new_v4()),None).await?;
            ensure!(
                mirror.0 == StatusCode::CREATED,
                "source material mirror: {mirror:?}"
            );
        }
        write(
            &mut f.user,
            &f.router,
            &format!("/api/v4/resources/{resource}"),
            2,
            json!({"action":"activate","version":"v1"}),
        )
        .await?;
        write(
            &mut f.user,
            &f.router,
            &format!("/api/v3/software/resources/{resource}/versions/v1"),
            0,
            json!({"action":"approve","evidence":["complete hash-only materials"]}),
        )
        .await?;
        write(
            &mut f.user,
            &f.router,
            &source_path,
            2,
            json!({"action":"withdraw","evidence":["withdraw source after committed import"]}),
        )
        .await?;
        f.peer
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .source_documents
            .clear();
        let replay = f
            .user
            .call(
                &f.router,
                Method::POST,
                "/api/v3/software/imports",
                Some(request),
            )
            .await?;
        ensure!(
            replay.0 == StatusCode::OK && replay.1 == imported.1,
            "import replay consulted withdrawn source: {replay:?}"
        );
        // Restore documents for the remaining exact protocols, not this already committed replay.
        f.peer
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .source_documents
            .insert(
                format!("/acme/homebrew-private/{commit}/Formula/app.rb"),
                bottle.clone().into_bytes(),
            );
        let mut state = f.peer.as_ref().unwrap().state.lock().unwrap();
        state.source_documents.insert(format!("/microsoft/winget-pkgs/{commit}/manifests/a/Acme/App/1.2/Acme.App.yaml"),format!("PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme\nPackageName: Acme Application\nLicense: Proprietary\nShortDescription: Controlled enterprise application\nInstallerType: msi\nScope: machine\nInstallers:\n  - Architecture: x64\n    InstallerUrl: {base}artifacts/x64.msi\n    InstallerSha256: '{sha}'\nManifestType: singleton\nManifestVersion: 1.10.0\n").into_bytes());
        state.source_documents.insert(format!("/acme/homebrew-private/{commit}/Casks/app.rb"),format!("cask \"app\" do\n  version \"1.2\"\n  sha256 \"{sha}\"\n  url \"{base}artifacts/app.dmg\"\n  name \"Application\"\n  desc \"Controlled application\"\n  homepage \"https://example.test/\"\n  app \"App.app\"\nend\n").into_bytes());
    }
    Ok(())
}
