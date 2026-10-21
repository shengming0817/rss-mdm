use crate::test_support::software::{Fixture, write};
use crate::test_support::{process::*, runtime::*, *};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=software.http: import API, original material binding and receipt replay"]
async fn rest_import_binds_original_material_and_replays_without_source() -> Result<()> {
    let peer = publication_support::Server::new().await;
    let source_id = format!("{}-import", peer.logical);
    let location = format!("{}import/", peer.base);
    let rss_mdm_software_service::publication::ExportDocument::Winget { mut manifest } =
        peer.winget_document()
    else {
        unreachable!()
    };
    manifest["Versions"][0]["PackageVersion"] = json!("1.2");
    let original = serde_json::to_vec(&json!({"Data":manifest}))?;
    peer.state.lock().unwrap().import_manifest = Some(original.clone());
    let mut f = Fixture::with_peer(Some(peer)).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let source_path = format!("/api/v1/software/sources/{source_id}/revisions/1");
        let registered = write(&mut f.user, &f.router, &source_path, 0, json!({"action":"register","definition":{"id":source_id,"revision":"1","protocol":{"kind":"winget_rest","location":location,"identifier":source_id}}})).await?;
        let native = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
        let behavior = json!({"kind":"msi","installer":"installer","scope":"system","install":native,"upgradeInvocation":native,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"}});
        let resource = Uuid::new_v4();
        let request = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"asOfUnixSeconds":1700000000,"source":registered["snapshot"],"resource":resource,"resourceVersion":"v1","package":"Acme.App","packageVersion":"1.2","platform":"windows","architecture":"x86_64","variant":"default","selection":{"kind":"winget","installerType":"msi","scope":"machine","installerId":null,"files":["manifest.json"]},"behavior":behavior,"installerLength":3,"additionalArtifacts":{},"dependencies":[],"signatures":[],"reboot":"report","downgrade":"deny","nativeExport":true}});
        let imported = f.user.call(&f.router, Method::POST, "/api/v1/software/imports", Some(request.clone())).await?;
        ensure!(imported.0 == StatusCode::OK, "import: {imported:?}");
        let definition = f.user.call(&f.router, Method::GET, &format!("/api/v1/resources/{resource}"), None).await?;
        ensure!(definition.0 == StatusCode::OK);
        let provenance = &definition.1["versions"][0]["variants"][0]["declaration"]["definition"]["provenance"];
        ensure!(provenance["kind"] == "imported");
        let files = provenance["files"].as_array().expect("imported source files");
        ensure!(files.len() == 1 && files[0]["path"] == "manifest.json");
        let material: rss_mdm_resource::SoftwareArtifact = serde_json::from_value(files[0]["content"].clone())?;
        let digest = rss_mdm_resource::Digest::of(&original);
        ensure!(material.sha256 == digest.bytes() && material.length == original.len() as u64);
        let verified = f.content.as_ref().unwrap().verify(&material.artifact()?).await?;
        ensure!(verified.read_plaintext(original.len())?.as_slice() == original.as_slice());
        drop(verified);
        let binding_count = || pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND resource='{resource}' AND version='v1' AND reference='{}' AND sha256=decode('{}','hex')",case_tenant(),material.reference,digest.bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()));
        ensure!(binding_count()?.trim() == "1", "original material not bound to resource");
        write(&mut f.user, &f.router, &source_path, 1, json!({"action":"disable"})).await?;
        f.peer.as_ref().unwrap().state.lock().unwrap().import_manifest = None;
        let replay = f.user.call(&f.router, Method::POST, "/api/v1/software/imports", Some(request)).await?;
        ensure!(replay == imported, "replay consulted withdrawn source: {replay:?}");
        ensure!(binding_count()?.trim() == "1", "replay changed original binding");
        Ok(())
    }).await
}
