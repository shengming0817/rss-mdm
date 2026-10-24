//! Generic software authority, real Apple transport, and conservative PKG effect settlement.
use super::*;
use crate::test_support::{software, software_execution};
use sha2::{Digest, Sha256};
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=apple.onboarding"]
async fn software_pkg_ack_is_unknown_and_does_not_reinstall() -> Result<()> {
    let mut f = Fixture::with_mdm_software().await?;
    let (peer, _device) = f.ready_local_peer().await?;
    setup::grants(&f.browser, &f.router).await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(
            f.app.flow.planning.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?,
        f.app.flow.assets.clone(),
        f.app.flow.compliance.clone(),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.work.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(automation.registration(f.signals.flow()).critical());
    launch.finish();
    let source = Uuid::new_v4();
    let registered = software::write(&mut f.browser,&f.router,&format!("/api/v1/software/sources/{source}/revisions/1"),0,
        json!({"action":"register","definition":{"id":source,"revision":"1","protocol":{"kind":"private"}}})).await?;
    let bytes = b"controlled generic native PKG";
    let proof = serde_json::to_vec(
        &json!({"sha256":Sha256::digest(bytes).to_vec(),"mechanism":"apple_developer_id","publisher":"Acme","verified":true}),
    )?;
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":300,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let resource = Uuid::new_v4();
    let definition = json!({"material":{"format":"pkg","installer":"package"},"source":registered["snapshot"],"package":"Acme.Generic","version":"1.2.3","artifacts":{"package":{"reference":"generic-pkg","length":bytes.len(),"sha256":Sha256::digest(bytes).to_vec()}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"pkg","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.acme.generic","version":"1.2.3"}},"signatures":[{"artifact":"package","mechanism":"apple_developer_id","publisher":"Acme","evidence":{"reference":"generic-proof","length":proof.len(),"sha256":Sha256::digest(&proof).to_vec()}}],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    let version = software_execution::seed_resource(
        &f.app.flow.planning,
        resource,
        "macos",
        "aarch64",
        definition.clone(),
    )
    .await?;
    for (artifact, bytes) in [
        ("generic-pkg", bytes.as_slice()),
        ("generic-proof", proof.as_slice()),
    ] {
        let request=Request::builder().method(Method::POST).uri(format!("/api/v1/resources/{resource}/content?version=v1&variant=default&platform=macos&architecture=aarch64&artifact={artifact}&operation={}",Uuid::new_v4()))
            .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",f.browser.csrf.as_ref().unwrap())
            .header("cookie",f.browser.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
        let _guard = software::content_setup_guard().await?;
        ensure!(f.router.clone().oneshot(request).await?.status() == StatusCode::CREATED);
    }
    software_execution::seed_enabled(
        &f.app.flow.planning,
        f.app.content_writer.as_ref().unwrap(),
        &version,
    )
    .await?;
    let scope = software_execution::prepared_scope(&f.app.flow.planning, &[case_device()]).await?;
    let policy = Uuid::new_v4();
    software::write(&mut f.browser,&f.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"software","channel":"mdm","resource":{"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":600,"rollout":{"stages":[{"scope":scope,"opensAt":0}]}}}})).await?;
    let (platform, _) = peer.next("DeviceInformation").await?;
    let response = peer
        .manage(
            "Acknowledged",
            Some(platform),
            Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])
                .into(),
            )),
        )
        .await?;
    let (install, payload) = match lifecycle::command(&response, "InstallEnterpriseApplication") {
        Ok(command) => command,
        Err(_) => peer.next("InstallEnterpriseApplication").await?,
    };
    ensure!(
        !payload.contains_key("Configuration"),
        "generic software must not bootstrap an Agent"
    );
    let manifest = payload["Manifest"].as_dictionary().unwrap();
    let item = manifest["items"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    let asset = item["assets"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    let url = url::Url::parse(asset["url"].as_string().unwrap())?;
    ensure!(url.path().starts_with("/api/v1/software/installations/"));
    let download = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{}?{}", url.path(), url.query().unwrap()))
                .header("host", "mdm.example.test")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(download.status() == StatusCode::OK);
    ensure!(
        axum::body::to_bytes(download.into_body(), 1024)
            .await?
            .as_ref()
            == bytes
    );
    let acknowledged = peer.manage("Acknowledged", Some(install), None).await?;
    ensure!(lifecycle::command(&acknowledged, "InstallEnterpriseApplication").is_err());
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            f.app.execution.recover_action_fixture(policy).await?;
            let runs = f
                .browser
                .call(
                    &f.router,
                    Method::GET,
                    &format!("/api/v1/policies/{policy}/runs"),
                    None,
                )
                .await?;
            if let Some(items) = runs.1["items"].as_array()
                && items.len() == 1
                && items[0]["effect"] == "unknown"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    f.app.execution.recover_action_fixture(policy).await?;
    let after = peer.manage("Idle", None, None).await?;
    ensure!(
        lifecycle::command(&after, "InstallEnterpriseApplication").is_err(),
        "Unknown PKG effect must block another install"
    );
    ensure!(owner.shutdown().join().await?.is_clean());
    f.close().await?;
    Ok(())
}
