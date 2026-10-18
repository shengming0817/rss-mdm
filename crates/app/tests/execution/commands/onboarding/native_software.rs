//! Real native transport with controlled bytes; no OS installation claim.
use super::*;
use crate::test_support::{software as content_setup, software_execution};
use sha2::{Digest, Sha256};
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn explicit_software_uses_native_run_without_agent_catalog() -> Result<()> {
    let mut host = crate::windows::test_support::Host::with_mdm_software().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    setup::grants(&client.browser, &client.router).await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        host.app.flow.planning.clone(),
        host.app.flow.assets.clone(),
        host.app.flow.compliance.clone(),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        automation
            .registration(host.notifications.signals.flow())
            .critical(),
    );
    launch.finish();
    let commands = client.command_worker(host.notifications.signals.clone())?;
    let source = Uuid::new_v4();
    let registered=content_setup::write(&mut client.browser,&client.router,&format!("/api/v1/software/sources/{source}/revisions/1"),0,json!({"action":"register","definition":{"id":source,"revision":"1","protocol":{"kind":"private"}}})).await?;
    let bytes = b"controlled generic native software";
    let proof = serde_json::to_vec(
        &json!({"sha256":Sha256::digest(bytes).to_vec(),"mechanism":"authenticode","publisher":"Acme","verified":true}),
    )?;
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":300,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let resource = Uuid::new_v4();
    let definition = json!({"source":registered["snapshot"],"package":"Acme.Generic","version":"1.2.3","artifacts":{"package":{"reference":"generic-msi","length":bytes.len(),"sha256":Sha256::digest(bytes).to_vec()}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{12345678-1234-4234-8234-123456789abc}","version":"1.2.3"}},"signatures":[{"artifact":"package","mechanism":"authenticode","publisher":"Acme","evidence":{"reference":"generic-proof","length":proof.len(),"sha256":Sha256::digest(&proof).to_vec()}}],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    let version = software_execution::seed_resource(
        &host.app.flow.planning,
        resource,
        "windows",
        "x86_64",
        definition,
    )
    .await?;
    for (artifact, bytes) in [
        ("generic-msi", bytes.as_slice()),
        ("generic-proof", proof.as_slice()),
    ] {
        let request=Request::builder().method(Method::POST).uri(format!("/api/v1/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&artifact={artifact}&operation={}",Uuid::new_v4()))
          .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",client.browser.csrf.as_ref().unwrap())
          .header("cookie",client.browser.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
        let _guard = content_setup::content_setup_guard().await?;
        let response = client.router.clone().oneshot(request).await?;
        ensure!(
            response.status() == StatusCode::CREATED,
            "upload {}",
            response.status()
        );
    }
    software_execution::seed_enabled(
        &host.app.flow.planning,
        host.app.content_writer.as_ref().unwrap(),
        &version,
    )
    .await?;
    let scope =
        software_execution::prepared_scope(&host.app.flow.planning, &[case_device()]).await?;
    let policy = Uuid::new_v4();
    content_setup::write(&mut client.browser,&client.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"software","channel":"mdm","resource":{"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":600,"rollout":{"stages":[{"scope":scope,"opensAt":0}]}}}})).await?;
    let mut saw_execute = false;
    let mut saw_observe = false;
    tokio::time::timeout(Duration::from_secs(90),async {
        for session in 1900..2000 {
            let (initial,mut response)=begin(&peer,session).await?;
            for _ in 0..12 {
                for command in &response.commands {
                    if let s::Command::Exec {items,..}=command {
                        for item in items {
                            if let Some(xml)=item.data.as_ref().filter(|_|item.target.as_deref().is_some_and(|u|u.ends_with("/DownloadInstall"))) {
                                let location=xml.0.split_once("<ContentURL>").and_then(|(_,v)|v.split_once("</ContentURL>")).context("native download URL")?.0;
                                let location=url::Url::parse(location)?;
                                let path=format!("{}?{}",location.path(),location.query().context("download grant")?);
                                let download=client.router.clone().oneshot(Request::builder().uri(&path).body(Body::empty())?).await?;
                                ensure!(download.status()==StatusCode::OK,"native content {}",download.status());
                                let wrong=client.router.clone().oneshot(Request::builder().uri(format!("{}?token={}",location.path(),"0".repeat(64))).body(Body::empty())?).await?;
                                ensure!(wrong.status()==StatusCode::FORBIDDEN,"invalid grant {}",wrong.status());
                            }
                        }
                    }
                }

                saw_execute |= response.commands.iter().any(|c|matches!(c,s::Command::Exec {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.ends_with("/DownloadInstall")))));
                saw_observe |= response.commands.iter().any(|c|matches!(c,s::Command::Get {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.contains("EnterpriseDesktopAppManagement") && u.ends_with("/Version")))));
                if response.commands.iter().all(|c|matches!(c,s::Command::Status(_))) { break; }
                response=post(&peer,&reply(&initial,&response,true)).await?;
            }
            host.app.execution.recover_action_fixture(policy).await?;
            let runs=client.browser.call(&client.router,Method::GET,&format!("/api/v1/policies/{policy}/runs"),None).await?;
            if runs.1["items"].as_array().is_some_and(|items|items.iter().any(|r|r["effect"]=="verified")) {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("native software never reached verified effect")
    }).await??;
    ensure!(
        saw_execute && saw_observe,
        "must execute once then verify read-only"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await?;
    Ok(())
}
