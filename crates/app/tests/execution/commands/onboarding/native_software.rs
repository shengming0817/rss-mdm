//! Real native transport with controlled bytes; no OS installation claim.
use super::*;
use crate::test_support::http::await_task;
use crate::test_support::{software as content_setup, software_execution};
use sha2::{Digest, Sha256};
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn explicit_software_uses_native_run_without_agent_catalog() -> Result<()> {
    native_case(false, false).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn associated_agent_unknown_blocks_native_alias_but_not_other_package() -> Result<()> {
    native_case(true, false).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn native_rollout_counts_unsupported_selected_architecture() -> Result<()> {
    native_case(false, true).await
}
#[allow(
    clippy::cognitive_complexity,
    reason = "end-to-end fixture keeps admission, transport, content grants and effect settlement in one owned lifecycle"
)]
async fn native_case(agent_unknown: bool, unsupported_architecture: bool) -> Result<()> {
    let mut host = crate::windows::test_support::Host::with_mdm_software().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(
        host.browser.clone(),
        &host.commands,
        &host.authority.identity,
        host.authority.audit.clone(),
        host.clock.clone(),
    )
    .await?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        &crate::test_support::http::prepared_subject(&client.browser)?,
        setup::installation_grants()?,
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(
            host.planning.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?,
        host.assets.clone(),
        host.compliance.clone(),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.work.clone()),
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
    let definition = rss_mdm_software_service::catalog::SourceDefinition {
        id: source.to_string(),
        revision: "1".into(),
        protocol: rss_mdm_software_service::catalog::SourceProtocol::Private,
    };
    let registered = host
        .planning
        .runtime
        .local_tx(
            host.planning.tenant,
            crate::identity::deadline(),
            move |tx| {
                Box::pin(async move {
                    rss_mdm_software_service::catalog::fixture::source_in(tx, definition)
                        .await
                        .map_err(|error| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol(error.to_string()),
                            )
                        })
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("source seed rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("source seed commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )?;
    let bytes = b"controlled generic native software";
    let proof = serde_json::to_vec(
        &json!({"sha256":Sha256::digest(bytes).to_vec(),"mechanism":"authenticode","publisher":"Acme","verified":true}),
    )?;
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":300,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let resource = Uuid::new_v4();
    let alias = Uuid::new_v4();
    let definition = json!({"material":{"format":"msi","installer":"package"},"source":registered,"package":"Acme.Generic","version":"1.2.3","artifacts":{"package":{"reference":"generic-msi","length":bytes.len(),"sha256":Sha256::digest(bytes).to_vec()}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{12345678-1234-4234-8234-123456789abc}","version":"1.2.3"}},"signatures":[{"artifact":"package","mechanism":"authenticode","publisher":"Acme","evidence":{"reference":"generic-proof","length":proof.len(),"sha256":Sha256::digest(&proof).to_vec()}}],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    for (reference, bytes) in [
        ("generic-msi", bytes.as_slice()),
        ("generic-proof", proof.as_slice()),
    ] {
        let artifact = rss_mdm_resource::Artifact::new(
            rss_mdm_resource::Id::new(reference)?,
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(bytes),
        )?;
        rss_mdm_content_service::fixture::artifact(
            host.commands.content.as_ref().unwrap(),
            &artifact,
            bytes.to_vec(),
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
        )
        .await?;
    }
    for resource in [resource, alias] {
        let mut definition = definition.clone();
        if agent_unknown && resource == alias {
            definition["package"] = json!("Acme.Other");
            definition["behavior"]["detect"]["productCode"] =
                json!("{22345678-1234-4234-8234-123456789abc}");
        }
        let version = software_execution::seed_resource(
            &host.planning.runtime,
            host.planning.tenant,
            resource,
            "windows",
            "x86_64",
            definition.clone(),
        )
        .await?;
        software_execution::seed_enabled(
            &host.planning.runtime,
            host.commands.content.as_ref().unwrap(),
            &version,
        )
        .await
        .context("enable reviewed fixture resource")?;
    }
    let scope = if agent_unknown {
        let label = crate::test_support::runtime::credential("native-conflicting-agent");
        let device = crate::test_support::case::name("native-conflicting-agent");
        let registered=crate::test_support::agent::seed_service(host.agent_enrollment.as_ref().context("agent enrollment")?,&label,device,json!({"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","software.msi.system.v1"],"executionContext":software_execution::context(software_execution::Platform::Windows)})).await.context("seed conflicting Agent peer")?;
        let device = registered["deviceId"].as_str().context("agent device")?;
        let agent_scope = software_execution::prepared_scope(&host.planning, &[device])
            .await
            .context("prepare Agent scope")?;
        let agent_policy = Uuid::new_v4();
        let mut definition =
            software_execution::authored(resource, agent_scope, "required_install");
        definition["action"]["resource"]["variants"] = json!({"windows_x86_64":"default"});
        content_setup::write(
            &mut client.browser,
            &client.router,
            &format!("/api/v1/policies/{agent_policy}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        let task = software_execution::claim_with(
            &client.router,
            &label,
            software_execution::Platform::Windows,
        )
        .await?;
        for event in [
            json!({"kind":"received"}),
            json!({"kind":"start"}),
            software_execution::result_event(&task, "install", None, "unknown", false)?,
        ] {
            let result =
                software_execution::event_with(&client.router, &label, &task, event).await?;
            ensure!(result.0 == StatusCode::OK, "agent unknown {result:?}");
        }
        // Legal confirmed association is a prerequisite; this test owns software admission, not association creation.
        use sqlx::Connection;
        let mut conn =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut conn)
            .await?;
        let mut association_tx = conn.begin().await?;
        let association = Uuid::new_v4();
        let empty = json!({"serial":[],"uuid":[],"manufacturer":[],"sources":[]});
        let hardware = json!({"mdm":empty,"agent":empty});
        sqlx::query("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES($1::uuid,$2,1,'confirmed','operator verified fixture',$3,'fixture',1)").bind(case_tenant()).bind(association).bind(hardware).execute(&mut *association_tx).await?;
        sqlx::query("INSERT INTO mdm_devices.members(tenant_id,association_id,device,channel,registration_id,generation) SELECT tenant_id,$2,device,channel,id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=ANY($3::text[]) AND state='active'").bind(case_tenant()).bind(association).bind(vec![case_device(),device]).execute(&mut *association_tx).await?;
        association_tx.commit().await?;
        conn.close().await?;
        let scope = Uuid::new_v4();
        crate::test_support::agent_execution::seed_scope(
            &host.planning,
            scope,
            json!([{"kind":"device","id":case_device()}]),
        )
        .await
        .context("prepare associated native scope")?;
        scope
    } else {
        software_execution::prepared_scope(&host.planning, &[case_device()]).await?
    };
    let stage = software_execution::prepared_scope(&host.planning, &[case_device()])
        .await
        .context("prepare native rollout stage")?;
    crate::test_support::planning_http::await_ingress().await?;
    let policy = Uuid::new_v4();
    let competing = Uuid::new_v4();
    for (policy, resource) in [(policy, resource), (competing, alias)] {
        content_setup::write(&mut client.browser,&client.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"software","channel":"mdm","resource":{"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":600,"rollout":{"stages":[{"scope":stage,"opensAt":0}]}}}})).await?;
    }
    let (a, b) = tokio::join!(
        host.commands.service.recover_action_fixture(policy),
        host.commands.service.recover_action_fixture(competing)
    );
    a?;
    b?;
    let mut stage_rechecked = false;
    let mut executes = 0;
    let mut saw_observe = false;
    let outcome=tokio::time::timeout(Duration::from_secs(90),async {
        for session in 1900..2000 {
            let (initial,mut response)=begin(&peer,session).await?;
            for _ in 0..12 {
                if !agent_unknown && !unsupported_architecture && !stage_rechecked
                    && response.commands.iter().any(|c|matches!(c,s::Command::Add {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.contains("EnterpriseDesktopAppManagement")))))
                {
                    change_stage(&mut client, stage, 1, false).await?;
                    let blocked = post(&peer, &native_reply(&initial,&response,false)).await?;
                    ensure!(!blocked.commands.iter().any(installation_write), "first write bypassed changed stage Scope");
                    change_stage(&mut client, stage, 2, true).await?;
                    stage_rechecked = true;
                    response = blocked;
                }
                for command in &response.commands {
                    if let s::Command::Exec {items,..}=command {
                        for item in items {
                            if let Some(xml)=item.data.as_ref().filter(|_|item.target.as_deref().is_some_and(|u|u.ends_with("/DownloadInstall"))) {
                                let location=xml.0.split_once("<ContentURL>").and_then(|(_,v)|v.split_once("</ContentURL>")).context("native download URL")?.0;
                                let location=url::Url::parse(location)?;
                                let path=format!("{}?{}",location.path(),location.query().context("download grant")?);
                                let download=client.router.clone().oneshot(Request::builder().uri(&path).header("host","mdm.example.test").body(Body::empty())?).await?;
                                ensure!(download.status()==StatusCode::OK,"native content {}",download.status());
                                let wrong=client.router.clone().oneshot(Request::builder().uri(format!("{}?token={}",location.path(),"0".repeat(64))).header("host","mdm.example.test").body(Body::empty())?).await?;
                                ensure!(wrong.status()==StatusCode::FORBIDDEN,"invalid grant {}",wrong.status());
                            }
                        }
                    }
                }

                executes += response.commands.iter().filter(|c|matches!(c,s::Command::Exec {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.ends_with("/DownloadInstall"))))).count();
                saw_observe |= response.commands.iter().any(|c|matches!(c,s::Command::Get {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.contains("EnterpriseDesktopAppManagement") && u.ends_with("/Version")))));
                if response.commands.iter().all(|c|matches!(c,s::Command::Status(_))) { break; }
                response=post(&peer,&native_reply(&initial,&response,unsupported_architecture)).await?;
            }
            host.commands.service.recover_action_fixture(policy).await?;
            host.commands.service.recover_action_fixture(competing).await?;
            if unsupported_architecture {
                let progress = client.browser.call(&client.router,Method::GET,&format!("/api/v1/policies/{policy}/software/rollout"),None).await?;
                ensure!(progress.0 == StatusCode::OK, "native rollout: {progress:?}");
                if progress.1["stages"][0]["ready"] == true && progress.1["stages"][0]["totalTargets"] == 1 {
                    ensure!(progress.1["stages"][0]["unsupportedCapability"] == 1, "unsupported variant missing from statistics: {progress:?}");
                    ensure!(executes == 0, "unsupported architecture must not install");
                    return Ok::<_,anyhow::Error>(());
                }
            }
            for policy in [policy,competing] {
            let runs=client.browser.call(&client.router,Method::GET,&format!("/api/v1/policies/{policy}/runs"),None).await?;
            ensure!(runs.0 == StatusCode::OK, "native runs: {runs:?}");
            if runs.1["items"].as_array().is_some_and(|items|items.iter().any(|r|r["effect"]=="verified")) {return Ok::<_,anyhow::Error>(());}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("native software never reached verified effect")
    }).await;
    if outcome.is_err() {
        use sqlx::Connection;
        let mut conn =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let state:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('run',r.id,'state',r.state,'operation',o.id,'status',d.status,'dispatchFailure',o.dispatch_failure,'attempts',(SELECT jsonb_agg(jsonb_build_object('phase',a.phase,'ordinal',a.ordinal,'items',(SELECT jsonb_agg(jsonb_build_object('kind',i.kind,'status',i.status,'accepted',i.receipt_accepted,'result',i.result_accepted)) FROM mdm_commands.attempt_items i WHERE i.tenant_id=a.tenant_id AND i.attempt=a.id))) FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id)) FROM mdm_commands.action_runs r LEFT JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(r.tenant_id,r.id) LEFT JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE r.tenant_id=$1::uuid").bind(case_tenant()).fetch_all(&mut conn).await?;
        conn.close().await?;
        anyhow::bail!(
            "native timeout, executes={executes}, observed={saw_observe}, state={state:?}"
        );
    }
    outcome??;
    if unsupported_architecture {
        ensure!(commands.shutdown().join().await?.is_clean());
        ensure!(owner.shutdown().join().await?.is_clean());
        host.close().await?;
        return Ok(());
    }
    ensure!(
        agent_unknown || stage_rechecked,
        "stage withdrawal was not exercised"
    );
    ensure!(
        executes == 1 && saw_observe,
        "must execute once then verify read-only"
    );
    for policy in [policy, competing] {
        host.commands.service.recover_action_fixture(policy).await?;
    }
    let (_, response) = begin(&peer, 2100).await?;
    ensure!(
        !response.commands.iter().any(|c|installation_write(c) || matches!(c,s::Command::Get {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.contains("EnterpriseDesktopAppManagement"))))),
        "verified effect must stop installation and observation work"
    );
    use sqlx::Connection;
    let mut conn =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let (runs,operations):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=ANY($2::uuid[])),(SELECT count(*) FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND authority->>'kind'='software')").bind(case_tenant()).bind(vec![policy,competing]).fetch_one(&mut conn).await?;
    ensure!(
        runs == 1 && operations == 1,
        "alias admitted duplicate runs={runs}, operations={operations}"
    );
    if agent_unknown {
        let blocked:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2").bind(case_tenant()).bind(policy).fetch_one(&mut conn).await?;
        ensure!(
            blocked == 0,
            "associated Agent Unknown must block matching MSI"
        );
    }
    conn.close().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await?;
    Ok(())
}

fn native_reply(
    initial: &s::Message,
    response: &s::Message,
    unsupported_architecture: bool,
) -> s::Message {
    let mut reply = super::reply(initial, response, true);
    for command in &mut reply.commands {
        let s::Command::Results(results) = command else {
            continue;
        };
        let Some(items) = response.commands.iter().find_map(|command| match command {
            s::Command::Get { id, items, .. } if Some(*id) == results.command_ref => Some(items),
            _ => None,
        }) else {
            continue;
        };
        results.items = items
            .iter()
            .map(|item| {
                let uri = item.target.as_deref().expect("requested URI");
                s::Item {
                    more_data: false,
                    target: None,
                    source: Some(uri.into()),
                    meta: None,
                    data: Some(Secret(
                        if unsupported_architecture && uri.ends_with("/ProcessorArchitecture") {
                            "ARM64"
                        } else {
                            reported_value(uri, response)
                        }
                        .into(),
                    )),
                }
            })
            .collect();
    }
    reply
}

async fn change_stage(
    client: &mut Client,
    stage: Uuid,
    revision: u64,
    included: bool,
) -> Result<()> {
    let targets = if included {
        json!([{"kind":"device","id":case_device()}])
    } else {
        json!([])
    };
    let path = format!("/api/v1/scopes/{stage}");
    let changed = content_setup::write(
        &mut client.browser,
        &client.router,
        &path,
        revision,
        json!({"action":"put","definition":{"targets":targets,"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_task(
        &mut client.browser,
        &client.router,
        &format!(
            "{path}/tasks/{}",
            changed["task"].as_str().context("scope task")?
        ),
    )
    .await?;
    crate::test_support::planning_http::await_ingress().await?;
    Ok(())
}
