//! Real native transport with controlled bytes; no OS installation claim.
use super::*;
use crate::test_support::http::await_task;
use crate::test_support::{software as content_setup, software_execution};
use sha2::{Digest, Sha256};
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn explicit_software_uses_native_run_without_agent_catalog() -> Result<()> {
    native_case(false, false, None).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn associated_agent_unknown_blocks_native_alias_but_not_other_package() -> Result<()> {
    native_case(true, false, None).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn native_rollout_counts_unsupported_selected_architecture() -> Result<()> {
    native_case(false, true, None).await
}
#[derive(Clone, Copy, PartialEq)]
enum ProjectionProbe {
    Resume,
    Withdraw,
    Expire,
    Unknown,
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn pending_projection_preserves_the_original_native_run() -> Result<()> {
    native_case(false, false, Some(ProjectionProbe::Resume)).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn pending_projection_does_not_hide_policy_withdrawal() -> Result<()> {
    native_case(false, false, Some(ProjectionProbe::Withdraw)).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn pending_projection_does_not_extend_run_deadline() -> Result<()> {
    native_case(false, false, Some(ProjectionProbe::Expire)).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn unknown_architecture_is_not_projection_pending_authority() -> Result<()> {
    native_case(false, false, Some(ProjectionProbe::Unknown)).await
}
#[allow(
    clippy::cognitive_complexity,
    reason = "end-to-end fixture keeps admission, transport, content grants and effect settlement in one owned lifecycle"
)]
async fn native_case(
    agent_unknown: bool,
    unsupported_architecture: bool,
    probe: Option<ProjectionProbe>,
) -> Result<()> {
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
    let automation = crate::test_support::workers::Workers::open(
        host.planning.clone(),
        None,
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        automation.scheduler.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        std::sync::Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
            crate::planning::test_support::scopes(&host.planning).await,
            automation.scheduler.store.clone(),
        ))
        .registration(
            host.notifications
                .signals
                .handle(crate::worker_wake::Work::Scopes),
        )
        .critical(),
    );
    automation.register(&host.notifications.signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.finish();
    let mut commands = if probe.is_none() {
        Some(client.command_worker(host.notifications.signals.clone())?)
    } else {
        None
    };
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
        // The scenario starts from a published Agent policy; settle preparation before authentication.
        crate::test_support::planning_http::await_ingress().await?;
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
    if probe.is_some() {
        observe_channel(&peer, 1800, false).await?;
        await_channel_projection().await?;
    }
    let policy = Uuid::new_v4();
    let competing = Uuid::new_v4();
    for (policy, resource) in [(policy, resource), (competing, alias)] {
        content_setup::write(&mut client.browser,&client.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"software","channel":"mdm","resource":{"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":600,"rollout":{"stages":[{"scope":stage,"opensAt":0}]}}}})).await?;
    }
    let (a, b) = tokio::join!(
        host.commands.service.discover_policy_fixture(policy),
        host.commands.service.discover_policy_fixture(competing)
    );
    a?;
    b?;
    // Discovery is separate from a device step. Freeze the real device run before
    // deliberately pausing its later projection/recovery boundary.
    if probe.is_some() {
        let mut c =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        for selected in [policy, competing] {
            let (version, registration, generation): (Uuid, Uuid, i64) = sqlx::query_as("SELECT p.current_version,r.id,r.generation FROM mdm_policy.policies p JOIN mdm_access.registrations r USING(tenant_id) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND r.device=$3 AND r.channel='mdm' AND r.state='active' AND r.purpose='primary'")
                .bind(case_tenant()).bind(selected).bind(case_device()).fetch_one(&mut c).await?;
            host.commands
                .service
                .recover_scheduled_fixture(version, registration, generation)
                .await?;
        }
        c.close().await?;
    }
    if let Some(probe) = probe {
        let resumed =
            projection_window(&host, &mut client, &peer, [policy, competing], probe).await?;
        if !resumed {
            ensure!(owner.shutdown().join().await?.is_clean());
            host.close().await?;
            return Ok(());
        }
        commands = Some(client.command_worker(host.notifications.signals.clone())?);
    }
    let commands = commands.context("command worker owns native execution")?;
    let mut accepted_stage_preserved = false;
    let mut executes = 0;
    let mut saw_observe = false;
    let outcome=tokio::time::timeout(Duration::from_secs(90),async {
        for session in 1900..2000 {
            let (initial,mut response)=begin(&peer,session).await?;
            for _ in 0..12 {
                if !agent_unknown && !unsupported_architecture && !accepted_stage_preserved
                    && response.commands.iter().any(|c|matches!(c,s::Command::Add {items,..} if items.iter().any(|i|i.target.as_deref().is_some_and(|u|u.contains("EnterpriseDesktopAppManagement")))))
                {
                    change_stage(&mut client, stage, 1, false).await?;
                    let blocked = post(&peer, &native_reply(&initial,&response,false)).await?;
                    ensure!(blocked.commands.iter().any(installation_write), "accepted native run must not repeat rollout selection");
                    change_stage(&mut client, stage, 2, true).await?;
                    accepted_stage_preserved = true;
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
            host.commands.service.discover_policy_fixture(policy).await?;
            host.commands.service.discover_policy_fixture(competing).await?;
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
        agent_unknown || accepted_stage_preserved,
        "accepted run after rollout change was not exercised"
    );
    ensure!(
        executes == 1 && saw_observe,
        "must execute once then verify read-only"
    );
    for policy in [policy, competing] {
        host.commands
            .service
            .discover_policy_fixture(policy)
            .await?;
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
    let diagnostic: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',r.id,'policy',v.policy,'state',r.state,'gatewayAccepted',r.gateway_accepted,'effect',r.software_effect,'result',r.result,'operation',o.id) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND v.policy=ANY($2::uuid[])").bind(case_tenant()).bind(vec![policy,competing]).fetch_all(&mut conn).await?;
    let snapshots: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('collection',c.id,'scope',c.scope,'deliveryPending',c.delivery_pending,'projection',(SELECT jsonb_agg(jsonb_build_object('batch',i.batch_id,'generation',i.generation,'sequence',i.collection_sequence)) FROM mdm.inventory i WHERE i.tenant_id=c.tenant_id AND i.scope=c.scope)) FROM (SELECT DISTINCT ON(scope) tenant_id,id,scope,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration IN(SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND sealed_at IS NOT NULL ORDER BY scope,sequence DESC) c")
        .bind(case_tenant()).bind(case_device()).fetch_all(&mut conn).await?;
    ensure!(
        runs == 1 && operations == 1,
        "alias admitted duplicate runs={runs}, operations={operations}, state={diagnostic:?}, snapshots={snapshots:?}"
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

async fn observe_channel(
    peer: &crate::windows::test_support::Peer,
    session: u32,
    unknown: bool,
) -> Result<()> {
    let (initial, mut response) = begin(peer, session).await?;
    for _ in 0..12 {
        ensure!(
            !response.commands.iter().any(installation_write),
            "pre-dispatch snapshot wrote an installation"
        );
        if response
            .commands
            .iter()
            .all(|c| matches!(c, s::Command::Status(_)))
        {
            return Ok(());
        }
        let mut reply = native_reply(&initial, &response, false);
        if unknown {
            for command in &mut reply.commands {
                if let s::Command::Results(results) = command {
                    for item in &mut results.items {
                        if item
                            .source
                            .as_deref()
                            .is_some_and(|uri| uri.ends_with("/ProcessorArchitecture"))
                        {
                            item.data = Some(Secret("unknown".into()));
                        }
                    }
                }
            }
        }
        response = post(peer, &reply).await?;
    }
    anyhow::bail!("channel snapshot did not finish")
}

async fn channel_observation(
    c: &mut sqlx::PgConnection,
) -> Result<rss_mdm_inventory_service::assets::channel::Observation> {
    use sqlx::Connection;
    let mut tx = c.begin().await?;
    crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
    let (registration,generation): (Uuid,i64) = sqlx::query_as("SELECT id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND state='active'")
        .bind(case_tenant()).bind(case_device()).fetch_one(&mut *tx).await?;
    let observed = rss_mdm_inventory_service::assets::channel::detail_in(
        &mut tx,
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        generation,
        rss_mdm_inventory::ReportSource::MdmWindows,
    )
    .await;
    let released = tx.rollback().await;
    let observed = observed?;
    released?;
    Ok(observed)
}

async fn await_channel_projection() -> Result<()> {
    use sqlx::Connection;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if matches!(
                channel_observation(&mut c).await?,
                rss_mdm_inventory_service::assets::channel::Observation::Ready(_)
            ) {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let closed = c.close().await;
    result.context("channel projection did not become ready")??;
    closed?;
    Ok(())
}

async fn projection_window(
    host: &crate::windows::test_support::Host,
    client: &mut Client,
    peer: &crate::windows::test_support::Peer,
    policies: [Uuid; 2],
    probe: ProjectionProbe,
) -> Result<bool> {
    use sqlx::Connection;
    let options = crate::device::test_support::options("postgres")?;
    let mut observer = sqlx::PgConnection::connect_with(&options).await?;
    let (run,policy):(Uuid,Uuid) = sqlx::query_as("SELECT r.id,v.policy FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=ANY($2::uuid[])")
        .bind(case_tenant()).bind(policies.to_vec()).fetch_one(&mut observer).await?;
    let mut locker = sqlx::PgConnection::connect_with(&options).await?;
    let mut lock = locker.begin().await?;
    // Pause only this tenant's Observation delivery, after snapshot A was projected.
    let held: Vec<String> = sqlx::query_scalar(
        "SELECT object_id FROM rss_observation.objects WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(case_tenant())
    .fetch_all(&mut *lock)
    .await?;
    ensure!(!held.is_empty());
    let result = async {
        observe_channel(peer,1801,probe == ProjectionProbe::Unknown).await?;
        let observed = channel_observation(&mut observer).await?;
        ensure!(matches!(observed, rss_mdm_inventory_service::assets::channel::Observation::ProjectionPending { .. }), "snapshot B must remain unprojected: {observed:?}");
        if probe == ProjectionProbe::Withdraw {
            content_setup::write(&mut client.browser,&client.router,&format!("/api/v1/policies/{policy}"),1,json!({"action":"disable"})).await?;
            crate::test_support::planning_http::await_ingress().await?;
        }
        if probe == ProjectionProbe::Expire {
            // Provider deadline fixture; the recovery algorithm still uses the real database clock.
            let mut expiry = observer.begin().await?;
            crate::Database::configure_transaction(&mut expiry, case_tenant()).await?;
            sqlx::query("UPDATE mdm_commands.action_runs SET available_at=0,deadline=1,state=jsonb_set(state,'{deadline}','1') WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(run).execute(&mut *expiry).await?;
            expiry.commit().await?;
        }
        host.commands.service.recover_native_run_fixture(run).await?;
        let state:Value = sqlx::query_scalar("SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut observer).await?;
        ensure!(state["execution"] == "not_started");
        ensure!(state["cancellation"] == if probe == ProjectionProbe::Resume { "none" } else { "confirmed" }, "pending projection changed authority: {state:?}");
        if probe == ProjectionProbe::Resume {
            for policy in policies { host.commands.service.discover_policy_fixture(policy).await?; }
        }
        let (runs,operations):(i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=ANY($2::uuid[])),(SELECT count(*) FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND authority->>'kind'='software')")
            .bind(case_tenant()).bind(policies.to_vec()).fetch_one(&mut observer).await?;
        ensure!(runs == 1 && operations == 0, "pending snapshot replaced a run or dispatched: {runs}/{operations}");
        Ok::<_,anyhow::Error>(())
    }.await;
    let released = lock.rollback().await;
    let closed = locker.close().await;
    let observed = observer.close().await;
    result?;
    released?;
    closed?;
    observed?;
    await_channel_projection().await?;
    Ok(probe == ProjectionProbe::Resume)
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
