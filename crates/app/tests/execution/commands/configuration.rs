//! Real immutable configuration content, disjoint native claims and object removal.
use crate::execution::test_support::{
    configuration::{change, published, resource_input, wait_diagnosis},
    native, *,
};
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_execution_service::*;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
use serde_json::{Value, json};
use sqlx::Connection;
use std::collections::BTreeMap;
const CORTANA: &str = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana";
const CAMERA: &str = "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera";
const TELEMETRY: &str = "./Device/Vendor/MSFT/Policy/Config/System/AllowTelemetry";
fn task(nodes: &[&str], remove: bool) -> Value {
    let operations:Vec<_>=nodes.iter().map(|node| json!({"kind":"node","node":node,"instance":[],"operation":if remove{"delete"}else{"replace"},"value":if remove{Value::Null}else{json!({"type":"integer","value":"1"})}})).collect();
    json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"sequence","operations":operations}}})
}
async fn resource(client: &mut Client, nodes: &[&str]) -> anyhow::Result<String> {
    resource_input(
        client,
        json!({"target":{"kind":"device"},"apply":task(nodes,false),"remove":task(nodes,true)}),
        nodes,
    )
    .await
}
fn respond(
    first: &s::Message,
    sent: &s::Message,
    values: &mut BTreeMap<String, String>,
    writes: &mut Vec<String>,
) -> anyhow::Result<s::Message> {
    fn status(
        commands: &mut Vec<s::Command>,
        message: u32,
        id: u32,
        kind: s::CommandName,
        code: u16,
    ) {
        commands.push(s::Command::Status(s::Status {
            id: commands.len() as u32 + 1,
            message_ref: message,
            command_ref: id,
            command: kind,
            target_refs: vec![],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        }));
    }
    fn commands(
        input: &[s::Command],
        output: &mut Vec<s::Command>,
        message: u32,
        values: &mut BTreeMap<String, String>,
        writes: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        for command in input {
            match command {
                s::Command::Status(_) => {}
                s::Command::Sequence {
                    id,
                    commands: children,
                } => {
                    status(output, message, *id, s::CommandName::Sequence, 200);
                    commands(children, output, message, values, writes)?;
                }
                s::Command::Add { id, items, .. } => {
                    for item in items {
                        let uri = item.target.as_deref().unwrap();
                        ensure!(
                            uri.starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/"),
                            "unexpected Add {uri}"
                        );
                        values.insert(uri.into(), item.data.as_ref().unwrap().0.clone());
                    }
                    status(output, message, *id, s::CommandName::Add, 200);
                }
                s::Command::Replace { id, items, .. } | s::Command::Delete { id, items, .. } => {
                    for item in items {
                        let uri = item.target.as_deref().unwrap();
                        ensure!(
                            [CORTANA, CAMERA, TELEMETRY].contains(&uri),
                            "unexpected mutation {uri}"
                        );
                        if matches!(command, s::Command::Delete { .. }) {
                            values.remove(uri);
                        } else {
                            let value = &item.data.as_ref().unwrap().0;
                            ensure!(value == "1");
                            values.insert(uri.into(), value.clone());
                        }
                        writes.push(uri.into());
                    }
                    status(
                        output,
                        message,
                        *id,
                        if matches!(command, s::Command::Delete { .. }) {
                            s::CommandName::Delete
                        } else {
                            s::CommandName::Replace
                        },
                        200,
                    );
                }
                s::Command::Get { id, items, .. } => {
                    for item in items {
                        let uri = item.target.as_deref().unwrap();
                        let value = match uri {
                            "./DevInfo/Mod" => Some("fixture-model"),
                            "./DevDetail/SwV" => Some("10.0.22621.0"),
                            "./Vendor/MSFT/DeviceStatus/OS/Edition" => Some("48"),
                            uri if uri
                                .starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/") =>
                            {
                                values.get(uri).map(String::as_str)
                            }
                            _ => {
                                ensure!(
                                    [CORTANA, CAMERA, TELEMETRY].contains(&uri),
                                    "unexpected query {uri}"
                                );
                                values.get(uri).map(String::as_str)
                            }
                        };
                        status(
                            output,
                            message,
                            *id,
                            s::CommandName::Get,
                            if value.is_some() { 200 } else { 404 },
                        );
                        if let Some(value) = value {
                            output.push(s::Command::Results(s::Results {
                                id: output.len() as u32 + 1,
                                message_ref: Some(message),
                                command_ref: Some(*id),
                                command: Some(s::CommandName::Get),
                                meta: None,
                                items: vec![s::Item {
                                    more_data: false,
                                    source: Some(uri.into()),
                                    target: None,
                                    meta: None,
                                    data: Some(Secret(value.into())),
                                }],
                            }));
                        }
                    }
                }
                _ => anyhow::bail!("unexpected native command family"),
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    status(
        &mut output,
        sent.header.message_id,
        0,
        s::CommandName::SyncHdr,
        200,
    );
    commands(
        &sent.commands,
        &mut output,
        sent.header.message_id,
        values,
        writes,
    )?;
    Ok(s::Message {
        header: s::Header {
            message_id: sent.header.message_id + 1,
            credential: None,
            ..first.header.clone()
        },
        commands: output,
        final_message: true,
    })
}
async fn exchange(
    peer: &crate::windows::test_support::Peer,
    session: u32,
    values: &mut BTreeMap<String, String>,
) -> anyhow::Result<Vec<String>> {
    exchange_with_readback(peer, session, values, None).await
}
async fn exchange_with_readback(
    peer: &crate::windows::test_support::Peer,
    session: u32,
    values: &mut BTreeMap<String, String>,
    readback: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let opened = native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        session,
        readback,
    )
    .await?;
    let mut sent = opened.response;
    let mut writes = Vec::new();
    for _ in 0..6 {
        if sent
            .commands
            .iter()
            .all(|c| matches!(c, s::Command::Status(_)))
        {
            return Ok(writes);
        }
        let packet = respond(&opened.first, &sent, values, &mut writes)?;
        let response = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "native configuration response: {}",
            response.status()
        );
        sent = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    }
    anyhow::bail!("configuration native exchange did not finish")
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.configuration"]
async fn native_object_sets_share_a_device_and_withdraw_only_their_own_objects()
-> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let mut grants: Vec<Value> = [
        "resource_read",
        "resource_write",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
    ]
    .into_iter()
    .map(|operation| json!({"operation":operation,"scope":{"kind":"tenant"}}))
    .collect();
    grants.extend(
        [
            "configuration_write",
            "inventory_read",
            "operation_read",
            "operation_cancel",
        ]
        .into_iter()
        .map(|operation| json!({"operation":operation,"scope":{"kind":"all_devices"}})),
    );
    let rule=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(
        rule.0 == StatusCode::OK,
        "native configuration grant: {rule:?}"
    );

    let mut automation_owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        client.app.flow.planning.clone(),
        client.app.flow.assets.clone(),
        client.app.flow.compliance.clone(),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut startup = automation_owner.startup()?;
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
    let mut values = BTreeMap::new();
    ensure!(exchange(&peer, 970, &mut values).await?.is_empty());
    let scope = Uuid::new_v4();
    let created=change(&mut client,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let page = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!(
                        "/api/v1/scopes/{scope}/tasks/{}",
                        created["task"].as_str().unwrap()
                    ),
                    None,
                )
                .await?;
            if page.1["status"] == "completed" {
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(page.1["status"] != "failed", "Scope failed: {page:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let a = resource(&mut client, &[CORTANA, CAMERA]).await?;
    let b = resource(&mut client, &[TELEMETRY]).await?;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for (id, resource) in [(first, &a), (second, &b)] {
        change(&mut client,&format!("/api/v1/policies/{id}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
    }
    let mut protected_pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let persisted: Vec<String> = sqlx::query_scalar("SELECT frozen::text FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy IN ($2,$3)")
        .bind(case_tenant()).bind(first).bind(second).fetch_all(&mut protected_pg).await?;
    ensure!(persisted.len() == 2);
    for input in persisted {
        ensure!(
            ![CORTANA, CAMERA, TELEMETRY]
                .iter()
                .any(|node| input.contains(node)),
            "frozen Policy native content remained plaintext"
        );
    }
    protected_pg.close().await?;
    let a_ops = published(&mut client, first).await?;
    let b_ops = published(&mut client, second).await?;
    ensure!(
        a_ops.len() == 1 && b_ops.len() == 1 && a_ops != b_ops,
        "disjoint native inputs collapsed into one device slot"
    );
    // A valid ciphertext from another Policy version cannot authorize this operation.
    let mut protected_pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let original: Value = sqlx::query_scalar(
        "SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy=$2",
    )
    .bind(case_tenant())
    .bind(second)
    .fetch_one(&mut protected_pg)
    .await?;
    sqlx::query("UPDATE mdm_policy.versions SET frozen=jsonb_set(frozen,'{native_sealed}',(SELECT frozen->'native_sealed' FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy=$2)) WHERE tenant_id=$1::uuid AND policy=$3")
        .bind(case_tenant()).bind(first).bind(second).execute(&mut protected_pg).await?;
    let denied = client
        .call(Method::GET, &format!("/{}", b_ops[0]), None)
        .await?;
    ensure!(
        denied.0 == StatusCode::SERVICE_UNAVAILABLE,
        "foreign Policy ciphertext was accepted: {denied:?}"
    );
    sqlx::query("UPDATE mdm_policy.versions SET frozen=$3 WHERE tenant_id=$1::uuid AND policy=$2")
        .bind(case_tenant())
        .bind(second)
        .bind(original)
        .execute(&mut protected_pg)
        .await?;
    ensure!(
        client
            .call(Method::GET, &format!("/{}", b_ops[0]), None)
            .await?
            .0
            == StatusCode::OK
    );
    protected_pg.close().await?;
    // Equal shared values do not make two different Sequence groups interchangeable.
    let overlapping_resource = resource(&mut client, &[CORTANA, TELEMETRY]).await?;
    let overlapping = Uuid::new_v4();
    change(&mut client,&format!("/api/v1/policies/{overlapping}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":overlapping_resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v1/policies/{overlapping}/assignments"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK);
            ensure!(
                read.1["items"][0]["reason"] != "configuration_conflict",
                "equal object content was mislabeled as a value conflict: {read:?}"
            );
            if read.1["items"][0]["reason"] == "native_group_conflict" {
                ensure!(read.1["items"][0]["availability"] == "unavailable");
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    change(
        &mut client,
        &format!("/api/v1/policies/{overlapping}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    ensure!(
        published(&mut client, first).await? == a_ops
            && published(&mut client, second).await? == b_ops,
        "conflict discarded the existing immutable dispatch identity"
    );
    // Identical native input has two Policy owners, but one immutable operation.
    let shared = Uuid::new_v4();
    change(&mut client,&format!("/api/v1/policies/{shared}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":a,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
    ensure!(
        published(&mut client, shared).await? == a_ops,
        "identical owners dispatched twice"
    );
    change(
        &mut client,
        &format!("/api/v1/policies/{first}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let mut writes = exchange(&peer, 971, &mut values).await?;
    writes.sort();
    let mut expected = vec![CORTANA.to_owned(), CAMERA.to_owned(), TELEMETRY.to_owned()];
    expected.sort();
    ensure!(writes == expected, "native writes: {writes:?}");
    for operation in a_ops.iter().chain(&b_ops) {
        let read = client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "applied",
            "native readback: {read:?}"
        );
    }
    // A remaining owner of one member must not let withdrawal clip a Sequence.
    let keeper_resource = resource(&mut client, &[CORTANA]).await?;
    let keeper = Uuid::new_v4();
    change(&mut client,&format!("/api/v1/policies/{keeper}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":keeper_resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"retain"}}})).await?;
    wait_diagnosis(&mut client, keeper, "native_group_conflict").await?;
    change(
        &mut client,
        &format!("/api/v1/policies/{shared}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    wait_diagnosis(&mut client, shared, "removal_blocked_by_shared_unit").await?;
    published(&mut client, keeper).await?;
    ensure!(exchange(&peer, 972, &mut values).await? == vec![CORTANA.to_owned()]);
    ensure!(
        values.get(CAMERA).map(String::as_str) == Some("1"),
        "partial withdrawal clipped the native Sequence"
    );
    change(
        &mut client,
        &format!("/api/v1/policies/{keeper}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;

    let removed = published(&mut client, shared).await?;
    ensure!(removed != a_ops);
    let mut writes = exchange(&peer, 974, &mut values).await?;
    writes.sort();
    let mut expected = vec![CORTANA.to_owned(), CAMERA.to_owned()];
    expected.sort();
    ensure!(
        writes == expected,
        "withdrawal touched another owner: {writes:?}"
    );
    ensure!(values.get(TELEMETRY).map(String::as_str) == Some("1"));
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    // Delete of permanent Policy leaves restores native defaults. A fake 404 must not
    // release guards for this unresolved removal, even after withdrawal is acknowledged.
    let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=ANY($2)").bind(case_tenant()).bind(vec![first,shared]).fetch_one(&mut pg).await?;
    ensure!(
        remaining > 0,
        "unverified default restoration released claims"
    );
    for id in &removed {
        let read = client.call(Method::GET, &format!("/{id}"), None).await?;
        ensure!(read.1["commandStatus"] != "applied");
        ensure!(read.1["observation"]["effect"] == "unverifiable");
        ensure!(
            read.1["observation"]["effectReason"]
                == "delete_restores_default_without_frozen_detector"
        );
    }
    for id in &removed {
        let read = client.call(Method::GET, &format!("/{id}"), None).await?;
        let cancelled = client
            .call(
                Method::POST,
                &format!("/{id}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":read.1["revision"]})),
            )
            .await?;
        ensure!(
            cancelled.0 == StatusCode::CONFLICT,
            "Policy child cannot be cancelled through the direct control route"
        );
    }
    // Reconstruct the execution adapter and drive the same policy reconciliation on persisted facts.
    let config = crate::test_support::identity::config(case_tenant())?;
    let restarted = Box::pin(crate::execution_assembly::open(
        &config,
        config.native_protector()?,
        crate::test_support::identity::audit_store(&config).await?,
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?,
        std::collections::BTreeMap::new(),
        rss_device_command_postgres::CommandClock::Postgres,
        crate::test_support::identity::session_authority(&config).await?,
    ))
    .await?;
    let timer = recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(2), &cancel);
    let recovery_policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(10),
        attempt_timeout: Duration::from_secs(1),
        scan_interval: Duration::from_millis(100),
        idle_scan_interval: Duration::from_millis(100),
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        max_attempts: 3,
    })?;
    restarted
        .service
        .run_recovery(
            &recovery_scope(client.app.identity.tenant),
            recovery_policy,
            &control,
            &tokio::sync::Notify::new(),
        )
        .await?;
    let policy_read = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{shared}/assignments"),
            None,
        )
        .await?;
    let current: Vec<Uuid> = policy_read.1["items"][0]["operationIds"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("operation IDs missing"))?
        .iter()
        .map(|v| Uuid::parse_str(v.as_str().unwrap()))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        current == removed,
        "cancel/restart reissued an uncertain Delete"
    );
    ensure!(
        exchange(&peer, 976, &mut values).await?.is_empty(),
        "unknown deletion replayed after recovery"
    );
    restarted.runtime.close().await;
    let other:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2").bind(case_tenant()).bind(second).fetch_one(&mut pg).await?;
    ensure!(other == 1);
    host.replace(&peer).await?;
    let replacement = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let ids = published(&mut client, second).await?;
            if ids != b_ops {
                return Ok::<_, anyhow::Error>(ids);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("new registration reused old Applied configuration evidence"))??;
    for id in replacement {
        let generation:i64=sqlx::query_scalar("SELECT registration_generation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).fetch_one(&mut pg).await?;
        ensure!(generation == 2);
    }
    pg.close().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(automation_owner.shutdown().join().await?.is_clean());
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.configuration"]
async fn associated_agent_health_executes_only_original_mdm_and_missing_channel_has_no_effects()
-> anyhow::Result<()> {
    use crate::test_support::{inventory, planning_http};
    use rss_mdm_inventory::{Scalar, builtin::CORPORATE_AGENT_HEALTHY};
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut pg)
        .await?;
    let (mdm_registration, mdm_epoch):(Uuid,Uuid)=sqlx::query_as("SELECT r.id,s.epoch FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='mdm' AND r.state='active' AND s.source='mdm.windows'").bind(case_tenant()).bind(case_device()).fetch_one(&mut pg).await?;
    crate::device::t2::associations::hardware(
        case_device(),
        mdm_registration,
        mdm_epoch,
        "mdm.windows",
        "2714-NATIVE",
    )?;
    let agent = crate::test_support::case::name("native-health-agent");
    let alone = crate::test_support::case::name("native-health-missing");
    let agent_registration = crate::device::t2::associations::seed(agent, "agent", "2714-native")?;
    let alone_registration =
        crate::device::t2::associations::seed(alone, "agent", "2714-native-alone")?;
    let field = CORPORATE_AGENT_HEALTHY;
    let definition = inventory::definition(field.as_str(), "agent.script", &[field]);
    inventory::register_definition(&definition)?;
    for registration in [agent_registration, alone_registration] {
        let epoch = Uuid::new_v4();
        let scope = crate::device::scope_dataset(
            client.app.identity.tenant,
            registration,
            "agent.script",
            epoch,
            field.as_str(),
        )?
        .encode()?;
        sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,'agent.script',$3,true)").bind(case_tenant()).bind(registration).bind(epoch).execute(&mut pg).await?;
        sqlx::query("INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),$1::uuid,'mdm.observation.v1','inventory-v7',$2,$3,'custom.corporate_agent.healthy',$4,'health-fixture',1,2,'known',$4,'health-fixture',1,2,$5,'agent.script',$6,0)").bind(case_tenant()).bind(scope).bind(serde_json::to_string(&definition.coverage()?)?).bind(serde_json::to_value(Scalar::Boolean(false))?).bind(registration).bind(epoch).execute(&mut pg).await?;
    }
    let config = crate::test_support::identity::config(case_tenant())?;
    let associations = rss_mdm_device_service::Associations::new(
        crate::test_support::identity::audit_store(&config).await?,
        client.app.identity.tenant,
        &[7; 32],
    )?;
    associations.reconcile().await?;
    let grants: Vec<_> = [
        "resource_read",
        "resource_write",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
        "group_read",
        "group_write",
        "group_recompute",
    ]
    .into_iter()
    .map(|operation| json!({"operation":operation,"scope":{"kind":"tenant"}}))
    .chain(
        ["configuration_write", "inventory_read", "operation_read"]
            .into_iter()
            .map(|operation| json!({"operation":operation,"scope":{"kind":"all_devices"}})),
    )
    .collect();
    let reply=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(reply.0 == StatusCode::OK, "{reply:?}");
    let automation = crate::test_support::start_automation(&serde_json::from_slice(
        &std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?,
    )?)
    .await?;
    let commands = client.command_worker(host.notifications.signals.clone())?;
    let mut values = BTreeMap::new();
    ensure!(exchange(&peer, 981, &mut values).await?.is_empty());
    let group = Uuid::new_v4();
    let scope = Uuid::new_v4();
    let policy = Uuid::new_v4();
    planning_http::call(&mut client.browser,&client.router,&format!("/api/v1/groups/{group}"),0,json!({"action":"create","assetContext":"associated_device","name":"Agent health remediation","description":"","criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":false}}}})).await?;
    planning_http::call(&mut client.browser,&client.router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let resource = resource(&mut client, &[CORTANA]).await?;
    let excluded_scope = Uuid::new_v4();
    planning_http::call(&mut client.browser,&client.router,&format!("/api/v1/scopes/{excluded_scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":alone}],"limitations":null,"exclusions":[]}})).await?;
    for index in 1..=17 {
        let excluded_policy = Uuid::from_u128(index);
        change(&mut client,&format!("/api/v1/policies/{excluded_policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":excluded_scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"retain"}}})).await?;
    }
    change(&mut client,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"retain"}}})).await?;
    planning_http::await_ingress().await?;
    use rss_mdm_execution_service::source_authority::{CandidateKind, SourceAuthority};
    let source = crate::planning::execution_source::ExecutionSource::new(
        client.app.flow.planning.objects.clone(),
    );
    let mut transaction = pg.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *transaction)
        .await?;
    let first_page = source
        .candidates_on(
            &mut transaction,
            client.app.identity.tenant,
            case_device(),
            CandidateKind::Configuration,
            Uuid::nil(),
        )
        .await?;
    ensure!(
        first_page.items.is_empty()
            && first_page.has_more
            && first_page.scanned_after == Uuid::from_u128(16),
        "excluded candidates lost bounded scan progress"
    );
    let next_page = source
        .candidates_on(
            &mut transaction,
            client.app.identity.tenant,
            case_device(),
            CandidateKind::Configuration,
            first_page.scanned_after,
        )
        .await?;
    ensure!(
        next_page.items.iter().any(|c| c.policy == policy),
        "eligible policy after empty page was skipped"
    );
    transaction.rollback().await?;
    let operations = published(&mut client, policy).await?;
    ensure!(
        operations.len() == 1,
        "associated target broadcast: {operations:?}"
    );
    let page = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/assignments"),
            None,
        )
        .await?
        .1;
    let missing = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["object"]["id"] == alone)
        .unwrap();
    ensure!(
        missing["availability"] == "unavailable" && missing["target"].is_null(),
        "{page}"
    );
    let effects:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND device=$2)+(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$2)").bind(case_tenant()).bind(alone).fetch_one(&mut pg).await?;
    ensure!(effects == 0, "missing channel produced executable effects");
    let targets:Vec<(String,Uuid,i64)>=sqlx::query_as("SELECT device,registration,registration_generation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(case_tenant()).bind(&operations).fetch_all(&mut pg).await?;
    ensure!(
        targets.len() == 1 && targets[0].0 == case_device() && targets[0].1 == mdm_registration
    );
    let mut writes = Vec::new();
    for session in 982..987 {
        writes.extend(
            exchange_with_readback(
                &peer,
                session,
                &mut values,
                (!writes.is_empty()).then_some(CORTANA),
            )
            .await?,
        );
        let progress = client
            .call(Method::GET, &format!("/{}", operations[0]), None)
            .await?;
        if progress.1["commandStatus"] == "applied" {
            break;
        }
        planning_http::await_ingress().await?;
    }
    let read = client
        .call(Method::GET, &format!("/{}", operations[0]), None)
        .await?;
    ensure!(
        writes == vec![CORTANA.to_owned()] && read.1["commandStatus"] == "applied",
        "original native result: writes={writes:?}, operation={read:?}"
    );
    crate::test_support::inventory::seed_source(alone, "mdm", "mdm.windows", "model")?;
    planning_http::await_ingress().await?;
    let page = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/assignments"),
            None,
        )
        .await?
        .1;
    let recovered = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["object"]["id"] == alone)
        .unwrap();
    ensure!(
        recovered["availability"] == "ready" && recovered["target"]["device"] == alone,
        "automatic channel recovery: {page}"
    );
    let frozen: Value = sqlx::query_scalar(
        "SELECT approval FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(operations[0])
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        frozen["source_objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["members"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["registrationId"] == agent_registration.to_string())),
        "original Agent evidence missing: {frozen}"
    );
    let authority: rss_mdm_execution_service::authority::ExecutionAuthority =
        serde_json::from_value(frozen)?;
    let source = crate::planning::execution_source::ExecutionSource::new(
        client.app.flow.planning.objects.clone(),
    );
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        authority.dispatch_ready(&source, &mut tx).await?,
        "fresh owner proof rejected original target"
    );
    tx.rollback().await?;
    crate::test_support::stop_worker(automation).await?;
    crate::device::t2::associations::seed(
        crate::test_support::case::name("native-health-duplicate"),
        "agent",
        "2714-NATIVE",
    )?;
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        !authority.dispatch_ready(&source, &mut tx).await?,
        "hardware contradiction before recomputation passed dispatch"
    );
    tx.rollback().await?;
    let original:(String,Uuid,i64)=sqlx::query_as("SELECT device,registration,registration_generation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(operations[0]).fetch_one(&mut pg).await?;
    ensure!(
        original == targets[0],
        "channel restoration rewrote original task attribution"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    pg.close().await?;
    host.close().await?;
    Ok(())
}
