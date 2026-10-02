//! Real immutable configuration content, disjoint native claims and object removal.
use crate::execution::test_support::{native, *};
use crate::execution::*;
use anyhow::ensure;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
use serde_json::{Value, json};
use sqlx::Connection;
use std::collections::BTreeMap;
use tower::ServiceExt;
const CORTANA: &str = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana";
const CAMERA: &str = "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera";
const TELEMETRY: &str = "./Device/Vendor/MSFT/Policy/Config/System/AllowTelemetry";
fn task(nodes: &[&str], remove: bool) -> Value {
    let operations:Vec<_>=nodes.iter().map(|node| json!({"kind":"node","node":node,"instance":[],"operation":if remove{"delete"}else{"replace"},"value":if remove{Value::Null}else{json!({"type":"integer","value":"1"})}})).collect();
    json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"sequence","operations":operations}}})
}
async fn change(
    client: &mut Client,
    path: &str,
    revision: u64,
    input: Value,
) -> anyhow::Result<Value> {
    let reply = client
        .browser
        .call(
            &client.router,
            Method::POST,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})),
        )
        .await?;
    ensure!(
        reply.0 == StatusCode::OK,
        "configuration write {path}: {reply:?}"
    );
    Ok(reply.1)
}
async fn resource(client: &mut Client, nodes: &[&str]) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let path = format!("/api/v4/resources/{id}");
    change(
        client,
        &path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    let bytes = serde_json::to_vec(
        &json!({"target":{"kind":"device"},"apply":task(nodes,false),"remove":task(nodes,true)}),
    )?;
    let sha = rss_mdm_resource::Digest::of(&bytes).bytes();
    change(client,&path,1,json!({"action":"version","version":"1","kind":"configuration","variants":[{"platform":"windows","architecture":"x86_64","key":"native","declaration":{"kind":"configuration","artifact":{"reference":"native-input","length":bytes.len(),"sha256":sha}}}]})).await?;
    let upload = format!(
        "/api/v3/resources/{id}/content?version=1&variant=native&platform=windows&architecture=x86_64&operation={}",
        Uuid::new_v4()
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(upload)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", client.browser.csrf.as_ref().unwrap())
        .header(
            "cookie",
            client
                .browser
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))?;
    let response = client.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    ensure!(
        status == StatusCode::CREATED,
        "configuration artifact upload: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let content_root = client
        .app
        .execution
        .content
        .as_ref()
        .unwrap()
        .config
        .directory
        .join(case_tenant());
    for entry in std::fs::read_dir(content_root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let stored = std::fs::read(entry.path())?;
            for node in nodes {
                ensure!(
                    !stored
                        .windows(node.len())
                        .any(|part| part == node.as_bytes()),
                    "native configuration content remained plaintext"
                );
            }
        }
    }
    change(client, &path, 2, json!({"action":"activate","version":"1"})).await?;
    Ok(id)
}
async fn published(client: &mut Client, policy: Uuid) -> anyhow::Result<Vec<Uuid>> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let page = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v3/policies/{policy}/devices"),
                    None,
                )
                .await?;
            ensure!(page.0 == StatusCode::OK, "configuration devices: {page:?}");
            let ids: Vec<Uuid> = page.1["items"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|d| d["operationIds"].as_array().unwrap())
                .map(|id| Uuid::parse_str(id.as_str().unwrap()))
                .collect::<std::result::Result<_, _>>()?;
            if !ids.is_empty() {
                let mut ready = true;
                for id in &ids {
                    let read = client.call(Method::GET, &format!("/{id}"), None).await?;
                    ready &= read.1["commandStatus"] == "published";
                }
                if ready {
                    return Ok::<_, anyhow::Error>(ids);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
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
    let opened = native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        session,
        None,
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
    let created=change(&mut client,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let page = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!(
                        "/api/v2/scopes/{scope}/tasks/{}",
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
        change(&mut client,&format!("/api/v3/policies/{id}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
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
    change(&mut client,&format!("/api/v3/policies/{overlapping}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":overlapping_resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v3/policies/{overlapping}/devices"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK);
            if let Some(diagnoses) = read.1["items"][0]["diagnoses"].as_array() {
                ensure!(
                    !diagnoses.iter().any(|d| d == "configuration_conflict"),
                    "equal object content was mislabeled as a value conflict: {read:?}"
                );
                if diagnoses.iter().any(|d| d == "native_group_conflict") {
                    return Ok::<_, anyhow::Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    change(
        &mut client,
        &format!("/api/v3/policies/{overlapping}"),
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
    change(&mut client,&format!("/api/v3/policies/{shared}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":a,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"remove"}}})).await?;
    ensure!(
        published(&mut client, shared).await? == a_ops,
        "identical owners dispatched twice"
    );
    change(
        &mut client,
        &format!("/api/v3/policies/{first}"),
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
    change(&mut client,&format!("/api/v3/policies/{keeper}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":keeper_resource,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"exit":"retain"}}})).await?;
    wait_diagnosis(&mut client, keeper, "native_group_conflict").await?;
    change(
        &mut client,
        &format!("/api/v3/policies/{shared}"),
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
        &format!("/api/v3/policies/{keeper}"),
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
    let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2").bind(case_tenant()).bind(first).fetch_one(&mut pg).await?;
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
    let other:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2").bind(case_tenant()).bind(second).fetch_one(&mut pg).await?;
    ensure!(other == 1);
    let remote = Uuid::new_v4();
    let remote_input = json!({"operationId":remote,"resource":{"id":a,"version":"1","platform":"windows","architecture":"x86_64","variant":"native"},"targets":{"kind":"devices","devices":[case_device()]},"action":{"kind":"apply_configuration"},"deadline":client.app.clock.unix_seconds()?+600});
    let accepted = client
        .browser
        .call(
            &client.router,
            Method::POST,
            "/api/v3/remote-operations",
            Some(remote_input.clone()),
        )
        .await?;
    ensure!(accepted.0 == StatusCode::OK, "remote native: {accepted:?}");
    ensure!(accepted.1["statusUrl"] == format!("/api/v3/remote-operations/{remote}"));
    ensure!(
        accepted
            == client
                .browser
                .call(
                    &client.router,
                    Method::POST,
                    "/api/v3/remote-operations",
                    Some(remote_input)
                )
                .await?,
        "remote replay changed the protected publication"
    );
    let frozen: String = sqlx::query_scalar("SELECT frozen::text FROM mdm_planning.remote_operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(remote).fetch_one(&mut pg).await?;
    ensure!(
        !frozen.contains(CORTANA) && !frozen.contains(CAMERA),
        "remote native input remained plaintext"
    );
    let delivery = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v3/remote-operations/{remote}"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK, "remote read: {read:?}");
            if let Some(id) = read.1["items"][0]["deliveryId"].as_str() {
                let id = Uuid::parse_str(id)?;
                if client.call(Method::GET, &format!("/{id}"), None).await?.1["commandStatus"]
                    == "published"
                {
                    return Ok::<_, anyhow::Error>(id);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let mut writes = exchange(&peer, 975, &mut values).await?;
    writes.sort();
    ensure!(
        writes == expected,
        "protected remote configuration was not applied: {writes:?}"
    );
    ensure!(
        client
            .call(Method::GET, &format!("/{delivery}"), None)
            .await?
            .1["commandStatus"]
            == "applied"
    );
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

async fn wait_diagnosis(client: &mut Client, policy: Uuid, expected: &str) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v3/policies/{policy}/devices"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK);
            if read.1["items"][0]["diagnoses"]
                .as_array()
                .is_some_and(|d| d.iter().any(|value| value == expected))
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Policy {policy} did not report {expected}"))?
}
