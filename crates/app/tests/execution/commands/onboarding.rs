//! Real mTLS/SyncML, approved software, Policy and one atomic independent Agent registration.
use crate::execution::test_support::{Client, case_device, case_tenant, native};
use crate::test_support::{channel_onboarding as setup, *};
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
async fn post(
    peer: &crate::windows::test_support::Peer,
    message: &s::Message,
) -> Result<s::Message> {
    let response = native::post(&peer.mutual, &peer.url, message).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status == StatusCode::OK,
        "SyncML {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(s::decode(&bytes, &CodecLimits::default())?)
}
async fn begin(
    peer: &crate::windows::test_support::Peer,
    session: u32,
) -> Result<(s::Message, s::Message)> {
    use base64::Engine;
    let mut initial = peer.message.clone();
    initial.header.session_id = session;
    post(peer, &initial).await?;
    let mut ack = peer.ack.clone();
    ack.header.session_id = session;
    if let s::Command::Status(s) = &mut ack.commands[0] {
        s.challenge.as_mut().unwrap().nonce = Some(Secret(
            base64::engine::general_purpose::STANDARD.encode([session as u8; 16]),
        ));
    }
    Ok((initial, post(peer, &ack).await?))
}
fn reply(initial: &s::Message, response: &s::Message, installed: bool) -> s::Message {
    let message = response.header.message_id;
    let mut output = s::Message {
        header: s::Header {
            message_id: message + 1,
            credential: None,
            ..initial.header.clone()
        },
        commands: vec![],
        final_message: true,
    };
    let mut status = |id, command, code| {
        output.commands.push(s::Command::Status(s::Status {
            id: output.commands.len() as u32 + 1,
            message_ref: message,
            command_ref: id,
            command,
            target_refs: vec![],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        }));
    };
    status(0, s::CommandName::SyncHdr, 200);
    for c in &response.commands {
        match c {
            s::Command::Get { id, items, .. } => {
                let uri = items[0].target.as_deref().unwrap();
                let is_product = uri.contains("EnterpriseDesktopAppManagement");
                let code = if is_product && !installed { 404 } else { 200 };
                output.commands.push(s::Command::Status(s::Status {
                    id: output.commands.len() as u32 + 1,
                    message_ref: message,
                    command_ref: *id,
                    command: s::CommandName::Get,
                    target_refs: vec![],
                    source_refs: vec![],
                    code,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }));
                if code == 200 {
                    let value = if uri.ends_with("/Mod") {
                        "MDM-only"
                    } else if uri.ends_with("/Edition") {
                        "48"
                    } else if uri.ends_with("ProcessorArchitecture") {
                        "AMD64"
                    } else if uri.ends_with("/Publisher") {
                        "RSS controlled publisher"
                    } else if uri.ends_with("/Version") {
                        "1.2.3"
                    } else if uri.ends_with("/Status") {
                        "70"
                    } else {
                        "10.0.19045.0"
                    };
                    output.commands.push(s::Command::Results(s::Results {
                        id: output.commands.len() as u32 + 1,
                        message_ref: Some(message),
                        command_ref: Some(*id),
                        command: Some(s::CommandName::Get),
                        meta: None,
                        items: vec![s::Item {
                            target: None,
                            source: Some(uri.into()),
                            meta: None,
                            data: Some(Secret(value.into())),
                        }],
                    }));
                }
            }
            s::Command::AgentInstall { id, command } => {
                let command = if matches!(
                    command,
                    rss_mdm_windows_mdm::agent_install::AgentCommand::Prepare { .. }
                ) {
                    s::CommandName::Add
                } else {
                    s::CommandName::Exec
                };
                output.commands.push(s::Command::Status(s::Status {
                    id: output.commands.len() as u32 + 1,
                    message_ref: message,
                    command_ref: *id,
                    command,
                    target_refs: vec![],
                    source_refs: vec![],
                    code: 200,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }));
            }
            _ => (),
        }
    }
    output
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn windows_policy_install_register_and_replay_use_independent_identity() -> Result<()> {
    let (host, mut client, peer, mut commands, owner, policy, operation) = start_fixture().await?;
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["taskAdmission"]["state"] == "eligible"
            && state["operationId"] == operation.to_string(),
        "{state}"
    );
    let (initial, execute) = execute(&peer).await?;
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v4/managed-registrations",
    );
    let input = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("managed-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.basic.v4","task.execute.v4"]});
    let spoof = peer
        .mutual
        .post(&url)
        .header("x-device-id", case_device())
        .json(&input)
        .send()
        .await?;
    ensure!(
        spoof.status() == StatusCode::BAD_REQUEST
            && spoof.json::<Value>().await?["code"] == "malformed_request"
    );
    let mut wrong = input.clone();
    wrong["architecture"] = json!("aarch64");
    ensure!(peer.mutual.post(&url).json(&wrong).send().await?.status() == StatusCode::FORBIDDEN);
    wrong["architecture"] = json!("x86_64");
    wrong["installationOperation"] = json!(Uuid::new_v4());
    ensure!(peer.mutual.post(&url).json(&wrong).send().await?.status() == StatusCode::FORBIDDEN);
    let package = Request::builder()
        .uri(format!("/api/agent/v4/installations/{operation}/package"))
        .header("host", "mdm.example.test")
        .header("range", "bytes=0-3")
        .body(Body::empty())?;
    let package = client.router.clone().oneshot(package).await?;
    ensure!(
        package.status() == StatusCode::PARTIAL_CONTENT,
        "package {}",
        package.status()
    );
    ensure!(
        axum::body::to_bytes(package.into_body(), 1024)
            .await?
            .as_ref()
            == &setup::bytes()[..4]
    );
    // Stop producers before fault injection, then restart the existing command runtime.
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.app
        .execution
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    let unknown = peer.mutual.post(&url).json(&input).send().await?;
    ensure!(
        unknown.status() == StatusCode::SERVICE_UNAVAILABLE
            && unknown.json::<Value>().await?["code"] == "operation_unknown"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    host.app
        .execution
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let unknown = peer.mutual.post(&url).json(&input).send().await?;
    ensure!(
        unknown.status() == StatusCode::SERVICE_UNAVAILABLE
            && unknown.json::<Value>().await?["code"] == "operation_unknown"
    );
    let response = peer.mutual.post(&url).json(&input).send().await?;
    let status = response.status();
    let receipt: Value = response.json().await?;
    ensure!(
        status == StatusCode::OK,
        "managed recovery {status}: {receipt}"
    );
    ensure!(receipt["deviceId"] != case_device());
    let again = peer.mutual.post(&url).json(&input).send().await?;
    ensure!(again.status() == StatusCode::OK);
    ensure!(again.json::<Value>().await? == receipt);
    let mut changed = input.clone();
    changed["credential"] = json!(credential("different-secret"));
    ensure!(peer.mutual.post(&url).json(&changed).send().await?.status() == StatusCode::CONFLICT);
    let mut duplicate = input.clone();
    duplicate["operationId"] = json!(Uuid::new_v4());
    ensure!(
        peer.mutual
            .post(&url)
            .json(&duplicate)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    commands = client.command_worker(host.notifications.signals.clone())?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="1");
    post(&peer, &reply(&initial, &execute, false)).await?;
    let (initial, observe) = begin(&peer, 903).await?;
    ensure!(
        !observe
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::AgentInstall { .. }))
    );
    post(&peer, &reply(&initial, &observe, true)).await?;
    let mut installed = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    for _ in 0..100 {
        if installed.1["observation"]["installation"] == "installed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        installed = client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
    }
    ensure!(
        installed.1["observation"]["installation"] == "installed",
        "{installed:?}"
    );
    ensure!(installed.1["observation"]["agentRegistration"]["deviceId"] == receipt["deviceId"]);
    ensure!(commands.shutdown().join().await?.is_clean());
    let subject = browser_subject(&client.browser, &client.router).await?;
    identity::set_grants(case_tenant(), &subject, vec![]).await?;
    ensure!(
        peer.mutual
            .post(&url)
            .json(&duplicate)
            .send()
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(peer.mutual.post(&url).json(&input).send().await?.status() == StatusCode::OK);
    setup::grants(&client.browser, &client.router).await?;
    host.replace(&peer).await?;
    ensure!(peer.mutual.post(&url).json(&input).send().await?.status() == StatusCode::UNAUTHORIZED);
    let report = json!({"wireVersion":4,"reportId":Uuid::new_v4(),"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}});
    ensure!(
        agent_call(
            &client.router,
            Method::POST,
            "/api/agent/v4/reports",
            Some(&credential("managed-agent")),
            Some(report)
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    host.close().await?;
    Ok(())
}

async fn start_fixture() -> Result<(
    crate::windows::test_support::Host,
    Client,
    crate::windows::test_support::Peer,
    rss_runtime::ShutdownStack,
    rss_runtime::ShutdownStack,
    Uuid,
    Uuid,
)> {
    start_fixture_until(None).await
}
async fn start_fixture_until(
    until: Option<i64>,
) -> Result<(
    crate::windows::test_support::Host,
    Client,
    crate::windows::test_support::Peer,
    rss_runtime::ShutdownStack,
    rss_runtime::ShutdownStack,
    Uuid,
    Uuid,
)> {
    let mut host = crate::windows::test_support::Host::with_agent(Some(setup::pin(true))).await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        host.app.flow.planning.clone(),
        host.app.flow.assets.clone(),
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
    let policy = setup::publish_until(
        &mut client.browser,
        &client.router,
        case_device(),
        true,
        until,
    )
    .await?;
    let (initial, response) = begin(&peer, 901).await?;
    ensure!(
        response
            .commands
            .iter()
            .filter(|c| matches!(c, s::Command::Get { .. }))
            .count()
            == 8
    );
    post(&peer, &reply(&initial, &response, false)).await?;
    let operation = setup::operation(policy).await?;
    Ok((host, client, peer, commands, owner, policy, operation))
}
async fn execute(peer: &crate::windows::test_support::Peer) -> Result<(s::Message, s::Message)> {
    let (initial, prepare) = begin(peer, 902).await?;
    let mut next = post(peer, &reply(&initial, &prepare, false)).await?;
    let mut initial = initial;
    for index in 0..30 {
        if next.commands.iter().any(|c| {
            matches!(
                c,
                s::Command::AgentInstall {
                    command: rss_mdm_windows_mdm::agent_install::AgentCommand::Install(_),
                    ..
                }
            )
        }) {
            return Ok((initial, next));
        }
        // The just-sealed normal report may still be awaiting Inventory/Scope projection.
        tokio::time::sleep(Duration::from_millis(150)).await;
        (initial, next) = begin(peer, 910 + index).await?;
    }
    anyhow::bail!("install was not released after projection: {next:?}")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn failed_prepare_rejects_without_dispatching_installation() -> Result<()> {
    let (host, mut client, peer, commands, owner, _, operation) = start_fixture().await?;
    let (initial, prepare) = begin(&peer, 902).await?;
    let mut response = reply(&initial, &prepare, false);
    for c in &mut response.commands {
        if let s::Command::Status(s) = c
            && s.command == s::CommandName::Add
        {
            s.code = 500;
        }
    }
    let next = post(&peer, &response).await?;
    ensure!(
        !next
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::AgentInstall { .. }))
    );
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "rejected" && state.1["observation"]["delivery"] == "rejected",
        "{state:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.attempts WHERE operation='{operation}' AND phase='execute'"))?.trim()=="0");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn native_enforcement_failure_is_separate_from_delivery_and_never_reinstalled() -> Result<()>
{
    let (host, mut client, peer, commands, owner, _, operation) = start_fixture().await?;
    let (initial, execute) = execute(&peer).await?;
    post(&peer, &reply(&initial, &execute, false)).await?;
    let (initial, query) = begin(&peer, 903).await?;
    let mut response = reply(&initial, &query, true);
    for c in &mut response.commands {
        if let s::Command::Results(r) = c {
            for i in &mut r.items {
                if i.source.as_deref().is_some_and(|s| s.ends_with("/Status")) {
                    i.data = Some(Secret("60".into()));
                }
            }
        }
    }
    post(&peer, &response).await?;
    let mut state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    for _ in 0..100 {
        if state.1["observation"]["installation"] == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        state = client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
    }
    ensure!(
        state.1["observation"]["installation"] == "failed"
            && state.1["observation"]["delivery"] == "acknowledged",
        "{state:?}"
    );
    let (_, query) = begin(&peer, 904).await?;
    ensure!(
        !query
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::AgentInstall { .. }))
    );
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["commandStatus"]
            == "rejected"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn cancellation_blocks_registration_and_preserves_uncertain_native_effect() -> Result<()> {
    let (host, mut client, peer, commands, owner, _, operation) = start_fixture().await?;
    execute(&peer).await?;
    let result = client
        .call(
            Method::POST,
            &format!("/{operation}/cancel"),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1})),
        )
        .await?;
    ensure!(result.0 == StatusCode::OK, "{result:?}");
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v4/managed-registrations",
    );
    let input = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("cancelled-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.basic.v4"]});
    ensure!(peer.mutual.post(url).json(&input).send().await?.status() == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "cancelled"
            && state.1["observation"]["installation"] == "unknown",
        "{state:?}"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn schedule_expiry_caps_installation_and_blocks_new_agent_registration() -> Result<()> {
    use crate::clock::Clock;
    let until = crate::clock::SystemClock.unix_seconds()? + 20;
    let (host, mut client, peer, commands, owner, _, operation) =
        start_fixture_until(Some(until)).await?;
    execute(&peer).await?;
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["deadline"]
            == until
    );
    tokio::time::timeout(Duration::from_secs(25), async {
        while crate::clock::SystemClock.unix_seconds()? <= until {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v4/managed-registrations",
    );
    let input = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("expired-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.basic.v4"]});
    ensure!(peer.mutual.post(url).json(&input).send().await?.status() == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["observation"]["installation"] == "unknown",
        "expiry is not a failed installation: {state:?}"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}
