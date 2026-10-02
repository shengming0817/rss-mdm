//! Real mTLS/SyncML, approved software, Policy and one atomic independent Agent registration.
use crate::execution::test_support::{Client, case_device, case_tenant, native};
use crate::test_support::{channel_onboarding as setup, *};
use anyhow::Context;
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
            s::Command::Add { id, .. } | s::Command::Exec { id, .. } => {
                let command = if matches!(c, s::Command::Add { .. }) {
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
            && state["operationIds"] == json!([operation]),
        "{state}"
    );
    let (initial, execute) = execute(&peer).await?;
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v5/managed-registrations",
    );
    let input = json!({"wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("managed-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v5","task.execute.v5"]});
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
        .uri(format!("/api/agent/v5/installations/{operation}/package"))
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
    for (field, value, code) in [
        ("wireVersion", json!(3), "unsupported_wire"),
        (
            "capabilities",
            json!(["inventory.basic.v3"]),
            "unsupported_capability",
        ),
        (
            "capabilities",
            json!(["inventory.collect.v5", "inventory.collect.v5"]),
            "unsupported_capability",
        ),
        ("deviceId", json!("untrusted"), "malformed_request"),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        let response = peer.mutual.post(&url).json(&invalid).send().await?;
        ensure!(response.status() == StatusCode::BAD_REQUEST);
        ensure!(response.json::<serde_json::Value>().await?["code"] == code);
    }
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
            .any(|c| matches!(c, s::Command::Add { .. } | s::Command::Exec { .. }))
    );
    post(&peer, &reply(&initial, &observe, true)).await?;
    let mut installed = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    for _ in 0..100 {
        if installed.1["agentInstallation"]["installation"] == "installed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        installed = client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
    }
    ensure!(
        installed.1["agentInstallation"]["installation"] == "installed",
        "{installed:?}"
    );
    ensure!(
        installed.1["agentInstallation"]["agentRegistration"]["deviceId"] == receipt["deviceId"]
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    let subject = browser_subject(&client.browser, &client.router).await?;
    identity::set_grants(case_tenant(), &subject, vec![]).await?;
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
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
    begin(&peer, 945).await?;
    let incomplete = pg(&format!(
        "SELECT r.id FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) WHERE r.tenant_id='{}' AND w.session_id='945' AND w.channel_state IS NOT NULL AND r.sealed_at IS NULL",
        case_tenant()
    ))?;
    let incomplete = incomplete.trim();
    ensure!(
        !incomplete.is_empty(),
        "expected an unfinished native channel collection"
    );
    host.replace(&peer).await?;
    let records = crate::audit_test_support::decode_hex(&pg(&format!(
        "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{}'",
        case_tenant()
    ))?)?;
    let terminal = records
        .iter()
        .find(|r| r.action() == "collection_finish" && r.operation() == Some(incomplete))
        .context("retired channel audit")?;
    ensure!(
        terminal.payload["registration"].as_str().is_some()
            && terminal.payload["details"]["collectionResult"] == "failed"
            && terminal.payload["details"]["reason"] == "superseded"
            && terminal.payload["details"]["sealedAt"].as_i64().is_some(),
        "{:?}",
        terminal.payload
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    ensure!(peer.mutual.post(&url).json(&input).send().await?.status() == StatusCode::UNAUTHORIZED);
    let report = json!({"wireVersion":5,"collection":receipt["collections"][0],"reportId":Uuid::new_v4(),"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}});
    ensure!(
        agent_call(
            &client.router,
            Method::POST,
            "/api/agent/v5/reports",
            Some(&credential("managed-agent")),
            Some(report)
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    host.close().await?;
    Ok(())
}

async fn package_status(router: &Router, operation: Uuid) -> Result<StatusCode> {
    let request = Request::builder()
        .uri(format!("/api/agent/v5/installations/{operation}/package"))
        .header("host", "mdm.example.test")
        .body(Body::empty())?;
    Ok(router.clone().oneshot(request).await?.status())
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
    let mut host = crate::windows::test_support::Host::with_agent(
        Some(setup::pin(true)),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
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
        if next
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Exec { .. }))
        {
            return Ok((initial, next));
        }
        // Admission can finish after the first exchange. A newly delivered Prepare still needs its ACK.
        if next
            .commands
            .iter()
            .any(|command| !matches!(command, s::Command::Status(_)))
        {
            next = post(peer, &reply(&initial, &next, false)).await?;
            if next
                .commands
                .iter()
                .any(|command| matches!(command, s::Command::Exec { .. }))
            {
                return Ok((initial, next));
            }
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
            .any(|c| matches!(c, s::Command::Add { .. } | s::Command::Exec { .. }))
    );
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "rejected"
            && state.1["agentInstallation"]["delivery"] == "rejected",
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
        if state.1["agentInstallation"]["installation"] == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        state = client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?;
    }
    ensure!(
        state.1["agentInstallation"]["installation"] == "failed"
            && state.1["agentInstallation"]["delivery"] == "acknowledged",
        "{state:?}"
    );
    let (_, query) = begin(&peer, 904).await?;
    ensure!(
        !query
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Add { .. } | s::Command::Exec { .. }))
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
        "/api/agent/v5/managed-registrations",
    );
    let input = json!({"wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("cancelled-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v5"]});
    ensure!(peer.mutual.post(url).json(&input).send().await?.status() == StatusCode::FORBIDDEN);
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "cancelled"
            && state.1["agentInstallation"]["installation"] == "unknown",
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
        "/api/agent/v5/managed-registrations",
    );
    let input = json!({"wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("expired-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v5"]});
    ensure!(peer.mutual.post(url).json(&input).send().await?.status() == StatusCode::FORBIDDEN);
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["agentInstallation"]["installation"] == "unknown",
        "expiry is not a failed installation: {state:?}"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn replacement_rejects_old_installation_and_requires_current_epoch_absence() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    execute(&peer).await?;
    let current = host.peer().await?;
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v5/managed-registrations",
    );
    let input = json!({"wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("replacement-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v5"]});
    ensure!(peer.mutual.post(&url).json(&input).send().await?.status() == StatusCode::UNAUTHORIZED);
    ensure!(
        current
            .mutual
            .post(&url)
            .json(&input)
            .send()
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["taskAdmission"]["state"] == "channel_unknown",
        "old epoch drove admission: {state}"
    );
    let (initial, query) = begin(&current, 940).await?;
    ensure!(
        !query
            .commands
            .iter()
            .any(|c| matches!(c, s::Command::Add { .. } | s::Command::Exec { .. }))
    );
    let count = || {
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND approval->>'kind'='agent_install'",
            case_tenant()
        ))
    };
    ensure!(
        count()?.trim() == "1",
        "old absence created a new installation"
    );
    post(&current, &reply(&initial, &query, false)).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while count()?.trim() != "2" {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["taskAdmission"]["state"] == "eligible",
        "current epoch not admitted: {state}"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn scope_exit_preserves_dispatched_installation_authority_until_its_deadline() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    execute(&peer).await?;
    let policy_view = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v3/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(policy_view.0 == StatusCode::OK, "{policy_view:?}");
    let scope = policy_view.1["definition"]["scope"]
        .as_str()
        .context("policy scope")?;
    let scope_path = format!("/api/v2/scopes/{scope}");
    let changed = software::write(
        &mut client.browser,
        &client.router,
        &scope_path,
        1,
        json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_task(
        &mut client.browser,
        &client.router,
        &format!(
            "{scope_path}/tasks/{}",
            changed["task"].as_str().context("scope task")?
        ),
    )
    .await?;
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["assignment"] != "eligible",
        "Scope exit not visible: {state}"
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::OK);
    let url = peer.url.replace(
        "/ManagementServer/MDM.svc",
        "/api/agent/v5/managed-registrations",
    );
    let input = json!({"wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("scope-exit-agent"),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v5"]});
    let response = peer.mutual.post(&url).json(&input).send().await?;
    let status = response.status();
    let receipt: Value = response.json().await?;
    ensure!(
        status == StatusCode::CREATED && receipt["deviceId"] != case_device(),
        "{status}: {receipt}"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn policy_freeze_distinguishes_superseded_identity_from_withdrawn_approval() -> Result<()> {
    let (host, mut client, _, commands, owner, policy, _) = start_fixture().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    let original = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v3/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(original.0 == StatusCode::OK, "{original:?}");
    let definition = original.1["definition"].clone();
    let resource = definition["action"]["resource"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing software resource: {original:?}"))?;
    let mut wrong = definition.clone();
    wrong["action"]["admissionOperation"] = json!(Uuid::new_v4());
    let rejected = client
        .browser
        .call(
            &client.router,
            Method::POST,
            &format!("/api/v3/policies/{}", Uuid::new_v4()),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,
            "input":{"action":"put","enabled":true,"definition":wrong}})),
        )
        .await?;
    ensure!(
        rejected.0 == StatusCode::CONFLICT && rejected.1["code"] == "operation_conflict",
        "wrong approval identity: {rejected:?}"
    );
    crate::test_support::software::write(
        &mut client.browser,
        &client.router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw","evidence":["freeze-rejection-contract"]}),
    )
    .await?;
    let rejected = client
        .browser
        .call(
            &client.router,
            Method::POST,
            &format!("/api/v3/policies/{}", Uuid::new_v4()),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,
            "input":{"action":"put","enabled":true,"definition":definition}})),
        )
        .await?;
    ensure!(
        rejected.0 == StatusCode::FORBIDDEN && rejected.1["code"] == "permission_denied",
        "withdrawn approval: {rejected:?}"
    );
    host.close().await
}
