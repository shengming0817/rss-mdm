//! Real mTLS/SyncML, authorized software, Policy and one atomic independent Agent registration.
mod native_software;
use crate::execution::test_support::{Client, case_device, case_tenant, native};
use crate::test_support::{
    agent::agent_call, http::await_task, http::browser_subject, process::pg, runtime::credential,
};
use crate::test_support::{channel_onboarding as setup, *};
use anyhow::Context;
use rss_mdm_execution_service::AttemptPhase;
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
// Device trust maintenance has its own correlated CSP commands. The business
// no-reinstallation guard continues to reject every Exec and every other Add.
fn installation_write(command: &s::Command) -> bool {
    match command {
        s::Command::Exec { .. } => true,
        s::Command::Add { items, .. } => items.iter().any(|item| {
            !item.target.as_deref().is_some_and(|uri| {
                uri.starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/")
            })
        }),
        _ => false,
    }
}
fn reported_value<'a>(uri: &str, response: &'a s::Message) -> &'a str {
    if uri.starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/") {
        return response
            .commands
            .iter()
            .find_map(|command| match command {
                s::Command::Add { items, .. } => items.iter().find_map(|item| {
                    (item.target.as_deref() == Some(uri))
                        .then(|| item.data.as_ref().unwrap().0.as_str())
                }),
                _ => None,
            })
            .expect("CA CSP readback requires the delivered certificate");
    }
    let leaf = uri.rsplit('/').next().unwrap();
    if uri.contains("/Win32AppInventory/") {
        return match leaf {
            "Win32InstalledProgram" => "exe-installed",
            "RegKey" => "rss-agent",
            "Publisher" => "RSS controlled publisher",
            "Version" => "1.2.3",
            "Source" => "Add/Remove Programs",
            _ => "RSS Agent",
        };
    }
    if uri.contains("EnterpriseModernAppManagement") {
        return match leaf {
            "Publisher" => "CN=RSS",
            "Version" => "1.2.3.0",
            "IsProvisioned" => "true",
            "Status" => "3",
            _ => "0",
        };
    }
    match leaf {
        "Mod" => "MDM-only",
        "Edition" => "48",
        "ProcessorArchitecture" => "AMD64",
        "Publisher" => "RSS controlled publisher",
        "Version" => "1.2.3",
        "Status" => "70",
        _ => "10.0.19045.0",
    }
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
    let mut commands = Vec::new();
    fn flatten<'a>(input: &'a [s::Command], output: &mut Vec<&'a s::Command>) {
        for command in input {
            output.push(command);
            if let s::Command::Sequence { commands, .. } | s::Command::Atomic { commands, .. } =
                command
            {
                flatten(commands, output);
            }
        }
    }
    flatten(&response.commands, &mut commands);
    for c in commands {
        match c {
            s::Command::Get { id, items, .. } => {
                let uri = items[0].target.as_deref().unwrap();
                let is_product = uri.contains("EnterpriseDesktopAppManagement")
                    || uri.contains("EnterpriseModernAppManagement");
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
                    let value = reported_value(uri, response);
                    output.commands.push(s::Command::Results(s::Results {
                        id: output.commands.len() as u32 + 1,
                        message_ref: Some(message),
                        command_ref: Some(*id),
                        command: Some(s::CommandName::Get),
                        meta: None,
                        items: vec![s::Item {
                            more_data: false,
                            target: None,
                            source: Some(uri.into()),
                            meta: None,
                            data: Some(Secret(value.into())),
                        }],
                    }));
                }
            }
            s::Command::Add { id, .. }
            | s::Command::Exec { id, .. }
            | s::Command::Sequence { id, .. }
            | s::Command::Atomic { id, .. } => {
                let command = if matches!(c, s::Command::Add { .. }) {
                    s::CommandName::Add
                } else if matches!(c, s::Command::Sequence { .. }) {
                    s::CommandName::Sequence
                } else if matches!(c, s::Command::Atomic { .. }) {
                    s::CommandName::Atomic
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
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn agent_maintenance_without_deadline_completes_more_data() -> Result<()> {
    let mut host = crate::windows::test_support::Host::with_agent(
        None,
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    setup::publish(
        &mut client.browser,
        &client.router,
        case_device(),
        &host.app,
        true,
    )
    .await?;
    let (initial, query) = begin(&peer, 951).await?;
    let run = pg(&format!(
        "SELECT r.id FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id='{}' AND w.session_id='951' AND w.kind='agent' AND r.deadline IS NULL AND r.sealed_at IS NULL",
        case_tenant()
    ))?;
    let run = Uuid::parse_str(run.trim())?;
    let mut first = reply(&initial, &query, true);
    let position = first.commands.iter().position(|c| matches!(c, s::Command::Results(r) if r.items[0].source.as_deref().is_some_and(|uri| uri.ends_with("/Publisher")))).context("Agent Publisher Get")?;
    let mut fragment = first.commands.remove(position);
    if let s::Command::Results(result) = &mut fragment {
        result.items[0].data = Some(Secret("RSS controlled ".into()));
        result.items[0].more_data = true;
        result.items[0].meta = Some(s::Meta {
            format: Some("chr".into()),
            size: Some("RSS controlled publisher".len() as u32),
            ..Default::default()
        });
    }
    first.commands.push(fragment.clone());
    first.final_message = false;
    let ack = post(&peer, &first).await?;
    ensure!(
        ack.commands
            .iter()
            .any(|c| matches!(c, s::Command::Status(s) if s.code == 213))
    );
    ensure!(!ack.commands.iter().any(|c| matches!(
        c,
        s::Command::Alert {
            alert: s::Alert::SessionAbort,
            ..
        }
    )));
    if let s::Command::Results(result) = &mut fragment {
        result.items[0].data = Some(Secret("publisher".into()));
        result.items[0].more_data = false;
        result.items[0].meta = None;
    }
    let mut tail = reply(&initial, &ack, true);
    tail.commands.push(fragment);
    let finished = post(&peer, &tail).await?;
    ensure!(!finished.commands.iter().any(|c| matches!(
        c,
        s::Command::Alert {
            alert: s::Alert::SessionAbort,
            ..
        }
    )));
    ensure!(pg(&format!("SELECT r.sealed_at IS NOT NULL AND r.result='snapshot' AND r.evidence->>'publisher'='RSS controlled publisher' AND r.evidence->>'version'='1.2.3' FROM mdm_access.collection_runs r WHERE r.tenant_id='{}' AND r.id='{}'", case_tenant(), run))?.trim() == "t", "Agent fragments did not publish installed evidence");
    host.close().await
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
    let (initial, execute, delivered_bootstrap) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let bootstrap_peer = bootstrap::issue_windows(
        &host.app,
        &client.router,
        &host.root,
        operation,
        delivered_bootstrap
            .as_ref()
            .context("native bootstrap delivery")?,
    )
    .await?;
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("managed-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    let mut wrong = input.clone();
    wrong["runtime"]["architecture"] = json!("aarch64");
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &wrong)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    wrong["runtime"]["architecture"] = json!("x86_64");
    wrong["installationOperation"] = json!(Uuid::new_v4());
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &wrong)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    let installer = execute
        .commands
        .iter()
        .find_map(|command| match command {
            s::Command::Exec { items, .. } => {
                items.first()?.data.as_ref().map(|data| data.0.as_str())
            }
            _ => None,
        })
        .expect("native installer command");
    let generated = installer
        .split_once("<ContentURL>")
        .expect("installer URL")
        .1
        .split_once("</ContentURL>")
        .unwrap()
        .0;
    let generated = url::Url::parse(generated)?;
    ensure!(
        generated
            .path()
            .starts_with("/api/v1/agent/enroll/installations/")
    );
    let package = Request::builder()
        .uri(generated.path())
        .header(
            "host",
            generated[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
        )
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
            == &installer_fixtures::msi(Some("1.2.3"), false)[..4]
    );
    // Stop producers before fault injection, then restart the existing command runtime.
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    let unknown = bootstrap::grant_fault(
        &client.router,
        &bootstrap_peer,
        &input,
        Some(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending),
    )
    .await?;
    ensure!(
        unknown.status() == StatusCode::SERVICE_UNAVAILABLE
            && unknown.json::<Value>().await?["code"] == "activation_unknown"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    let unknown = bootstrap::grant_fault(
        &client.router,
        &bootstrap_peer,
        &input,
        Some(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck),
    )
    .await?;
    ensure!(
        unknown.status() == StatusCode::SERVICE_UNAVAILABLE
            && unknown.json::<Value>().await?["code"] == "activation_unknown"
    );
    let response = bootstrap::grant(&client.router, &bootstrap_peer, &input).await?;
    let status = response.status();
    let receipt: Value = response.json().await?;
    ensure!(
        status == StatusCode::OK,
        "managed recovery {status}: {receipt}"
    );
    ensure!(receipt["state"] == "available");
    let again = bootstrap::grant(&client.router, &bootstrap_peer, &input).await?;
    ensure!(again.status() == StatusCode::OK);
    ensure!(again.json::<Value>().await? == receipt);
    let mut changed = input.clone();
    changed["secret"] = json!(credential("different-secret"));
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &changed)
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    let mut duplicate = input.clone();
    duplicate["operationId"] = json!(Uuid::new_v4());
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &duplicate)
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_grants WHERE tenant_id='{}' AND source='native' AND (native_authority ? 'secret' OR native_authority ? 'input')",case_tenant()))?.trim()=="0", "native authority must not persist bootstrap secrets");
    // The consumed grant is already bound to its independent daily key and total install budget.
    pg(&format!(
        "UPDATE mdm_access.agent_bootstraps SET deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-1 WHERE tenant_id='{}' AND installation='{operation}' AND state='consumed'",
        case_tenant()
    ))?;
    let receipt = crate::test_support::agent::complete_grant(
        host.app.agent_enrollment.as_ref().unwrap(),
        &receipt,
        &input,
        &credential("managed-agent"),
    )
    .await?;
    ensure!(receipt["deviceId"] != case_device());
    commands = client.command_worker(host.notifications.signals.clone())?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="1");
    post(&peer, &reply(&initial, &execute, false)).await?;
    let (initial, observe) = begin(&peer, 903).await?;
    ensure!(!observe.commands.iter().any(installation_write));
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
    let cleanup = pg(&format!(
        "SELECT cleanup FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}'",
        case_tenant()
    ))?;
    let cleanup = Uuid::parse_str(cleanup.trim()).context("activation queues bootstrap cleanup")?;
    let view = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    software::write(
        &mut client.browser,
        &client.router,
        &format!("/api/v1/policies/{policy}"),
        1,
        json!({"action":"put","enabled":false,"definition":view.1["definition"]}),
    )
    .await?;
    let future = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 301;
    host.app
        .execution
        .advance_installation_authorization_to(future)?;
    begin(&peer, 1600).await?;
    let recovered = pg(&format!(
        "SELECT cleanup FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}'",
        case_tenant()
    ))?;
    ensure!(
        Uuid::parse_str(recovered.trim())? != cleanup,
        "expired cleanup must be retried even after Policy withdrawal"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND id='{cleanup}'",
            case_tenant()
        ))?
        .trim()
            == "1",
        "cleanup retry preserves original command history"
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    let subject = browser_subject(&client.browser, &client.router).await?;
    identity::change_grants(case_tenant(), &subject, vec![]).await?;
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &duplicate)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
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
    let records = crate::audit_test_support::audit_records().await?;
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
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    let report = json!({"wireVersion":1,"collection":receipt["collections"][0],"reportId":Uuid::new_v4(),"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}});
    ensure!(
        agent_call(
            &client.router,
            Method::POST,
            "/api/v1/agent/runtime/reports",
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
        .uri(format!(
            "/api/v1/agent/enroll/installations/{operation}/package"
        ))
        .header("host", "mdm.example.test:9445")
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
    let (host, client, peer, commands, owner, policy, operation, _) =
        start_fixture_until(None).await?;
    Ok((host, client, peer, commands, owner, policy, operation))
}
async fn start_fixture_until(
    window_seconds: Option<i64>,
) -> Result<(
    crate::windows::test_support::Host,
    Client,
    crate::windows::test_support::Peer,
    rss_runtime::ShutdownStack,
    rss_runtime::ShutdownStack,
    Uuid,
    Uuid,
    Option<i64>,
)> {
    start_fixture_format(window_seconds, false).await
}
async fn start_fixture_format(
    window_seconds: Option<i64>,
    msix: bool,
) -> Result<(
    crate::windows::test_support::Host,
    Client,
    crate::windows::test_support::Peer,
    rss_runtime::ShutdownStack,
    rss_runtime::ShutdownStack,
    Uuid,
    Uuid,
    Option<i64>,
)> {
    let mut host = crate::windows::test_support::Host::with_agent(
        None,
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
        crate::automation::PlanningWork::connect(
            host.app.flow.planning.clone(),
            crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
        )
        .await?,
        host.app.flow.assets.clone(),
        host.app.flow.compliance.clone(),
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
    use crate::clock::Clock;
    // Fixture bootstrapping does not consume the business schedule window.
    let until = window_seconds
        .map(|window| {
            crate::clock::SystemClock
                .unix_seconds()
                .map(|now| now + window)
        })
        .transpose()?;
    let policy = if msix {
        setup::publish_msix(
            &mut client.browser,
            &client.router,
            case_device(),
            &host.app,
        )
        .await?
    } else {
        setup::publish_until(
            &mut client.browser,
            &client.router,
            case_device(),
            &host.app,
            true,
            until,
        )
        .await?
    };
    let (initial, response) = begin(&peer, 901).await?;
    ensure!(
        response
            .commands
            .iter()
            .filter(|c| matches!(c, s::Command::Get { items, .. } if !items[0].target.as_deref().unwrap().starts_with("./Device/Vendor/MSFT/RootCATrustedCertificates/")))
            .count()
            == if msix {9} else {6}
    );
    post(&peer, &reply(&initial, &response, false)).await?;
    let operation = setup::operation(policy).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let published = pg(&format!("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps b JOIN rss_device_command.commands d ON d.tenant_id=b.tenant_id AND d.command_id=b.delivery::text WHERE b.tenant_id='{}' AND b.installation='{operation}' AND d.status='published')",case_tenant()))?;
            if published.trim()=="t" {break Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    Ok((
        host, client, peer, commands, owner, policy, operation, until,
    ))
}
const INSTALL_URI: &str = "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7B12345678-1234-4234-8234-123456789ABC%7D/DownloadInstall";
fn installation_command(message: &s::Message, phase: AttemptPhase) -> Option<u32> {
    message.commands.iter().find_map(|command| {
        let items = match (phase, command) {
            (AttemptPhase::Prepare, s::Command::Add { items, .. })
            | (AttemptPhase::Execute, s::Command::Exec { items, .. }) => items,
            _ => return None,
        };
        (items.len() == 1 && items[0].target.as_deref() == Some(INSTALL_URI)).then(|| command.id())
    })
}
#[test]
fn installation_wait_rejects_absent_unrelated_and_wrong_phase_commands() {
    let mut message = s::Message {
        header: s::Header {
            session_id: 1,
            message_id: 1,
            target: "device".into(),
            source: "server".into(),
            credential: None,
            meta: None,
        },
        commands: vec![],
        final_message: true,
    };
    assert_eq!(installation_command(&message, AttemptPhase::Prepare), None);
    let mut items = vec![s::Item {
        more_data: false,
        target: Some("./unrelated".into()),
        source: None,
        meta: None,
        data: None,
    }];
    message.commands.push(s::Command::Exec {
        id: 1,
        meta: None,
        items: items.clone(),
    });
    assert_eq!(installation_command(&message, AttemptPhase::Execute), None);
    items[0].target = Some(INSTALL_URI.into());
    message.commands = vec![s::Command::Exec {
        id: 2,
        meta: None,
        items: items.clone(),
    }];
    assert_eq!(installation_command(&message, AttemptPhase::Prepare), None);
    assert_eq!(
        installation_command(&message, AttemptPhase::Execute),
        Some(2)
    );
    message.commands = vec![s::Command::Add {
        id: 3,
        meta: None,
        items,
    }];
    assert_eq!(
        installation_command(&message, AttemptPhase::Prepare),
        Some(3)
    );
}
async fn installation(
    peer: &crate::windows::test_support::Peer,
    client: &mut Client,
    policy: Uuid,
    operation: Uuid,
    phase: AttemptPhase,
) -> Result<(s::Message, s::Message, Option<s::Message>)> {
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect_with(
        &crate::device::test_support::options("mdm_command_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut readiness = Value::Null;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let (mut initial, mut next) = begin(peer, 902).await?;
        let mut session = 910;
        let mut bootstrap=None;
        loop {
            if !bootstrap::windows_fields(&next.commands).is_empty(){bootstrap=Some(next.clone());}
            if let Some(command) = installation_command(&next, phase) {
                ensure!(pg(&format!("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id='{}' AND a.operation='{operation}' AND a.phase='{}' AND a.session={} AND a.message={} AND i.command={command} AND i.uri='{INSTALL_URI}')",case_tenant(),phase.as_str(),next.header.session_id,next.header.message_id))?.trim()=="t", "installation command has no correlated durable attempt");
                if phase==AttemptPhase::Execute && bootstrap.is_none() {
                    let diagnostic=pg(&format!("SELECT jsonb_build_object('status',(SELECT status FROM rss_device_command.commands WHERE tenant_id=o.tenant_id AND command_id=o.id::text),'accepted',o.gateway_accepted,'failure',o.dispatch_failure,'required',o.authority->'required','stage',o.authority->'stage','attempts',(SELECT jsonb_agg(jsonb_build_object('phase',a.phase,'session',a.session)) FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id)) FROM mdm_access.agent_bootstraps b JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(b.tenant_id,b.delivery) WHERE b.tenant_id='{}' AND b.installation='{operation}'",case_tenant()))?;
                    anyhow::bail!("bootstrap delivery missing: {diagnostic}");
                }
                return Ok((initial, next, bootstrap));
            }
            if next.commands.iter().any(|c| !matches!(c, s::Command::Status(_))) {
                next = post(peer, &reply(&initial, &next, false)).await?;
                if installation_command(&next, phase).is_some() {
                    continue;
                }
            }
            // Assignment readiness alone does not prove that the newest sealed
            // Agent report has reached Inventory. Observe the production read
            // boundary before starting another session and another collection.
            loop {
                let mut tx = connection.begin().await?;
                crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
                rss_mdm_inventory_postgres::lock_watermark_in(&mut tx, rss_request_context::TenantId::parse(case_tenant())?).await?;
                let scope_fresh: bool = sqlx::query_scalar("SELECT mdm_planning.scope_admission((SELECT (definition->>'scope')::uuid FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2),NULL)->>'state'='fresh'")
                    .bind(case_tenant()).bind(policy).fetch_one(&mut *tx).await?;
                let absent = rss_mdm_execution_service::agent_install::absent_on(
                    &mut tx, case_tenant(), case_device(),
                ).await.map_err(|error| anyhow::anyhow!("installation absence readiness: {error:?}"))?;
                tx.rollback().await?;
                readiness = json!({"scopeFresh": scope_fresh, "absenceKnown": absent.is_some()});
                if scope_fresh && absent.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            (initial, next) = begin(peer, session).await?;
            session += 1;
        }
    }).await;
    match result {
        Ok(result) => result,
        Err(error) => {
            let diagnosis =
                setup::diagnosis(&mut client.browser, &client.router, policy, case_device())
                    .await?;
            let attempts = pg(&format!(
                "SELECT coalesce(jsonb_agg(jsonb_build_object('phase',a.phase,'session',a.session,'message',a.message,'command',i.command,'status',i.status,'receiptAccepted',i.receipt_accepted,'resultAccepted',i.result_accepted)),'[]') FROM mdm_commands.attempts a LEFT JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id='{}' AND a.operation='{operation}'",
                case_tenant()
            ))?;
            anyhow::bail!(
                "installation {} did not become ready: {error}; operation={operation}; diagnosis={diagnosis}; attempts={attempts}; readiness={readiness}",
                phase.as_str()
            )
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn failed_prepare_rejects_without_dispatching_installation() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, prepare, _) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Prepare).await?;
    let command =
        installation_command(&prepare, AttemptPhase::Prepare).expect("correlated MSI prepare");
    ensure!(installation_command(&prepare, AttemptPhase::Execute).is_none());
    ensure!(pg(&format!("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id='{}' AND a.operation='{operation}' AND a.phase='prepare' AND i.command={command} AND NOT coalesce(i.receipt_accepted,false))",case_tenant()))?.trim()=="t", "Prepare was counted as acknowledged before its receipt");
    let mut response = reply(&initial, &prepare, false);
    for c in &mut response.commands {
        if let s::Command::Status(s) = c
            && s.command == s::CommandName::Add
            && s.message_ref == prepare.header.message_id
            && s.command_ref == command
        {
            s.code = 500;
        }
    }
    let next = post(&peer, &response).await?;
    ensure!(!next.commands.iter().any(installation_write));
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "rejected"
            && state.1["agentInstallation"]["delivery"] == "rejected",
        "{state:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.attempts WHERE operation='{operation}' AND phase='execute'"))?.trim()=="0");
    ensure!(pg(&format!("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id='{}' AND a.operation='{operation}' AND a.phase='prepare' AND a.session={} AND a.message={} AND i.command={command} AND i.status=500 AND i.receipt_accepted)",case_tenant(),prepare.header.session_id,prepare.header.message_id))?.trim()=="t", "failed Prepare receipt was not accepted");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn native_enforcement_failure_is_separate_from_delivery_and_never_reinstalled() -> Result<()>
{
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, execute, _) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    post(&peer, &reply(&initial, &execute, false)).await?;
    let (initial, query) = begin(&peer, 903).await?;
    let mut response = reply(&initial, &query, true);
    let mut statuses = 0;
    for c in &mut response.commands {
        if let s::Command::Results(r) = c {
            for i in &mut r.items {
                if i.source.as_deref().is_some_and(|s| s.ends_with("/Status")) {
                    statuses += 1;
                    i.data = Some(Secret("60".into()));
                }
            }
        }
    }
    ensure!(
        statuses == 1,
        "installer enforcement Status was not reached exactly once"
    );
    response.final_message = false;
    let interim = post(&peer, &response).await?;
    let mut end = response.clone();
    end.header.message_id += 1;
    end.commands = vec![s::Command::Status(s::Status {
        id: 1,
        message_ref: interim.header.message_id,
        command_ref: 0,
        command: s::CommandName::SyncHdr,
        target_refs: vec![],
        source_refs: vec![],
        code: 200,
        items: vec![],
        challenge: None,
        credential: None,
    })];
    end.final_message = true;
    post(&peer, &end).await?;
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
    ensure!(!query.commands.iter().any(installation_write));
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
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let bootstrap_peer = bootstrap::issue(&host.app, &client.router, &host.root, operation).await?;
    let result = client
        .call(
            Method::POST,
            &format!("/{operation}/cancel"),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1})),
        )
        .await?;
    ensure!(
        result.0 == StatusCode::CONFLICT,
        "Policy-owned installation cannot be directly cancelled: {result:?}"
    );
    let view = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(view.0 == StatusCode::OK);
    software::write(
        &mut client.browser,
        &client.router,
        &format!("/api/v1/policies/{policy}"),
        1,
        json!({"action":"put","enabled":false,"definition":view.1["definition"]}),
    )
    .await?;
    client.publish_operation(operation).await?;
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("cancelled-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["commandStatus"] == "published"
            && state.1["authorization"] == "blocked"
            && state.1["agentInstallation"]["delivery"] == "unknown"
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
    let (host, mut client, peer, commands, owner, policy, operation, until) =
        start_fixture_until(Some(300)).await?;
    let until = until.expect("scheduled fixture");
    installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let bootstrap_peer = bootstrap::issue(&host.app, &client.router, &host.root, operation).await?;
    ensure!(
        client
            .call(Method::GET, &format!("/{operation}"), None)
            .await?
            .1["deadline"]
            == until
    );
    ensure!(
        package_status(&client.router, operation).await? == StatusCode::OK,
        "package was never accessible before expiry"
    );
    client
        .app
        .execution
        .advance_installation_authorization_to(until)?;
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("expired-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(
        state.1["agentInstallation"]["installation"] == "unknown",
        "expiry is not a failed installation: {state:?}"
    );
    ensure!(
        state.1["deadline"] == until,
        "expiry changed frozen deadline"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_grants WHERE tenant_id='{}' AND native_authority->>'installation'='{operation}'",case_tenant()))?.trim()=="0");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn replacement_rejects_old_installation_and_requires_current_epoch_absence() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let bootstrap_peer = bootstrap::issue(&host.app, &client.router, &host.root, operation).await?;
    let current = host.enrolled_peer().await?;
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("replacement-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    ensure!(
        bootstrap::grant(&client.router, &bootstrap_peer, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    ensure!(
        current
            .mutual
            .post(current.url.replace(
                "/ManagementServer/MDM.svc",
                "/api/v1/agent/enroll/native-grants"
            ))
            .json(&input)
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::FORBIDDEN);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    crate::test_support::planning_http::await_ingress().await?;
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["taskAdmission"]["state"] == "channel_unknown",
        "old epoch drove admission: {state}"
    );
    let (initial, query) = begin(&current, 940).await?;
    ensure!(!query.commands.iter().any(installation_write));
    let count = || {
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND authority->>'kind'='agent_install' AND authority->>'stage'='install'",
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
    installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let bootstrap_peer = bootstrap::issue(&host.app, &client.router, &host.root, operation).await?;
    let policy_view = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(policy_view.0 == StatusCode::OK, "{policy_view:?}");
    let scope = policy_view.1["definition"]["scope"]
        .as_str()
        .context("policy scope")?;
    let scope_path = format!("/api/v1/scopes/{scope}");
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
    crate::test_support::planning_http::await_ingress().await?;
    let state =
        setup::diagnosis(&mut client.browser, &client.router, policy, case_device()).await?;
    ensure!(
        state["availability"] == "unavailable" && state["reason"] == "source_removed",
        "Scope exit not visible: {state}"
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::OK);
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("scope-exit-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    let response = bootstrap::grant(&client.router, &bootstrap_peer, &input).await?;
    let status = response.status();
    let receipt: Value = response.json().await?;
    ensure!(
        status == StatusCode::OK && receipt["state"] == "available",
        "{status}: {receipt}"
    );
    let grant: Value = serde_json::from_str(pg(&format!("SELECT jsonb_build_object('device',device,'installation',native_authority->>'installation','state',state) FROM mdm_access.agent_grants WHERE tenant_id='{}' AND operation_id='{}'",case_tenant(),input["operationId"].as_str().unwrap()))?.trim())?;
    ensure!(
        grant["device"]
            .as_str()
            .is_some_and(|id| id != case_device())
            && grant["installation"] == operation.to_string()
            && grant["state"] == "available"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn policy_freeze_distinguishes_superseded_identity_from_withdrawn_authority() -> Result<()> {
    let (host, mut client, _, commands, owner, policy, _) = start_fixture().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    let original = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(original.0 == StatusCode::OK, "{original:?}");
    let definition = original.1["definition"].clone();
    let release = definition["action"]["packages"]["windows_x86_64"]
        .as_str()
        .unwrap();
    let resource = pg(&format!(
        "SELECT binding->>'resource' FROM mdm_agent_packages.releases WHERE tenant_id='{}' AND id='{release}'",
        case_tenant()
    ))?;
    let resource = resource.trim();
    let mut wrong = definition.clone();
    wrong["action"]["admissionOperation"] = json!(Uuid::new_v4());
    let rejected = client
        .browser
        .call(
            &client.router,
            Method::POST,
            &format!("/api/v1/policies/{}", Uuid::new_v4()),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,
            "input":{"action":"put","enabled":true,"definition":wrong}})),
        )
        .await?;
    ensure!(
        rejected.0 == StatusCode::BAD_REQUEST && rejected.1["code"] == "malformed_request",
        "retired authority identity: {rejected:?}"
    );
    crate::test_support::software::write(
        &mut client.browser,
        &client.router,
        &format!("/api/v1/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    let rejected = client
        .browser
        .call(
            &client.router,
            Method::POST,
            &format!("/api/v1/policies/{}", Uuid::new_v4()),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,
            "input":{"action":"put","enabled":true,"definition":definition}})),
        )
        .await?;
    ensure!(
        rejected.0 == StatusCode::FORBIDDEN && rejected.1["code"] == "permission_denied",
        "withdrawn authority: {rejected:?}"
    );
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn installed_report_blocks_execute_after_preparation() -> Result<()> {
    use sqlx::Row;
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, prepare, _) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Prepare).await?;
    // A pending maintenance query preserves the previous sealed channel fact,
    // including when Group reads its historical quality at a newer watermark.
    let mut tx = client.app.access.begin(case_tenant()).await?;
    let scope: String = sqlx::query_scalar("SELECT scope FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND source='mdm.windows' AND result='pending' ORDER BY sequence DESC LIMIT 1")
        .bind(case_tenant()).fetch_one(&mut *tx).await?;
    let watermark: i64 =
        sqlx::query_scalar("SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut *tx)
            .await?;
    let quality = rss_mdm_inventory_service::collection::read::quality_at(
        &mut tx,
        case_tenant().into(),
        vec![scope],
        watermark,
        serde_json::to_string(&rss_mdm_inventory::CollectionScope::Device)?,
    )
    .await?;
    ensure!(
        quality.len() == 1 && quality[0].try_get::<String, _>("result")? == "snapshot",
        "pending maintenance displaced sealed channel quality"
    );
    tx.rollback().await?;
    // Collect the new installed fact before attempting to advance the prepared
    // command. Using the old absence here would incorrectly send Execute.
    let response = post(&peer, &reply(&initial, &prepare, true)).await?;
    ensure!(installation_command(&response, AttemptPhase::Execute).is_none());
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id='{}' AND operation='{operation}' AND phase='execute'", case_tenant()))?.trim()=="0");
    ensure!(pg(&format!("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id='{}' AND source='mdm.windows' AND result='snapshot' AND evidence->>'version'='1.2.3' AND sealed_at IS NOT NULL)", case_tenant()))?.trim()=="t");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn msix_hosted_install_is_frozen_and_provisioning_is_not_agent_activation() -> Result<()> {
    let (host, mut client, peer, commands, owner, _policy, operation, _) =
        start_fixture_format(None, true).await?;
    fn hosted(commands: &[s::Command]) -> Option<&str> {
        for command in commands {
            match command {
                s::Command::Exec { items, .. } => {
                    if let Some(item) = items.first()
                        && item
                            .target
                            .as_deref()
                            .is_some_and(|uri| uri.ends_with("/HostedInstall"))
                    {
                        return item.data.as_ref().map(|d| d.0.as_str());
                    }
                }
                s::Command::Sequence { commands, .. } | s::Command::Atomic { commands, .. } => {
                    if let Some(value) = hosted(commands) {
                        return Some(value);
                    }
                }
                _ => (),
            }
        }
        None
    }
    let (initial, execution) = tokio::time::timeout(Duration::from_secs(30), async {
        for session in 1000..1100 {
            let (initial, next) = begin(&peer, session).await?;
            if hosted(&next.commands).is_some() {
                return Ok::<_, anyhow::Error>((initial, next));
            }
            post(&peer, &reply(&initial, &next, false)).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("HostedInstall never dispatched")
    })
    .await??;
    let xml = hosted(&execution.commands).unwrap();
    ensure!(
        xml.contains(&format!("/installations/{operation}/package"))
            && xml.contains("ValidateDependencies=\"1\"")
            && !xml.contains("CommandLine"),
        "{xml}"
    );
    ensure!(package_status(&client.router, operation).await? == StatusCode::OK);
    // The execute acknowledgement can already carry the next correlated query.
    // Drive those real responses until installation evidence is visible; one new
    // session is not proof that this operation's inventory query was delivered.
    let mut response = post(&peer, &reply(&initial, &execution, false)).await?;
    ensure!(
        hosted(&response.commands).is_none(),
        "provisioning dispatched a second installer"
    );
    let mut initial = initial;
    let mut session = 1101;
    let state = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if response
                .commands
                .iter()
                .any(|c| !matches!(c, s::Command::Status(_)))
            {
                response = post(&peer, &reply(&initial, &response, true)).await?;
            } else {
                (initial, response) = begin(&peer, session).await?;
                session += 1;
            }
            ensure!(
                hosted(&response.commands).is_none(),
                "provisioning dispatched a second installer"
            );
            let state = client
                .call(Method::GET, &format!("/{operation}"), None)
                .await?;
            ensure!(state.0 == StatusCode::OK, "{state:?}");
            if state.1["agentInstallation"]["installation"] == "provisioned" {
                return Ok::<_, anyhow::Error>(state);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("correlated MSIX provisioning evidence")??;
    ensure!(state.1["agentInstallation"]["agentRegistration"].is_null());
    let (initial, next) = begin(&peer, session).await?;
    ensure!(
        hosted(&next.commands).is_none(),
        "provisioning must not run a second installer"
    );
    post(&peer, &reply(&initial, &next, true)).await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn agent_handoff_completes_windows_issuance_and_authenticated_signin() -> Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let handoff =
        crate::test_support::native_handoff::Handoff::new(rss_mdm_resource::Platform::Windows)
            .await?;
    let id = Uuid::parse_str(handoff.receipt["enrollmentId"].as_str().unwrap())?;
    let peer = host
        .peer_from_agent_handoff(id, handoff.password.clone())
        .await?;
    begin(&peer, 2101).await?;
    let count = pg(&format!(
        "SELECT count(*) FROM mdm_access.agent_native_enrollments l JOIN mdm_access.registrations r ON(r.tenant_id,r.request_id)=(l.tenant_id,l.request) WHERE l.tenant_id='{}' AND l.request='{id}' AND l.source_registration='{}' AND r.state='active' AND r.first_authenticated_at IS NOT NULL AND r.id<>l.source_registration",
        case_tenant(),
        handoff.source["registrationId"].as_str().unwrap()
    ))?;
    ensure!(
        count.trim() == "1",
        "native authenticated sign-in must bind the originating Agent task"
    );
    handoff.close().await?;
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn installed_exe_invalidates_prior_msi_absence_and_blocks_second_installer() -> Result<()> {
    let (host, mut client, peer, commands, owner, _policy, operation) = start_fixture().await?;
    setup::publish_exe(
        &mut client.browser,
        &client.router,
        case_device(),
        &host.app,
    )
    .await?;
    let (initial, mut response) = begin(&peer, 2200).await?;
    let frozen: Value = serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_object('id',w.id,'digest',r.evidence->'catalogDigest','catalog',w.channel_state->'catalog') FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id='{}' AND w.session_id='2200' AND w.kind='agent'",
        case_tenant()
    ))?)?;
    let collection = frozen["id"].as_str().context("new catalog collection")?;
    ensure!(
        frozen["catalog"]["win32"]
            .as_array()
            .is_some_and(|v| v.iter().any(|v| v["key"] == "rss-agent"))
    );
    let mut evidence = None;
    for _ in 0..24 {
        ensure!(
            !response.commands.iter().any(installation_write),
            "new catalog invalidates old absence before dispatch"
        );
        response = post(&peer, &reply(&initial, &response, false)).await?;
        let observed = pg(&format!(
            "SELECT evidence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{collection}' AND sealed_at IS NOT NULL",
            case_tenant()
        ))?;
        if !observed.trim().is_empty() {
            evidence = Some(serde_json::from_str::<Value>(&observed)?);
            break;
        }
    }
    let evidence = evidence.context("new Win32 traversal did not seal")?;
    ensure!(
        evidence["catalog_digest"] == frozen["digest"] && evidence["identity"] == "win32:rss-agent",
        "EXE evidence must belong to the current catalog: {evidence}"
    );
    ensure!(
        evidence["checked_identities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "win32:rss-agent")
    );
    crate::test_support::planning_http::await_ingress().await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.attempts WHERE tenant_id='{}' AND operation='{operation}' AND phase='execute'",case_tenant()))?.trim()=="0");
    let state = client
        .call(Method::GET, &format!("/{operation}"), None)
        .await?;
    ensure!(state.1["agentInstallation"]["agentRegistration"].is_null());
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn historical_msix_catalog_crosses_native_read_batch_without_losing_absence() -> Result<()> {
    let mut host = crate::windows::test_support::Host::with_agent(
        None,
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    for patch in 0..11 {
        setup::publish_msix_release(
            &mut client.browser,
            &client.router,
            &host.app,
            &format!("1.2.{patch}.0"),
        )
        .await?;
    }
    let (initial, mut response) = begin(&peer, 2300).await?;
    let frozen: Value = serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_object('id',w.id,'digest',r.evidence->'catalogDigest','batches',jsonb_array_length(w.channel_state->'plans')) FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id='{}' AND w.session_id='2300' AND w.kind='agent'",
        case_tenant()
    ))?)?;
    ensure!(
        frozen["batches"] == 2,
        "67 reads must traverse two bounded plans"
    );
    let collection = frozen["id"].as_str().context("historical collection")?;
    let mut evidence = None;
    for _ in 0..24 {
        response = post(&peer, &reply(&initial, &response, false)).await?;
        let value = pg(&format!(
            "SELECT evidence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{collection}' AND sealed_at IS NOT NULL",
            case_tenant()
        ))?;
        if !value.trim().is_empty() {
            evidence = Some(serde_json::from_str::<Value>(&value)?);
            break;
        }
    }
    let evidence = evidence.context("complete historical catalog never sealed")?;
    ensure!(
        evidence["catalog_digest"] == frozen["digest"]
            && evidence["checked_identities"].as_array().unwrap().len() == 11
    );
    let missing = pg(&format!(
        "SELECT count(*) FROM mdm_windows.collections w,LATERAL jsonb_array_elements(w.channel_state->'statuses') status WHERE w.tenant_id='{}' AND w.id='{collection}' AND status='404'::jsonb",
        case_tenant()
    ))?;
    ensure!(
        missing.trim() == "66",
        "all 11 historical identities must be observed"
    );
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn expired_known_bootstrap_recovers_without_reinstall_or_unknown_resigning() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let parent_deadline = pg(&format!(
        "SELECT input_context->>'deadline' FROM mdm_commands.operations WHERE tenant_id='{}' AND id='{operation}'",
        case_tenant()
    ))?;
    let prepared_deadline = pg(&format!(
        "SELECT deadline FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}' AND active",
        case_tenant()
    ))?;
    ensure!(
        parent_deadline == prepared_deadline,
        "offline time must not consume certificate lifetime before signing"
    );
    let (initial, execute, delivered) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let old = bootstrap::issue_windows(
        &host.app,
        &client.router,
        &host.root,
        operation,
        delivered.as_ref().context("first bootstrap")?,
    )
    .await?;
    post(&peer, &reply(&initial, &execute, false)).await?;
    pg(&format!(
        "UPDATE mdm_access.agent_bootstraps SET deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-1 WHERE tenant_id='{}' AND installation='{operation}' AND state='issued'",
        case_tenant()
    ))?;
    begin(&peer, 2400).await?;
    let count = pg(&format!(
        "SELECT jsonb_build_array(count(*),count(*) FILTER(WHERE active)) FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}'",
        case_tenant()
    ))?;
    ensure!(
        serde_json::from_str::<Value>(&count)? == json!([2, 1]),
        "expired known identity must retain history and create one attempt"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND authority->>'stage'='install'",case_tenant()))?.trim()=="1");
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("retired-bootstrap"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    ensure!(
        bootstrap::grant(&client.router, &old, &input)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    // An unconfirmed CA dispatch is not permission to create a fresh identity.
    pg(&format!(
        "UPDATE mdm_access.agent_bootstraps SET state='signing',deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-1 WHERE tenant_id='{}' AND installation='{operation}' AND active",
        case_tenant()
    ))?;
    begin(&peer, 2401).await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}'",case_tenant()))?.trim()=="2");
    ensure!(
        pg(&format!(
            "SELECT input_context->>'deadline' FROM mdm_commands.operations WHERE tenant_id='{}' AND id='{operation}'",
            case_tenant()
        ))? == parent_deadline
    );
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

fn cleanup_reply(initial: &s::Message, response: &s::Message, fail: Option<Uuid>) -> s::Message {
    let mut out = reply(initial, response, false);
    fn visit(
        commands: &[s::Command],
        fail: Option<Uuid>,
        out: &mut s::Message,
        message: u32,
    ) -> bool {
        let mut failed = false;
        for command in commands {
            match command {
                s::Command::Get { id, items, .. }
                    if items.iter().all(|item| {
                        item.target.as_deref().is_some_and(|uri| {
                            uri.contains("/ClientCertificateInstall/SCEP/")
                                && uri
                                    .rsplit('/')
                                    .next()
                                    .is_some_and(|key| Uuid::parse_str(key).is_ok())
                        })
                    }) =>
                {
                    let still_present = fail.is_some_and(|id| {
                        items.iter().any(|i| {
                            i.target
                                .as_ref()
                                .is_some_and(|uri| uri.ends_with(&id.to_string()))
                        })
                    });
                    if !still_present {
                        out.commands.retain(|entry|!matches!(entry,s::Command::Results(r) if r.command_ref==Some(*id)));
                        for entry in &mut out.commands {
                            if let s::Command::Status(status) = entry
                                && status.command_ref == *id
                            {
                                status.code = 404;
                            }
                        }
                    }
                }
                s::Command::Delete { id, items, .. } => {
                    let rejected = fail.is_some_and(|id| {
                        items.iter().any(|i| {
                            i.target
                                .as_ref()
                                .is_some_and(|uri| uri.contains(&id.to_string()))
                        })
                    });
                    out.commands.push(s::Command::Status(s::Status {
                        id: out.commands.len() as u32 + 1,
                        message_ref: message,
                        command_ref: *id,
                        command: s::CommandName::Delete,
                        target_refs: vec![],
                        source_refs: vec![],
                        code: if rejected { 500 } else { 200 },
                        items: vec![],
                        challenge: None,
                        credential: None,
                    }));
                    failed |= rejected;
                }
                s::Command::Atomic { id, commands } | s::Command::Sequence { id, commands }
                    if visit(commands, fail, out, message) =>
                {
                    for entry in &mut out.commands {
                        if let s::Command::Status(status) = entry
                            && status.command_ref == *id
                        {
                            status.code = 500;
                        }
                    }
                    failed = true;
                }
                _ => (),
            }
        }
        failed
    }
    visit(
        &response.commands,
        fail,
        &mut out,
        response.header.message_id,
    );
    // Results removed for 404 must not leave duplicate IDs when Delete receipts are appended.
    for (index, command) in out.commands.iter_mut().enumerate() {
        match command {
            s::Command::Status(status) => status.id = index as u32 + 1,
            s::Command::Results(result) => result.id = index as u32 + 1,
            _ => unreachable!("fixture replies contain only correlated statuses and results"),
        }
    }
    out
}

// Consume every server continuation in its originating session; do not lose readbacks.
async fn cleanup_session(
    peer: &crate::windows::test_support::Peer,
    session: u32,
    fail: Option<Uuid>,
    trace: &mut std::collections::BTreeSet<(Uuid, &'static str)>,
) -> Result<()> {
    fn observe(
        commands: &[s::Command],
        trace: &mut std::collections::BTreeSet<(Uuid, &'static str)>,
    ) {
        for command in commands {
            let (items, phase) = match command {
                s::Command::Delete { items, .. } => (items, "delete"),
                s::Command::Get { items, .. } => (items, "readback"),
                s::Command::Atomic { commands, .. } | s::Command::Sequence { commands, .. } => {
                    observe(commands, trace);
                    continue;
                }
                _ => continue,
            };
            for item in items {
                if let Some(uri) = item.target.as_deref()
                    && uri.contains("/ClientCertificateInstall/SCEP/")
                    && let Some(id) = uri.rsplit('/').next().and_then(|v| Uuid::parse_str(v).ok())
                {
                    trace.insert((id, phase));
                }
            }
        }
    }
    let (initial, mut wire) = begin(peer, session).await?;
    loop {
        if wire
            .commands
            .iter()
            .all(|c| matches!(c, s::Command::Status(_)))
        {
            return Ok(());
        }
        ensure!(
            (wire.header.message_id as usize) < CodecLimits::default().session_messages,
            "cleanup session exhausted protocol message budget: {trace:?}"
        );
        observe(&wire.commands, trace);
        let response = cleanup_reply(&initial, &wire, fail);
        wire = post(peer, &response).await?;
    }
}

async fn finish_cleanup(
    peer: &crate::windows::test_support::Peer,
    object: Uuid,
    first_session: u32,
    fail: Option<Uuid>,
) -> Result<std::collections::BTreeSet<(Uuid, &'static str)>> {
    let mut trace = std::collections::BTreeSet::new();
    let result=tokio::time::timeout(Duration::from_secs(30),async {
        let mut session=first_session;
        loop {
            cleanup_session(peer,session,fail,&mut trace).await?;
            let state=pg(&format!("SELECT cleanup_complete FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND id='{object}'",case_tenant()))?;
            if state.trim()=="t" && fail.is_none_or(|pending|trace.contains(&(pending,"delete"))) {return Ok::<_,anyhow::Error>(());}
            session+=1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await;
    result.map_err(|error| {
        anyhow::anyhow!(
            "cleanup {object} did not finish: {error}; correlated native commands: {trace:?}"
        )
    })??;
    ensure!(
        trace.contains(&(object, "delete")) && trace.contains(&(object, "readback")),
        "cleanup completed without both actual Delete and absence readback: {trace:?}"
    );
    Ok(trace)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn historical_bootstrap_cleanup_survives_current_identity_completion() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, execute, wire) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    bootstrap::issue_windows(
        &host.app,
        &client.router,
        &host.root,
        operation,
        wire.as_ref().context("initial identity")?,
    )
    .await?;
    post(&peer, &reply(&initial, &execute, false)).await?;
    let old:Uuid=Uuid::parse_str(pg(&format!("SELECT id FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}' AND active",case_tenant()))?.trim())?;
    pg(&format!(
        "UPDATE mdm_access.agent_bootstraps SET deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-1 WHERE tenant_id='{}' AND id='{old}'",
        case_tenant()
    ))?;
    let mut replacement = None;
    'sessions: for session in 2500..2540 {
        let (start, mut wire) = begin(&peer, session).await?;
        for _ in 0..CodecLimits::default().session_messages {
            if !bootstrap::windows_fields(&wire.commands).is_empty() {
                replacement = Some(
                    bootstrap::issue_windows(
                        &host.app,
                        &client.router,
                        &host.root,
                        operation,
                        &wire,
                    )
                    .await?,
                );
                post(&peer, &reply(&start, &wire, false)).await?;
                break 'sessions;
            }
            // A newly prepared identity can arrive in any response of this session.
            // Consume that response before opening another session.
            wire = post(&peer, &reply(&start, &wire, false)).await?;
            if !wire.commands.iter().any(|command| {
                matches!(
                    command,
                    s::Command::Get { .. }
                        | s::Command::Add { .. }
                        | s::Command::Replace { .. }
                        | s::Command::Delete { .. }
                        | s::Command::Exec { .. }
                        | s::Command::Sequence { .. }
                        | s::Command::Atomic { .. }
                )
            }) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let replacement = replacement.context("replacement identity was not delivered")?;
    let current = pg(&format!(
        "SELECT id FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}' AND active",
        case_tenant()
    ))?;
    let current = current.trim();
    let secret = credential("independent-cleanup");
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":secret,"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows),"platform":"windows","architecture":"x86_64","capabilities":["inventory.collect.v1","task.execute.v1"]}});
    let response = bootstrap::grant(&client.router, &replacement, &input).await?;
    ensure!(response.status() == StatusCode::OK);
    let grant: Value = response.json().await?;
    crate::test_support::agent::complete_grant(
        host.app.agent_enrollment.as_ref().unwrap(),
        &grant,
        &input,
        &secret,
    )
    .await?;
    let current = Uuid::parse_str(current)?;
    let trace = finish_cleanup(&peer, current, 2600, Some(old)).await?;
    ensure!(
        trace.contains(&(old, "delete")),
        "old identity must receive its deliberately failed deletion"
    );
    let original = pg(&format!(
        "SELECT cleanup FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND id='{old}' AND NOT cleanup_complete",
        case_tenant()
    ))?;
    let original = Uuid::parse_str(original.trim()).context("historical cleanup stays pending")?;
    host.app.execution.advance_installation_authorization_to(
        crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 301,
    )?;
    finish_cleanup(&peer, old, 2700, None).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND id='{original}'",
            case_tenant()
        ))?
        .trim()
            == "1"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}' AND authority->>'stage'='install'",case_tenant()))?.trim()=="1");
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn retirement_keeps_unregistered_installed_agent_as_explicit_residue() -> Result<()> {
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, execute, bootstrap_wire) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    // Complete the independent bootstrap certificate delivery without activating
    // an Agent registration. Otherwise that older uncertain command is the first blocker.
    bootstrap::issue_windows(
        &host.app,
        &client.router,
        &host.root,
        operation,
        bootstrap_wire
            .as_ref()
            .context("native bootstrap delivery")?,
    )
    .await?;
    let mut next = post(&peer, &reply(&initial, &execute, false)).await?;
    while next
        .commands
        .iter()
        .any(|c| !matches!(c, s::Command::Status(_)))
    {
        ensure!((next.header.message_id as usize) < CodecLimits::default().session_messages);
        next = post(&peer, &reply(&initial, &next, true)).await?;
    }
    let (initial, observe) = begin(&peer, 903).await?;
    let mut next = post(&peer, &reply(&initial, &observe, true)).await?;
    while next
        .commands
        .iter()
        .any(|c| !matches!(c, s::Command::Status(_)))
    {
        ensure!((next.header.message_id as usize) < CodecLimits::default().session_messages);
        next = post(&peer, &reply(&initial, &next, true)).await?;
    }
    tokio::time::timeout(Duration::from_secs(30),async {
        loop {
            if pg(&format!("SELECT status FROM rss_device_command.commands WHERE tenant_id='{}' AND command_id='{operation}'",case_tenant()))?.trim()=="applied" {break Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await??;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="0");
    let scope = Uuid::new_v4();
    crate::test_support::agent_execution::seed_scope(
        &host.app.flow.planning,
        scope,
        json!([{"kind":"device","id":case_device()}]),
    )
    .await?;
    let subject = browser_subject(&client.browser, &client.router).await?;
    let mut grants = identity::device_grants(
        None,
        &[
            "enrollment",
            "inventory_read",
            "software_deploy",
            "operation_read",
            "operation_cancel",
            "device_unmanage",
        ],
    )?;
    for name in [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "release_publish",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
        "group_read",
        "group_write",
        "group_recompute",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::seed_grants(case_tenant(), &subject, grants).await?;
    let exit = Uuid::new_v4();
    software::write(&mut client.browser,&client.router,&format!("/api/v1/policies/{exit}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}})).await?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    software::write(
        &mut client.browser,
        &client.router,
        &format!("/api/v1/policies/{exit}/reruns"),
        1,
        json!({"deadline":now+300}),
    )
    .await?;
    let retirement=tokio::time::timeout(Duration::from_secs(30),async {
        loop {
            let row=pg(&format!("SELECT operation::text FROM mdm_devices.retirement_channels WHERE tenant_id='{}' AND device='{}' AND stage='cleanup' AND effect='blocked' AND reason='agent_installation_removal_unavailable' AND blocking_execution='{operation}'",case_tenant(),case_device()))?;
            if !row.trim().is_empty() {break Ok::<_,anyhow::Error>(row.trim().to_owned());}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await.map_err(|error| anyhow::anyhow!("retirement residue not projected: {error}; channels={}; operations={}",
        pg(&format!("SELECT coalesce(jsonb_agg(to_jsonb(c)),'[]') FROM mdm_devices.retirement_channels c WHERE tenant_id='{}'",case_tenant())).unwrap_or_default(),
        pg(&format!("SELECT coalesce(jsonb_agg(jsonb_build_object('id',o.id,'kind',o.authority->>'kind','stage',o.authority->>'stage','status',d.status,'terminal',d.terminal_at)),'[]') FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id='{}'",case_tenant())).unwrap_or_default()))??;
    ensure!(pg(&format!("SELECT state FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}' AND purpose='primary'",case_tenant(),case_device()))?.trim()=="active");
    let (status,receipt)=client.browser.call(&client.router,Method::POST,&format!("/api/v1/device-retirements/{retirement}/force-revoke"),Some(json!({"operationId":Uuid::new_v4(),"reason":"device program cleanup requires operator"}))).await?;
    ensure!(status == StatusCode::OK, "{receipt}");
    ensure!(pg(&format!("SELECT effect||':'||blocking_execution::text FROM mdm_devices.retirement_channels WHERE tenant_id='{}' AND operation='{retirement}'",case_tenant()))?.trim()==format!("unknown:{operation}"));
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    host.close().await
}

fn installation_counts() -> Result<String> {
    pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_access.agent_bootstraps WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn assembled_channel_block_rejects_installation_freeze_without_side_effects() -> Result<()> {
    use crate::channel_status::{ChannelName, ChannelState, Reason};
    use rss_mdm_execution_service::AgentInstallationAdmission;
    let (host, mut client, _, commands, owner, policy, _) = start_fixture().await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    // The existing policy and bootstrap were accepted by this fully assembled owner.
    ensure!(
        host.app
            .channels
            .ready_signing_revision(crate::windows::test_support::now())
            == Some(1)
    );
    let original = client
        .browser
        .call(
            &client.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(original.0 == StatusCode::OK, "{original:?}");
    let before = installation_counts()?;
    host.app.channels.set(
        ChannelName::Agent,
        ChannelState::Degraded,
        Some(Reason::DependencyUnavailable),
    )?;
    ensure!(
        host.app
            .channels
            .ready_signing_revision(crate::windows::test_support::now())
            .is_none()
    );
    let rejected_policy = Uuid::new_v4();
    let rejected = client.browser.call(&client.router, Method::POST, &format!("/api/v1/policies/{rejected_policy}"),
        Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":original.1["definition"]}}))).await?;
    ensure!(
        rejected.0 == StatusCode::NOT_IMPLEMENTED && rejected.1["code"] == "action_not_supported",
        "closed installation admission: {rejected:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{rejected_policy}'",case_tenant()))?.trim() == "0");
    ensure!(
        installation_counts()? == before,
        "rejected freeze created command/bootstrap state"
    );
    host.app
        .channels
        .set(ChannelName::Agent, ChannelState::Ready, None)?;
    rotate_loaded_signing_authority(&mut client).await?;
    ensure!(
        host.app
            .channels
            .ready_signing_revision(crate::windows::test_support::now())
            == Some(1)
    );
    let stale_policy = Uuid::new_v4();
    let rejected = client.browser.call(&client.router, Method::POST, &format!("/api/v1/policies/{stale_policy}"),
        Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":original.1["definition"]}}))).await?;
    ensure!(
        rejected.0 == StatusCode::CONFLICT,
        "stale loaded signing admission: {rejected:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{stale_policy}'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    ensure!(
        installation_counts()? == before,
        "stale signing freeze created command/bootstrap state"
    );
    host.close().await
}

async fn rotate_loaded_signing_authority(client: &mut Client) -> Result<()> {
    let subject = browser_subject(&client.browser, &client.router).await?;
    identity::seed_grants(
        case_tenant(),
        &subject,
        [
            crate::authorization::Permission::RegistrationConfigurationRead,
            crate::authorization::Permission::RegistrationConfigurationWrite,
        ]
        .into_iter()
        .map(|operation| crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        })
        .collect(),
    )
    .await?;
    let (status, current) = client
        .browser
        .call(
            &client.router,
            Method::GET,
            "/api/v1/task-signing/trust",
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "current signing: {status} {current}"
    );
    client.browser.operation = Some(Uuid::new_v4());
    let (status, prepared) = client
        .browser
        .call(
            &client.router,
            Method::POST,
            "/api/v1/task-signing/trust",
            Some(json!({"action":"prepare","expectedRevision":current["revision"]})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "prepare signing: {status} {prepared}"
    );
    let key = prepared["keys"]
        .as_array()
        .context("prepared keys")?
        .iter()
        .find(|key| key["state"] == "prepared")
        .context("prepared key")?["id"]
        .clone();
    client.browser.operation = Some(Uuid::new_v4());
    let (status, activated) = client
        .browser
        .call(
            &client.router,
            Method::POST,
            "/api/v1/task-signing/trust",
            Some(json!({"action":"activate","expectedRevision":prepared["revision"],"keyId":key})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK && activated["revision"] == 3,
        "activate signing: {status} {activated}"
    );
    client.browser.operation = None;
    setup::grants(&client.browser, &client.router).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.onboarding"]
async fn assembled_bootstrap_block_rejects_requeue_atomically() -> Result<()> {
    use rss_mdm_execution_service::AgentInstallationAdmission;
    let (host, mut client, peer, commands, owner, policy, operation) = start_fixture().await?;
    let (initial, execute, delivered) =
        installation(&peer, &mut client, policy, operation, AttemptPhase::Execute).await?;
    let _issued = bootstrap::issue_windows(
        &host.app,
        &client.router,
        &host.root,
        operation,
        delivered
            .as_ref()
            .context("accepted bootstrap before capability block")?,
    )
    .await?;
    post(&peer, &reply(&initial, &execute, false)).await?;
    ensure!(commands.shutdown().join().await?.is_clean());
    ensure!(owner.shutdown().join().await?.is_clean());
    use crate::channel_status::{ChannelName, ChannelState, Reason};
    ensure!(
        host.app
            .channels
            .ready_signing_revision(crate::windows::test_support::now())
            == Some(1)
    );
    host.app.channels.set(
        ChannelName::AgentBootstrap,
        ChannelState::Degraded,
        Some(Reason::MaterialRevoked),
    )?;
    ensure!(
        host.app
            .channels
            .ready_signing_revision(crate::windows::test_support::now())
            .is_none()
    );
    pg(&format!(
        "UPDATE mdm_access.agent_bootstraps SET deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-1 WHERE tenant_id='{}' AND installation='{operation}' AND state='issued'",
        case_tenant()
    ))?;
    let before = installation_counts()?;
    let mut poll = peer.message.clone();
    poll.header.session_id = 2600;
    let rejected = native::post(&peer.mutual, &peer.url, &poll).await?;
    ensure!(
        rejected.status() == StatusCode::NOT_IMPLEMENTED,
        "bootstrap with blocked assembled capability: {}",
        rejected.status()
    );
    ensure!(
        installation_counts()? == before,
        "rejected bootstrap created a command or identity attempt"
    );
    ensure!(pg(&format!("SELECT jsonb_build_array(count(*),count(*) FILTER(WHERE active)) FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND installation='{operation}'",case_tenant()))?.trim() == "[1, 1]", "failed requeue changed the original active bootstrap");
    host.close().await
}
