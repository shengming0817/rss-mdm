//! Complete native diagnostic files through real TLS/SyncML, PG roles, recovery and HTTP.
use super::windows::operation;
use crate::execution::test_support::{
    native::{begin, post, report},
    *,
};
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use base64::Engine;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
use serde_json::json;
use sqlx::Connection;

async fn grants(
    client: &mut Client,
    rule: Uuid,
    revision: u64,
    diagnostic: bool,
) -> anyhow::Result<()> {
    let mut permissions = vec!["operation_read", "operation_cancel"];
    if diagnostic {
        permissions.push("device_diagnostics");
    }
    let grants = permissions
        .into_iter()
        .map(
            |operation| json!({"operation":operation,"scope":{"kind":"device","id":case_device()}}),
        )
        .collect::<Vec<_>>();
    let updated=client.browser.call(&client.router,Method::PUT,&format!("/api/v1/authorization/rules/{rule}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":{"subject":{"kind":"user","user":crate::test_support::identity::user(case_tenant(),crate::test_support::case::admin())},"grants":grants}}))).await?;
    ensure!(
        updated.0 == StatusCode::OK,
        "diagnostic grants: {updated:?}"
    );
    Ok(())
}
async fn create(client: &mut Client) -> anyhow::Result<()> {
    create_with_id(client, Uuid::new_v4()).await
}
async fn create_with_id(client: &mut Client, id: Uuid) -> anyhow::Result<()> {
    accept_with_id(client, id, false).await?;
    client.publish_operation(client.operation).await?;
    Ok(())
}
async fn accept_with_id(client: &mut Client, id: Uuid, trigger: bool) -> anyhow::Result<()> {
    client.operation = id;
    let trigger = trigger.then(|| json!({"kind":"node","node":"./Vendor/MSFT/DiagnosticLog/DeviceStateData/MdmConfiguration","instance":[],"operation":"exec","value":{"type":"text","value":""}}));
    let accepted=client.call(Method::POST,"",Some(json!({"operationId":client.operation,"inputVersion":"diagnostic-1","deadline":crate::windows::test_support::now()+300,"target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"diagnostic_log","request":{"trigger":trigger,"fileContext":"DeviceManagement","blockSizeKb":1,"maxBytes":4096}}}}))).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "diagnostic create: {accepted:?}"
    );
    Ok(())
}
fn reply(
    first: &s::Message,
    response: &s::Message,
    count: i64,
    index: u32,
    data: &[u8],
) -> s::Message {
    let mut packet = s::Message {
        header: s::Header {
            message_id: response.header.message_id + 1,
            credential: None,
            ..first.header.clone()
        },
        commands: vec![s::Command::Status(s::Status {
            id: 1,
            message_ref: response.header.message_id,
            command_ref: 0,
            command: s::CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        })],
        final_message: true,
    };
    let mut pending = response.commands.iter().rev().collect::<Vec<_>>();
    while let Some(command) = pending.pop() {
        let (name, items) = match command {
            s::Command::Get { items, .. } => (s::CommandName::Get, Some(items)),
            s::Command::Replace { items, .. } => (s::CommandName::Replace, Some(items)),
            s::Command::Exec { items, .. } => (s::CommandName::Exec, Some(items)),
            s::Command::Sequence { commands, .. } => {
                pending.extend(commands.iter().rev());
                (s::CommandName::Sequence, None)
            }
            _ => continue,
        };
        let id = packet.commands.len() as u32 + 1;
        packet.commands.push(s::Command::Status(s::Status {
            id,
            message_ref: response.header.message_id,
            command_ref: command.id(),
            command: name,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }));
        if name == s::CommandName::Get {
            let items = items
                .unwrap()
                .iter()
                .map(|item| {
                    let uri = item.target.clone().unwrap();
                    let value = if uri.ends_with("/BlockCount") {
                        count.to_string()
                    } else if uri.ends_with("/BlockIndexToRead") {
                        index.to_string()
                    } else if uri.ends_with("/BlockData") {
                        base64::engine::general_purpose::STANDARD.encode(data)
                    } else if uri.ends_with("/Edition") {
                        "48".into()
                    } else if uri.ends_with("/Mod") {
                        "Diagnostic Device".into()
                    } else {
                        "10.0.26100.0".into()
                    };
                    s::Item {
                        more_data: false,
                        source: Some(uri),
                        target: None,
                        meta: None,
                        data: Some(Secret(value)),
                    }
                })
                .collect();
            let id = packet.commands.len() as u32 + 1;
            packet.commands.push(s::Command::Results(s::Results {
                id,
                message_ref: Some(response.header.message_id),
                command_ref: Some(command.id()),
                command: Some(name),
                meta: None,
                items,
            }));
        }
    }
    packet
}
async fn exchange(
    peer: &crate::windows::test_support::Peer,
    packet: &s::Message,
) -> anyhow::Result<s::Message> {
    let response = post(&peer.mutual, &peer.url, packet).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "diagnostic SyncML: {}",
        response.status()
    );
    Ok(s::decode(
        &response.bytes().await?,
        &CodecLimits::default(),
    )?)
}
async fn warm(peer: &crate::windows::test_support::Peer, session: u32) -> anyhow::Result<()> {
    let start = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        session,
        None,
    )
    .await?;
    let _ = exchange(
        peer,
        &report(&start.first, &start.gets, "10.0.26100.0", 200),
    )
    .await?;
    Ok(())
}
async fn collect(
    peer: &crate::windows::test_support::Peer,
    client: &mut Client,
    session: u32,
    invalid_index: bool,
) -> anyhow::Result<Vec<u8>> {
    let initial = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        session,
        None,
    )
    .await?;
    let mut response = initial.response;
    if response
        .commands
        .iter()
        .any(|c| matches!(c, s::Command::Exec { .. }))
    {
        let packet = reply(&initial.first, &response, 2, 0, &[]);
        response = exchange(peer, &packet).await?;
        let again = exchange(peer, &packet).await?;
        ensure!(
            s::encode(&again, &CodecLimits::default())?
                == s::encode(&response, &CodecLimits::default())?
        );
        ensure!(
            operation(client).await?["observation"]["diagnostic"]["step"]["kind"] == "size",
            "trigger receipt did not advance to size negotiation"
        );
    }
    let mut bytes = vec![b'X'; 1024];
    bytes.extend_from_slice(b"private-diagnostic-canary-tail");
    for (count, index, data) in [
        (2, 0, &[][..]),
        (2, 0, &[][..]),
        (2, u32::from(invalid_index), &bytes[..1024]),
        (2, 1, &bytes[1024..]),
        (2, 0, &[][..]),
    ] {
        let packet = reply(&initial.first, &response, count, index, data);
        response = exchange(peer, &packet).await?;
        // Exact wire replay restores the same transcript and never duplicates accepted blocks.
        let again = exchange(peer, &packet).await?;
        ensure!(
            s::encode(&again, &CodecLimits::default())?
                == s::encode(&response, &CodecLimits::default())?
        );
        let detail = operation(client).await?;
        ensure!(!detail.to_string().contains("private-diagnostic-canary"));
        ensure!(
            detail["observation"]["receipts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["value"].is_null()),
            "diagnostic raw value projection"
        );
        if invalid_index && detail["observation"]["diagnostic"]["transfer"] == "blocked" {
            return Ok(bytes.clone());
        }
    }
    Ok(bytes)
}
async fn recovery_report(
    client: &Client,
    budget: Duration,
) -> anyhow::Result<rss_reconcile::Report> {
    recovery_report_with_attempt(client, budget, Duration::from_secs(6)).await
}
async fn recovery_report_with_attempt(
    client: &Client,
    budget: Duration,
    attempt_timeout: Duration,
) -> anyhow::Result<rss_reconcile::Report> {
    use rss_mdm_execution_service::recovery;
    let timer = recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, budget, &cancel);
    let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 1,
        // A stopped test worker leaves a bounded lease, just as a crashed owner does.
        lease_ttl: Duration::from_secs(3),
        attempt_timeout,
        // One attempt per test run; do not start another at the controller cutoff.
        scan_interval: Duration::from_secs(10),
        idle_scan_interval: Duration::from_millis(20),
        initial_backoff: Duration::from_secs(2),
        max_backoff: Duration::from_secs(2),
        max_attempts: 3,
    })?;
    let report = client
        .app
        .execution
        .run_recovery(
            &rss_mdm_execution_service::recovery_scope(client.app.identity.tenant),
            policy,
            &control,
            &tokio::sync::Notify::new(),
        )
        .await?;
    Ok(report)
}
async fn recover(client: &Client) -> anyhow::Result<()> {
    let report = recovery_report(client, Duration::from_secs(8)).await?;
    ensure!(
        report.execution_failed == 0,
        "diagnostic recovery: {report:?}"
    );
    Ok(())
}

async fn download(client: &Client, path: &str) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let cookie = client
        .browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", "mdm.example.test")
        .header("cookie", cookie)
        .body(axum::body::Body::empty())?;
    let response = client.router.clone().oneshot(request).await?;
    let status = response.status();
    if status == StatusCode::OK {
        ensure!(response.headers()["cache-control"] == "no-store");
    }
    Ok((
        status,
        response.into_body().collect().await?.to_bytes().to_vec(),
    ))
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn complete_file_restarts_replays_downloads_and_stops_after_revocation() -> anyhow::Result<()>
{
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    warm(&peer, 1300).await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let rule = Uuid::new_v4();
    grants(&mut client, rule, 0, true).await?;
    accept_with_id(&mut client, Uuid::new_v4(), true).await?;
    recover(&client).await?;
    ensure!(
        operation(&mut client).await?["observation"]["diagnostic"]["transfer"] == "pending",
        "recovery abandoned a queued request before dispatch"
    );
    client.publish_operation(client.operation).await?;
    let bytes = collect(&peer, &mut client, 1301, false).await?;
    let detail = operation(&mut client).await?;
    ensure!(
        detail["commandStatus"] == "applied"
            && detail["observation"]["diagnostic"]["receivedBytes"] == bytes.len()
    );
    ensure!(
        detail["observation"]["diagnostic"]["artifact"].is_null(),
        "native receipt claimed file publication"
    );
    let id = client.operation;
    let browser = std::mem::take(&mut client.browser);
    host = host.restart().await?;
    client = Client::with_browser(host.browser.clone(), host.app.clone(), browser);
    client.operation = id;
    recover(&client).await?;
    let detail = operation(&mut client).await?;
    let artifact = &detail["observation"]["diagnostic"]["artifact"];
    ensure!(
        artifact["length"] == bytes.len()
            && artifact["sha256"]
                == rss_mdm_resource::Digest::of(&bytes)
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
        "artifact metadata: {detail}"
    );
    let path = artifact["downloadUrl"].as_str().unwrap();
    let downloaded = download(&client, path).await?;
    ensure!(
        downloaded.0 == StatusCode::OK && downloaded.1 == bytes,
        "complete bytes changed"
    );
    recover(&client).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_content.diagnostic_artifacts WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(id).fetch_one(&mut pg).await?;
    ensure!(count == 1, "duplicate association");
    #[cfg(feature = "integration")]
    let waiting_download = {
        let ready = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        client
            .app
            .queries
            .pause_diagnostic_download_after_file_work(ready.clone(), resume.clone());
        let waiting_client = Client::with_browser(
            client.router.clone(),
            client.app.clone(),
            client.browser.clone(),
        );
        let path = path.to_owned();
        let task = tokio::spawn(async move { download(&waiting_client, &path).await });
        tokio::time::timeout(Duration::from_secs(5), ready.notified()).await?;
        (task, resume)
    };
    grants(&mut client, rule, 1, false).await?;
    #[cfg(feature = "integration")]
    {
        waiting_download.1.notify_one();
        ensure!(
            waiting_download.0.await??.0 == StatusCode::FORBIDDEN,
            "file prepared before revocation was served after revocation"
        );
    }
    ensure!(download(&client, path).await?.0 == StatusCode::FORBIDDEN);
    grants(&mut client, rule, 2, true).await?;
    let expires_at = artifact["expiresAt"].clone();
    sqlx::query("UPDATE mdm_content.diagnostic_artifacts SET expires_at=1 WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(id).execute(&mut pg).await?;
    sqlx::query("UPDATE mdm_commands.operations SET diagnostic_progress=jsonb_set(diagnostic_progress,'{expiresAt}','1'::jsonb) WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).execute(&mut pg).await?;
    ensure!(
        download(&client, path).await?.0 == StatusCode::CONFLICT,
        "expired artifact was served"
    );
    let expired = operation(&mut client).await?;
    ensure!(
        expired["observation"]["diagnostic"]["transfer"] == "expired"
            && expired["observation"]["diagnostic"]["reason"] == "diagnostic_retention_expired"
            && expired["observation"]["diagnostic"]["expiresAt"] == 1
            && expires_at.is_number()
    );
    pg.close().await?;
    host.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn waiting_first_page_does_not_hide_a_complete_file() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    warm(&peer, 1340).await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    grants(&mut client, Uuid::new_v4(), 0, true).await?;
    let complete = Uuid::from_u128(Uuid::new_v4().as_u128() | (0xff << 120));
    create_with_id(&mut client, complete).await?;
    let bytes = collect(&peer, &mut client, 1341, false).await?;
    for _ in 0..64 {
        create_with_id(
            &mut client,
            Uuid::from_u128(Uuid::new_v4().as_u128() & ((1 << 120) - 1)),
        )
        .await?;
    }
    client.operation = complete;
    recover(&client).await?;
    let detail = operation(&mut client).await?;
    ensure!(
        download(
            &client,
            detail["observation"]["diagnostic"]["artifact"]["downloadUrl"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!(
                    "complete file hidden behind pending page: {detail}"
                ))?
        )
        .await?
        .1 == bytes
    );
    host.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn invalid_cursor_and_revoked_pending_file_never_publish() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    warm(&peer, 1310).await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let rule = Uuid::new_v4();
    grants(&mut client, rule, 0, true).await?;
    create(&mut client).await?;
    collect(&peer, &mut client, 1311, true).await?;
    ensure!(operation(&mut client).await?["observation"]["diagnostic"]["transfer"] == "blocked");
    create(&mut client).await?;
    collect(&peer, &mut client, 1312, false).await?;
    grants(&mut client, rule, 1, false).await?;
    recover(&client).await?;
    let detail = operation(&mut client).await?;
    ensure!(
        detail["observation"]["diagnostic"]["transfer"] == "abandoned"
            && detail["observation"]["diagnostic"]["artifact"].is_null()
    );
    grants(&mut client, rule, 2, true).await?;
    recover(&client).await?;
    ensure!(
        operation(&mut client).await?["observation"]["diagnostic"]["transfer"] == "abandoned",
        "regrant restarted an abandoned file"
    );
    host.close().await?;
    Ok(())
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn published_file_without_committed_association_recovers_same_identity() -> anyhow::Result<()>
{
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    warm(&peer, 1320).await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    grants(&mut client, Uuid::new_v4(), 0, true).await?;
    create(&mut client).await?;
    let bytes = collect(&peer, &mut client, 1321, false).await?;
    client
        .app
        .execution
        .inject_diagnostic_association_fault(PgTransactionFault::CommitPending);
    // Leave the controller alive beyond the failed attempt so it can record the
    // outcome, but stop before the next backoff/lease allows a successful retry.
    let failed =
        recovery_report_with_attempt(&client, Duration::from_millis(2500), Duration::from_secs(2))
            .await?;
    ensure!(
        failed.execution_failed > 0,
        "association fault did not run: {failed:?}"
    );
    let pending = operation(&mut client).await?;
    ensure!(
        pending["observation"]["diagnostic"]["artifact"].is_null(),
        "file success was exposed as database commit"
    );
    let directory = client
        .app
        .content_writer
        .as_ref()
        .unwrap()
        .config
        .directory
        .join(case_tenant());
    let files = std::fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("diagnostic-")
        })
        .collect::<Vec<_>>();
    ensure!(files.len() == 1, "complete orphan missing: {files:?}");
    ensure!(
        !std::fs::read(&files[0])?
            .windows(32)
            .any(|v| v == &bytes[..32]),
        "orphan plaintext"
    );
    let id = client.operation;
    let browser = std::mem::take(&mut client.browser);
    host = host.restart().await?;
    client = Client::with_browser(host.browser.clone(), host.app.clone(), browser);
    client.operation = id;
    recover(&client).await?;
    let detail = operation(&mut client).await?;
    ensure!(
        download(
            &client,
            detail["observation"]["diagnostic"]["artifact"]["downloadUrl"]
                .as_str()
                .unwrap()
        )
        .await?
        .1 == bytes
    );
    ensure!(
        std::fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("diagnostic-"))
            .count()
            == 1,
        "recovery duplicated file"
    );
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn cancelled_and_replaced_registration_do_not_materialize() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    warm(&peer, 1330).await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    grants(&mut client, Uuid::new_v4(), 0, true).await?;
    create(&mut client).await?;
    let initial = begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1331,
        None,
    )
    .await?;
    let detail = operation(&mut client).await?;
    let cancelled = client
        .call(
            Method::POST,
            &format!("/{}/cancel", client.operation),
            Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":detail["revision"]})),
        )
        .await?;
    ensure!(
        cancelled.0 == StatusCode::OK,
        "cancel diagnostics: {cancelled:?}"
    );
    let _ = exchange(
        &peer,
        &reply(&initial.first, &initial.response, 2, 0, b"late"),
    )
    .await?;
    recover(&client).await?;
    ensure!(operation(&mut client).await?["observation"]["diagnostic"]["transfer"] == "abandoned");
    create(&mut client).await?;
    collect(&peer, &mut client, 1332, false).await?;
    host.replace(&peer).await?;
    recover(&client).await?;
    let detail = operation(&mut client).await?;
    ensure!(
        detail["observation"]["diagnostic"]["transfer"] == "abandoned"
            && detail["observation"]["diagnostic"]["artifact"].is_null(),
        "old generation artifact: {detail}"
    );
    host.close().await?;
    Ok(())
}
