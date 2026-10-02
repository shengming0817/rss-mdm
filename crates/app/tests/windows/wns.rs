//! A real TLS participant checks OAuth, raw wake headers and token refresh independently.
use crate::windows::test_support::root;
use anyhow::{Result, ensure};
use rss_mdm_windows_channel::push::PushOutcome;
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_push_transport_refreshes_tokens_without_claiming_command_delivery() -> Result<()> {
    let root = root()?;
    let mut config: crate::windows::WindowsConfig =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    config.management.listen = listener.local_addr()?;
    config.management.origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = (*crate::native::tls::configuration(&config.management, None)?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await?;
        let io = acceptor.accept(io).await?;
        let mut connection = h2::server::handshake(io).await?;
        let mut handlers = tokio::task::JoinSet::new();
        // 401 invalidates the cached token, so precisely two OAuth requests occur.
        for (token, status) in [
            (true, 200),
            (false, 200),
            (false, 401),
            (true, 200),
            (false, 429),
            (false, 410),
            (false, 403),
        ] {
            let (request, mut send) = connection
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("WNS connection closed"))??;
            ensure!(request.method() == "POST");
            if token {
                ensure!(request.uri().path() == "/accesstoken.srf");
                ensure!(request.headers()["content-type"] == "application/x-www-form-urlencoded");
            } else {
                ensure!(request.uri().path() == "/wake");
                ensure!(request.headers()["authorization"] == "Bearer fixture-token");
                ensure!(request.headers()["content-type"] == "application/octet-stream");
                ensure!(request.headers()["x-wns-type"] == "wns/raw");
                ensure!(request.headers()["x-wns-cache-policy"] == "cache");
                ensure!(request.headers()["x-wns-ttl"] == "60");
                ensure!(request.headers()["x-wns-requestforstatus"] == "true");
            }
            handlers.spawn(async move {
                let mut stream = request.into_body();
                let mut body = Vec::new();
                while let Some(chunk) = stream.data().await {
                    let chunk = chunk?;
                    stream.flow_control().release_capacity(chunk.len())?;
                    body.extend(chunk);
                    ensure!(body.len() <= 1024);
                }
                if token {
                    ensure!(body == b"grant_type=client_credentials&client_id=fixture-sid&client_secret=fixture-secret&scope=notify.windows.com");
                } else { ensure!(body.is_empty()); }
                let response = axum::http::Response::builder().status(status).header("x-wns-notificationstatus","received").body(())?;
                let mut response = send.send_response(response, false)?;
                response.send_data(axum::body::Bytes::from_static(if token {
                    br#"{"token_type":"bearer","access_token":"fixture-token","expires_in":3600}"#
                } else { b"" }), true)?;
                Ok::<(),anyhow::Error>(())
            });
        }
        tokio::select! {
            () = stopped.cancelled() => {},
            next = connection.accept() => ensure!(next.is_none(), "unexpected WNS request"),
        }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok::<(), anyhow::Error>(())
    });
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("ca.crt"),
        )?)?)
        .build()?;
    let push = rss_mdm_windows_channel::push::Push::fixture(
        "fixture.pfn".into(),
        "fixture-sid".into(),
        "fixture-secret".into(),
        client,
        &config.management.origin,
        crate::windows::test_support::monotonic(),
    )?;
    ensure!(push.send("https://localhost/wake").await.is_err());
    for (status, outcome) in [
        (200, PushOutcome::Accepted),
        (401, PushOutcome::Retryable),
        (429, PushOutcome::Retryable),
        (410, PushOutcome::Unregistered),
        (403, PushOutcome::Rejected),
    ] {
        let receipt = push.send("https://db5.notify.windows.com/wake").await?;
        ensure!(receipt.status == status && receipt.outcome == outcome);
    }
    stop.cancel();
    drop(push);
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=windows.management"]
async fn native_push_routes_require_correlated_pfn_and_refresh_without_resetting_leases()
-> Result<()> {
    use crate::{
        execution::test_support::native,
        windows::test_support::{Host, case_tenant},
    };
    use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
    use sqlx::Row;
    let mut host = Host::with_push().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let registration = peer.intent.registration;
    let pool =
        sqlx::PgPool::connect_with(crate::device::test_support::options("postgres")?).await?;
    let lease = uuid::Uuid::new_v4();
    for (round, pfn, uri, revision) in [
        (0, "wrong.pfn", "https://db5.notify.windows.com/wake", 0),
        (1, "fixture.pfn", "https://db5.notify.windows.com/wake", 1),
        (2, "fixture.pfn", "https://db5.notify.windows.com/wake", 1),
        (
            3,
            "fixture.pfn",
            "https://db5.notify.windows.com/changed",
            2,
        ),
    ] {
        let mut first = peer.message.clone();
        first.header.session_id = 1600 + round;
        ensure!(
            native::post(&peer.mutual, &peer.url, &first)
                .await?
                .status()
                .is_success()
        );
        let mut ack = peer.ack.clone();
        ack.header.session_id = first.header.session_id;
        if let s::Command::Status(status) = &mut ack.commands[0] {
            use base64::Engine;
            status.challenge.as_mut().unwrap().nonce = Some(Secret(
                base64::engine::general_purpose::STANDARD.encode([round as u8 + 30; 16]),
            ));
        }

        let response = native::post(&peer.mutual, &peer.url, &ack).await?;
        ensure!(response.status().is_success());
        let response = s::decode(&response.bytes().await?, &CodecLimits::default())?;
        let (push_id, items) = response
            .commands
            .iter()
            .find_map(|c| match c {
                s::Command::Get { id, items, .. }
                    if items
                        .iter()
                        .any(|i| i.target.as_ref().is_some_and(|u| u.ends_with("/Push/PFN"))) =>
                {
                    Some((*id, items.clone()))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("missing native WNS query"))?;
        let gets = response
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } if *id != push_id => {
                    Some((*id, items[0].target.clone().unwrap()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut packet = native::report(&first, &gets, "10.0.26100.0", 200);
        let id = packet.commands.iter().map(s::Command::id).max().unwrap() + 1;
        packet.commands.push(s::Command::Status(s::Status {
            id,
            message_ref: response.header.message_id,
            command_ref: push_id,
            command: s::CommandName::Get,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }));
        packet.commands.push(s::Command::Results(s::Results {
            id: id + 1,
            message_ref: Some(response.header.message_id),
            command_ref: Some(push_id),
            command: Some(s::CommandName::Get),
            meta: None,
            items: items
                .into_iter()
                .map(|i| {
                    let source = i.target.unwrap();
                    let value = if source.ends_with("/PFN") { pfn } else { uri };
                    s::Item {
                        source: Some(source),
                        target: None,
                        meta: None,
                        data: Some(Secret(value.into())),
                        more_data: false,
                    }
                })
                .collect(),
        }));
        let result = native::post(&peer.mutual, &peer.url, &packet).await?;
        ensure!(
            result.status().is_success(),
            "WNS route report {}",
            result.status()
        );
        let original = result.bytes().await?;
        ensure!(
            native::post(&peer.mutual, &peer.url, &packet)
                .await?
                .bytes()
                .await?
                == original
        );
        let row=sqlx::query("SELECT revision,uri,lease_id,outcome,expires_at>clock_timestamp()+interval '29 days' AS fresh FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2")
            .bind(case_tenant()).bind(registration).fetch_optional(&pool).await?;
        if revision == 0 {
            ensure!(row.is_none());
            continue;
        }
        let row = row.unwrap();
        ensure!(row.try_get::<i64, _>("revision")? == revision);
        ensure!(row.try_get::<bool, _>("fresh")?);
        ensure!(
            !row.try_get::<Vec<u8>, _>("uri")?
                .windows(uri.len())
                .any(|v| v == uri.as_bytes())
        );
        if round == 2 {
            ensure!(row.try_get::<Option<uuid::Uuid>, _>("lease_id")? == Some(lease));
            ensure!(row.try_get::<Option<String>, _>("outcome")?.as_deref() == Some("rejected"));
        }
        if round == 3 {
            ensure!(row.try_get::<Option<uuid::Uuid>, _>("lease_id")?.is_none());
        }
        if round == 1 {
            sqlx::query("UPDATE mdm_windows.push_channels SET expires_at=clock_timestamp()+interval '1 hour',lease_id=$3,lease_until=clock_timestamp()+interval '30 seconds',outcome='rejected' WHERE tenant_id=$1::uuid AND registration=$2")
                .bind(case_tenant()).bind(registration).bind(lease).execute(&pool).await?;
        }
    }
    // Use the production claim/settle loop with the App authority bridge and a real TLS WNS peer.
    let (origin, transport, server, stop) = worker_transport().await?;
    let mut windows = crate::windows::test_support::windows()?;
    let channel = Arc::get_mut(&mut windows.channel).unwrap();
    channel.push = Some(rss_mdm_windows_channel::push::Push::fixture(
        "fixture.pfn".into(),
        "fixture-sid".into(),
        "fixture-secret".into(),
        transport,
        &origin,
        crate::windows::test_support::monotonic(),
    )?);
    let database = host.store.windows_store();
    let eligibility = crate::windows::WakeEligibility(host.app.execution.clone());
    ensure!(
        !rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.app.protection,
            &database,
            &host.app.audit_store,
            case_tenant()
        )
        .await?,
        "no work must not wake a device"
    );
    let mut command =
        crate::execution::test_support::Client::start(host.browser.clone(), host.app.clone())
            .await?;
    command.accept_approved().await?;
    command.publish_operation(command.operation).await?;
    ensure!(
        rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.app.protection,
            &database,
            &host.app.audit_store,
            case_tenant()
        )
        .await?
    );
    let row = sqlx::query("SELECT outcome,lease_id,settled_id,next_push>clock_timestamp() AS delayed FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2").bind(case_tenant()).bind(registration).fetch_one(&pool).await?;
    ensure!(
        row.try_get::<String, _>("outcome")? == "accepted"
            && row.try_get::<Option<uuid::Uuid>, _>("lease_id")?.is_none()
            && row
                .try_get::<Option<uuid::Uuid>, _>("settled_id")?
                .is_some()
            && row.try_get::<bool, _>("delayed")?
    );
    let command_view = command
        .call(
            axum::http::Method::GET,
            &format!("/{}", command.operation),
            None,
        )
        .await?;
    ensure!(
        command_view.1["commandStatus"] == "published",
        "WNS acceptance became delivery: {}",
        command_view.1
    );
    ensure!(
        !rss_mdm_windows_channel::push::wake_once(
            &windows.channel,
            &eligibility,
            &host.app.protection,
            &database,
            &host.app.audit_store,
            case_tenant()
        )
        .await?
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    pool.close().await;
    host.close().await
}

async fn worker_transport() -> Result<(
    String,
    reqwest::Client,
    tokio::task::JoinHandle<Result<()>>,
    tokio_util::sync::CancellationToken,
)> {
    let root = root()?;
    let config: crate::windows::WindowsConfig =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = (*crate::native::tls::configuration(&config.management, None)?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await?;
        let mut connection = h2::server::handshake(acceptor.accept(io).await?).await?;
        let mut handlers = tokio::task::JoinSet::new();
        for token in [true, false] {
            let (request, mut send) = connection
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("WNS connection closed"))??;
            ensure!(request.method() == "POST");
            ensure!(
                request.uri().path()
                    == if token {
                        "/accesstoken.srf"
                    } else {
                        "/changed"
                    }
            );
            if !token {
                ensure!(
                    request.headers()["authorization"] == "Bearer fixture-token"
                        && request.headers()["x-wns-type"] == "wns/raw"
                );
            }
            handlers.spawn(async move {
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await { let chunk = chunk?; body.flow_control().release_capacity(chunk.len())?; if !token { ensure!(chunk.is_empty()); } }
                let response = axum::http::Response::builder().status(200).header("x-wns-notificationstatus", "received").body(())?;
                let mut response = send.send_response(response,false)?;
                response.send_data(axum::body::Bytes::from_static(if token {br#"{"token_type":"bearer","access_token":"fixture-token","expires_in":3600}"#} else {b""}),true)?;
                Ok::<(),anyhow::Error>(())
            });
        }
        tokio::select! { ()=stopped.cancelled()=>{}, next=connection.accept()=>ensure!(next.is_none(),"unexpected wake") }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok(())
    });
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("ca.crt"),
        )?)?)
        .build()?;
    Ok((origin, client, server, stop))
}
