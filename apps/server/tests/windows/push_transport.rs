//! A real TLS participant checks OAuth, raw wake headers and token refresh independently.
use anyhow::{Result, ensure};
use rss_mdm_windows_channel::push::PushOutcome;
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "make t2 MODULE=windows.push_transport"]
async fn raw_push_transport_refreshes_tokens_and_returns_receipts() -> Result<()> {
    let root = std::path::PathBuf::from(std::env::var("MDM_WINDOWS_FIXTURES")?);
    let mut config: crate::windows::WindowsConfig =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    config.management.origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = crate::test_support::tls::server(&root, "windows-tls.pk8", None)?;
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
        for (token, status, retry_after, delivery) in [
            (true, 200, None, None),
            (false, 200, None, Some("received")),
            (false, 200, None, None),
            (false, 200, None, Some("dropped")),
            (false, 200, None, Some("channelthrottled")),
            (false, 200, None, Some("invalid")),
            (false, 401, None, None),
            (true, 200, None, None),
            (false, 406, Some("180"), None),
            (false, 429, None, None),
            (false, 404, None, None),
            (false, 410, None, None),
            (false, 403, None, None),
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
                let mut response = axum::http::Response::builder().status(status);
                if let Some(delivery) = delivery { response = response.header("x-wns-status",delivery); }
                if let Some(wait) = retry_after { response = response.header("retry-after",wait); }
                let response = response.body(())?;
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
    ensure!(matches!(
        push.send("https://localhost/wake").await,
        Err(rss_mdm_windows_channel::Error::Malformed)
    ));
    for (status, outcome) in [
        (200, PushOutcome::Accepted),
        (200, PushOutcome::Accepted),
        (200, PushOutcome::Retryable),
        (200, PushOutcome::Retryable),
        (200, PushOutcome::Unknown),
        (401, PushOutcome::Retryable),
        (406, PushOutcome::Retryable),
        (429, PushOutcome::Retryable),
        (404, PushOutcome::Unregistered),
        (410, PushOutcome::Unregistered),
        (403, PushOutcome::Rejected),
    ] {
        let receipt = push.send("https://db5.notify.windows.com/wake").await?;
        ensure!(receipt.status == status && receipt.outcome == outcome);
        ensure!(
            receipt.retry_after
                == (status == 406)
                    .then_some(rss_mdm_windows_channel::push::RetryAfter::Seconds(180))
        );
    }
    stop.cancel();
    drop(push);
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    Ok(())
}
