//! TLS + HTTP/2 APNs participant verifies actual headers, body and client certificate.
use super::*;
use anyhow::{Result, ensure};
use axum::{body::Bytes, http::Response};
use std::{path::PathBuf, sync::Arc};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, pem::PemObject},
    },
};
#[tokio::test]
#[ignore = "Apple T2: controlled HTTP/2 APNs with certificate authentication"]
async fn production_transport_receipts_are_not_command_evidence() -> Result<()> {
    let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let config: crate::apple::config::Config =
        serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = crate::native::TlsEndpoint {
        listen: listener.local_addr()?,
        origin: format!("https://localhost:{}", listener.local_addr()?.port()),
        certificate_file: root.join("server.crt"),
        private_key_file: root.join("apple-tls.pk8"),
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(&std::fs::read(
        root.join("apple-root.pem"),
    )?)?)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let mut tls = (*crate::native::tls::configuration(&endpoint, Some(verifier))?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let id = Uuid::new_v4();
    let expected_id = id.to_string();
    let topic = config.apns_topic.clone();
    let server = tokio::spawn(async move {
        let (io, _) = listener.accept().await?;
        let io = acceptor.accept(io).await?;
        ensure!(
            io.get_ref()
                .1
                .peer_certificates()
                .is_some_and(|c| c.len() == 1)
        );
        let mut h2 = h2::server::handshake(io).await?;
        let mut handlers = tokio::task::JoinSet::new();
        for status in [200, 410, 429, 503, 400] {
            let (request, mut send) = h2
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("APNs connection closed"))??;
            ensure!(request.method() == "POST" && request.uri().path() == "/3/device/0102feff");
            ensure!(
                request.headers()["apns-topic"] == topic
                    && request.headers()["apns-id"] == expected_id
                    && request.headers()["apns-expiration"] == "0"
            );
            handlers.spawn(async move {
                let mut stream = request.into_body();
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.data().await {
                    let chunk = chunk?;
                    stream.flow_control().release_capacity(chunk.len())?;
                    bytes.extend(chunk);
                }
                ensure!(
                    serde_json::from_slice::<serde_json::Value>(&bytes)?
                        == serde_json::json!({"mdm":"fixture-magic"})
                );
                let mut response =
                    send.send_response(Response::builder().status(status).body(())?, false)?;
                response.send_data(Bytes::from_static(b"{}"), true)?;
                Ok::<(), anyhow::Error>(())
            });
        }
        h2.graceful_shutdown();
        while h2.accept().await.is_some() {}
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        Ok::<(), anyhow::Error>(())
    });
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let client =
        reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                root.join("ca.crt"),
            )?)?);
    let mut push = Push::with_client(&config, now, client)?;
    push.origin = endpoint.origin;
    for (status, outcome) in [
        (200, Outcome::Accepted),
        (410, Outcome::Unregistered),
        (429, Outcome::Retryable),
        (503, Outcome::Retryable),
        (400, Outcome::Rejected),
    ] {
        let receipt = push
            .send(id, &[1, 2, 254, 255], "fixture-magic", now)
            .await?;
        ensure!(receipt.id == id && receipt.status == status && receipt.outcome == outcome);
    }
    drop(push);
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    Ok(())
}
