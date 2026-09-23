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
pub(in crate::apple) struct Participant {
    pub(in crate::apple) push: Push,
    server: tokio::task::JoinHandle<Result<()>>,
}
impl Participant {
    pub(in crate::apple) async fn start(statuses: Vec<u16>, token: Vec<u8>) -> Result<Self> {
        Self::start_with_rotation(statuses, token, false).await
    }
    pub(in crate::apple) async fn start_with_rotation(
        statuses: Vec<u16>,
        token: Vec<u8>,
        rotate: bool,
    ) -> Result<Self> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let mut config: crate::apple::config::Config =
            serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        let rotated = tempfile::tempdir()?;
        if rotate {
            config.apns_certificate_file = rotated.path().join("apns.pem");
            let status = std::process::Command::new("openssl")
                .args(["x509", "-req", "-in"])
                .arg(root.join("apple-apns.csr"))
                .arg("-CA")
                .arg(root.join("apple-root.pem"))
                .arg("-CAkey")
                .arg(root.join("apple-root.key"))
                .args(["-set_serial", "2471", "-days", "90", "-sha256", "-extfile"])
                .arg(root.join("apple-apns.ext"))
                .arg("-out")
                .arg(&config.apns_certificate_file)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?;
            ensure!(status.success(), "APNs rotation fixture signing failed");
        }
        let expected_certificate =
            CertificateDer::from_pem_slice(&std::fs::read(&config.apns_certificate_file)?)?;
        if rotate {
            let original =
                CertificateDer::from_pem_slice(&std::fs::read(root.join("apple-apns.pem"))?)?;
            ensure!(
                expected_certificate != original,
                "rotation fixture reused the original certificate"
            );
        }
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
        let expected_token = token
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let topic = config.apns_topic.clone();
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await?;
            let io = acceptor.accept(io).await?;
            ensure!(
                io.get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|c| c.len() == 1 && c[0] == expected_certificate)
            );
            let mut h2 = h2::server::handshake(io).await?;
            let mut handlers = tokio::task::JoinSet::new();
            for status in statuses {
                let (request, mut send) = h2
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("APNs connection closed"))??;
                ensure!(
                    request.method() == "POST"
                        && request.uri().path() == format!("/3/device/{expected_token}")
                );
                ensure!(
                    request.headers()["apns-topic"] == topic
                        && Uuid::parse_str(request.headers()["apns-id"].to_str()?).is_ok()
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
        let client = reqwest::Client::builder().no_proxy().add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?,
        );
        let mut push = Push::with_client(&config, now, client)?;
        push.origin = endpoint.origin;
        Ok(Self { push, server })
    }
    pub(in crate::apple) async fn close(self) -> Result<()> {
        drop(self.push);
        tokio::time::timeout(Duration::from_secs(5), self.server).await???;
        Ok(())
    }
    pub(in crate::apple) async fn unavailable_push() -> Result<Push> {
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let config = serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let mut push = Push::with_client(&config, now, reqwest::Client::builder().no_proxy())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        push.origin = format!("https://localhost:{}", listener.local_addr()?.port());
        drop(listener);
        Ok(push)
    }
}
#[tokio::test]
#[ignore = "Apple T2: controlled HTTP/2 APNs with certificate authentication"]
async fn production_transport_receipts_are_not_command_evidence() -> Result<()> {
    let participant =
        Participant::start(vec![200, 410, 429, 503, 400], vec![1, 2, 254, 255]).await?;
    let id = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    for (status, outcome) in [
        (200, Outcome::Accepted),
        (410, Outcome::Unregistered),
        (429, Outcome::Retryable),
        (503, Outcome::Retryable),
        (400, Outcome::Rejected),
    ] {
        let receipt = participant
            .push
            .send(id, &[1, 2, 254, 255], "fixture-magic", now)
            .await?;
        ensure!(receipt.id == id && receipt.status == status && receipt.outcome == outcome);
    }
    participant.close().await
}
