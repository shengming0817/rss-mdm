use super::*;
use axum::{Router, routing::get};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn handshake_diagnostics_preserve_closed_failure_classification() {
    let error = std::io::Error::other(rustls::Error::InvalidCertificate(
        rustls::CertificateError::UnknownIssuer,
    ));
    assert_eq!(classify_tls(&error), ConnectionFailure::ClientCertificate);
    let error = std::io::Error::other("synthetic-secret");
    let result = event("mdm-management-tls", classify_tls(&error));
    assert_eq!(result["kind"], "handshake_protocol");
    assert!(!result.to_string().contains("synthetic-secret"));
    assert_eq!(
        event("mdm-enrollment-tls", ConnectionFailure::HandshakeTimeout)["kind"],
        "handshake_timeout"
    );
}

#[tokio::test]
async fn actual_rss_connection_failures_are_visible_without_payloads() {
    if std::env::var_os("MDM_PANIC_DIAGNOSTIC_CHILD").is_some() {
        crate::install_diagnostics().unwrap();
        tracing::error!(target: "sqlx::query", "synthetic-secret");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().route("/", get(|| async { "healthy" })).route(
            "/panic",
            get(|| async {
                std::panic::panic_any("synthetic-secret");
                #[allow(unreachable_code)]
                "unreachable"
            }),
        );
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(2)).unwrap(),
            Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .unwrap();
        let policy = rss_axum::Http1ServePolicy::new(
            rss_axum::ServePolicy::new(
                8,
                Duration::from_secs(1),
                Duration::from_millis(30),
                Duration::from_secs(1),
            )
            .unwrap(),
            Duration::from_secs(1),
            64,
            32768,
        )
        .unwrap();
        owner
            .startup()
            .unwrap()
            .stage_task_with_token(rss_axum::serve_http1_registration(
                listener,
                router,
                rss_axum::PlainTransport,
                "mdm-enrollment-tls",
                policy,
            ));
        for bytes in [
            b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"malformed-synthetic-secret\r\n\r\n",
            b"",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ] {
            let response = tokio::time::timeout(Duration::from_secs(2), async {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(bytes).await.unwrap();
                let mut response = Vec::new();
                // A peer error may close by reset; the healthy response must still succeed.
                let result = stream.read_to_end(&mut response).await;
                if bytes.starts_with(b"GET / HTTP") {
                    result.unwrap();
                }
                response
            })
            .await
            .unwrap();
            if bytes.starts_with(b"GET / HTTP") {
                assert!(String::from_utf8(response).unwrap().ends_with("healthy"));
            }
        }
        assert!(owner.shutdown().join().await.unwrap().is_clean());
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native::tls::tests::actual_rss_connection_failures_are_visible_without_payloads",
            "--nocapture",
        ])
        .env("MDM_PANIC_DIAGNOSTIC_CHILD", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("synthetic-secret"));
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(events.iter().any(|e| e["event"] == "mdm_panic"));
    for outcome in ["panic", "peer_error", "establishment_timeout"] {
        assert!(
            events.iter().any(|e| e["fields"]["outcome"] == outcome
                && e["fields"]["listener"] == "mdm-enrollment-tls"),
            "missing {outcome}: {stderr}"
        );
    }
}

pub(crate) async fn verify_tls_lifecycle(
    access: Arc<AccessStore>,
    tls: Arc<rustls::ServerConfig>,
    root: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let peer = "127.0.0.1".parse()?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(root.join("ca.crt"))?) {
        roots.add(cert?)?;
    }
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    for established in [false, true] {
        let admission = Admission::new(
            std::sync::Arc::new(crate::Monotonic(|| {
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            })),
            Arc::new(tokio::sync::Semaphore::new(4)),
            "mdm-enrollment-tls",
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let router = Router::new().route(
            "/",
            get({
                let entered = entered.clone();
                let dropped = dropped.clone();
                move |Extension(peer): Extension<Peer>, Extension(_gate): Extension<RequestGate>| {
                    let entered = entered.clone();
                    let dropped = dropped.clone();
                    async move {
                        assert!(peer.chain().is_empty());
                        let _guard = Dropped(dropped);
                        entered.notify_one();
                        std::future::pending::<&'static str>().await
                    }
                }
            }),
        );
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_millis(100))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        owner.startup()?.stage_task_with_token(registration(
            listener,
            TlsRouter {
                admission: admission.clone(),
                listen: address,
                tls: tls.clone(),
                router,
            },
            access.clone(),
            "11111111-1111-4111-8111-111111111111".into(),
            "mdm-enrollment-tls",
        ));
        let stream = TcpStream::connect(address).await?;
        let mut io: Box<dyn tokio::io::AsyncRead + Unpin> = if established {
            let mut stream = tokio_rustls::TlsConnector::from(client.clone())
                .connect("localhost".try_into()?, stream)
                .await?;
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await?;
            tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
            Box::new(stream)
        } else {
            Box::new(stream)
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.active_connections(peer) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let receipt =
            tokio::time::timeout(Duration::from_secs(2), owner.shutdown().join()).await??;
        ensure!(
            receipt.is_clean() != established,
            "unexpected TLS drain outcome"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.active_connections(peer) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        ensure!(
            !established || dropped.load(Ordering::SeqCst),
            "handler survived RSS owner termination"
        );
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(2), io.read(&mut byte)).await?;
        ensure!(
            matches!(closed, Ok(0) | Err(_)),
            "connection survived RSS owner termination"
        );
    }
    Ok(())
}
