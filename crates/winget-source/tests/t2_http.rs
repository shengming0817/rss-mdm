use rss_mdm_winget_source::*;
use rss_request_context::TenantId;
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
fn tenant() -> TenantId {
    TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap()
}
fn query() -> Query {
    Query::new(
        tenant(),
        "private",
        "Acme.App",
        "1.2",
        Architecture::X64,
        InstallerType::Msi,
        Scope::Machine,
    )
    .unwrap()
}
fn access() -> Access {
    Access::new(tenant(), "private", "source-token", "never-log-this").unwrap()
}
fn info() -> String {
    r#"{"Data":{"SourceIdentifier":"private","ServerSupportedVersions":["1.0.0"]}}"#.into()
}
async fn server(
    responses: Vec<(u16, String, String)>,
) -> (Source, tokio::task::JoinHandle<Vec<String>>) {
    let (source, listener, tls) = fixture("source.invalid", "/api/").await;
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, headers, body) in responses {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut socket = tls.accept(socket).await.unwrap();
            assert_eq!(socket.get_ref().1.server_name(), Some("source.invalid"));
            let mut bytes = Vec::new();
            loop {
                let b = socket.read_u8().await.unwrap();
                bytes.push(b);
                assert!(bytes.len() < 16384);
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            let response = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    (source, task)
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn actual_https_exact_protocol_and_credentials() {
    let (source, task) = server(vec![
        (200, String::new(), info()),
        (200, String::new(), include_str!("fixtures/msi.json").into()),
    ])
    .await;
    let client = Client::new(source).unwrap();
    let m = client.query(&query(), &access()).await.unwrap();
    assert_eq!(m.sha256(), [0x11; 32]);
    let requests = task.await.unwrap();
    assert!(requests[0].starts_with("GET /api/information HTTP/1.1"));
    assert!(requests[1].starts_with("GET /api/packageManifests/Acme.App?Version=1.2 HTTP/1.1"));
    for r in requests {
        let r = r.to_ascii_lowercase();
        assert!(r.contains("version: 1.0.0\r\n"));
        assert!(r.contains("authorization: bearer never-log-this\r\n"));
    }
    assert!(!format!("{:?}", access()).contains("never-log-this"));
    assert!(!format!("{m:?}").contains("https://"));
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn real_https_failures_do_not_look_successful() {
    for (status, headers, body, expected) in [
        (
            302,
            "Location: http://127.0.0.1:1/secret\r\n".into(),
            String::new(),
            Error::HttpStatus {
                stage: RequestStage::Information,
                status: 302,
            },
        ),
        (
            404,
            String::new(),
            String::new(),
            Error::HttpStatus {
                stage: RequestStage::Information,
                status: 404,
            },
        ),
        (
            503,
            String::new(),
            String::new(),
            Error::HttpStatus {
                stage: RequestStage::Information,
                status: 503,
            },
        ),
        (200, String::new(), "invalid".into(), Error::InvalidResponse),
        (
            200,
            String::new(),
            info().replace("1.0.0", "1.10.0"),
            Error::Unsupported,
        ),
        (
            200,
            String::new(),
            info().replace("private", "public"),
            Error::IdentityMismatch,
        ),
        (200, String::new(), "x".repeat(512), Error::BudgetExceeded),
    ] {
        let (source, task) = server(vec![(status, headers, body)]).await;
        let client =
            Client::with_limits(source, Duration::from_secs(1), Duration::from_secs(2), 256)
                .unwrap();
        assert_eq!(client.query(&query(), &access()).await, Err(expected));
        task.await.unwrap();
    }
}
#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn total_timeout_and_cross_tenant_before_io() {
    let (source, listener, _tls) = fixture("source.invalid", "/").await;
    let client = Client::with_limits(
        source,
        Duration::from_millis(50),
        Duration::from_millis(100),
        1024,
    )
    .unwrap();
    let other = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let a = Access::new(other, "private", "source-token", "token").unwrap();
    assert_eq!(client.query(&query(), &a).await, Err(Error::TenantMismatch));
    for a in [
        Access::new(tenant(), "other", "source-token", "token").unwrap(),
        Access::new(tenant(), "private", "wrong-reference", "token").unwrap(),
    ] {
        assert_eq!(
            client.query(&query(), &a).await,
            Err(Error::IdentityMismatch)
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert!(matches!(
        client.query(&query(), &access()).await,
        Err(Error::Timeout(RequestStage::Query))
    ));
    assert!(
        Source::new(
            tenant(),
            "private",
            "http://example.com/",
            vec!["8.8.8.8".parse().unwrap()],
            "ref"
        )
        .is_err()
    );
    assert!(
        Source::new(
            tenant(),
            "private",
            "https://127.0.0.1/",
            vec!["8.8.8.8".parse().unwrap()],
            "ref"
        )
        .is_err()
    );
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn chunked_body_is_bounded_without_content_length() {
    let (source, listener, tls) = fixture("source.invalid", "/").await;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tls.accept(socket).await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
            assert!(request.len() < 16384);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let chunk = "a".repeat(96);
        // Each frame fits; the cumulative second frame exceeds the 128-byte budget.
        for _ in 0..2 {
            socket
                .write_all(format!("60\r\n{chunk}\r\n").as_bytes())
                .await
                .unwrap();
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    let client =
        Client::with_limits(source, Duration::from_secs(1), Duration::from_secs(2), 128).unwrap();
    assert_eq!(
        client.query(&query(), &access()).await,
        Err(Error::BudgetExceeded)
    );
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn manifest_404_is_not_an_information_endpoint_failure() {
    let (source, task) = server(vec![
        (200, String::new(), info()),
        (404, String::new(), String::new()),
    ])
    .await;
    assert_eq!(
        Client::new(source)
            .unwrap()
            .query(&query(), &access())
            .await,
        Err(Error::NotFound)
    );
    task.await.unwrap();
    let (source, task) = server(vec![
        (200, String::new(), info()),
        (503, String::new(), String::new()),
    ])
    .await;
    assert_eq!(
        Client::new(source)
            .unwrap()
            .query(&query(), &access())
            .await,
        Err(Error::HttpStatus {
            stage: RequestStage::Manifest,
            status: 503
        })
    );
    task.await.unwrap();
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn total_budget_spans_information_and_manifest() {
    let (source, listener, tls) = fixture("source.invalid", "/").await;
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), async move {
            let (first, _) = listener.accept().await.unwrap();
            let mut first = tls.accept(first).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(first.read_u8().await.unwrap());
                assert!(request.len() < 16384);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let body = info();
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            drop(first);
            let (second, _) = listener.accept().await.unwrap();
            let mut second = tls.accept(second).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(second.read_u8().await.unwrap());
                assert!(request.len() < 16384);
            }
            assert!(request.starts_with(b"GET /packageManifests/"));
            // Keep the second response pending until the total query budget cancels it.
            assert_eq!(
                second.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        })
        .await
        .unwrap();
    });
    let client = Client::with_limits(
        source,
        Duration::from_millis(100),
        Duration::from_millis(600),
        1024,
    )
    .unwrap();
    assert_eq!(
        client.query(&query(), &access()).await,
        Err(Error::Timeout(RequestStage::Query))
    );
    task.await.unwrap();
}

async fn fixture(host: &str, path: &str) -> (Source, TcpListener, tokio_rustls::TlsAcceptor) {
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    let root =
        std::path::PathBuf::from(std::env::var("SOURCE_T2_TLS").expect("run make source-t2"));
    let address: IpAddr = std::env::var("SOURCE_T2_ADDRESS")
        .expect("run make source-t2")
        .parse()
        .unwrap();
    assert!(!address.is_loopback());
    let listener = TcpListener::bind((address, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let source = Source::new(
        tenant(),
        "private",
        &format!("https://{host}:{port}{path}"),
        vec![address],
        "source-token",
    )
    .unwrap()
    .with_root_certificate(&std::fs::read(root.join("ca.pem")).unwrap())
    .unwrap();
    let certificate = CertificateDer::from_pem_file(root.join("server.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_file(root.join("server.key")).unwrap();
    let config = ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    (
        source,
        listener,
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
    )
}

#[tokio::test]
#[ignore = "explicit real-provider T2 target"]
async fn tls_rejects_untrusted_ca_and_wrong_hostname_before_credentials() {
    for trusted in [false, true] {
        let (mut source, listener, tls) = fixture(
            if trusted {
                "wrong.invalid"
            } else {
                "source.invalid"
            },
            "/",
        )
        .await;
        if !trusted {
            let address = listener.local_addr().unwrap();
            source = Source::new(
                tenant(),
                "private",
                &format!("https://source.invalid:{}/", address.port()),
                vec![address.ip()],
                "source-token",
            )
            .unwrap();
        }
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(tls.accept(socket).await.is_err());
        });
        assert_eq!(
            Client::new(source)
                .unwrap()
                .query(&query(), &access())
                .await,
            Err(Error::Transport(RequestStage::Information))
        );
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
}
