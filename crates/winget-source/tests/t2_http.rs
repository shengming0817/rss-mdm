use rss_mdm_winget_source::*;
use rss_request_context::TenantId;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
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
    Access::new(tenant(), "private", "source-token", Some("never-log-this")).unwrap()
}
fn info() -> String {
    r#"{"Data":{"SourceIdentifier":"private","ServerSupportedVersions":["1.0.0"]}}"#.into()
}
async fn server(
    responses: Vec<(u16, String, String)>,
) -> (Source, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let source = Source::new(
        tenant(),
        "private",
        &format!("http://localhost:{port}/api/"),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "source-token",
        Network::LoopbackHttp,
    )
    .unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, headers, body) in responses {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
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
async fn actual_http_exact_protocol_and_credentials() {
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
async fn real_http_failures_do_not_look_successful() {
    for (status, headers, body, expected) in [
        (
            302,
            "Location: http://127.0.0.1:1/secret\r\n".into(),
            String::new(),
            Error::HttpStatus(302),
        ),
        (404, String::new(), String::new(), Error::HttpStatus(404)),
        (503, String::new(), String::new(), Error::HttpStatus(503)),
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let source = Source::new(
        tenant(),
        "private",
        &format!("http://127.0.0.1:{port}/"),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "source-token",
        Network::LoopbackHttp,
    )
    .unwrap();
    let client = Client::with_limits(
        source,
        Duration::from_millis(50),
        Duration::from_millis(100),
        1024,
    )
    .unwrap();
    let other = TenantId::parse("20000000-0000-0000-0000-000000000001").unwrap();
    let a = Access::new(other, "private", "source-token", None).unwrap();
    assert_eq!(client.query(&query(), &a).await, Err(Error::TenantMismatch));
    assert_eq!(client.query(&query(), &access()).await, Err(Error::Timeout));
    assert!(
        Source::new(
            tenant(),
            "private",
            "http://example.com/",
            vec!["8.8.8.8".parse().unwrap()],
            "ref",
            Network::LoopbackHttp
        )
        .is_err()
    );
    assert!(
        Source::new(
            tenant(),
            "private",
            "https://127.0.0.1/",
            vec!["8.8.8.8".parse().unwrap()],
            "ref",
            Network::Https
        )
        .is_err()
    );
}
