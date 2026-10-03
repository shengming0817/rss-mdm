use super::*;
use crate::{body, config::Secrets};
use bytes::Bytes;
use futures::StreamExt;
use std::time::Instant;
struct Timer;
impl Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "explicit test clock adapter in the Tokio time domain"
    )]
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
struct NoSecrets;
impl Secrets for NoSecrets {
    fn resolve(&self, _: &str) -> Result<Credentials> {
        Err(Error::Denied)
    }
}
fn config() -> Config {
    Config {
        endpoint: "https://localhost:9000".into(),
        region: "us-east-1".into(),
        bucket: "content".into(),
        namespace: "allowed".into(),
        credentials_reference: "fixture".into(),
        private_ca_pem: None,
        max_concurrent: 1,
        connect_timeout: Duration::from_secs(1),
    }
}
fn store() -> Result<Store> {
    Ok(Store {
        client: config().client(Arc::new(NoSecrets))?,
        bucket: "content".into(),
        namespace: "allowed".into(),
        scope: [1; 32],
        permits: Arc::new(Semaphore::new(1)),
        clock: Arc::new(Timer),
    })
}
fn budget() -> Result<Budget> {
    Budget::new(
        Arc::new(Timer),
        Duration::from_secs(2),
        Duration::from_millis(20),
        100,
        2,
    )
}
fn content(bytes: &[u8]) -> Content {
    Content {
        length: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}
fn input(parts: Vec<&'static [u8]>) -> ByteStreamInput {
    Box::pin(futures::stream::iter(
        parts.into_iter().map(|b| Ok(Bytes::from_static(b))),
    ))
}
#[test]
fn restored_coordinates_cannot_escape_namespace() -> Result<()> {
    let s = store()?;
    for key in [
        "../x", "/x", "x//y", "x/..", "x%2fy", "x?y", "x#y", "x\\y", "x/.", "é",
    ] {
        assert_eq!(s.target(key), Err(Error::Input));
    }
    let mut foreign = s.target("blob")?;
    foreign.scope = [2; 32];
    let restored: Target =
        serde_json::from_value(serde_json::to_value(foreign).map_err(|_| Error::Input)?)
            .map_err(|_| Error::Input)?;
    assert_eq!(s.key(&restored), Err(Error::Input));
    assert!(s.target(&"x".repeat(1024)).is_err());
    for version in ["null", "", "bad\nversion"] {
        assert!(s.object(s.target("blob")?, version).is_err());
    }
    Ok(())
}
#[test]
fn connection_and_credentials_fail_closed() -> Result<()> {
    for endpoint in [
        "http://localhost",
        "https://user:secret@localhost",
        "https://localhost/path",
        "https://localhost?secret=x",
    ] {
        let mut c = config();
        c.endpoint = endpoint.into();
        assert_eq!(c.validate(), Err(Error::Configuration));
    }
    let c = Credentials::new(
        "private-access".into(),
        "private-secret".into(),
        Some("private-token".into()),
        None,
    )?;
    let debug = format!("{c:?}");
    assert!(!debug.contains("private-"));
    let s = store()?;
    let _permit = s.permit()?;
    assert!(matches!(s.permit(), Err(Error::Busy)));
    Ok(())
}
#[tokio::test]
async fn upload_rejects_truncation_excess_and_wrong_hash() -> Result<()> {
    for source in [
        input(vec![b"ab"]),
        input(vec![b"abc", b"d"]),
        input(vec![b"abd"]),
    ] {
        assert!(
            body::upload(source, content(b"abc"), budget()?)
                .collect()
                .await
                .is_err()
        );
    }
    let bytes = body::upload(input(vec![b"a", b"bc", b""]), content(b"abc"), budget()?)
        .collect()
        .await
        .map_err(|_| Error::Integrity)?;
    assert_eq!(bytes.into_bytes(), Bytes::from_static(b"abc"));
    assert!(
        body::upload(input(vec![]), content(b""), budget()?)
            .collect()
            .await
            .is_ok()
    );
    Ok(())
}
#[tokio::test]
async fn read_reports_terminal_integrity_and_releases_permit() -> Result<()> {
    let s = store()?;
    let mut stream = body::download(
        aws_sdk_s3::primitives::ByteStream::from_static(b"ab"),
        3,
        Some(content(b"abc").sha256),
        budget()?,
        Some(s.permit()?),
    );
    assert!(matches!(s.permit(), Err(Error::Busy)));
    assert_eq!(stream.next().await, Some(Ok(Bytes::from_static(b"ab"))));
    assert_eq!(stream.next().await, Some(Err(Error::Integrity)));
    assert_eq!(stream.next().await, None);
    assert!(s.permit().is_ok());
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn idle_wait_and_absolute_cutoff_are_bounded() -> Result<()> {
    let mut b = budget()?;
    let cutoff = b.deadline;
    let copy = b.clone();
    assert_eq!(copy.deadline, cutoff);
    b.idle = Duration::from_millis(10);
    let source = Box::pin(futures::stream::pending());
    assert!(
        body::upload(source, content(b"abc"), b)
            .collect()
            .await
            .is_err()
    );
    Ok(())
}
