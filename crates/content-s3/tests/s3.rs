//! Canonical real TLS provider tests. Discovered/executed only by content.s3 T2.
use crate::*;
use bytes::Bytes;
use futures::StreamExt;
use rss_request_context::Clock;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_rustls::{TlsAcceptor, rustls};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
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
struct Fixture {
    data: Value,
    namespace: String,
}
struct FixtureSecrets {
    access: String,
    secret: String,
}
impl Secrets for FixtureSecrets {
    fn resolve(&self, reference: &str) -> Result<Credentials> {
        if reference != "fixture-content" {
            return Err(Error::Denied);
        }
        Credentials::new(self.access.clone(), self.secret.clone(), None, None)
    }
}
impl Fixture {
    fn load() -> TestResult<Self> {
        let data: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
        let context: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_CASE_CONTEXT")?)?)?;
        let namespace = format!(
            "content/{}",
            context["namespace"].as_str().ok_or(Error::Input)?
        );
        Ok(Self { data, namespace })
    }
    fn string(&self, key: &str) -> TestResult<&str> {
        self.data[key]
            .as_str()
            .ok_or_else(|| Error::Configuration.into())
    }
    fn config(&self) -> TestResult<Config> {
        Ok(Config {
            endpoint: self.string("endpoint")?.into(),
            region: self.string("region")?.into(),
            bucket: self.string("bucket")?.into(),
            namespace: self.namespace.clone(),
            credentials_reference: "fixture-content".into(),
            private_ca_pem: Some(std::fs::read(self.string("ca")?)?),
            max_concurrent: 2,
            connect_timeout: Duration::from_secs(2),
        })
    }
    fn secrets(&self, root: bool) -> TestResult<Arc<dyn Secrets>> {
        Ok(Arc::new(FixtureSecrets {
            access: self
                .string(if root { "rootAccessKey" } else { "accessKey" })?
                .into(),
            secret: self
                .string(if root { "rootSecretKey" } else { "secretKey" })?
                .into(),
        }))
    }
    async fn store(&self) -> TestResult<Store> {
        self.connect(self.config()?, false).await
    }
    async fn connect(&self, config: Config, root: bool) -> TestResult<Store> {
        Ok(Store::connect(config, self.secrets(root)?, Arc::new(Timer), budget()?).await?)
    }
}
fn budget() -> Result<Budget> {
    Budget::new(
        Arc::new(Timer),
        Duration::from_secs(30),
        Duration::from_secs(3),
        16 * 1024 * 1024,
        20,
    )
}
fn content(bytes: &[u8]) -> Content {
    Content {
        length: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}
fn source(bytes: Bytes) -> ByteStreamInput {
    let pieces: Vec<_> = bytes.chunks(65_536).map(Bytes::copy_from_slice).collect();
    Box::pin(futures::stream::iter(pieces.into_iter().map(Ok)))
}
fn confirmed<T>(result: Mutation<T>) -> TestResult<T> {
    match result {
        Mutation::Confirmed(value) => Ok(value),
        Mutation::Unknown(error) => Err(error.into()),
    }
}
fn verified(written: Written) -> TestResult<Verified> {
    match written {
        Written::Verified(value) => Ok(value),
        Written::Unverified { error, .. } => Err(error.into()),
    }
}
async fn create(store: &Store, key: &str, op: &str, bytes: Bytes) -> TestResult<Verified> {
    let write = store.write(store.target(key)?, op, content(&bytes))?;
    verified(confirmed(
        store.put(&write, source(bytes), budget()?).await?,
    )?)
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn stream_range_condition_and_two_clients() -> TestResult {
    let f = Fixture::load()?;
    let a = f.store().await?;
    let b = f.store().await?;
    let bytes = Bytes::from_static(b"immutable software bytes");
    let first = create(&a, "shared", "first", bytes.clone()).await?;
    let revalidated = b.verify(first.object(), first.content(), budget()?).await?;
    let mut stream = b.read(&revalidated, 3, 12, budget()?).await?;
    let mut range = Vec::new();
    while let Some(chunk) = stream.next().await {
        range.extend_from_slice(&chunk?);
    }
    assert_eq!(range, &bytes[3..12]);
    let target = a.target("race")?;
    let one = a.write(target.clone(), "one", content(b"one"))?;
    let two = b.write(target, "two", content(b"two"))?;
    let (left, right) = tokio::join!(
        a.put(&one, source(Bytes::from_static(b"one")), budget()?),
        b.put(&two, source(Bytes::from_static(b"two")), budget()?)
    );
    let chosen = match (left, right) {
        (Ok(Mutation::Confirmed(w)), Err(Error::Conflict)) => verified(w)?,
        (Err(Error::Conflict), Ok(Mutation::Confirmed(w))) => verified(w)?,
        other => return Err(format!("conditional race unexpected result: {other:?}").into()),
    };
    assert!(matches!(
        a.delete(chosen.object(), budget()?).await?,
        Mutation::Confirmed(())
    ));
    confirmed(a.delete(first.object(), budget()?).await?)?;
    assert!(matches!(
        a.inspect(first.object(), budget()?).await,
        Err(Error::Missing)
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn multipart_resume_exact_manifest_and_abort() -> TestResult {
    let f = Fixture::load()?;
    let a = f.store().await?;
    let b = f.store().await?;
    let first = Bytes::from(vec![b'a'; 5 * 1024 * 1024]);
    let last = Bytes::from_static(b"tail");
    let mut hash = Sha256::new();
    hash.update(&first);
    hash.update(&last);
    let write = a.write(
        a.target("multipart")?,
        "multipart",
        Content {
            length: (first.len() + last.len()) as u64,
            sha256: hash.finalize().into(),
        },
    )?;
    let upload = confirmed(a.begin(&write, budget()?).await?)?;
    let receipt = confirmed(
        a.part(&upload, 1, content(&first), source(first), budget()?)
            .await?,
    )?;
    let saved = serde_json::to_vec(&upload)?;
    drop(a);
    let resumed: Upload = serde_json::from_slice(&saved)?;
    let mut parts = match b.status(&resumed, budget()?).await? {
        UploadState::Active(parts) => parts,
        _ => return Err(Error::Missing.into()),
    };
    assert_eq!(parts, [receipt]);
    let tail = confirmed(
        b.part(&resumed, 2, content(&last), source(last), budget()?)
            .await?,
    )?;
    parts.push(tail);
    let object = verified(confirmed(b.complete(&resumed, &parts, budget()?).await?)?)?;
    assert!(matches!(
        b.status(&resumed, budget()?).await?,
        UploadState::Absent
    ));
    let abandoned = b.write(b.target("abandoned")?, "abandoned", content(b"bytes"))?;
    let original = confirmed(b.begin(&abandoned, budget()?).await?)?;
    let sibling = confirmed(b.begin(&abandoned, budget()?).await?)?;
    confirmed(b.abort(&original, budget()?).await?)?;
    assert!(matches!(
        b.status(&sibling, budget()?).await?,
        UploadState::Active(_)
    ));
    confirmed(b.abort(&sibling, budget()?).await?)?;
    confirmed(b.delete(object.object(), budget()?).await?)?;
    Ok(())
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn replaced_parts_never_complete_old_manifest() -> TestResult {
    let f = Fixture::load()?;
    let a = f.store().await?;
    let b = f.store().await?;
    let write = a.write(a.target("parts-race")?, "parts-race", content(b"first"))?;
    let upload = confirmed(a.begin(&write, budget()?).await?)?;
    let old = confirmed(
        a.part(
            &upload,
            1,
            content(b"first"),
            source(Bytes::from_static(b"first")),
            budget()?,
        )
        .await?,
    )?;
    confirmed(
        b.part(
            &upload,
            1,
            content(b"other"),
            source(Bytes::from_static(b"other")),
            budget()?,
        )
        .await?,
    )?;
    assert!(matches!(
        a.complete(&upload, &[old], budget()?).await,
        Err(Error::Conflict)
    ));
    confirmed(a.abort(&upload, budget()?).await?)?;
    Ok(())
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn permission_configuration_integrity_and_exact_delete() -> TestResult {
    let f = Fixture::load()?;
    let a = f.store().await?;
    let mut forbidden = f.config()?;
    forbidden.namespace = "forbidden".into();
    let denied = f.connect(forbidden, false).await?;
    let write = denied.write(denied.target("escape")?, "escape", content(b"x"))?;
    assert!(matches!(
        denied
            .put(&write, source(Bytes::from_static(b"x")), budget()?)
            .await,
        Err(Error::Denied)
    ));
    let mut unversioned = f.config()?;
    unversioned.bucket = "unversioned".into();
    assert!(
        matches!(f.connect(unversioned,false).await,Err(error) if error.downcast_ref::<Error>()==Some(&Error::Configuration))
    );
    let mut wrong_ca = f.config()?;
    wrong_ca.private_ca_pem = Some(b"not a CA".to_vec());
    assert!(f.connect(wrong_ca, false).await.is_err());
    let one = create(&a, "versions", "original", Bytes::from_static(b"original")).await?;
    let mismatch = Content {
        length: one.content().length,
        sha256: [0; 32],
    };
    assert!(matches!(
        a.verify(one.object(), mismatch, budget()?).await,
        Err(Error::Integrity)
    ));
    // Fixture administration installs another current version; the adapter still deletes only old.
    let root = f.config()?.client(f.secrets(true)?)?;
    let new = root
        .put_object()
        .bucket("content")
        .key(format!("{}/versions", f.namespace))
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"new-version",
        ))
        .send()
        .await?;
    let newer = a.object(
        a.target("versions")?,
        new.version_id().ok_or(Error::Integrity)?,
    )?;
    confirmed(a.delete(one.object(), budget()?).await?)?;
    assert!(matches!(
        a.inspect(one.object(), budget()?).await,
        Err(Error::Missing)
    ));
    assert_eq!(a.inspect(&newer, budget()?).await?.length, 11);
    confirmed(a.delete(&newer, budget()?).await?)?;
    // A missing bucket must remain configuration failure, even if HEAD returns generic 404.
    let absent = a.object(a.target("missing")?, "selected-version")?;
    assert!(matches!(
        a.inspect(&absent, budget()?).await,
        Err(Error::Missing)
    ));
    Ok(())
}

// Real reverse proxy; errors are injected only after a successful provider response is read.
// 1 PUT, 2 initiate, 3 complete, 4 part, 5 truncated GET, 6 incorrect Content-Range.
struct FaultProxy {
    endpoint: String,
    armed: Arc<AtomicU8>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl FaultProxy {
    async fn start(f: &Fixture) -> TestResult<Self> {
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(std::fs::read(
            f.string("certificate")?,
        )?))
        .collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(std::fs::read(
            f.string("key")?,
        )?))?
        .ok_or(Error::Configuration)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://localhost:{}", listener.local_addr()?.port());
        let upstream = f.string("endpoint")?.to_owned();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                f.string("ca")?,
            )?)?)
            .build()?;
        let armed = Arc::new(AtomicU8::new(0));
        let state = armed.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {value=listener.accept()=>value,_=children.join_next(),if !children.is_empty()=>continue};
                let Ok((socket, _)) = accepted else { break };
                let (acceptor, client, upstream, state) = (
                    acceptor.clone(),
                    client.clone(),
                    upstream.clone(),
                    state.clone(),
                );
                children.spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(move |request| {
                        forward(request, client.clone(), upstream.clone(), state.clone())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Ok(Self {
            endpoint,
            armed,
            task,
        })
    }
    fn arm(&self, code: u8) {
        self.armed.store(code, Ordering::SeqCst);
    }
}
async fn forward(
    request: hyper::Request<hyper::body::Incoming>,
    client: reqwest::Client,
    upstream: String,
    armed: Arc<AtomicU8>,
) -> TestResult<hyper::Response<axum::body::Body>> {
    let method = request.method().clone();
    let query = request.uri().query().unwrap_or("").to_owned();
    let is_get = method == "GET";
    let code = if method == "PUT" && query.contains("partNumber=") {
        4
    } else if method == "PUT" {
        1
    } else if method == "POST" && query.contains("uploadId=") {
        3
    } else if method == "POST" && query.contains("uploads") {
        2
    } else if is_get {
        armed.load(Ordering::SeqCst)
    } else {
        0
    };
    let path = request
        .uri()
        .path_and_query()
        .ok_or(Error::Input)?
        .as_str()
        .to_owned();
    let headers = request.headers().clone();
    let body =
        reqwest::Body::wrap_stream(axum::body::Body::new(request.into_body()).into_data_stream());
    let response = client
        .request(method, upstream + &path)
        .headers(headers)
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let mut headers = response.headers().clone();
    let mut bytes = response.bytes().await?;
    if code != 0
        && status.is_success()
        && armed
            .compare_exchange(code, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        if code <= 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "response lost after provider effect",
            )
            .into());
        }
        if code == 5 && !bytes.is_empty() {
            bytes = bytes.slice(..bytes.len() - 1);
        }
        if code == 6 {
            headers.insert(
                "content-range",
                hyper::header::HeaderValue::from_static("bytes 0-1/2"),
            );
        }
    }
    let mut output = hyper::Response::new(axum::body::Body::from(bytes));
    *output.status_mut() = status;
    *output.headers_mut() = headers;
    Ok(output)
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn actual_write_response_loss_and_stream_failures() -> TestResult {
    let f = Fixture::load()?;
    let proxy = FaultProxy::start(&f).await?;
    let mut config = f.config()?;
    config.endpoint = proxy.endpoint.clone();
    let a = f.connect(config, false).await?;
    let write = a.write(
        a.target("lost-put")?,
        "lost-put",
        content(b"persisted bytes"),
    )?;
    proxy.arm(1);
    assert!(matches!(
        a.put(
            &write,
            source(Bytes::from_static(b"persisted bytes")),
            budget()?
        )
        .await?,
        Mutation::Unknown(_)
    ));
    let recovered = match a.recover(&write, budget()?).await? {
        Recovery::Matched(w) => verified(w)?,
        _ => return Err(Error::Integrity.into()),
    };
    let wrong_operation = a.write(
        write.target().clone(),
        "different-operation",
        write.content(),
    )?;
    assert!(matches!(
        a.recover(&wrong_operation, budget()?).await?,
        Recovery::Unresolved
    ));
    proxy.arm(6);
    assert!(matches!(
        a.read(&recovered, 1, 5, budget()?).await,
        Err(Error::Integrity)
    ));
    proxy.arm(5);
    match a
        .read(&recovered, 0, recovered.content().length, budget()?)
        .await
    {
        Ok(mut stream) => {
            let mut failed = false;
            while let Some(chunk) = stream.next().await {
                if chunk.is_err() {
                    failed = true;
                }
            }
            assert!(failed);
        }
        Err(error) => assert!(matches!(error, Error::Transient | Error::Integrity)),
    }
    confirmed(a.delete(recovered.object(), budget()?).await?)?;
    Ok(())
}

#[tokio::test]
#[ignore = "real RustFS TLS fixture, run make t2 MODULE=content.s3"]
async fn lost_initiation_part_and_complete_preserve_original_identity() -> TestResult {
    let f = Fixture::load()?;
    let proxy = FaultProxy::start(&f).await?;
    let mut config = f.config()?;
    config.endpoint = proxy.endpoint.clone();
    let a = f.connect(config.clone(), false).await?;
    let write = a.write(
        a.target("lost-multipart")?,
        "lost-multipart",
        content(b"complete bytes"),
    )?;
    proxy.arm(2);
    assert!(matches!(
        a.begin(&write, budget()?).await?,
        Mutation::Unknown(_)
    ));
    let found = a.candidates(write.target(), budget()?).await?;
    assert_eq!(found.ids.len(), 1);
    // Explicit selection, not automatic adapter adoption.
    let upload = a.upload(write.clone(), &found.ids[0])?;
    proxy.arm(4);
    assert!(matches!(
        a.part(
            &upload,
            1,
            write.content(),
            source(Bytes::from_static(b"complete bytes")),
            budget()?
        )
        .await?,
        Mutation::Unknown(_)
    ));
    let b = f.connect(config, false).await?;
    let parts = match b.status(&upload, budget()?).await? {
        UploadState::Active(parts) => parts,
        _ => return Err(Error::Missing.into()),
    };
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].sha256(), write.content().sha256);
    proxy.arm(3);
    assert!(matches!(
        b.complete(&upload, &parts, budget()?).await?,
        Mutation::Unknown(_)
    ));
    assert!(matches!(
        b.status(&upload, budget()?).await?,
        UploadState::Absent
    ));
    let object = match b.recover(&write, budget()?).await? {
        Recovery::Matched(w) => verified(w)?,
        _ => return Err(Error::Integrity.into()),
    };
    confirmed(b.delete(object.object(), budget()?).await?)?;
    Ok(())
}
