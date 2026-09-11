//! TLS termination and peer evidence belong to the product listener.
//! ref: rustls 0.23.44 server/builder.rs; hyper 1.11.1 server/conn/http1.rs.
use super::{TlsEndpoint, TlsRouter};
use crate::{
    AccessStore, ConfigIssue, Error,
    audit::{Audit, FailureReason},
};
use axum::{Extension, Router};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError};
use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
        server::danger::ClientCertVerifier,
    },
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(super) struct Peer {
    chain: Arc<Vec<CertificateDer<'static>>>,
}
impl Peer {
    pub(super) fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}
pub(super) fn configuration(
    endpoint: &TlsEndpoint,
    client: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<Arc<rustls::ServerConfig>, Error> {
    let build = || {
        let certs = crate::config::read(&endpoint.certificate_file, 128 * 1024, false)?;
        let certs = CertificateDer::pem_slice_iter(&certs)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Malformed)?;
        if certs.is_empty() || certs.len() > 4 {
            return Err(Error::Malformed);
        }
        let key = crate::config::read(&endpoint.private_key_file, 32768, true)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| Error::Malformed)?;
        let builder = match client {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        let mut config = builder
            .with_single_cert(certs, key)
            .map_err(|_| Error::Malformed)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Full client-certificate authentication on every connection; per-request validity is rechecked too.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Arc::new(config))
    };
    build().map_err(|_| Error::Configuration(ConfigIssue::WindowsTls))
}
pub(crate) fn registration(
    listener: tokio::net::TcpListener,
    app: TlsRouter,
    access: Arc<AccessStore>,
    tenant: String,
    name: &'static str,
) -> ManagedTaskRegistration {
    let (start, _) = ManagedTask::prepare(name, Duration::from_secs(10));
    start.into_registration(move |token| serve(listener, app, access, tenant, name, token))
}
pub(super) async fn serve(
    listener: tokio::net::TcpListener,
    app: TlsRouter,
    access: Arc<AccessStore>,
    tenant: String,
    name: &'static str,
    token: CancellationToken,
) -> Result<(), ShutdownError> {
    let acceptor = TlsAcceptor::from(app.tls);
    let mut peers = FuturesUnordered::new();
    loop {
        tokio::select! {
            biased;
            ()=token.cancelled()=>break,
            Some(result)=peers.next(),if !peers.is_empty()=>{ report(name,result); },
            accepted=listener.accept(),if peers.len()<128=>{
                let (stream,_)=accepted.map_err(ShutdownError::new)?;
                peers.push(guarded_connection(connection(stream,acceptor.clone(),app.router.clone(),token.clone(),access.clone(),tenant.clone(),name)));
            }
        }
    }
    drop(listener);
    while let Some(result) = peers.next().await {
        report(name, result);
    }
    Ok(())
}
async fn connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    router: Router,
    token: CancellationToken,
    access: Arc<AccessStore>,
    tenant: String,
    name: &'static str,
) -> Result<(), ConnectionFailure> {
    let handshake = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream));
    let stream = tokio::select! {
        biased;
        ()=token.cancelled()=>return Ok(()),
        result=handshake=>match result {
            Ok(Ok(stream))=>stream,
            _=>{
                let audit=Audit::new(tenant,if name=="mdm-management-tls" { "windows_management" } else { "protected_request" });
                let failed=!matches!(tokio::time::timeout(Duration::from_secs(2),access.record(&audit,401,"denied")).await,Ok(Ok(())));
                audit.finalize(failed.then_some(FailureReason::Persistent));
                return Ok(());
            }
        }
    };
    let peer = Peer {
        chain: Arc::new(
            stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap_or_default()
                .to_vec(),
        ),
    };
    let router = router.layer(Extension(peer));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(64)
        .max_buf_size(32768);
    let connection =
        builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router));
    tokio::pin!(connection);
    tokio::select! {
        biased;
        ()=token.cancelled()=>{ connection.as_mut().graceful_shutdown(); connection.await.map_err(classify) },
        result=&mut connection=>result.map_err(classify),
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConnectionFailure {
    Timeout,
    Parse,
    Io,
    Panic,
}
fn classify(error: hyper::Error) -> ConnectionFailure {
    if error.is_timeout() {
        ConnectionFailure::Timeout
    } else if error.is_parse() {
        ConnectionFailure::Parse
    } else {
        ConnectionFailure::Io
    }
}
type ConnectionResult = std::thread::Result<Result<(), ConnectionFailure>>;
async fn guarded_connection(
    future: impl std::future::Future<Output = Result<(), ConnectionFailure>>,
) -> ConnectionResult {
    AssertUnwindSafe(future).catch_unwind().await
}
fn event(name: &str, result: ConnectionResult) -> Option<serde_json::Value> {
    let kind = match result {
        Ok(Ok(())) => return None,
        Ok(Err(kind)) => kind,
        Err(_) => ConnectionFailure::Panic,
    };
    Some(serde_json::json!({"event":"mdm_tls_connection_failure","listener":name,"kind":kind}))
}
fn report(name: &str, result: ConnectionResult) {
    if let Some(event) = event(name, result) {
        eprintln!("{event}");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn connection_diagnostics_classify_actual_hyper_errors_without_payloads() {
        use tokio::io::AsyncWriteExt;
        for (bytes, expected) in [
            (
                b"malformed-secret\r\n\r\n".as_slice(),
                ConnectionFailure::Parse,
            ),
            (b"".as_slice(), ConnectionFailure::Timeout),
        ] {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(bytes).await.unwrap();
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(5));
            let error = builder
                .serve_connection(
                    TokioIo::new(server),
                    TowerToHyperService::new(Router::new()),
                )
                .await
                .unwrap_err();
            let failure = classify(error);
            assert_eq!(failure, expected);
            let value = event("mdm-management-tls", Ok(Err(failure))).unwrap();
            assert_eq!(value["listener"], "mdm-management-tls");
            assert!(!value.to_string().contains("secret"));
        }
    }
    #[tokio::test]
    async fn actual_connection_panic_never_logs_payload() {
        if std::env::var_os("MDM_PANIC_DIAGNOSTIC_CHILD").is_some() {
            crate::install_panic_diagnostics();
            let result = guarded_connection(async {
                std::panic::panic_any("synthetic-secret");
            })
            .await;
            report("mdm-enrollment-tls", result);
            return;
        }
        // A separate test process isolates the global hook from other test threads.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::tls::tests::actual_connection_panic_never_logs_payload",
                "--nocapture",
            ])
            .env("MDM_PANIC_DIAGNOSTIC_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("synthetic-secret"));
        assert!(stderr.contains("mdm_panic"));
        assert!(stderr.contains("\"listener\":\"mdm-enrollment-tls\""));
        assert!(stderr.contains("\"kind\":\"panic\""));
    }
}
