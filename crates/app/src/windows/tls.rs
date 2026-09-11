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
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
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
        let certs = rustls_pemfile::certs(&mut certs.as_slice())
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
            Some(_)=peers.next(),if !peers.is_empty()=>{},
            accepted=listener.accept(),if peers.len()<128=>{
                let (stream,_)=accepted.map_err(ShutdownError::new)?;
                peers.push(AssertUnwindSafe(connection(stream,acceptor.clone(),app.router.clone(),token.clone(),access.clone(),tenant.clone(),name)).catch_unwind());
            }
        }
    }
    drop(listener);
    while peers.next().await.is_some() {}
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
) {
    let handshake = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream));
    let stream = tokio::select! {
        biased;
        ()=token.cancelled()=>return,
        result=handshake=>match result {
            Ok(Ok(stream))=>stream,
            _=>{
                let audit=Audit::new(tenant,if name=="mdm-management-tls" { "windows_management" } else { "protected_request" });
                let failed=!matches!(tokio::time::timeout(Duration::from_secs(2),access.record(&audit,401,"denied")).await,Ok(Ok(())));
                audit.finalize(failed.then_some(FailureReason::Persistent));
                return;
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
        ()=token.cancelled()=>{ connection.as_mut().graceful_shutdown(); let _=connection.await; },
        _=&mut connection=>{},
    }
}
