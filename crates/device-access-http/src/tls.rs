//! DA TLS preparation delegates connection capacity, HTTP budgets and drain to RSS.
//! ref: rss aa7d4d72a06046691a07237c63a336d8100e9900 crates/axum/src/server.rs.
use crate::Services;
use axum::Extension;
use rss_axum::{AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport};
use rss_mdm_certificate::ClientCertificateEvidence;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
    server::TlsStream,
};
#[derive(Clone)]
struct Peer(Option<ClientCertificateEvidence>);
struct Transport(TlsAcceptor);
impl ConnectionTransport for Transport {
    type Io = TlsStream<TcpStream>;
    type Metadata = Peer;
    type Guard = ();
    type Error = std::io::Error;
    async fn prepare(
        &self,
        tcp: TcpStream,
        _: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Peer, ()>, Self::Error> {
        let tls = self.0.accept(tcp).await?;
        let peer = ClientCertificateEvidence::from_tls(&tls).map_err(std::io::Error::other)?;
        Ok(EstablishedTransport::new(tls, Peer(peer), ()))
    }
}
/// Prepare a managed listener using the live registration verifier, including anonymous bootstrap.
/// The host supplies validated capacity, TLS/establishment/header budgets and drain policy.
/// RSS retains each connection from TCP acceptance through HTTP completion and shutdown.
pub fn registration(
    tcp: TcpListener,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    services: Arc<Services>,
    policy: rss_axum::Http1ServePolicy,
) -> std::io::Result<rss_runtime::ManagedTaskRegistration> {
    let config = ServerConfig::builder()
        .with_client_cert_verifier(services.registrations.trust().enrollment_verifier())
        .with_single_cert(certificates, key)
        .map_err(std::io::Error::other)?;
    let router = crate::router(services)
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Da)
        .layer(axum::middleware::from_fn(
            |Extension(info): Extension<AcceptedConnectionInfo<Peer>>,
             mut request: axum::extract::Request,
             next: axum::middleware::Next| async move {
                if let Some(evidence) = &info.metadata().0 {
                    request.extensions_mut().insert(evidence.clone());
                }
                next.run(request).await
            },
        ));
    Ok(rss_axum::serve_http1_registration(
        tcp,
        router,
        Transport(TlsAcceptor::from(Arc::new(config))),
        "da-http",
        policy,
    ))
}

/// Browser TLS has a separate boundary and never treats a Cookie as device authentication.
pub fn browser(
    tcp: TcpListener,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    router: axum::Router,
    policy: rss_axum::Http1ServePolicy,
) -> std::io::Result<rss_runtime::ManagedTaskRegistration> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(std::io::Error::other)?;
    let router = router.layer(axum::middleware::from_fn(
        |Extension(info): Extension<AcceptedConnectionInfo<Peer>>,
         mut request: axum::extract::Request,
         next: axum::middleware::Next| async move {
            request
                .extensions_mut()
                .insert(rss_identity_http_axum::ClientAddress(
                    info.socket_peer().ip(),
                ));
            next.run(request).await
        },
    ));
    Ok(rss_axum::serve_http1_registration(
        tcp,
        router,
        Transport(TlsAcceptor::from(Arc::new(config))),
        "da-browser",
        policy,
    ))
}
