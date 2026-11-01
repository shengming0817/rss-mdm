//! Actual TLS possession is projected from rustls after the configured DA trust verifier succeeds.
//! ref: rustls v0.23.35 rustls/src/verify.rs ClientCertVerifier.
use crate::Services;
use axum::extract::{ConnectInfo, connect_info::Connected};
use rss_mdm_certificate::ClientCertificateEvidence;
use std::{sync::Arc, time::Duration};
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
impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("authenticated", &self.0.is_some())
            .finish()
    }
}
struct Listener {
    tcp: TcpListener,
    tls: TlsAcceptor,
    handshakes: tokio::task::JoinSet<Option<(TlsStream<TcpStream>, Peer)>>,
}
impl axum::serve::Listener for Listener {
    type Io = TlsStream<TcpStream>;
    type Addr = Peer;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                ready = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    if let Some(Ok(Some(connection))) = ready { return connection; }
                }
                accepted = self.tcp.accept(), if self.handshakes.len() < 64 => {
                    let Ok((tcp, _)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let acceptor = self.tls.clone();
                    self.handshakes.spawn(async move {
                        let tls = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await.ok()?.ok()?;
                        let peer = ClientCertificateEvidence::from_tls(&tls).ok()?;
                        Some((tls, Peer(peer)))
                    });
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(Peer(None))
    }
}
impl Connected<axum::serve::IncomingStream<'_, Listener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        stream.remote_addr().clone()
    }
}
/// The listener uses the registration owner's live certificate verifier, including bootstrap without mTLS.
pub async fn serve(
    tcp: TcpListener,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    services: Arc<Services>,
) -> std::io::Result<()> {
    let config = ServerConfig::builder()
        .with_client_cert_verifier(services.registrations.trust().enrollment_verifier())
        .with_single_cert(certificates, key)
        .map_err(std::io::Error::other)?;
    let router = crate::router(services)
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Da)
        .layer(axum::middleware::from_fn(
            |ConnectInfo(peer): ConnectInfo<Peer>,
             mut request: axum::extract::Request,
             next: axum::middleware::Next| async move {
                if let Some(evidence) = peer.0 {
                    request.extensions_mut().insert(evidence);
                }
                next.run(request).await
            },
        ));
    axum::serve(
        Listener {
            tcp,
            tls: TlsAcceptor::from(Arc::new(config)),
            handshakes: tokio::task::JoinSet::new(),
        },
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .await
}
