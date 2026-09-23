//! Product TLS preparation; RSS exclusively owns accepted IO and HTTP lifecycle.
//! ref: rustls/tokio-rustls src/server.rs@4f913c754aa4171440e50ceb6a160ceebb0d326e
use super::{
    TlsEndpoint, TlsRouter,
    admission::{Admission, ConnectionPermit, RequestGate},
};
use crate::{
    AccessStore, ConfigIssue, Error,
    audit::{Audit, FailureReason},
};
use axum::{
    Extension,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use rss_axum::{AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport};
use rss_runtime::ManagedTaskRegistration;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
        server::danger::ClientCertVerifier,
    },
    server::TlsStream,
};

#[derive(Clone)]
pub(crate) struct Peer {
    chain: Arc<Vec<CertificateDer<'static>>>,
}
impl Peer {
    pub(crate) fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}
pub(crate) fn configuration(
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
    build().map_err(|_| Error::Configuration(ConfigIssue::NativeTls))
}
pub(crate) fn registration(
    listener: TcpListener,
    app: TlsRouter,
    access: Arc<AccessStore>,
    tenant: String,
    kind: super::NativeListenerKind,
) -> ManagedTaskRegistration {
    rss_axum::serve_http1_registration(
        listener,
        app.router.layer(middleware::from_fn(evidence)),
        TlsTransport {
            acceptor: TlsAcceptor::from(app.tls),
            admission: app.admission,
            access,
            tenant,
            kind,
        },
        kind.name(),
        crate::lifecycle::http_policy(),
    )
}

// Only this product adapter projects RSS-bound preparation metadata into handler inputs.
async fn evidence(
    Extension(info): Extension<AcceptedConnectionInfo<(Peer, RequestGate)>>,
    mut request: Request,
    next: Next,
) -> Response {
    let (peer, gate) = info.metadata();
    request.extensions_mut().insert(peer.clone());
    request.extensions_mut().insert(gate.clone());
    next.run(request).await
}

struct TlsTransport {
    acceptor: TlsAcceptor,
    admission: Arc<Admission>,
    access: Arc<AccessStore>,
    tenant: String,
    kind: super::NativeListenerKind,
}
impl ConnectionTransport for TlsTransport {
    type Io = TlsStream<TcpStream>;
    type Metadata = (Peer, RequestGate);
    type Guard = ConnectionPermit;
    type Error = ConnectionFailure;

    async fn prepare(
        &self,
        stream: TcpStream,
        socket_peer: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error> {
        // Capacity refusal is reported by Admission; it performs no TLS or PG work.
        let permit = self
            .admission
            .connection(socket_peer.ip())
            .ok_or(ConnectionFailure::Capacity)?;
        let stream = match tokio::time::timeout(
            Duration::from_secs(5),
            self.acceptor.accept(stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            failed => {
                let kind = match failed {
                    Err(_) => ConnectionFailure::HandshakeTimeout,
                    Ok(Err(error)) => classify_tls(&error),
                    Ok(Ok(_)) => unreachable!("successful handshake handled above"),
                };
                // Emit before the bounded audit so cancellation cannot hide the diagnosed failure.
                eprintln!("{}", event(self.kind.name(), kind));
                let audit = Audit::new(self.tenant.clone(), self.kind.audit_action());
                let failed = !matches!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        self.access.record(&audit, 401, "denied")
                    )
                    .await,
                    Ok(Ok(()))
                );
                audit.finalize(failed.then_some(FailureReason::Persistent));
                return Err(kind);
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
        // The move-only permit goes to RSS; cloned request metadata never owns its lifetime.
        let gate = permit.gate();
        Ok(EstablishedTransport::new(stream, (peer, gate), permit))
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConnectionFailure {
    Capacity,
    HandshakeTimeout,
    HandshakeProtocol,
    ClientCertificate,
}
fn classify_tls(error: &std::io::Error) -> ConnectionFailure {
    match error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented) => {
            ConnectionFailure::ClientCertificate
        }
        _ => ConnectionFailure::HandshakeProtocol,
    }
}
fn event(name: &str, kind: ConnectionFailure) -> serde_json::Value {
    serde_json::json!({"event":"mdm_tls_connection_failure","listener":name,"kind":kind})
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::verify_tls_lifecycle;
