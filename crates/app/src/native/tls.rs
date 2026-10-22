//! Product TLS preparation; RSS exclusively owns accepted IO and HTTP lifecycle.
//! ref: rustls/tokio-rustls src/server.rs@4f913c754aa4171440e50ceb6a160ceebb0d326e
use super::{
    TlsEndpoint, TlsRouter,
    admission::{Admission, ConnectionPermit, RequestGate},
};
use crate::{ConfigIssue, Error};
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

use rss_mdm_certificate::HandshakePeer;
/// The exact certificate interval travels with the loaded TLS configuration.
/// ref: rustls src/webpki/verify.rs@v/0.23.46 (verify_server_name).
pub(crate) struct Configuration {
    server: Arc<rustls::ServerConfig>,
    validity: std::ops::Range<i64>,
}
impl Configuration {
    #[cfg(test)]
    pub(crate) fn fixture_server(&self) -> rustls::ServerConfig {
        (*self.server).clone()
    }

    pub(crate) fn with_client_verifier(
        &self,
        verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<Arc<Self>, Error> {
        let config =
            rustls::ServerConfig::builder_with_provider(self.server.crypto_provider().clone())
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| Error::Configuration(ConfigIssue::NativeTls))?
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(self.server.cert_resolver.clone());
        Ok(Arc::new(Self {
            server: server_policy(config),
            validity: self.validity.clone(),
        }))
    }
    pub(crate) fn valid_at(&self, now: i64) -> bool {
        self.validity.contains(&now)
    }
}
fn server_policy(mut config: rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Arc::new(config)
}
fn validity(
    certs: &[CertificateDer<'_>],
    endpoint: &TlsEndpoint,
) -> Result<std::ops::Range<i64>, Error> {
    use x509_cert::der::Decode;
    let origin = url::Url::parse(&endpoint.origin).map_err(|_| Error::Malformed)?;
    let name = rustls::pki_types::ServerName::try_from(origin.host_str().ok_or(Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    let leaf =
        rustls::server::ParsedCertificate::try_from(&certs[0]).map_err(|_| Error::Malformed)?;
    rustls::client::verify_server_name(&leaf, &name).map_err(|_| Error::Malformed)?;
    let mut interval = 0..i64::MAX;
    for der in certs {
        let cert = x509_cert::Certificate::from_der(der.as_ref()).map_err(|_| Error::Malformed)?;
        let v = cert.tbs_certificate.validity;
        interval.start = interval.start.max(
            i64::try_from(v.not_before.to_unix_duration().as_secs())
                .map_err(|_| Error::Malformed)?,
        );
        interval.end = interval.end.min(
            i64::try_from(v.not_after.to_unix_duration().as_secs())
                .map_err(|_| Error::Malformed)?,
        );
    }
    if !interval.contains(&time::OffsetDateTime::now_utc().unix_timestamp()) {
        return Err(Error::Malformed);
    }
    Ok(interval)
}
pub(crate) fn configuration(
    endpoint: &TlsEndpoint,
    client: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<Arc<Configuration>, Error> {
    let build = || {
        let certs = crate::config::read(&endpoint.certificate_file, 128 * 1024, false)?;
        let certs = CertificateDer::pem_slice_iter(&certs)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Malformed)?;
        if certs.is_empty() || certs.len() > 4 {
            return Err(Error::Malformed);
        }
        let validity = validity(&certs, endpoint)?;
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
        let config = builder
            .with_single_cert(certs, key)
            .map_err(|_| Error::Malformed)?;
        Ok(Arc::new(Configuration {
            server: server_policy(config),
            validity,
        }))
    };
    build().map_err(|error| match error {
        Error::Configuration(
            ConfigIssue::FileAccess | ConfigIssue::FileShape | ConfigIssue::FileSize,
        ) => error,
        _ => Error::Configuration(ConfigIssue::NativeTls),
    })
}
pub(crate) fn registration(
    listener: TcpListener,
    app: TlsRouter,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: String,
    kind: super::NativeListenerKind,
    gateway: std::net::IpAddr,
) -> ManagedTaskRegistration {
    let router = if kind == super::NativeListenerKind::Agent {
        app.router
            .layer(middleware::from_fn(super::admission::admit_agent))
    } else {
        app.router
    };
    rss_axum::serve_http1_registration(
        listener,
        router.layer(middleware::from_fn(evidence)),
        TlsTransport {
            acceptor: TlsAcceptor::from(app.tls.server.clone()),
            configuration: app.tls,
            admission: app.admission,
            audit_store,
            tenant,
            kind,
            gateway,
        },
        kind.name(),
        crate::lifecycle::http_policy(),
    )
}

// Only this product adapter projects RSS-bound preparation metadata into handler inputs.
async fn evidence(
    Extension(info): Extension<AcceptedConnectionInfo<(Option<HandshakePeer>, RequestGate)>>,
    mut request: Request,
    next: Next,
) -> Response {
    let (peer, gate) = info.metadata();
    if let Some(peer) = peer {
        request.extensions_mut().insert(peer.clone());
    }
    request.extensions_mut().insert(gate.clone());
    next.run(request).await
}

struct TlsTransport {
    configuration: Arc<Configuration>,
    acceptor: TlsAcceptor,
    admission: Arc<Admission>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: String,
    kind: super::NativeListenerKind,
    gateway: std::net::IpAddr,
}
impl ConnectionTransport for TlsTransport {
    type Io = TlsStream<TcpStream>;
    type Metadata = (Option<HandshakePeer>, RequestGate);
    type Guard = ConnectionPermit;
    type Error = ConnectionFailure;

    async fn prepare(
        &self,
        mut stream: TcpStream,
        socket_peer: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error> {
        let source = super::proxy::source(&mut stream, socket_peer, self.gateway)
            .await
            .map_err(|_| ConnectionFailure::Gateway)?;
        if !self
            .configuration
            .valid_at(time::OffsetDateTime::now_utc().unix_timestamp())
        {
            return Err(ConnectionFailure::ServerCertificate);
        }
        // Capacity refusal is reported by Admission; it performs no TLS or PG work.
        let permit = self
            .admission
            .connection(source.ip())
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
                let audit = RequestAudit::new(self.tenant.clone(), self.kind.audit_action());
                let budget =
                    rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
                let control = budget.control();
                let failed = self
                    .audit_store
                    .settle_request(&audit, 401, "denied", &control)
                    .await
                    .is_err();
                audit.finalize(failed.then_some(FailureReason::Persistent));
                return Err(kind);
            }
        };
        let peer = HandshakePeer::from_completed_tls(stream.get_ref().1).ok();
        // The move-only permit goes to RSS; cloned request metadata never owns its lifetime.
        let gate = permit.gate();
        Ok(EstablishedTransport::new(stream, (peer, gate), permit))
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConnectionFailure {
    Gateway,
    Capacity,
    HandshakeTimeout,
    HandshakeProtocol,
    ClientCertificate,
    ServerCertificate,
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
#[path = "../../tests/native/tls.rs"]
mod tests;

use rss_mdm_audit_integration::{FailureReason, RequestAudit};
