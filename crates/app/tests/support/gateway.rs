//! Completed TLS possession for protocol participants. No public listener configuration exists in Rust.
//! The production gateway adapter has separate actual Nginx integration coverage.
use rss_axum::{AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport};
use rss_mdm_certificate::{ClientCertificateEvidence, GatewayConnection};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
/// Combine the two complete hosts only for controlled in-process business fixtures.
/// Dispatch happens above both nested routers, matching production's protocol separation.
pub(crate) fn browser_agent(
    browser: axum::Router,
    agent: axum::Router,
    console_host: &str,
) -> axum::Router {
    use tower::ServiceExt;
    let console_host = console_host.to_owned();
    axum::Router::new().fallback(move |request: axum::extract::Request| {
        let public_package = request
            .uri()
            .path()
            .strip_prefix("/api/v1/agent/enroll/packages")
            .is_some_and(|p| p.is_empty() || p.starts_with('/'));
        let console_package = public_package
            && request.headers().get("host").and_then(|h| h.to_str().ok())
                == Some(console_host.as_str());
        let target = if request.uri().path().starts_with("/api/v1/agent/") && !console_package {
            agent.clone()
        } else {
            browser.clone()
        };
        async move {
            target
                .oneshot(request)
                .await
                .unwrap_or_else(|never| match never {})
        }
    })
}

#[derive(Clone)]
struct Metadata {
    certificate: Option<ClientCertificateEvidence>,
    source: IpAddr,
    gateway: GatewayConnection,
}
struct Transport(tokio_rustls::TlsAcceptor);
impl ConnectionTransport for Transport {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Metadata = Metadata;
    type Guard = ();
    type Error = anyhow::Error;
    async fn prepare(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error> {
        let gateway = GatewayConnection::from_stream(&stream, "127.0.0.1".parse()?)?;
        let io = self.0.accept(stream).await?;
        let certificate = ClientCertificateEvidence::from_completed_tls(io.get_ref().1).ok();
        Ok(EstablishedTransport::new(
            io,
            Metadata {
                certificate,
                source: peer.ip(),
                gateway,
            },
            (),
        ))
    }
}
pub(crate) async fn registration(
    listener: TcpListener,
    channel: crate::native::ChannelRouter,
    _audit: Arc<rss_mdm_audit_integration::AuditStore>,
    _tenant: String,
    kind: crate::native::ChannelKind,
) -> anyhow::Result<rss_runtime::ManagedTaskRegistration> {
    use crate::native::ChannelKind::*;
    let (variable, key) = match kind {
        Agent => ("MDM_AGENT_PKI_FIXTURES", "agent-tls.pk8"),
        WindowsEnrollment | WindowsManagement => ("MDM_WINDOWS_FIXTURES", "windows-tls.pk8"),
        _ => ("MDM_APPLE_FIXTURES", "apple-tls.pk8"),
    };
    let root = std::path::PathBuf::from(std::env::var(variable)?);
    let verifier: Option<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>> =
        if kind == WindowsEnrollment {
            None
        } else {
            Some(Arc::new(super::tls::Possession))
        };
    let tls = super::tls::server(&root, key, verifier)?;
    let origin = channel
        .origins
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("fixture origin missing"))?;
    let router = channel.router.layer(axum::middleware::from_fn(
        move |mut request: axum::extract::Request, next: axum::middleware::Next| {
            let admission = channel.admission.clone();
            let origin = origin.clone();
            async move {
                let Some(info) = request
                    .extensions()
                    .get::<AcceptedConnectionInfo<Metadata>>()
                    .map(|i| i.metadata().clone())
                else {
                    return axum::http::StatusCode::FORBIDDEN.into_response();
                };
                if let Some(cert) = info.certificate {
                    request.extensions_mut().insert(cert);
                }
                request
                    .extensions_mut()
                    .insert(info.gateway.request_origin(origin));
                request
                    .extensions_mut()
                    .insert(rss_identity_http_axum::ClientAddress(info.source));
                let Some(gate) = admission.gate(info.source) else {
                    return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
                };
                request.extensions_mut().insert(gate);
                next.run(request).await
            }
        },
    ));
    Ok(rss_axum::serve_http1_registration(
        listener,
        router,
        Transport(tokio_rustls::TlsAcceptor::from(Arc::new(tls))),
        "fixture-protocol-gateway",
        crate::lifecycle::http_policy(),
    ))
}
use axum::response::IntoResponse;

/// External TLS carrier for production process tests; forwards real possession to its private HTTP ingress.
pub(crate) fn proxy(
    listener: TcpListener,
    target: SocketAddr,
    root: std::path::PathBuf,
    origin: String,
    key_file: &str,
) -> anyhow::Result<rss_runtime::ManagedTaskRegistration> {
    let tls = super::tls::server(&root, key_file, Some(Arc::new(super::tls::Possession)))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let router = axum::Router::new().fallback(move |mut request: axum::extract::Request| {
        let client = client.clone();
        let origin = origin.clone();
        async move {
            let result = async {
                let info = request
                    .extensions()
                    .get::<AcceptedConnectionInfo<Metadata>>()
                    .ok_or_else(|| anyhow::anyhow!("missing real connection"))?
                    .metadata()
                    .clone();
                for name in [
                    "connection",
                    "host",
                    "cookie",
                    "forwarded",
                    "x-rss-public-origin",
                    "x-rss-client-cert",
                    "x-forwarded-for",
                ] {
                    request.headers_mut().remove(name);
                }
                let certificate = if let Some(cert) = info.certificate {
                    let pem = openssl::x509::X509::from_der(cert.chain()[0].as_ref())?.to_pem()?;
                    pem.iter().map(|b| format!("%{b:02X}")).collect::<String>()
                } else {
                    String::new()
                };
                let url = format!("http://{target}{}", request.uri());
                let outgoing = client
                    .request(request.method().clone(), url)
                    .headers(request.headers().clone())
                    .header(
                        "host",
                        origin
                            .strip_prefix("https://")
                            .ok_or_else(|| anyhow::anyhow!("origin"))?,
                    )
                    .header("x-rss-public-origin", origin)
                    .header("x-rss-client-cert", certificate)
                    .header("x-forwarded-for", info.source.to_string());
                let body = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024).await?;
                let response = outgoing.body(body).send().await?;
                let mut result = axum::response::Response::builder().status(response.status());
                *result.headers_mut().unwrap() = response.headers().clone();
                anyhow::Ok(result.body(axum::body::Body::from(response.bytes().await?))?)
            }
            .await;
            result.unwrap_or_else(|_| axum::http::StatusCode::BAD_GATEWAY.into_response())
        }
    });
    Ok(rss_axum::serve_http1_registration(
        listener,
        router,
        Transport(tokio_rustls::TlsAcceptor::from(Arc::new(tls))),
        "fixture-process-gateway",
        crate::lifecycle::http_policy(),
    ))
}
