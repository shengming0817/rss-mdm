//! A trusted gateway attests possession; each channel independently verifies certificate authority.
//! ref: nginx ngx_http_ssl_module.c ($ssl_client_escaped_cert), optional_no_ca external verification.
use crate::Error;
use std::{net::IpAddr, sync::Arc};
use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};

/// Only the configured gateway's real TCP connection can construct this capability.
/// The deployment must isolate that connection from clients and other workloads.
#[derive(Clone)]
pub struct GatewayConnection {
    _private: (),
}
impl GatewayConnection {
    /// Capture the actual socket peer before HTTP decoding. HTTP headers cannot supply this input.
    pub fn from_stream(stream: &tokio::net::TcpStream, expected: IpAddr) -> Result<Self, Error> {
        if expected.is_unspecified()
            || stream.peer_addr().map_err(|_| Error::Unauthorized)?.ip() != expected
        {
            return Err(Error::Unauthorized);
        }
        Ok(Self { _private: () })
    }

    /// Bind a request locator to this authenticated gateway connection.
    /// The HTTP adapter additionally validates its canonical spelling and allowed route.
    pub fn request_origin(&self, origin: String) -> GatewayOrigin {
        GatewayOrigin(origin)
    }

    /// Decode only a gateway-overwritten TLS certificate field. A raw certificate alone is not evidence.
    pub fn client_certificate(&self, escaped: &str) -> Result<ClientCertificateEvidence, Error> {
        if escaped.is_empty() || escaped.len() > 98_304 {
            return Err(Error::Unauthorized);
        }
        let pem = percent_encoding::percent_decode_str(escaped).collect::<Vec<_>>();
        if pem.len() > 32_768 {
            return Err(Error::Unauthorized);
        }
        let chain = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Unauthorized)?;
        if chain.len() != 1 {
            return Err(Error::Unauthorized);
        }
        Ok(ClientCertificateEvidence {
            chain: Arc::from(chain),
        })
    }
}

/// A public request origin attested by the configured gateway, never a device-supplied claim.
#[derive(Clone)]
pub struct GatewayOrigin(String);
impl GatewayOrigin {
    /// Exact public HTTPS origin projected by the ingress adapter.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Certificate possession attested by the validated ingress connection, not by request text.
/// This value does not establish tenant, purpose, certificate validity or current registration.
#[derive(Clone)]
pub struct ClientCertificateEvidence {
    chain: Arc<[CertificateDer<'static>]>,
}
impl ClientCertificateEvidence {
    /// Borrow the attested certificate for the exact channel's current trust verifier.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// Device/provider fixtures may capture real TLS possession without running a product gateway.
    #[cfg(any(test, feature = "integration"))]
    pub fn from_completed_tls(
        connection: &tokio_rustls::rustls::ServerConnection,
    ) -> Result<Self, Error> {
        if connection.is_handshaking() {
            return Err(Error::Unauthorized);
        }
        let chain = connection
            .peer_certificates()
            .filter(|v| !v.is_empty())
            .ok_or(Error::Unauthorized)?;
        Ok(Self {
            chain: Arc::from(chain),
        })
    }
}

#[cfg(test)]
#[path = "../tests/peer.rs"]
mod tests;
