//! Handshake provenance is distinct from a channel's certificate authorization.
//! ref: tokio-rustls src/server.rs@4f913c754aa4171440e50ceb6a160ceebb0d326e
use crate::Error;
use std::sync::Arc;
use tokio_rustls::rustls::{ServerConnection, pki_types::CertificateDer};

#[derive(Clone)]
pub struct HandshakePeer {
    chain: Arc<[CertificateDer<'static>]>,
}
impl HandshakePeer {
    pub fn from_completed_tls(connection: &ServerConnection) -> Result<Self, Error> {
        if connection.is_handshaking() {
            return Err(Error::Unauthorized);
        }
        let chain = connection
            .peer_certificates()
            .filter(|c| !c.is_empty())
            .ok_or(Error::Unauthorized)?;
        Ok(Self {
            chain: Arc::from(chain),
        })
    }
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}

#[cfg(test)]
#[path = "../tests/peer.rs"]
mod tests;
