//! Ephemeral HTTPS destination for native provider and Webhook worker tests.
use anyhow::Result;
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
pub(crate) struct Listener(tokio::net::TcpListener, TlsAcceptor);
impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = self.0.accept().await.expect("fixture listener");
            if let Ok(tls) = self.1.accept(tcp).await {
                return (tls, addr);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
impl Listener {
    pub(crate) async fn open(dir: &Path) -> Result<Self> {
        let cert = CertificateDer::from_pem_file(dir.join("server.pem"))?;
        let key = PrivateKeyDer::from_pem_file(dir.join("server.key"))?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self(tcp, TlsAcceptor::from(Arc::new(tls))))
    }
    pub(crate) fn address(&self) -> Result<SocketAddr> {
        Ok(self.0.local_addr()?)
    }
}
