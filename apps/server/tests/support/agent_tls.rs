//! Real completed TLS proof shared by controlled Agent scenarios.
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_device_trust::agent::AgentTrust;
use std::{path::Path, sync::Arc, time::Duration};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
        },
    },
};
use x509_cert::der::{DecodePem, Encode};
pub(crate) async fn peer(
    trust: &AgentTrust,
    chain: &[Vec<u8>],
    root: &Path,
) -> anyhow::Result<ClientCertificateEvidence> {
    peer_with_key(trust, chain, root, "agent.pk8").await
}
pub(crate) async fn peer_with_key(
    trust: &AgentTrust,
    chain: &[Vec<u8>],
    root: &Path,
    key_file: &str,
) -> anyhow::Result<ClientCertificateEvidence> {
    peer_with_verifier(trust.verifier(), chain, root, key_file).await
}
pub(crate) async fn peer_with_verifier(
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    chain: &[Vec<u8>],
    root: &Path,
    key_file: &str,
) -> anyhow::Result<ClientCertificateEvidence> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certificates = CertificateDer::pem_slice_iter(&std::fs::read(root.join("server.crt"))?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
        root.join("agent-tls.pk8"),
    )?));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(
        x509_cert::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?.to_der()?,
    ))?;
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
                root.join(key_file),
            )?)),
        )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accept = async {
        let (stream, _) = listener.accept().await?;
        let tls = TlsAcceptor::from(Arc::new(server)).accept(stream).await?;
        Ok::<_, anyhow::Error>(ClientCertificateEvidence::from_completed_tls(
            tls.get_ref().1,
        )?)
    };
    let connect = async {
        let stream = tokio::net::TcpStream::connect(address).await?;
        Ok::<_, anyhow::Error>(
            TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("localhost")?, stream)
                .await?,
        )
    };
    let (peer, client) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(accept, connect)
    })
    .await?;
    client?;
    peer
}
