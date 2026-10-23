//! TLS participants for external providers and native protocol fixtures only.
//! Product ingress is tested separately against the production Nginx renderer.
use std::{path::Path, sync::Arc};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
pub(crate) fn server(
    root: &Path,
    key: &str,
    verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> anyhow::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?;
    let builder = if let Some(verifier) = verifier {
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(
        CertificateDer::pem_slice_iter(&std::fs::read(root.join("server.crt"))?)
            .collect::<Result<Vec<_>, _>>()?,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(root.join(key))?)),
    )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
/// Like optional_no_ca, this fixture proves possession only. Domain handlers verify trust.
#[derive(Debug)]
pub(crate) struct Possession;
impl rustls::server::danger::ClientCertVerifier for Possession {
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        s: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            s,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        s: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            s,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
