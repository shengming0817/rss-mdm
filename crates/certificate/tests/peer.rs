use super::*;
use tokio_rustls::rustls;

#[test]
fn an_unfinished_connection_cannot_mint_handshake_evidence() {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    let connection = ServerConnection::new(Arc::new(config)).unwrap();
    assert!(matches!(
        HandshakePeer::from_completed_tls(&connection),
        Err(Error::Unauthorized)
    ));
}
