//! Actual anonymous TLS peers exercise the production RSS connection owner.
use super::{
    material::{Material, Server},
    *,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};
async fn connect(material: &Material, server: &Server) -> Result<TlsStream<TcpStream>> {
    connect_origin(material, &server.origin).await
}
async fn connect_origin(material: &Material, origin: &str) -> Result<TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(material.directory.join("task-trust-ca/ca.pem"))?
    {
        roots.add(certificate?)?;
    }
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let address = origin
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap();
    Ok(connector
        .connect(
            ServerName::try_from("localhost")?,
            TcpStream::connect(address).await?,
        )
        .await?)
}
pub async fn bounded_connections(material: &Material, server: &Server) -> Result<()> {
    let mut peers = Vec::new();
    // The host's four slots include established HTTP connections, not just TLS preparation.
    for _ in 0..4 {
        peers.push(tokio::time::timeout(Duration::from_secs(2), connect(material, server)).await??);
    }
    peers[0]
        .write_all(b"GET /api/v1/da/pki/trust HTTP/1.1\r\nHost:")
        .await?;
    let mut overflow = Box::pin(connect(material, server));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut overflow)
            .await
            .is_err()
    );
    // Closing one established connection releases its slot before the header deadline.
    drop(peers.pop());
    let overflow = tokio::time::timeout(Duration::from_secs(2), overflow).await??;
    // Incomplete headers must be disconnected by the configured three-second budget.
    let mut bytes = Vec::new();
    let _closed =
        tokio::time::timeout(Duration::from_secs(5), peers[0].read_to_end(&mut bytes)).await?;
    drop(overflow);
    drop(peers);
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        material
            .client(None)?
            .get(format!("{}/pki/trust", server.origin))
            .send(),
    )
    .await??;
    assert!(response.status().is_success());
    Ok(())
}

pub async fn slow_body(
    material: &Material,
    origin: &str,
    tenant: rss_request_context::TenantId,
) -> Result<()> {
    let mut peer = connect_origin(material, origin).await?;
    peer.write_all(format!("POST /api/v1/apple/platform-sso/{tenant}/token HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\na=",origin.trim_start_matches("https://")).as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), peer.read_to_end(&mut response)).await??;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 503"));
    Ok(())
}
