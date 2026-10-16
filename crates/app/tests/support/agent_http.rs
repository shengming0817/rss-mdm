//! HTTP over the actual Agent TLS listener.
use std::{path::PathBuf, sync::Arc};
fn root() -> PathBuf { PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES").unwrap()) }
pub(crate) type AgentHttp =
    tokio::io::BufReader<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
pub(crate) async fn connect_agent(
    address: std::net::SocketAddr,
    chain: Option<&[Vec<u8>]>,
) -> anyhow::Result<AgentHttp> {
    connect_agent_with_key(address, chain, "agent.pk8").await
}
pub(crate) async fn connect_agent_with_key(
    address: std::net::SocketAddr,
    chain: Option<&[Vec<u8>]>,
    key_file: &str,
) -> anyhow::Result<AgentHttp> {
    use tokio_rustls::{
        TlsConnector,
        rustls::{
            self,
            pki_types::{
                CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
            },
        },
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(root().join("ca.crt"))?) {
        roots.add(cert?)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let config = match chain {
        Some(chain) => builder.with_client_auth_cert(
            chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
                root().join(key_file),
            )?)),
        )?,
        None => builder.with_no_client_auth(),
    };
    let stream = tokio::net::TcpStream::connect(address).await?;
    Ok(tokio::io::BufReader::new(
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost")?, stream)
            .await?,
    ))
}
pub(crate) async fn agent_http(
    io: &mut AgentHttp,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<(u16, serde_json::Value)> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let body = body
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: mdm.example.test:9445\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    io.get_mut().write_all(head.as_bytes()).await?;
    io.get_mut().write_all(&body).await?;
    io.get_mut().flush().await?;
    let mut line = String::new();
    io.read_line(&mut line).await?;
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status"))?
        .parse()?;
    let mut length = None;
    loop {
        line.clear();
        anyhow::ensure!(
            io.read_line(&mut line).await? != 0,
            "truncated HTTP headers"
        );
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    if status == 204 {
        anyhow::ensure!(length.is_none_or(|n| n == 0), "204 must have no body");
        return Ok((status, serde_json::Value::Null));
    }
    let mut bytes = vec![0; length.ok_or_else(|| anyhow::anyhow!("missing HTTP content-length"))?];
    io.read_exact(&mut bytes).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

