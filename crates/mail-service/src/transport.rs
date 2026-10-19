//! 固定测试投递；RFC 3207 §4.2、RFC 4954、RFC 5321 §4.5.3.1。
//! TLS 后重新 EHLO；认证前不发送秘密；DATA 的未知结果不自动重投。
use crate::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tls {
    Implicit,
    Starttls,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub hostname: String,
    pub address: SocketAddr,
    pub tls: Tls,
    pub ca_pem: Vec<u8>,
}
pub struct Credentials {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}
pub(crate) fn mailbox(value: &str) -> Result<()> {
    let (local, domain) = value.split_once('@').ok_or(Error::Input)?;
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !domain.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::Input);
    }
    Ok(())
}
impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        if self.hostname.is_empty()
            || self.hostname.len() > 253
            || self.ca_pem.is_empty()
            || self.ca_pem.len() > 1024 * 1024
            || self.address.port() == 0
            || self.address.ip().is_unspecified()
            || self.address.ip().is_multicast()
            || !self.hostname.split('.').all(|p| {
                !p.is_empty()
                    && p.len() <= 63
                    && !p.starts_with('-')
                    && !p.ends_with('-')
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}
async fn response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u16, Vec<String>)> {
    let mut lines = Vec::new();
    let mut expected = None;
    for _ in 0..32 {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await.map_err(|_| Error::Provider)?;
            bytes.push(byte);
            if bytes.len() > 512 {
                return Err(Error::Provider);
            }
            if byte == b'\n' {
                break;
            }
        }
        if bytes.len() < 5
            || !bytes.ends_with(b"\r\n")
            || !bytes[..3].iter().all(u8::is_ascii_digit)
        {
            return Err(Error::Provider);
        }
        let code = ((bytes[0] - b'0') as u16) * 100
            + ((bytes[1] - b'0') as u16) * 10
            + (bytes[2] - b'0') as u16;
        if expected.is_some_and(|v| v != code) {
            return Err(Error::Provider);
        }
        expected = Some(code);
        let more = match bytes[3] {
            b' ' => false,
            b'-' => true,
            _ => return Err(Error::Provider),
        };
        let text = std::str::from_utf8(&bytes[4..bytes.len() - 2]).map_err(|_| Error::Provider)?;
        if text.chars().any(char::is_control) {
            return Err(Error::Provider);
        }
        lines.push(text.to_owned());
        if !more {
            return Ok((code, lines));
        }
    }
    Err(Error::Provider)
}
async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: &[u8],
    expected: u16,
) -> Result<Vec<String>> {
    stream
        .write_all(command)
        .await
        .map_err(|_| Error::Provider)?;
    stream.flush().await.map_err(|_| Error::Provider)?;
    let (code, lines) = response(stream).await?;
    if code != expected {
        return Err(Error::Provider);
    }
    Ok(lines)
}
async fn tls(
    stream: tokio::net::TcpStream,
    endpoint: &Endpoint,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    };
    let certificates = CertificateDer::pem_slice_iter(&endpoint.ca_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Input)?;
    if certificates.is_empty() || certificates.len() > 32 {
        return Err(Error::Input);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| Error::Input)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Input)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from(endpoint.hostname.clone()).map_err(|_| Error::Input)?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(|_| Error::Provider)
}
/// 部署端只传入已批准的精确地址和 TLS 名字，不执行 DNS 或代理转发。
/// before_data 必须先持久提交原操作的 submitting 检查点。
pub async fn test<F, Fut>(
    endpoint: &Endpoint,
    credentials: &Credentials,
    sender: &str,
    recipient: &str,
    operation: uuid::Uuid,
    sent_at: i64,
    before_data: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    endpoint.validate()?;
    mailbox(sender)?;
    mailbox(recipient)?;
    if !(1..=253402300799).contains(&sent_at)
        || operation.is_nil()
        || credentials.username.is_empty()
        || credentials.username.len() > 1024
        || credentials.password.is_empty()
        || credentials.password.len() > 4096
        || credentials.username.contains('\0')
        || credentials.password.contains('\0')
    {
        return Err(Error::Input);
    }
    // 总预算覆盖 TCP、TLS、认证及 DATA；调用者用已提交检查点区分未知提交。
    tokio::time::timeout(Duration::from_secs(45),async {
        let mut tcp=tokio::net::TcpStream::connect(endpoint.address).await.map_err(|_|Error::Provider)?;
        tcp.set_nodelay(true).map_err(|_|Error::Provider)?;
        let mut stream=match endpoint.tls {
            Tls::Implicit=>{
                let mut stream=tls(tcp,endpoint).await?;
                if response(&mut stream).await?.0!=220 {return Err(Error::Provider);}
                stream
            }
            Tls::Starttls=>{
                if response(&mut tcp).await?.0!=220 {return Err(Error::Provider);}
                let capabilities=command(&mut tcp,b"EHLO rss-mdm.invalid\r\n",250).await?;
                if !capabilities.iter().any(|v|v.eq_ignore_ascii_case("STARTTLS")){return Err(Error::Provider);}
                command(&mut tcp,b"STARTTLS\r\n",220).await?;
                tls(tcp,endpoint).await?
            }
        };
        let capabilities=command(&mut stream,b"EHLO rss-mdm.invalid\r\n",250).await?;
        if !capabilities.iter().any(|line|{
            let mut words=line.split_ascii_whitespace();
            words.next().is_some_and(|v|v.eq_ignore_ascii_case("AUTH")) && words.any(|v|v.eq_ignore_ascii_case("PLAIN"))
        }){return Err(Error::Provider);}
        let plain=Zeroizing::new(format!("\0{}\0{}",credentials.username.as_str(),credentials.password.as_str()));
        let encoded=Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(plain.as_bytes()));
        let auth=Zeroizing::new(format!("AUTH PLAIN {}\r\n",encoded.as_str()));
        command(&mut stream,auth.as_bytes(),235).await?;
        command(&mut stream,format!("MAIL FROM:<{sender}>\r\n").as_bytes(),250).await?;
        command(&mut stream,format!("RCPT TO:<{recipient}>\r\n").as_bytes(),250).await?;
        before_data().await?;
        stream.write_all(b"DATA\r\n").await.map_err(|_|Error::Unknown)?;
        stream.flush().await.map_err(|_|Error::Unknown)?;
        let (code,_)=response(&mut stream).await.map_err(|_|Error::Unknown)?;
        if code!=354 {return Err(if (400..600).contains(&code){Error::Rejected}else{Error::Unknown});}
        // 仅固定产品资格消息，不接收用户提供的主题、正文或附加收件人。
        let date=httpdate::fmt_http_date(std::time::UNIX_EPOCH+Duration::from_secs(sent_at as u64));
        let body=format!("Date: {date}\r\nFrom: <{sender}>\r\nTo: <{recipient}>\r\nMessage-ID: <{operation}@rss-mdm.invalid>\r\nSubject: RSS MDM SMTP qualification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nRSS MDM SMTP qualification operation {operation}.\r\n.\r\n");
        stream.write_all(body.as_bytes()).await.map_err(|_|Error::Unknown)?;
        stream.flush().await.map_err(|_|Error::Unknown)?;
        let (code,_)=response(&mut stream).await.map_err(|_|Error::Unknown)?;
        if code!=250 {return Err(if (400..600).contains(&code){Error::Rejected}else{Error::Unknown});}
        // 已取得 DATA 250 即完成提交；QUIT 失败不能把已接受消息变成重投。
        Ok(())
    }).await.map_err(|_|Error::Provider)?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_reply_parser_rejects_mixed_codes_and_header_injection() {
        let mut valid = &b"250-relay.example\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n"[..];
        assert_eq!(response(&mut valid).await.unwrap().0, 250);
        let mut mixed = &b"250-start\r\n550 end\r\n"[..];
        assert!(response(&mut mixed).await.is_err());
        let long = format!("250 {}\r\n", "a".repeat(512)).into_bytes();
        assert!(response(&mut long.as_slice()).await.is_err());
        assert!(mailbox("sender@example.com\r\nRCPT TO:<evil@example.com>").is_err());
        assert!(mailbox("sender@example.com").is_ok());
    }
}
