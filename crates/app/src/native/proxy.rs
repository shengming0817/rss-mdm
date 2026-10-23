//! Trusted gateway transport metadata. It never supplies a device identity.
//! ref: haproxy/haproxy doc/proxy-protocol.txt@v3.2.0, section 2.1.
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::TcpStream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Peer,
    Header,
    Timeout,
}

/// The listener always requires PROXY v1. There is no direct-TLS autodetection.
pub(super) async fn source(
    stream: &mut TcpStream,
    peer: SocketAddr,
    gateway: IpAddr,
) -> Result<SocketAddr, Failure> {
    if peer.ip() != gateway {
        return Err(Failure::Peer);
    }
    tokio::time::timeout(Duration::from_secs(3), read(stream))
        .await
        .map_err(|_| Failure::Timeout)?
}
async fn read(stream: &mut TcpStream) -> Result<SocketAddr, Failure> {
    let mut bytes = [0u8; 107];
    for index in 0..bytes.len() {
        bytes[index] = stream.read_u8().await.map_err(|_| Failure::Header)?;
        if bytes[index] == b'\n' {
            return parse(&bytes[..=index]);
        }
    }
    Err(Failure::Header)
}
fn parse(bytes: &[u8]) -> Result<SocketAddr, Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::Header)?;
    let line = text.strip_suffix("\r\n").ok_or(Failure::Header)?;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 6 || fields[0] != "PROXY" {
        return Err(Failure::Header);
    }
    let source: IpAddr = fields[2].parse().map_err(|_| Failure::Header)?;
    let destination: IpAddr = fields[3].parse().map_err(|_| Failure::Header)?;
    match (fields[1], source, destination) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => (),
        _ => return Err(Failure::Header),
    }
    let port: u16 = fields[4].parse().map_err(|_| Failure::Header)?;
    let _: u16 = fields[5].parse().map_err(|_| Failure::Header)?;
    if source.is_unspecified() || source.is_multicast() {
        return Err(Failure::Header);
    }
    Ok(SocketAddr::new(source, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_complete_addressed_v1_headers() {
        assert_eq!(
            parse(b"PROXY TCP4 192.0.2.3 192.0.2.4 1200 443\r\n").unwrap(),
            "192.0.2.3:1200".parse().unwrap()
        );
        assert_eq!(
            parse(b"PROXY TCP6 2001:db8::1 2001:db8::2 1200 443\r\n").unwrap(),
            "[2001:db8::1]:1200".parse().unwrap()
        );
        for value in [
            "PROXY UNKNOWN\r\n",
            "PROXY TCP4 ::1 ::2 1200 443\r\n",
            "PROXY TCP4 192.0.2.3 192.0.2.4 65536 443\r\n",
            "PROXY TCP4 192.0.2.3 192.0.2.4 1200 443\n",
            "PROXY TCP4 192.0.2.3 192.0.2.4 1200 443 extra\r\n",
        ] {
            assert_eq!(parse(value.as_bytes()), Err(Failure::Header));
        }
    }
    #[tokio::test]
    async fn preserves_tls_bytes_and_rejects_untrusted_peer() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut socket, peer) = listener.accept().await.unwrap();
        assert_eq!(
            source(&mut socket, peer, "192.0.2.1".parse().unwrap()).await,
            Err(Failure::Peer)
        );
        client
            .write_all(b"PROXY TCP4 192.0.2.3 192.0.2.4 1200 443\r\n\x16\x03\x03")
            .await
            .unwrap();
        assert_eq!(
            source(&mut socket, peer, peer.ip()).await.unwrap().ip(),
            "192.0.2.3".parse::<IpAddr>().unwrap()
        );
        let mut tls = [0; 3];
        socket.read_exact(&mut tls).await.unwrap();
        assert_eq!(tls, [0x16, 3, 3]);
    }
}
