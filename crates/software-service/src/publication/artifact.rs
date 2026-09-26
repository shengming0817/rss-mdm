//! One anonymous HTTPS reader. Source credentials never enter this module.
use super::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOrigin {
    pub base: String,
    pub addresses: Vec<IpAddr>,
    pub private_ca: Option<Vec<u8>>,
}
pub struct ArtifactReader {
    origins: Vec<(url::Url, reqwest::Client)>,
    max_bytes: u64,
    deadline: Duration,
}
impl ArtifactReader {
    pub fn new(origins: Vec<ArtifactOrigin>, max_bytes: u64, deadline: Duration) -> Result<Self> {
        if origins.is_empty()
            || origins.len() > 64
            || max_bytes == 0
            || deadline.is_zero()
            || deadline > Duration::from_secs(3600)
        {
            return Err(Error::Input);
        }
        let mut clients = Vec::new();
        for origin in origins {
            let url = checked_url(&origin.base)?;
            if !url.path().ends_with('/')
                || origin.addresses.is_empty()
                || origin.addresses.len() > 16
                || origin.addresses.iter().any(denied_ip)
            {
                return Err(Error::Input);
            }
            let host = url.host_str().ok_or(Error::Input)?;
            if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
                && !origin.addresses.contains(&ip)
            {
                return Err(Error::Input);
            }
            let addresses: Vec<_> = origin
                .addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, url.port_or_known_default().unwrap_or(443)))
                .collect();
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(host, &addresses)
                .connect_timeout(Duration::from_secs(5).min(deadline));
            if let Some(ca) = origin.private_ca {
                builder = builder.tls_built_in_root_certs(false).add_root_certificate(
                    reqwest::Certificate::from_pem(&ca)
                        .map_err(|cause| Error::Input.context("artifact::new", cause))?,
                );
            }
            clients.push((
                url,
                builder
                    .build()
                    .map_err(|cause| Error::Input.context("artifact::new", cause))?,
            ));
        }
        Ok(Self {
            origins: clients,
            max_bytes,
            deadline,
        })
    }
    /// Open only an explicitly allowlisted immutable object; caller must verify the complete stream.
    pub async fn open(&self, url: &str, length: u64) -> Result<reqwest::Response> {
        if length == 0 || length > self.max_bytes {
            return Err(Error::ArtifactBudget);
        }
        let url = checked_url(url)?;
        let client = &self
            .origins
            .iter()
            .find(|(base, _)| base.origin() == url.origin() && url.path().starts_with(base.path()))
            .ok_or(Error::ArtifactAddress)?
            .1;
        tokio::time::timeout(self.deadline, async {
            let response = client
                .get(url)
                .header("Accept-Encoding", "identity")
                .send()
                .await
                .map_err(|cause| Error::ArtifactTransport.context("artifact::verify", cause))?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::ArtifactTransport);
            }
            if response.content_length().is_some_and(|n| n != length)
                || response
                    .headers()
                    .get("Content-Encoding")
                    .is_some_and(|v| v != "identity")
            {
                return Err(Error::ArtifactDigest);
            }
            Ok(response)
        })
        .await
        .map_err(|cause| Error::ArtifactTimeout.context("artifact::open", cause))?
    }
    pub async fn verify(&self, url: &str, length: u64, digest: [u8; 32]) -> Result<()> {
        tokio::time::timeout(self.deadline, async {
            let mut response = self.open(url, length).await.map_err(|error| match error {
                Error::Diagnostic {
                    category, source, ..
                } => Error::Diagnostic {
                    stage: "artifact::verify",
                    category,
                    source,
                },
                other => other,
            })?;
            let mut hash = Sha256::new();
            let mut seen = 0u64;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|cause| Error::ArtifactTransport.context("artifact::verify", cause))?
            {
                seen = seen
                    .checked_add(chunk.len() as u64)
                    .ok_or(Error::ArtifactBudget)?;
                if seen > length {
                    return Err(Error::ArtifactBudget);
                }
                hash.update(&chunk);
            }
            if seen != length || hash.finalize().as_slice() != digest {
                return Err(Error::ArtifactDigest);
            }
            Ok(())
        })
        .await
        .map_err(|cause| Error::ArtifactTimeout.context("artifact::verify", cause))?
    }
}
fn denied_ip(ip: &IpAddr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v) => v.is_link_local(),
            IpAddr::V6(v) => v.is_unicast_link_local() || v.to_ipv4_mapped().is_some(),
        }
}
pub(super) fn checked_url(raw: &str) -> Result<url::Url> {
    if raw.len() > 2048 || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Input);
    }
    // A proxy or origin may decode again after URL parsing. Do not allow an
    // encoded separator, dot segment or percent to escape the pinned base path.
    let bytes = raw.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\\' {
            return Err(Error::Input);
        }
        if *byte == b'%' {
            let encoded = bytes.get(index + 1..index + 3).ok_or(Error::Input)?;
            let high = (encoded[0] as char).to_digit(16).ok_or(Error::Input)?;
            let low = (encoded[1] as char).to_digit(16).ok_or(Error::Input)?;
            if matches!(high * 16 + low, 0x2e | 0x2f | 0x5c | 0x25) {
                return Err(Error::Input);
            }
        }
    }
    let u = url::Url::parse(raw)
        .map_err(|cause| Error::Input.context("artifact::checked_url", cause))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::Input);
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_urls_reject_ambiguous_encoded_paths() {
        for suffix in [
            "%2e%2e%2fadmin",
            "%2E%2E%5Cadmin",
            "%252e%252e%252fadmin",
            "pkg%2fname.msi",
            "pkg%5Cname.msi",
            "bad%",
            "bad%zz",
        ] {
            assert!(
                checked_url(&format!("https://packages.example/artifacts/{suffix}")).is_err(),
                "{suffix}"
            );
        }
        for suffix in [
            "product-1.2.msi",
            "Acme%20Suite.pkg",
            "%E4%BC%81%E4%B8%9A.zip",
            "org%40name.zip",
        ] {
            assert!(
                checked_url(&format!("https://packages.example/artifacts/{suffix}")).is_ok(),
                "{suffix}"
            );
        }
    }
}
