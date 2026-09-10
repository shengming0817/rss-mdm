use crate::*;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use url::Url;

/// Trusted composition supplies reviewed addresses; DNS cannot redirect the connection.
#[derive(Clone)]
pub struct Source {
    tenant: TenantId,
    id: String,
    base: Url,
    addresses: Vec<SocketAddr>,
    credential_ref: String,
    root_certificate: Option<reqwest::Certificate>,
}
impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Source([redacted])")
    }
}
impl Source {
    pub fn new(
        tenant: TenantId,
        id: &str,
        base: &str,
        addresses: Vec<IpAddr>,
        credential_ref: &str,
    ) -> Result<Self, Error> {
        identity(id)?;
        identity(credential_ref)?;
        let base = Url::parse(base).map_err(|_| Error::InvalidInput)?;
        let host = base.host_str().ok_or(Error::InvalidInput)?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.path().ends_with('/')
            || addresses.is_empty()
            || addresses.len() > 16
        {
            return Err(Error::InvalidInput);
        }
        if base.scheme() != "https"
            || addresses.iter().any(|ip| {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_loopback()
                    || match ip {
                        IpAddr::V4(v) => v.is_link_local(),
                        IpAddr::V6(v) => v.is_unicast_link_local() || v.to_ipv4_mapped().is_some(),
                    }
            })
        {
            return Err(Error::AddressDenied);
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
            && !addresses.contains(&ip)
        {
            return Err(Error::AddressDenied);
        }
        let port = base.port_or_known_default().ok_or(Error::InvalidInput)?;
        Ok(Self {
            tenant,
            id: id.into(),
            base,
            addresses: addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            credential_ref: credential_ref.into(),
            root_certificate: None,
        })
    }
    /// Trust only this PEM root for this source, retaining hostname and certificate validation.
    /// The product must authorize the private CA; malformed PEM returns InvalidInput.
    pub fn with_root_certificate(mut self, pem: &[u8]) -> Result<Self, Error> {
        self.root_certificate =
            Some(reqwest::Certificate::from_pem(pem).map_err(|_| Error::InvalidInput)?);
        Ok(self)
    }
}
/// A resolved source credential, scoped to a tenant, source and reference by the caller.
/// This is not proof that the caller was authenticated by a product API.
pub struct Access {
    tenant: TenantId,
    source: String,
    reference: String,
    bearer: HeaderValue,
}
impl Access {
    pub fn new(
        tenant: TenantId,
        source: &str,
        reference: &str,
        bearer: &str,
    ) -> Result<Self, Error> {
        identity(source)?;
        identity(reference)?;
        if bearer.is_empty()
            || bearer.len() > 8192
            || !bearer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        let mut bearer =
            HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| Error::InvalidInput)?;
        bearer.set_sensitive(true);
        Ok(Self {
            tenant,
            source: source.into(),
            reference: reference.into(),
            bearer,
        })
    }
}
impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Access([redacted])")
    }
}
pub struct Client {
    source: Source,
    http: reqwest::Client,
    total: Duration,
    limit: usize,
}
impl Client {
    pub fn new(source: Source) -> Result<Self, Error> {
        Self::with_limits(
            source,
            Duration::from_secs(5),
            Duration::from_secs(30),
            MAX_RESPONSE,
        )
    }
    pub fn with_limits(
        source: Source,
        connect: Duration,
        total: Duration,
        limit: usize,
    ) -> Result<Self, Error> {
        if connect.is_zero()
            || total.is_zero()
            || connect > total
            || total > Duration::from_secs(30)
            || limit == 0
            || limit > MAX_RESPONSE
        {
            return Err(Error::InvalidInput);
        }
        let host = source.base.host_str().ok_or(Error::InvalidInput)?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .resolve_to_addrs(host, &source.addresses)
            .connect_timeout(connect);
        if let Some(certificate) = &source.root_certificate {
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate.clone());
        }
        let http = builder
            .build()
            .map_err(|_| Error::Transport(RequestStage::Setup))?;
        Ok(Self {
            source,
            http,
            total,
            limit,
        })
    }
    pub async fn query(&self, query: &Query, access: &Access) -> Result<Manifest, Error> {
        if query.tenant != self.source.tenant || access.tenant != self.source.tenant {
            return Err(Error::TenantMismatch);
        }
        if query.source != self.source.id
            || access.source != self.source.id
            || access.reference != self.source.credential_ref
        {
            return Err(Error::IdentityMismatch);
        }
        tokio::time::timeout(self.total, self.query_inner(query, access))
            .await
            .map_err(|_| Error::Timeout(RequestStage::Query))?
    }
    async fn query_inner(&self, query: &Query, access: &Access) -> Result<Manifest, Error> {
        let info = self
            .get(
                self.source
                    .base
                    .join("information")
                    .map_err(|_| Error::InvalidInput)?,
                access,
                RequestStage::Information,
            )
            .await?;
        let info: serde_json::Value =
            serde_json::from_slice(&info).map_err(|_| Error::InvalidResponse)?;
        if info["Data"]["SourceIdentifier"].as_str() != Some(self.source.id.as_str()) {
            return Err(Error::IdentityMismatch);
        }
        let versions = info["Data"]["ServerSupportedVersions"]
            .as_array()
            .ok_or(Error::InvalidResponse)?;
        if !versions
            .iter()
            .any(|v| v.as_str() == Some(CONTRACT_VERSION))
        {
            return Err(Error::Unsupported);
        }
        // Authentication modes requiring later REST versions are not silently ignored.
        if info["Data"].get("Authentication").is_some() {
            return Err(Error::Unsupported);
        }
        let mut url = self
            .source
            .base
            .join("packageManifests/")
            .map_err(|_| Error::InvalidInput)?;
        url.path_segments_mut()
            .map_err(|_| Error::InvalidInput)?
            .pop_if_empty()
            .push(&query.package);
        url.query_pairs_mut().append_pair("Version", &query.version);
        parse_manifest(query, &self.get(url, access, RequestStage::Manifest).await?)
    }
    async fn get(&self, url: Url, access: &Access, stage: RequestStage) -> Result<Vec<u8>, Error> {
        let request = self
            .http
            .get(url)
            .header("Version", CONTRACT_VERSION)
            .header("Accept", "application/json")
            .header(AUTHORIZATION, access.bearer.clone());
        let mut response = request.send().await.map_err(|e| transport(stage, e))?;
        if !response.status().is_success() {
            if stage == RequestStage::Manifest && response.status().as_u16() == 404 {
                return Err(Error::NotFound);
            }
            return Err(Error::HttpStatus {
                stage,
                status: response.status().as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.limit as u64)
        {
            return Err(Error::BudgetExceeded);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| transport(stage, e))? {
            if chunk.len() > self.limit - bytes.len() {
                return Err(Error::BudgetExceeded);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
fn transport(stage: RequestStage, e: reqwest::Error) -> Error {
    if e.is_timeout() {
        Error::Timeout(RequestStage::Query)
    } else {
        Error::Transport(stage)
    }
}
