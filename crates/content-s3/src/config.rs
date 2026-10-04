use crate::{Error, Result};
use aws_credential_types::provider::{ProvideCredentials, error::CredentialsError, future};
use aws_sdk_s3::{
    Client,
    config::{Credentials as AwsCredentials, Region, retry::RetryConfig, timeout::TimeoutConfig},
};
use aws_smithy_http_client::tls::{self, TrustStore};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

/// Trusted host connection inputs. No ambient credentials or TLS-disable option.
#[derive(Clone)]
pub struct Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Canonical relative prefix, without a trailing slash. Targets are always below it.
    pub namespace: String,
    pub credentials_reference: String,
    /// None uses the SDK's standard roots; Some supplies the sole private trust bundle.
    pub private_ca_pem: Option<Vec<u8>>,
    pub max_concurrent: usize,
    pub connect_timeout: Duration,
}
/// Secret values are not serializable and all Debug fields are redacted.
pub struct Credentials {
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expires: Option<SystemTime>,
}
impl Credentials {
    pub fn new(
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        expires: Option<SystemTime>,
    ) -> Result<Self> {
        if access_key.is_empty()
            || secret_key.is_empty()
            || access_key.bytes().any(|b| b.is_ascii_control())
            || secret_key.bytes().any(|b| b.is_ascii_control())
            || session_token
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.bytes().any(|b| b.is_ascii_control()))
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            access_key: Zeroizing::new(access_key),
            secret_key: Zeroizing::new(secret_key),
            session_token: session_token.map(Zeroizing::new),
            expires,
        })
    }
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}
/// Host-owned lookup/refresh. Implementations must be nonblocking and return only safe errors.
pub trait Secrets: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<Credentials>;
}
#[derive(Clone)]
struct Provider {
    secrets: Arc<dyn Secrets>,
    reference: String,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentCredentials(<redacted>)")
    }
}
impl ProvideCredentials for Provider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async {
            let c = self.secrets.resolve(&self.reference).map_err(|_| {
                CredentialsError::provider_error("host content credentials unavailable")
            })?;
            Ok(AwsCredentials::new(
                c.access_key.as_str(),
                c.secret_key.as_str(),
                c.session_token.as_ref().map(|s| s.to_string()),
                c.expires,
                "content-host",
            ))
        })
    }
}
impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        let endpoint = url::Url::parse(&self.endpoint).map_err(|_| Error::Configuration)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || !(1..=1024).contains(&self.max_concurrent)
            || self.connect_timeout.is_zero()
            || self.private_ca_pem.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(Error::Configuration);
        }
        crate::model::relative(&self.namespace).map_err(|_| Error::Configuration)?;
        if self.namespace.len() > 512
            || !(3..=63).contains(&self.bucket.len())
            || !self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
        {
            return Err(Error::Configuration);
        }
        crate::model::token(&self.region, 128).map_err(|_| Error::Configuration)?;
        crate::model::token(&self.credentials_reference, 256).map_err(|_| Error::Configuration)
    }
    // Same TLS construction in production and real-provider tests; no public client injection.
    // Extraction: RSS 5b63e10a... adapters/s3/src/private_ca.rs.
    pub(crate) fn client(&self, secrets: Arc<dyn Secrets>) -> Result<Client> {
        self.validate()?;
        let mut http = aws_smithy_http_client::Builder::new().tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ));
        if let Some(ca) = &self.private_ca_pem {
            let context = tls::TlsContext::builder()
                .with_trust_store(TrustStore::empty().with_pem_certificate(ca.clone()))
                .build()
                .map_err(|_| Error::Configuration)?;
            http = http.tls_context(context);
        }
        Ok(Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .endpoint_url(&self.endpoint)
                .region(Region::new(self.region.clone()))
                .credentials_provider(Provider {
                    secrets,
                    reference: self.credentials_reference.clone(),
                })
                .force_path_style(true)
                .http_client(http.build_https())
                .retry_config(RetryConfig::standard().with_max_attempts(1))
                .timeout_config(
                    TimeoutConfig::builder()
                        .connect_timeout(self.connect_timeout)
                        .build(),
                )
                .build(),
        ))
    }
}
