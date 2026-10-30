//! ref: aws-sigv4 1.6.0 src/http_request.rs; no custom SigV4 implementation.
use super::super::{Error, Result};
use crate::clock::Clock;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    },
    sign::v4,
};
use reqwest::{Method, StatusCode};
use std::time::Duration;
use zeroize::Zeroizing;
pub(super) struct Client {
    endpoint: url::Url,
    region: String,
    client: reqwest::Client,
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}
pub(super) struct Response {
    pub status: StatusCode,
    pub body: Zeroizing<Vec<u8>>,
}
impl Client {
    pub fn new(
        endpoint: &str,
        region: &str,
        ca: &[u8],
        access: Zeroizing<String>,
        secret: Zeroizing<String>,
        token: Option<Zeroizing<String>>,
    ) -> Result<Self> {
        let url = url::Url::parse(endpoint).map_err(|_| Error::Input)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || region.is_empty()
            || region.len() > 64
        {
            return Err(Error::Input);
        }
        let roots = reqwest::Certificate::from_pem_bundle(ca).map_err(|_| Error::Input)?;
        if roots.is_empty() || roots.len() > 16 {
            return Err(Error::Input);
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(12))
            .tls_built_in_root_certs(false);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        let client = builder.build().map_err(|_| Error::Input)?;
        Ok(Self {
            endpoint: url,
            region: region.into(),
            client,
            access,
            secret,
            token,
        })
    }
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: &[u8],
        content_type: &str,
    ) -> Result<Response> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('?')
            || path.contains('#')
        {
            return Err(Error::Input);
        }
        let mut url = self.endpoint.clone();
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let identity = aws_credential_types::Credentials::new(
            self.access.to_string(),
            self.secret.to_string(),
            self.token.as_ref().map(|t| t.to_string()),
            None,
            "rss-mdm-deployment",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("s3")
            .time(
                std::time::UNIX_EPOCH
                    .checked_add(Duration::from_secs(
                        u64::try_from(
                            crate::clock::SystemClock
                                .unix_seconds()
                                .map_err(|_| Error::Storage)?,
                        )
                        .map_err(|_| Error::Storage)?,
                    ))
                    .ok_or(Error::Storage)?,
            )
            .settings(settings)
            .build()
            .map_err(|_| Error::Input)?
            .into();
        let signable = SignableRequest::new(
            method.as_str(),
            url.as_str(),
            [("content-type", content_type)].into_iter(),
            SignableBody::Bytes(body),
        )
        .map_err(|_| Error::Input)?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|_| Error::Input)?
            .into_parts();
        if !instructions.params().is_empty() {
            return Err(Error::Input);
        }
        let mut request = self
            .client
            .request(method, url)
            .header("content-type", content_type)
            .body(body.to_vec());
        for (name, value) in instructions.headers() {
            request = request.header(name, value);
        }
        let mut response = request.send().await.map_err(|_| Error::Storage)?;
        if response.content_length().is_some_and(|n| n > 1024 * 1024) {
            return Err(Error::Input);
        }
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
            if chunk.len() > 1024 * 1024 - bytes.len() {
                return Err(Error::Input);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            body: Zeroizing::new(bytes),
        })
    }
}
