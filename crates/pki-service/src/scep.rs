//! step-ca v0.30.2 authenticates the exact request bytes before any JSON is trusted.
//! ref: smallstep/certificates authority/provisioner/webhook.go@v0.30.2
use crate::Error;
use base64::{Engine, engine::general_purpose::STANDARD};
use http::HeaderMap;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub timestamp: String,
    pub provisioner_name: Option<String>,
    pub x509_certificate_request: CertificateRequest,
    pub scep_challenge: Option<String>,
    #[serde(rename = "scepTransactionID")]
    pub transaction: String,
    pub x509_certificate: Option<CertificateRequest>,
    pub scep_error_code: Option<i32>,
}
#[derive(Deserialize)]
pub struct CertificateRequest {
    pub raw: String,
}
impl CertificateRequest {
    pub fn der(&self) -> Result<Vec<u8>, Error> {
        if self.raw.len() > 44_000 {
            return Err(Error::Request);
        }
        STANDARD.decode(&self.raw).map_err(|_| Error::Request)
    }
}

pub fn decode(
    key: &ring::hmac::Key,
    id: &str,
    headers: &HeaderMap,
    bytes: &[u8],
    now: i64,
) -> Result<Request, Error> {
    let header = |name: &'static str| {
        if headers.get_all(name).iter().count() != 1 {
            return Err(Error::Forbidden);
        }
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Forbidden)
    };
    if bytes.len() > 128 * 1024 || header("x-smallstep-webhook-id")? != id {
        return Err(Error::Forbidden);
    }
    let signature = header("x-smallstep-signature")?;
    if signature.len() != 64 || !signature.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(Error::Forbidden);
    }
    let signature = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).map_err(|_| Error::Forbidden))
        .collect::<Result<Vec<_>, _>>()?;
    ring::hmac::verify(key, bytes, &signature).map_err(|_| Error::Forbidden)?;
    let request: Request = serde_json::from_slice(bytes).map_err(|_| Error::Request)?;
    let timestamp = time::OffsetDateTime::parse(
        &request.timestamp,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| Error::Request)?
    .unix_timestamp();
    if timestamp.abs_diff(now) > 300
        || request.transaction.is_empty()
        || request.transaction.len() > 255
        || request.transaction.chars().any(char::is_control)
    {
        return Err(Error::Forbidden);
    }
    Ok(request)
}

/// Decode the secret returned by step-ca's webhook provisioning API.
pub fn key(encoded: &[u8]) -> Result<ring::hmac::Key, Error> {
    let decoded =
        zeroize::Zeroizing::new(STANDARD.decode(encoded).map_err(|_| Error::Configuration)?);
    if decoded.len() < 32 {
        return Err(Error::Configuration);
    }
    Ok(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &decoded))
}

/// A CA's authenticated callback identity is bound to one retained issuer and stage.
pub struct Credentials {
    pub issuer: String,
    pub challenge_id: String,
    pub challenge_key: ring::hmac::Key,
    pub notify_id: String,
    pub notify_key: ring::hmac::Key,
}
#[derive(Clone, Copy)]
pub enum Stage {
    Challenge,
    Notify,
}
pub struct Verifier {
    credentials: Vec<Credentials>,
}
/// Only the signature verifier can construct this proof.
pub struct VerifiedRequest {
    issuer: String,
    request: Request,
}
impl VerifiedRequest {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
}
impl Verifier {
    pub fn new(credentials: Vec<Credentials>) -> Result<Self, Error> {
        if credentials.is_empty() || credentials.len() > 32 {
            return Err(Error::Configuration);
        }
        let mut ids = std::collections::HashSet::new();
        let mut issuers = std::collections::HashSet::new();
        for credential in &credentials {
            if credential.issuer.len() != 64
                || !credential
                    .issuer
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !issuers.insert(&credential.issuer)
            {
                return Err(Error::Configuration);
            }
            for id in [&credential.challenge_id, &credential.notify_id] {
                if id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    || !ids.insert(id)
                {
                    return Err(Error::Configuration);
                }
            }
        }
        Ok(Self { credentials })
    }
    pub fn verify(
        &self,
        stage: Stage,
        headers: &HeaderMap,
        bytes: &[u8],
        now: i64,
    ) -> Result<VerifiedRequest, Error> {
        if headers.get_all("x-smallstep-webhook-id").iter().count() != 1 {
            return Err(Error::Forbidden);
        }
        let id = headers
            .get("x-smallstep-webhook-id")
            .and_then(|h| h.to_str().ok())
            .ok_or(Error::Forbidden)?;
        for credential in &self.credentials {
            let (expected, key) = match stage {
                Stage::Challenge => (&credential.challenge_id, &credential.challenge_key),
                Stage::Notify => (&credential.notify_id, &credential.notify_key),
            };
            if id == expected {
                return Ok(VerifiedRequest {
                    issuer: credential.issuer.clone(),
                    request: decode(key, expected, headers, bytes, now)?,
                });
            }
        }
        Err(Error::Forbidden)
    }
}

#[cfg(feature = "integration")]
impl Verifier {
    /// Signing helper for authenticated in-process provider fixtures, never exposed over HTTP.
    pub fn signature_fixture(
        &self,
        issuer: &str,
        stage: Stage,
        bytes: &[u8],
    ) -> Result<(&str, ring::hmac::Tag), Error> {
        let c = self
            .credentials
            .iter()
            .find(|c| c.issuer == issuer)
            .ok_or(Error::Configuration)?;
        let (id, key) = match stage {
            Stage::Challenge => (&c.challenge_id, &c.challenge_key),
            Stage::Notify => (&c.notify_id, &c.notify_key),
        };
        Ok((id, ring::hmac::sign(key, bytes)))
    }
}
