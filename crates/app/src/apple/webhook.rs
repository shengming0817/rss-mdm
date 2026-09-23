//! step-ca v0.30.2 authenticates the exact request bytes before any JSON is trusted.
//! ref: smallstep/certificates authority/provisioner/webhook.go@v0.30.2
use crate::Error;
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
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
pub(super) struct CertificateRequest {
    pub raw: String,
}
impl CertificateRequest {
    pub fn der(&self) -> Result<Vec<u8>, Error> {
        if self.raw.len() > 44_000 {
            return Err(Error::Malformed);
        }
        STANDARD.decode(&self.raw).map_err(|_| Error::Malformed)
    }
}

pub(super) fn decode(
    key: &ring::hmac::Key,
    id: &str,
    headers: &HeaderMap,
    bytes: &[u8],
    now: i64,
) -> Result<Request, Error> {
    let header = |name: &'static str| {
        if headers.get_all(name).iter().count() != 1 {
            return Err(Error::Unauthorized);
        }
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Unauthorized)
    };
    if bytes.len() > 128 * 1024 || header("x-smallstep-webhook-id")? != id {
        return Err(Error::Unauthorized);
    }
    let signature = header("x-smallstep-signature")?;
    if signature.len() != 64 || !signature.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(Error::Unauthorized);
    }
    let signature = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).map_err(|_| Error::Unauthorized))
        .collect::<Result<Vec<_>, _>>()?;
    ring::hmac::verify(key, bytes, &signature).map_err(|_| Error::Unauthorized)?;
    let request: Request = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
    let timestamp = time::OffsetDateTime::parse(
        &request.timestamp,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| Error::Malformed)?
    .unix_timestamp();
    if timestamp.abs_diff(now) > 300
        || request.transaction.is_empty()
        || request.transaction.len() > 255
        || request.transaction.chars().any(char::is_control)
    {
        return Err(Error::Unauthorized);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_body_is_required_and_replay_window_is_bounded() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-secret");
        let bytes=br#"{"timestamp":"2026-09-23T00:00:00Z","x509CertificateRequest":{"raw":"AQ=="},"scepTransactionID":"tx"}"#;
        let signature = ring::hmac::sign(&key, bytes)
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let mut headers = HeaderMap::new();
        headers.insert("x-smallstep-webhook-id", "rss".parse().unwrap());
        headers.insert("x-smallstep-signature", signature.parse().unwrap());
        let now = time::OffsetDateTime::parse(
            "2026-09-23T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
        .unix_timestamp();
        assert!(decode(&key, "rss", &headers, bytes, now).is_ok());
        assert!(decode(&key, "rss", &headers, bytes, now + 301).is_err());
        assert!(decode(&key, "other", &headers, bytes, now).is_err());
        assert!(decode(&key, "rss", &headers, b"{}", now).is_err());
        headers.append("x-smallstep-signature", signature.parse().unwrap());
        assert!(decode(&key, "rss", &headers, bytes, now).is_err());
    }
}
