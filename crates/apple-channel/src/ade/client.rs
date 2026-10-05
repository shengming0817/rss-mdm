//! Apple ADE protocol adapter. No caller-controlled production authority or redirects.
//! ref: NanoDEP client/auth.go@f3eedc15d92933b1e793f60001141299e1791f23.
use crate::Error;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize, Serialize)]
pub(super) struct Token {
    consumer_key: Zeroizing<String>,
    consumer_secret: Zeroizing<String>,
    access_token: Zeroizing<String>,
    access_secret: Zeroizing<String>,
    access_token_expiry: String,
}
impl Token {
    pub fn parse(bytes: &[u8], now: i64) -> Result<Self, Error> {
        let token: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        for s in [
            &token.consumer_key,
            &token.consumer_secret,
            &token.access_token,
            &token.access_secret,
        ] {
            if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
                return Err(Error::Malformed);
            }
        }
        if token.expires()? <= now {
            return Err(Error::Conflict);
        }
        Ok(token)
    }
    pub fn expires(&self) -> Result<i64, Error> {
        time::OffsetDateTime::parse(
            &self.access_token_expiry,
            &time::format_description::well_known::Rfc3339,
        )
        .map(|d| d.unix_timestamp())
        .map_err(|_| Error::Malformed)
    }
}
pub(super) struct Client {
    http: reqwest::Client,
    origin: String,
    token: Token,
    session: Zeroizing<String>,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum RemoteError {
    #[error("Apple authorization rejected")]
    Unauthorized,
    #[error("Apple cursor invalid")]
    Cursor,
    #[error("Apple throttled")]
    Throttled,
    #[error("Apple response invalid")]
    Invalid,
    #[error("Apple operation outcome unknown")]
    Unknown,
}
impl Client {
    pub fn new(token: Token) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .user_agent("RSS-MDM-ADE/1")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Conflict)?;
        Ok(Self {
            http,
            origin: "https://mdmenrollment.apple.com".into(),
            token,
            session: Zeroizing::new(String::new()),
        })
    }
    #[cfg(feature = "integration")]
    pub fn fixture(mut self, http: reqwest::Client, origin: String) -> Self {
        self.http = http;
        self.origin = origin;
        self
    }
    async fn session(&mut self) -> Result<(), RemoteError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if self.token.expires().map_err(|_| RemoteError::Invalid)? <= now {
            return Err(RemoteError::Unauthorized);
        }
        let url = format!("{}/session", self.origin);
        let mut pairs = vec![
            ("oauth_consumer_key", self.token.consumer_key.to_string()),
            ("oauth_nonce", uuid::Uuid::new_v4().simple().to_string()),
            ("oauth_signature_method", "HMAC-SHA1".into()),
            ("oauth_timestamp", now.to_string()),
            ("oauth_token", self.token.access_token.to_string()),
            ("oauth_version", "1.0".into()),
        ];
        pairs.sort();
        let parameters = Zeroizing::new(
            pairs
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect::<Vec<_>>()
                .join("&"),
        );
        let input = Zeroizing::new(format!("GET&{}&{}", encode(&url), encode(&parameters)));
        let key = Zeroizing::new(format!(
            "{}&{}",
            encode(&self.token.consumer_secret),
            encode(&self.token.access_secret)
        ));
        let pkey = openssl::pkey::PKey::hmac(key.as_bytes()).map_err(|_| RemoteError::Invalid)?;
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha1(), &pkey)
            .map_err(|_| RemoteError::Invalid)?;
        signer
            .update(input.as_bytes())
            .map_err(|_| RemoteError::Invalid)?;
        pairs.push((
            "oauth_signature",
            STANDARD.encode(signer.sign_to_vec().map_err(|_| RemoteError::Invalid)?),
        ));
        let header = Zeroizing::new(format!(
            "OAuth realm=\"ADM\",{}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, encode(v)))
                .collect::<Vec<_>>()
                .join(",")
        ));
        for (_, value) in &mut pairs {
            value.zeroize();
        }
        let response = self
            .http
            .get(url)
            .header("Authorization", header.as_str())
            .header("X-Server-Protocol-Version", "10")
            .send()
            .await
            .map_err(|_| RemoteError::Unknown)?;
        let body = bounded(response).await?;
        let s = body
            .get("auth_session_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or(RemoteError::Invalid)?;
        self.session = Zeroizing::new(s.into());
        Ok(())
    }
    pub async fn request(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, RemoteError> {
        if self.session.is_empty() {
            self.session().await?;
        }
        for round in 0..2 {
            let mut request = self
                .http
                .request(method.clone(), format!("{}{path}", self.origin))
                .header("X-ADM-Auth-Session", self.session.as_str())
                .header("X-Server-Protocol-Version", "10");
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = request.send().await.map_err(|_| RemoteError::Unknown)?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && round == 0 {
                self.session().await?;
                continue;
            }
            if let Some(s) = response.headers().get("X-ADM-Auth-Session") {
                let s = s.to_str().map_err(|_| RemoteError::Invalid)?;
                if s.is_empty() || s.len() > 4096 {
                    return Err(RemoteError::Invalid);
                }
                self.session = Zeroizing::new(s.into());
            }
            let success = response.status().is_success();
            let result = bounded(response).await;
            // A write may have committed even if its success receipt cannot be parsed.
            return if success
                && method != reqwest::Method::GET
                && path != "/server/devices"
                && path != "/devices/sync"
                && matches!(result, Err(RemoteError::Invalid))
            {
                Err(RemoteError::Unknown)
            } else {
                result
            };
        }
        Err(RemoteError::Unauthorized)
    }
}
async fn bounded(mut response: reqwest::Response) -> Result<Value, RemoteError> {
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(RemoteError::Unauthorized);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(RemoteError::Throttled);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| RemoteError::Unknown)? {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(RemoteError::Invalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| RemoteError::Invalid)?;
    if !status.is_success() {
        if matches!(
            value.get("error_code").and_then(Value::as_str),
            Some("EXPIRED_CURSOR" | "EXHAUSTED_CURSOR" | "INVALID_CURSOR")
        ) {
            return Err(RemoteError::Cursor);
        }
        return Err(if status.is_server_error() {
            RemoteError::Unknown
        } else {
            RemoteError::Invalid
        });
    }
    Ok(value)
}
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
