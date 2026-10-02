//! WNS carries an empty native wake signal; acceptance is never command delivery evidence.
//! ref: Microsoft push-notification-windows-mdm and WNS request/response headers.
#[cfg(feature = "integration")]
pub use crate::push_worker::cycle as wake_once;
pub use crate::push_worker::{WakeEligibility, registration};
use crate::{Error, Failure};
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    Accepted,
    Retryable,
    Unknown,
    Unregistered,
    Rejected,
}
impl PushOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Retryable => "retryable",
            Self::Unknown => "unknown",
            Self::Unregistered => "unregistered",
            Self::Rejected => "rejected",
        }
    }
}
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

pub struct Push {
    clock: std::sync::Arc<dyn rss_observation::Clock>,
    client: reqwest::Client,
    token_url: String,
    #[cfg(feature = "integration")]
    transport_origin: Option<reqwest::Url>,
    sid: String,
    secret: Zeroizing<String>,
    pub pfn: String,
    pub configuration: [u8; 32],
    token: tokio::sync::Mutex<Option<(Zeroizing<String>, Instant)>>,
}
pub struct Receipt {
    pub status: u16,
    pub outcome: PushOutcome,
    /// Validated server minimum wait; persistence applies at least the local backoff too.
    pub retry_after: Option<Duration>,
}
fn retry_after(headers: &reqwest::header::HeaderMap, now: SystemTime) -> Option<Duration> {
    let mut values = headers.get_all(reqwest::header::RETRY_AFTER).iter();
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || value.is_empty() || value.len() > 128 {
        return None;
    }
    let seconds = if value.bytes().all(|b| b.is_ascii_digit()) {
        value.parse::<u64>().ok()?
    } else {
        let wait = httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default();
        wait.as_secs()
            .checked_add(u64::from(wait.subsec_nanos() != 0))?
    };
    // Bound the untrusted interval to a representable scheduling value; never truncate a valid wait.
    (seconds <= i32::MAX as u64).then(|| Duration::from_secs(seconds))
}
fn unavailable(_: impl std::fmt::Debug) -> Error {
    Error::Unavailable(Failure::Protocol)
}
/// Channel URIs are device claims until validated; redirects and arbitrary hosts are forbidden.
pub fn channel_uri(value: &str) -> Result<reqwest::Url, Error> {
    let uri = reqwest::Url::parse(value).map_err(|_| Error::Malformed)?;
    if value.len() > 4096
        || uri.scheme() != "https"
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
        || uri.port_or_known_default() != Some(443)
        || !uri
            .host_str()
            .is_some_and(|h| h == "notify.windows.com" || h.ends_with(".notify.windows.com"))
    {
        return Err(Error::Malformed);
    }
    Ok(uri)
}
impl Push {
    pub fn new(
        pfn: String,
        sid: String,
        secret: String,
        clock: std::sync::Arc<dyn rss_observation::Clock>,
    ) -> Result<Self, Error> {
        if pfn.is_empty()
            || pfn.len() > 256
            || !pfn
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || sid.is_empty()
            || sid.len() > 512
            || secret.is_empty()
            || secret.len() > 4096
        {
            return Err(Error::Malformed);
        }
        use sha2::{Digest, Sha256};
        let configuration = Sha256::digest(&*Zeroizing::new(
            serde_json::to_vec(&("wns", &pfn, &sid, &secret)).map_err(unavailable)?,
        ))
        .into();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(unavailable)?;
        Ok(Self {
            clock,
            client,
            token_url: "https://login.live.com/accesstoken.srf".into(),
            #[cfg(feature = "integration")]
            transport_origin: None,
            pfn,
            sid,
            secret: Zeroizing::new(secret),
            configuration,
            token: tokio::sync::Mutex::new(None),
        })
    }
    async fn bearer(&self) -> Result<Zeroizing<String>, Error> {
        let mut cached = self.token.lock().await;
        if let Some((token, expires)) = &*cached
            && *expires > self.clock.now() + Duration::from_secs(30)
        {
            return Ok(token.clone());
        }
        let mut response = self
            .client
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.sid.as_str()),
                ("client_secret", self.secret.as_str()),
                ("scope", "notify.windows.com"),
            ])
            .send()
            .await
            .map_err(unavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unavailable(Failure::Protocol));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(unavailable)? {
            if bytes.len().saturating_add(chunk.len()) > 16384 {
                return Err(Error::Unavailable(Failure::Protocol));
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(serde::Deserialize)]
        struct Token {
            token_type: String,
            access_token: Zeroizing<String>,
            expires_in: u64,
        }
        let value: Token = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if !value.token_type.eq_ignore_ascii_case("bearer")
            || !(60..=86400).contains(&value.expires_in)
            || value.access_token.is_empty()
            || !value
                .access_token
                .bytes()
                .all(|b| (0x21..0x7f).contains(&b))
        {
            return Err(Error::Unavailable(Failure::Protocol));
        }
        let token = value.access_token;
        *cached = Some((
            token.clone(),
            self.clock.now() + Duration::from_secs(value.expires_in),
        ));
        Ok(token)
    }
    pub async fn send(&self, channel: &str) -> Result<Receipt, Error> {
        let uri = channel_uri(channel)?;
        #[cfg(feature = "integration")]
        let uri = if let Some(origin) = &self.transport_origin {
            origin.join(uri.path()).map_err(unavailable)?
        } else {
            uri
        };
        let token = match self.bearer().await {
            Ok(token) => token,
            Err(_) => {
                return Ok(Receipt {
                    status: 0,
                    outcome: PushOutcome::Retryable,
                    retry_after: None,
                });
            }
        };
        let response = self
            .client
            .post(uri)
            .bearer_auth(token.as_str())
            .header("content-type", "application/octet-stream")
            .header("x-wns-type", "wns/raw")
            .header("x-wns-cache-policy", "cache")
            .header("x-wns-ttl", "60")
            .header("x-wns-requestforstatus", "true")
            .body(Vec::new())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return Ok(Receipt {
                    status: 0,
                    outcome: if error.is_connect() {
                        PushOutcome::Retryable
                    } else {
                        PushOutcome::Unknown
                    },
                    retry_after: None,
                });
            }
        };
        let status = response.status().as_u16();
        let outcome = match status {
            200 if response
                .headers()
                .get("x-wns-notificationstatus")
                .is_some_and(|v| v == "received") =>
            {
                PushOutcome::Accepted
            }
            200 | 406 | 429 | 500..=599 => PushOutcome::Retryable,
            401 => {
                *self.token.lock().await = None;
                PushOutcome::Retryable
            }
            404 | 410 => PushOutcome::Unregistered,
            _ => PushOutcome::Rejected,
        };
        let retry_after = (outcome == PushOutcome::Retryable)
            .then(|| retry_after(response.headers(), SystemTime::now()))
            .flatten();
        Ok(Receipt {
            status,
            outcome,
            retry_after,
        })
    }
}

#[cfg(feature = "integration")]
impl Push {
    /// Controlled TLS transport only; native URI validation still runs before mapping.
    pub fn fixture(
        pfn: String,
        sid: String,
        secret: String,
        client: reqwest::Client,
        origin: &str,
        clock: std::sync::Arc<dyn rss_observation::Clock>,
    ) -> Result<Self, Error> {
        let mut push = Self::new(pfn, sid, secret, clock)?;
        let origin = reqwest::Url::parse(origin).map_err(unavailable)?;
        if origin.scheme() != "https" || origin.host_str() != Some("localhost") {
            return Err(Error::Malformed);
        }
        push.token_url = origin
            .join("/accesstoken.srf")
            .map_err(unavailable)?
            .to_string();
        push.transport_origin = Some(origin);
        push.client = client;
        Ok(push)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_wait_handles_seconds_dates_and_rejects_ambiguous_or_invalid_values() {
        use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(86400) + Duration::from_millis(500);
        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers, now), None);
        for (value, seconds) in [
            ("180", Some(180)),
            ("0", Some(0)),
            ("Fri, 02 Jan 1970 00:02:00 GMT", Some(120)),
            ("Thu, 01 Jan 1970 00:00:00 GMT", Some(0)),
            ("-1", None),
            ("+1", None),
            ("1.5", None),
            ("2147483648", None),
            ("18446744073709551616", None),
            ("later", None),
        ] {
            headers.insert(RETRY_AFTER, HeaderValue::from_static(value));
            assert_eq!(
                retry_after(&headers, now),
                seconds.map(Duration::from_secs),
                "{value}"
            );
        }
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        headers.append(RETRY_AFTER, HeaderValue::from_static("180"));
        assert_eq!(retry_after(&headers, now), None);
    }
    #[test]
    fn device_channel_is_limited_to_the_native_notification_service() {
        assert!(channel_uri("https://db5.notify.windows.com/?token=opaque").is_ok());
        for uri in [
            "http://db5.notify.windows.com/",
            "https://notify.windows.com.evil.test/",
            "https://localhost/",
            "https://notify.windows.com:8443/",
            "https://u@notify.windows.com/",
            "https://notify.windows.com/#fragment",
        ] {
            assert!(channel_uri(uri).is_err(), "{uri}");
        }
    }
}
