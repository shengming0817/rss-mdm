//! Certificate-authenticated production HTTP/2 APNs. An accepted push is never command evidence.
//! ref: micromdm/nanomdm push/nanopush/provider.go@b2fd8e1655633d1721b1fbebd7301e5d14c46bc0
use crate::{ConfigIssue, Error, Failure};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{DecodePem, Encode},
};

pub(super) struct Push {
    client: reqwest::Client,
    pub(super) configuration: [u8; 32],
    origin: String,
    topic: String,
    pub(super) expires: u64,
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Accepted,
    Retryable,
    Unregistered,
    Rejected,
}
pub(super) struct Receipt {
    pub id: Uuid,
    pub status: u16,
    pub outcome: Outcome,
    pub reason: Option<Reason>,
    pub timestamp: Option<u64>,
}
impl Push {
    pub(super) fn load(config: &super::config::Config, now: i64) -> Result<Self, Error> {
        let client = reqwest::Client::builder();
        #[cfg(test)]
        let client = if let Some((_, root)) = &config.test_push_transport {
            client.no_proxy().add_root_certificate(
                reqwest::Certificate::from_pem(&crate::config::read(root, 128 * 1024, false)?)
                    .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?,
            )
        } else {
            client
        };
        Self::with_client(config, now, client)
    }
    fn with_client(
        config: &super::config::Config,
        now: i64,
        client: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        let mut pem = crate::config::read(&config.apns_certificate_file, 128 * 1024, false)?;
        let leaf = Certificate::from_pem(&pem)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        use sha2::{Digest, Sha256};
        let configuration = Sha256::digest(
            leaf.to_der()
                .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?,
        )
        .into();
        let topic = leaf
            .tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .filter(|a| a.oid.to_string() == "0.9.2342.19200300.100.1.1")
            .map(|a| a.value.value())
            .collect::<Vec<_>>();
        let expires = leaf
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if topic != vec![config.apns_topic.as_bytes()]
            || now <= 0
            || expires <= now as u64
            || leaf
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                > now as u64
        {
            return Err(Error::Configuration(ConfigIssue::AppleApns));
        }
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&crate::config::read(
            &config.apns_private_key_file,
            32768,
            true,
        )?);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        let client = client
            .identity(identity)
            .https_only(true)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        let origin = "https://api.push.apple.com".to_owned();
        #[cfg(test)]
        let origin = config
            .test_push_transport
            .as_ref()
            .map_or(origin, |(origin, _)| origin.clone());
        Ok(Self {
            client,
            configuration,
            origin,
            topic: config.apns_topic.clone(),
            expires,
        })
    }
    pub(super) async fn send(
        &self,
        id: Uuid,
        token: &[u8],
        magic: &str,
        now: i64,
    ) -> Result<Receipt, Error> {
        if now <= 0 || self.expires <= now as u64 {
            return Err(Error::Unavailable(Failure::Certificate));
        }
        if token.is_empty() || token.len() > 512 || magic.is_empty() || magic.len() > 1024 {
            return Err(Error::Malformed);
        }
        let token = token
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut response = self
            .client
            .post(format!("{}/3/device/{token}", self.origin))
            .header("apns-topic", &self.topic)
            .header("apns-id", id.to_string())
            .header("apns-expiration", "0")
            .json(&serde_json::json!({"mdm":magic}))
            .send()
            .await
            .map_err(|_| Error::Unavailable(Failure::ApplePush))?;
        if response.version() != reqwest::Version::HTTP_2 {
            return Err(Error::Unavailable(Failure::ApplePush));
        }
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Unavailable(Failure::ApplePush))?
        {
            if bytes.len() + chunk.len() > 4096 {
                return Ok(Receipt {
                    id,
                    status,
                    outcome: Outcome::Retryable,
                    reason: Some(Reason::InvalidResponse),
                    timestamp: None,
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(classify(id, status, &bytes))
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    TokenInvalid,
    Certificate,
    Topic,
    Payload,
    Request,
    Throttled,
    Server,
    IdleTimeout,
    InvalidResponse,
}
fn classify(id: Uuid, status: u16, bytes: &[u8]) -> Receipt {
    #[derive(Deserialize)]
    struct Body {
        reason: String,
        timestamp: Option<u64>,
    }
    if status == 200 && bytes.is_empty() {
        return Receipt {
            id,
            status,
            outcome: Outcome::Accepted,
            reason: None,
            timestamp: None,
        };
    }
    let body = serde_json::from_slice::<Body>(bytes).ok();
    let reason = body.as_ref().map(|b| b.reason.as_str()).unwrap_or("");
    let (outcome, reason) = match (status, reason) {
        (400, "BadDeviceToken" | "DeviceTokenNotForTopic")
        | (410, "Unregistered" | "ExpiredToken") => (Outcome::Unregistered, Reason::TokenInvalid),
        (
            403,
            "BadCertificate"
            | "BadCertificateEnvironment"
            | "Forbidden"
            | "ExpiredProviderToken"
            | "InvalidProviderToken"
            | "MissingProviderToken"
            | "UnrelatedKeyIdInToken"
            | "BadEnvironmentKeyIdInToken",
        ) => (Outcome::Rejected, Reason::Certificate),
        (400, "BadTopic" | "MissingTopic" | "TopicDisallowed") => {
            (Outcome::Rejected, Reason::Topic)
        }
        (413, "PayloadTooLarge") | (400, "PayloadEmpty") => (Outcome::Rejected, Reason::Payload),
        (
            400,
            "BadCollapseId" | "BadExpirationDate" | "BadMessageId" | "BadPriority"
            | "DuplicateHeaders" | "InvalidPushType" | "MissingDeviceToken",
        )
        | (404, "BadPath")
        | (405, "MethodNotAllowed") => (Outcome::Rejected, Reason::Request),
        (400, "IdleTimeout") => (Outcome::Retryable, Reason::IdleTimeout),
        (429, "TooManyRequests" | "TooManyProviderTokenUpdates") => {
            (Outcome::Retryable, Reason::Throttled)
        }
        (500..=599, _) => (Outcome::Retryable, Reason::Server),
        _ => (Outcome::Retryable, Reason::InvalidResponse),
    };
    Receipt {
        id,
        status,
        outcome,
        reason: Some(reason),
        timestamp: body.and_then(|b| b.timestamp),
    }
}
#[derive(Clone, Copy)]
pub(super) enum WakeHealth {
    Idle,
    Healthy,
    Configuration,
}
#[derive(Default)]
struct Health {
    failures: u8,
    configuration: bool,
}
impl Health {
    fn observe(&mut self, result: &Result<WakeHealth, Error>) -> (bool, Duration) {
        match result {
            Ok(value) => {
                self.failures = 0;
                match value {
                    WakeHealth::Healthy => self.configuration = false,
                    WakeHealth::Configuration => self.configuration = true,
                    WakeHealth::Idle => {}
                }
            }
            Err(_) => self.failures = self.failures.saturating_add(1),
        }
        (
            !self.configuration && self.failures < 3,
            Duration::from_secs(1 << self.failures.min(5)),
        )
    }
}
pub(crate) fn registration(
    apple: std::sync::Arc<super::Apple>,
    commands: std::sync::Arc<crate::commands::Commands>,
    access: std::sync::Arc<crate::AccessStore>,
    tenant: String,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("apple-apns", Duration::from_secs(8));
    task.into_registration(move |token| async move {
        let mut certificate_levels = [None; 3];
        let mut health = Health::default();
        loop {
            if let Ok(now) = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock) { apple.report_certificate_health(now, &mut certificate_levels); }
            let result = tokio::select! { biased; ()=token.cancelled()=>return Ok(()), result=async {
                let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
                super::renewal::maintain(&apple, &access, &tenant, now).await?;
                wake(&apple.push,&commands).await
            }=>result };
            let (ready, delay) = health.observe(&result);
            let changed = apple.push_ready.swap(ready, std::sync::atomic::Ordering::Relaxed) != ready;
            if result.is_err() || changed { eprintln!("{}",serde_json::json!({"event":"apple_push_health","ready":ready,"consecutive_internal_failures":health.failures,"configuration_failure":health.configuration})); }
            tokio::select! { biased; ()=token.cancelled()=>return Ok(()), ()=tokio::time::sleep(delay)=>{} }
        }
    })
}
pub(super) async fn wake(
    push: &Push,
    commands: &crate::commands::Commands,
) -> Result<WakeHealth, Error> {
    use crate::clock::Clock;
    let Some(wake) = commands.apple_wake(&push.configuration).await? else {
        return Ok(WakeHealth::Idle);
    };
    let now = crate::clock::SystemClock.unix_seconds()?;
    let (status, outcome, reason, timestamp, failure) =
        match push.send(wake.id, &wake.token, &wake.magic, now).await {
            Ok(receipt) if receipt.id == wake.id => (
                Some(receipt.status),
                receipt.outcome,
                receipt.reason,
                receipt.timestamp,
                None,
            ),
            Err(Error::Unavailable(Failure::Certificate)) => (
                None,
                Outcome::Retryable,
                None,
                None,
                Some("certificate_expired"),
            ),
            _ => (None, Outcome::Retryable, None, None, Some("transport")),
        };
    commands.apple_pushed(&wake, status, outcome).await?;
    if outcome != Outcome::Accepted {
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_push_result","registration":wake.registration,"token_revision":wake.revision,"status":status,"outcome":outcome,"reason":reason,"timestamp":timestamp,"failure":failure})
        );
    }
    Ok(if outcome == Outcome::Rejected {
        WakeHealth::Configuration
    } else {
        WakeHealth::Healthy
    })
}

#[cfg(test)]
#[path = "push_tests.rs"]
pub(super) mod tests;
