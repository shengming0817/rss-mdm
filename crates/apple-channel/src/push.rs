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

pub struct Push {
    clock: std::sync::Arc<dyn rss_mdm_flow_service::clock::Clock>,
    client: reqwest::Client,
    pub configuration: [u8; 32],
    origin: String,
    topic: String,
    pub expires: u64,
}
use rss_mdm_execution_service::channels::PushOutcome;
pub struct Receipt {
    pub id: Uuid,
    pub status: u16,
    pub outcome: PushOutcome,
    pub reason: Option<Reason>,
    pub timestamp: Option<u64>,
}
impl Push {
    pub fn from_bytes(
        topic: String,
        certificate: &[u8],
        private_key: &[u8],
        clock: std::sync::Arc<dyn rss_mdm_flow_service::clock::Clock>,
    ) -> Result<Self, Error> {
        Self::with_client(
            topic,
            certificate,
            private_key,
            clock,
            reqwest::Client::builder(),
        )
    }
    fn with_client(
        topic: String,
        certificate: &[u8],
        private_key: &[u8],
        clock: std::sync::Arc<dyn rss_mdm_flow_service::clock::Clock>,
        client: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        if certificate.is_empty()
            || certificate.len() > 128 * 1024
            || private_key.is_empty()
            || private_key.len() > 32768
        {
            return Err(Error::Configuration(ConfigIssue::AppleApns));
        }
        let now = clock.unix_seconds()?;
        let mut pem = zeroize::Zeroizing::new(certificate.to_vec());
        let configured_topic = topic;
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
        if topic != vec![configured_topic.as_bytes()]
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
        pem.extend_from_slice(private_key);
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
        Ok(Self {
            client,
            configuration,
            origin,
            topic: configured_topic,
            clock,
            expires,
        })
    }
    pub async fn send(
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
                    outcome: PushOutcome::Retryable,
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
pub enum Reason {
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
            outcome: PushOutcome::Accepted,
            reason: None,
            timestamp: None,
        };
    }
    let body = serde_json::from_slice::<Body>(bytes).ok();
    let reason = body.as_ref().map(|b| b.reason.as_str()).unwrap_or("");
    let (outcome, reason) = match (status, reason) {
        (400, "BadDeviceToken" | "DeviceTokenNotForTopic")
        | (410, "Unregistered" | "ExpiredToken") => {
            (PushOutcome::Unregistered, Reason::TokenInvalid)
        }
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
        ) => (PushOutcome::Rejected, Reason::Certificate),
        (400, "BadTopic" | "MissingTopic" | "TopicDisallowed") => {
            (PushOutcome::Rejected, Reason::Topic)
        }
        (413, "PayloadTooLarge") | (400, "PayloadEmpty") => {
            (PushOutcome::Rejected, Reason::Payload)
        }
        (
            400,
            "BadCollapseId" | "BadExpirationDate" | "BadMessageId" | "BadPriority"
            | "DuplicateHeaders" | "InvalidPushType" | "MissingDeviceToken",
        )
        | (404, "BadPath")
        | (405, "MethodNotAllowed") => (PushOutcome::Rejected, Reason::Request),
        (400, "IdleTimeout") => (PushOutcome::Retryable, Reason::IdleTimeout),
        (429, "TooManyRequests" | "TooManyProviderTokenUpdates") => {
            (PushOutcome::Retryable, Reason::Throttled)
        }
        (500..=599, _) => (PushOutcome::Retryable, Reason::Server),
        _ => (PushOutcome::Retryable, Reason::InvalidResponse),
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
pub enum WakeHealth {
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
pub fn registration(
    apple: std::sync::Arc<super::Apple>,
    execution: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    access: std::sync::Arc<crate::Store>,
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: String,
    notify: std::sync::Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("apple-apns", Duration::from_secs(8));
    task.into_registration(move |token| async move {
        let mut certificate_levels = [None; 3];
        let mut health = Health::default();
        loop {
            if let Ok(now) = apple.push.clock.unix_seconds() { apple.report_certificate_health(now, &mut certificate_levels); }
            let result = tokio::select! { biased; ()=token.cancelled()=>return Ok(()), result=cycle(&apple, &execution, &access, &audit_store, &tenant)=>result };
            let health_result = result.as_ref().map(|(_, wake, _)| *wake).map_err(|_| Error::Unavailable(Failure::AppleStorage));
            let (ready, delay) = health.observe(&health_result);
            let changed = apple.push_ready.swap(ready, std::sync::atomic::Ordering::Relaxed) != ready;
            if result.is_err() || changed { eprintln!("{}",serde_json::json!({"event":"apple_push_health","ready":ready,"consecutive_internal_failures":health.failures,"configuration_failure":health.configuration})); }
            match result {
                Ok((progress, wake, _)) if progress > 0 || !matches!(wake, WakeHealth::Idle) => continue,
                Ok((_, _, nearest)) => {
                    crate::wait(&notify, &token, nearest).await;
                }
                Err(_) => { tokio::select! { biased; ()=token.cancelled()=>return Ok(()), ()=tokio::time::sleep(delay)=>{} } }
            }
        }
    })
}
pub async fn wake(
    push: &Push,
    execution: &rss_mdm_execution_service::ExecutionService,
) -> Result<WakeHealth, Error> {
    let Some(wake) = execution.apple_wake(&push.configuration).await? else {
        return Ok(WakeHealth::Idle);
    };
    let now = push.clock.unix_seconds()?;
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
                PushOutcome::Retryable,
                None,
                None,
                Some("certificate_expired"),
            ),
            _ => (None, PushOutcome::Retryable, None, None, Some("transport")),
        };
    execution.apple_pushed(&wake, status, outcome).await?;
    if outcome != PushOutcome::Accepted {
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_push_result","registration":wake.registration,"token_revision":wake.revision,"status":status,"outcome":outcome,"reason":reason,"timestamp":timestamp,"failure":failure})
        );
    }
    Ok(if outcome == PushOutcome::Rejected {
        WakeHealth::Configuration
    } else {
        WakeHealth::Healthy
    })
}

pub async fn cycle(
    apple: &super::Apple,
    execution: &rss_mdm_execution_service::ExecutionService,
    access: &crate::Store,
    audit_store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
) -> Result<(usize, WakeHealth, Option<Duration>), Error> {
    let now = apple.push.clock.unix_seconds()?;
    let progress = super::renewal::maintain(apple, access, audit_store, tenant, now).await?;
    let wake = wake(&apple.push, execution).await?;
    let nearest = if progress == 0 && matches!(wake, WakeHealth::Idle) {
        super::renewal::next_maintenance(access, tenant).await?
    } else {
        None
    };
    Ok((progress, wake, nearest))
}

#[cfg(feature = "integration")]
impl Push {
    pub fn fixture(
        topic: String,
        certificate: &[u8],
        private_key: &[u8],
        clock: std::sync::Arc<dyn rss_mdm_flow_service::clock::Clock>,
        client: reqwest::ClientBuilder,
        origin: String,
    ) -> Result<Self, Error> {
        let mut push = Self::with_client(topic, certificate, private_key, clock, client)?;
        push.origin = origin;
        Ok(push)
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

#[cfg(test)]
#[path = "../tests/apns.rs"]
mod tests;
