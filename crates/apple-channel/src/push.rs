//! Certificate-authenticated production HTTP/2 APNs. An accepted push is never command evidence.
//! ref: micromdm/nanomdm push/nanopush/provider.go@b2fd8e1655633d1721b1fbebd7301e5d14c46bc0
use crate::{ConfigIssue, Error, Failure};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;
use x509_cert::{Certificate, der::DecodePem};

pub struct Push {
    clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
    client: reqwest::Client,
    origin: String,
    topic: String,
    pub expires: u64,
}
use crate::protocol_types::PushOutcome;
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
        clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
    ) -> Result<Self, Error> {
        Self::with_client(
            topic,
            certificate,
            private_key,
            clock,
            reqwest::Client::builder(),
        )
    }
    #[cfg(feature = "integration")]
    pub(crate) fn at_loopback(mut self, port: u16) -> Self {
        self.origin = format!("https://localhost:{port}");
        self
    }
    pub(crate) fn with_client(
        topic: String,
        certificate: &[u8],
        private_key: &[u8],
        clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
        client: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        if certificate.is_empty()
            || certificate.len() > 128 * 1024
            || private_key.is_empty()
            || private_key.len() > 32768
        {
            return Err(Error::Configuration(ConfigIssue::AppleApns));
        }
        let now = clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let mut pem = zeroize::Zeroizing::new(certificate.to_vec());
        let configured_topic = topic;
        let leaf = Certificate::from_pem(&pem)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
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

/// The database lease is scoped to one device or user channel.
#[derive(Clone)]
pub struct Channel {
    pub(crate) device: Uuid,
    pub(crate) user_key: String,
    pub(crate) topic: String,
    pub(crate) material_revision: i64,
}
pub(crate) type Candidate = (Uuid, Uuid, String, String);

fn failure(tenant: impl std::fmt::Display, stage: &'static str) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"apple_push_failure","tenant":tenant.to_string(),"stage":stage})
    );
}

pub fn registration(
    app: std::sync::Arc<crate::HttpState>,
    limits: rss_mdm_work_page::external::Limits,
    notify: std::sync::Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    use rss_mdm_work_page::Failure::Retry;
    let (task, _) = rss_runtime::ManagedTask::prepare("apple-apns", Duration::from_secs(8));
    task.into_registration(move |stop| async move {
        let idle = Duration::from_secs(5);
        let maintenance = rss_mdm_work_page::run(
            limits.total,
            idle,
            &stop,
            &notify,
            |after| {
                let store = &app.access;
                async move {
                    store
                        .maintenance_work_scopes(after)
                        .await
                        .map_err(|_| eprintln!("apple_maintenance_discovery_failed"))
                }
            },
            |tenant| {
                let app = app.clone();
                async move {
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(|_| failure(tenant, "authority"))?;
                    let execution = app.execution(tenant);
                    let apple = app
                        .apple(execution)
                        .await
                        .map_err(|_| failure(tenant, "load_materials"))?;
                    let time = apple
                        .push
                        .clock
                        .unix_seconds()
                        .ok_or_else(|| failure(tenant, "clock"))?;
                    apple
                        .check_materials(&app.access, &tenant.to_string(), time)
                        .await
                        .map_err(|_| failure(tenant, "check_materials"))?;
                    let progress =
                        super::renewal::maintain(execution, &apple, &app.audit_store, time)
                            .await
                            .map_err(|_| failure(tenant, "renewal"))?;
                    if progress > 0 {
                        return Ok(Duration::ZERO);
                    }
                    super::renewal::next_maintenance(&app.access, &tenant.to_string())
                        .await
                        .map(|v| v.unwrap_or(idle))
                        .map_err(|_| failure(tenant, "next_maintenance"))
                }
            },
            |_| {},
        );
        let sends = rss_mdm_work_page::run_limited(
            limits.total,
            idle,
            &stop,
            &notify,
            (
                |key: &Candidate| limits.work(key.0, key.3.clone(), (key.0, key.1, key.2.clone())),
                |after: Option<Candidate>| {
                    let app = &app;
                    async move {
                        let observed = app.clock.unix_seconds().ok_or(Retry)?;
                        app.access
                            .push_channel_page(after, observed)
                            .await
                            .map_err(|_| {
                                eprintln!("apple_push_discovery_failed");
                                Retry
                            })
                    }
                },
            ),
            |(tenant, device, user_key, topic), stop| {
                let app = app.clone();
                async move {
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(|_| Retry)?;
                    let execution = app.execution(tenant);
                    let apple = app.apple(execution).await.map_err(|_| {
                        failure(tenant, "load_materials");
                        Retry
                    })?;
                    if stop.is_cancelled() || apple.push.topic != topic {
                        return Ok(idle);
                    }
                    let now = apple.push.clock.unix_seconds().ok_or_else(|| {
                        failure(tenant, "clock");
                        Retry
                    })?;
                    apple
                        .check_materials(&app.access, &tenant.to_string(), now)
                        .await
                        .map_err(|_| {
                            failure(tenant, "check_materials");
                            Retry
                        })?;
                    let material_revision = apple.material_selection().apns.ok_or_else(|| {
                        failure(tenant, "apns_revision");
                        Retry
                    })?;
                    if stop.is_cancelled() {
                        return Ok(idle);
                    }
                    wake(
                        execution,
                        &apple.push,
                        &app.delivery,
                        Channel {
                            device,
                            user_key,
                            topic,
                            material_revision,
                        },
                        now,
                    )
                    .await
                    .map(|_| idle)
                    .map_err(|_| {
                        failure(tenant, "wake");
                        Retry
                    })
                }
            },
            |_| {},
        );
        let ((), outcome) = tokio::join!(maintenance, sends);
        let outcome: Result<(), std::convert::Infallible> = outcome;
        match outcome {
            Ok(()) => Ok(()),
            Err(never) => match never {},
        }
    })
}
async fn wake(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    push: &Push,
    delivery: &crate::delivery::Delivery,
    channel: Channel,
    now: i64,
) -> Result<WakeHealth, Error> {
    let Some(wake) = delivery.wake(execution, channel).await? else {
        return Ok(WakeHealth::Idle);
    };
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
    if !delivery.pushed(&wake, status, outcome).await? {
        return Ok(WakeHealth::Idle);
    }
    if outcome != PushOutcome::Accepted {
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_push_result","wake_id":wake.id,"channel":if wake.user_key.is_empty(){"device"}else{"user"},"device":wake.device,"token_revision":wake.revision,"status":status,"outcome":outcome,"reason":reason,"timestamp":timestamp,"failure":failure})
        );
    }
    Ok(if outcome == PushOutcome::Rejected {
        WakeHealth::Configuration
    } else {
        WakeHealth::Healthy
    })
}

#[cfg(test)]
#[path = "../tests/apns.rs"]
mod tests;
