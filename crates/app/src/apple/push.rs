//! Certificate-authenticated production HTTP/2 APNs. An accepted push is never command evidence.
//! ref: micromdm/nanomdm push/nanopush/provider.go@b2fd8e1655633d1721b1fbebd7301e5d14c46bc0
use crate::{ConfigIssue, Error, Failure};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;
use x509_cert::{Certificate, der::DecodePem};

pub(super) struct Push {
    client: reqwest::Client,
    origin: String,
    topic: String,
    expires: u64,
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
}
impl Push {
    pub(super) fn load(config: &super::config::Config, now: i64) -> Result<Self, Error> {
        Self::with_client(config, now, reqwest::Client::builder())
    }
    fn with_client(
        config: &super::config::Config,
        now: i64,
        client: reqwest::ClientBuilder,
    ) -> Result<Self, Error> {
        let mut pem = crate::config::read(&config.apns_certificate_file, 128 * 1024, false)?;
        let leaf =
            Certificate::from_pem(&pem).map_err(|_| Error::Configuration(ConfigIssue::Apple))?;
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
            return Err(Error::Configuration(ConfigIssue::Apple));
        }
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&crate::config::read(
            &config.apns_private_key_file,
            32768,
            true,
        )?);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|_| Error::Configuration(ConfigIssue::Apple))?;
        let client = client
            .identity(identity)
            .https_only(true)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(|_| Error::Configuration(ConfigIssue::Apple))?;
        Ok(Self {
            client,
            origin: "https://api.push.apple.com".into(),
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
        let response = self
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
        let outcome = match status {
            200 => Outcome::Accepted,
            410 => Outcome::Unregistered,
            429 | 500..=599 => Outcome::Retryable,
            _ => Outcome::Rejected,
        };
        Ok(Receipt {
            id,
            status,
            outcome,
        })
    }
}

pub(crate) fn registration(
    apple: std::sync::Arc<super::Apple>,
    commands: std::sync::Arc<crate::commands::Commands>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("apple-apns", Duration::from_secs(8));
    task.into_registration(move|token|async move {
        let mut tick=tokio::time::interval(Duration::from_secs(1));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select!{biased;()=token.cancelled()=>return Ok(()),_=tick.tick()=>{}}
            let result=tokio::select!{biased;()=token.cancelled()=>return Ok(()),result=wake(&apple,&commands)=>result};
            if result.is_err(){eprintln!("{}",serde_json::json!({"event":"apple_push_failure"}));}
        }
    })
}
async fn wake(apple: &super::Apple, commands: &crate::commands::Commands) -> Result<(), Error> {
    use crate::clock::Clock;
    let Some(wake) = commands.apple_wake().await? else {
        return Ok(());
    };
    let now = crate::clock::SystemClock.unix_seconds()?;
    let (status, outcome) = match apple
        .push
        .send(wake.id, &wake.token, &wake.magic, now)
        .await
    {
        Ok(receipt) if receipt.id == wake.id => (Some(receipt.status), receipt.outcome),
        _ => (None, Outcome::Retryable),
    };
    commands.apple_pushed(&wake, status, outcome).await
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
