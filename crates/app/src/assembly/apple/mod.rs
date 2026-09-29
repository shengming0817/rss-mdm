//! Apple file loading, TLS listener configuration and channel construction.
pub(crate) mod config;
use crate::{ConfigIssue, Error};
use base64::Engine;
#[cfg(not(test))]
use rss_mdm_certificate::apple as certificate;
use std::sync::Arc;
#[cfg(test)]
#[path = "../../../tests/apple/certificate_support.rs"]
mod certificate;
pub(crate) struct Apple {
    pub(crate) channel: Arc<rss_mdm_apple_channel::Apple>,
    pub(crate) config: config::Config,
    pub(crate) tls: Arc<tokio_rustls::rustls::ServerConfig>,
}
impl Apple {
    pub(crate) fn load(config: config::Config, now: i64) -> Result<Self, Error> {
        let authority = certificate::AppleDeviceTrust::from_bytes(
            &crate::config::read(&config.issuer_certificate_file, 32768, false)
                .map_err(|_| Error::Configuration(ConfigIssue::AppleScep))?,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::AppleScep))?;
        let signer = certificate::ProfileSigner::from_bytes(
            &crate::config::read(&config.profile_certificate_file, 128 * 1024, false)
                .map_err(|_| Error::Configuration(ConfigIssue::AppleProfileSigner))?,
            &crate::config::read(&config.profile_private_key_file, 32768, true)
                .map_err(|_| Error::Configuration(ConfigIssue::AppleProfileSigner))?,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::AppleProfileSigner))?;
        let push = load_push(&config).map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        let challenge_key = webhook_key(&config.challenge_webhook)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleChallengeWebhook))?;
        let notify_key = webhook_key(&config.notify_webhook)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleNotifyWebhook))?;
        let tls =
            crate::native::tls::configuration(&config.management, Some(authority.verifier()))?;
        let options = rss_mdm_apple_channel::Config {
            management: rss_mdm_apple_channel::Origin {
                origin: config.management.origin.clone(),
            },
            scep_url: config.scep_url.clone(),
            scep_provisioner: config.scep_provisioner.clone(),
            apns_topic: config.apns_topic.clone(),
            challenge_webhook: rss_mdm_apple_channel::Webhook {
                id: config.challenge_webhook.id.clone(),
            },
            notify_webhook: rss_mdm_apple_channel::Webhook {
                id: config.notify_webhook.id.clone(),
            },
        };
        let channel = Arc::new(rss_mdm_apple_channel::Apple::new(
            options,
            authority,
            signer,
            push,
            challenge_key,
            notify_key,
        ));
        Ok(Self {
            config,
            channel,
            tls,
        })
    }
}
fn load_push(config: &config::Config) -> Result<rss_mdm_apple_channel::push::Push, Error> {
    let certificate = crate::config::read(&config.apns_certificate_file, 128 * 1024, false)?;
    let key = crate::config::read(&config.apns_private_key_file, 32768, true)?;
    #[cfg(test)]
    if let Some((origin, root)) = &config.test_push_transport {
        let client = reqwest::Client::builder().no_proxy().add_root_certificate(
            reqwest::Certificate::from_pem(&crate::config::read(root, 128 * 1024, false)?)
                .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?,
        );
        return Ok(rss_mdm_apple_channel::push::Push::fixture(
            config.apns_topic.clone(),
            &certificate,
            &key,
            Arc::new(crate::clock::SystemClock),
            client,
            origin.clone(),
        )?);
    }
    Ok(rss_mdm_apple_channel::push::Push::from_bytes(
        config.apns_topic.clone(),
        &certificate,
        &key,
        Arc::new(crate::clock::SystemClock),
    )?)
}
fn webhook_key(config: &config::Webhook) -> Result<ring::hmac::Key, Error> {
    let secret = crate::config::read(&config.secret_file, 1024, true)?;
    let secret = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(secret.as_slice())
            .map_err(|_| Error::Configuration(ConfigIssue::SecretContents))?,
    );
    if secret.len() < 32 {
        return Err(Error::Configuration(ConfigIssue::SecretContents));
    }
    Ok(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret))
}

pub(crate) fn router(
    apple: Option<&Apple>,
    app: Arc<rss_mdm_apple_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
) -> Option<crate::native::TlsRouter> {
    use crate::native::{TlsRouter, admission};
    use axum::middleware;
    use rss_mdm_apple_channel::boundary::Envelope;
    let apple = apple?;
    let router = rss_mdm_apple_channel::router(
        app.clone(),
        Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: apple
                .config
                .management
                .origin
                .trim_start_matches("https://")
                .into(),
            clock: clock.clone(),
            audit_store: app.audit_store.clone(),
            requests: app.requests.clone(),
            tenant: app.identity.tenant().to_string(),
        },
    )
    .layer(middleware::from_fn(admission::admit));
    Some(TlsRouter {
        admission: admission::Admission::new(clock, app.requests.clone(), "apple-management-tls"),
        listen: apple.config.management.listen,
        tls: apple.tls.clone(),
        router,
    })
}
#[cfg(test)]
#[path = "../../../tests/apple/push_support.rs"]
pub(crate) mod push;
#[cfg(test)]
#[path = "../../../tests/apple/mod.rs"]
mod tests;
