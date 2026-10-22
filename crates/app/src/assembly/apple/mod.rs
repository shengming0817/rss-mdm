//! Apple material consumption, TLS listener configuration and channel construction.
pub(crate) mod config;
use crate::{ConfigIssue, Error};
use std::sync::Arc;
#[cfg(test)]
#[path = "../../../tests/apple/certificate_support.rs"]
mod certificate;
pub(crate) struct Apple {
    pub(crate) channel: Arc<rss_mdm_apple_channel::Apple>,
    pub(crate) config: config::Config,
    pub(crate) tls: Arc<crate::native::tls::Configuration>,
}
impl Apple {
    pub(crate) fn load(
        protection: Arc<rss_mdm_native_protection::Protector>,
        config: config::Config,
        materials: rss_mdm_apple_channel::runtime_materials::runtime::Loaded,
        now: i64,
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
    ) -> Result<Self, Error> {
        let trust = crate::device_pki::load(
            &config.trust_file,
            rss_mdm_agent_wire::pki::Purpose::Apple,
            now,
        )?;
        if trust
            .public()
            .map_err(|_| Error::Configuration(ConfigIssue::AppleScep))?
            .origin
            != config.management.origin
        {
            return Err(Error::Configuration(ConfigIssue::AppleScep));
        }
        let authority = rss_mdm_device_trust::apple::AppleDeviceTrust::from_trust(trust)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleScep))?;
        let push = load_push(&config, &materials)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        let webhooks = crate::ca_webhooks::load(&config.webhooks, &authority.trust)?;
        let tls =
            crate::native::tls::configuration(&config.management, Some(authority.verifier()))?;
        let options = rss_mdm_apple_channel::Config {
            management: rss_mdm_apple_channel::Origin {
                origin: config.management.origin.clone(),
            },
            apns_topic: materials.apns_topic.clone(),
            identity_seed: rss_mdm_apple_channel::IdentitySeed {
                challenge_id: config.identity_seed.challenge_id.clone(),
                notify_id: config.identity_seed.notify_id.clone(),
            },
        };
        let channel = Arc::new(
            rss_mdm_apple_channel::Apple::new(
                protection,
                options,
                authority,
                materials.profile,
                push,
                materials.binding,
                webhooks,
                providers,
            )
            .with_account_keys(materials.accounts),
        );
        Ok(Self {
            config,
            channel,
            tls,
        })
    }
}
fn load_push(
    config: &config::Config,
    materials: &rss_mdm_apple_channel::runtime_materials::runtime::Loaded,
) -> Result<rss_mdm_apple_channel::push::Push, Error> {
    let certificate = &materials.apns_certificate;
    let key = &materials.apns_private_key;
    let _ = config;
    #[cfg(test)]
    if let Some((origin, root)) = &config.test_push_transport {
        let client = reqwest::Client::builder().no_proxy().add_root_certificate(
            reqwest::Certificate::from_pem(&crate::config::read(root, 128 * 1024, false)?)
                .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?,
        );
        return Ok(rss_mdm_apple_channel::push::Push::fixture(
            materials.apns_topic.clone(),
            certificate,
            key,
            Arc::new(crate::clock::SystemClock),
            client,
            origin.clone(),
        )?);
    }
    Ok(rss_mdm_apple_channel::push::Push::from_bytes(
        materials.apns_topic.clone(),
        certificate,
        key,
        Arc::new(crate::clock::SystemClock),
    )?)
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
