//! Product-owned Apple MDM. Device identity and durable execution remain in the product.
pub(crate) mod certificate;
pub(crate) mod config;
pub(crate) mod profile;
pub(crate) mod protocol;
pub(crate) mod push;

mod enrollment;
mod webhook;
use crate::{ConfigIssue, Error};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
pub(crate) struct Apple {
    config: config::Config,
    authority: certificate::Authority,
    signer: certificate::Signer,
    push: push::Push,
    challenge_key: ring::hmac::Key,
    notify_key: ring::hmac::Key,
    configuration: [u8; 32],
    tls: Arc<tokio_rustls::rustls::ServerConfig>,
}
impl Apple {
    pub(crate) fn signed_firewall(
        &self,
        identifier: &str,
        profile: uuid::Uuid,
        enabled: bool,
        now: i64,
    ) -> Result<Vec<u8>, Error> {
        self.signer
            .sign(&profile::firewall(identifier, profile, enabled)?, now)
    }

    pub(crate) fn load(config: config::Config, now: i64) -> Result<Self, Error> {
        let authority = certificate::Authority::load(&config.issuer_certificate_file, now)?;
        let signer = certificate::Signer::load(
            &config.profile_certificate_file,
            &config.profile_private_key_file,
            now,
        )?;
        let push = push::Push::load(&config, now)?;
        let challenge_key = webhook_key(&config.challenge_webhook)?;
        let notify_key = webhook_key(&config.notify_webhook)?;
        let configuration = Sha256::digest(
            serde_json::to_vec(&(
                "mdm.apple.enrollment/v1",
                &config.management.origin,
                &config.scep_url,
                &config.scep_provisioner,
                &config.apns_topic,
                &config.challenge_webhook.id,
                &config.notify_webhook.id,
                authority.issuer_fingerprint,
            ))
            .expect("closed configuration"),
        )
        .into();
        let tls = crate::native::tls::configuration(
            &config.management,
            Some(authority.verifier.clone()),
        )?;
        Ok(Self {
            config,
            authority,
            signer,
            push,
            challenge_key,
            notify_key,
            configuration,
            tls,
        })
    }
}
fn webhook_key(config: &config::Webhook) -> Result<ring::hmac::Key, Error> {
    let secret = crate::config::read(&config.secret_file, 1024, true)?;
    let secret = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(secret.as_slice())
            .map_err(|_| Error::Configuration(ConfigIssue::Apple))?,
    );
    if secret.len() < 32 {
        return Err(Error::Configuration(ConfigIssue::Apple));
    }
    Ok(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret))
}
mod checkin;
pub(crate) fn browser_routes() -> axum::Router<Arc<crate::api::App>> {
    use axum::routing::post;
    axum::Router::new()
        .route(
            "/api/v3/enrollments/{id}/profile",
            post(enrollment::download),
        )
        .route("/native/apple/scep/challenge", post(enrollment::challenge))
        .route("/native/apple/scep/notify", post(enrollment::notify))
        .layer(axum::extract::DefaultBodyLimit::max(128 * 1024))
}
pub(crate) fn router(
    app: Arc<crate::api::App>,
    clock: Arc<dyn rss_observation::Clock>,
) -> Option<crate::native::TlsRouter> {
    use crate::{
        api::{Envelope, envelope},
        native::{TlsRouter, admission},
    };
    use axum::{Router, extract::DefaultBodyLimit, middleware, routing::put};
    let apple = app.apple.as_ref()?;
    let router = Router::new()
        .route("/checkin", put(checkin::checkin))
        .route("/mdm", put(checkin::manage))
        .with_state(app.clone())
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(
            Envelope {
                host: apple
                    .config
                    .management
                    .origin
                    .trim_start_matches("https://")
                    .into(),
                clock: clock.clone(),
                access: app.access.clone(),
                requests: app.requests.clone(),
                tenant: app.identity.tenant.to_string(),
            },
            envelope,
        ))
        .layer(middleware::from_fn(admission::admit));
    Some(TlsRouter {
        admission: admission::Admission::new(clock, app.requests.clone(), "apple-management-tls"),
        listen: apple.config.management.listen,
        tls: apple.tls.clone(),
        router,
    })
}

#[cfg(test)]
mod tests;
