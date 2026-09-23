//! Product-owned Apple MDM. Device identity and durable execution remain in the product.
pub(crate) mod attempt;
pub(crate) mod certificate;
pub(crate) mod config;
pub(crate) mod profile;
pub(crate) mod protocol;
pub(crate) mod push;

mod enrollment;
mod renewal;
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
    push_ready: std::sync::atomic::AtomicBool,
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
        let authority = certificate::Authority::load(&config.issuer_certificate_file, now)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleScep))?;
        let signer = certificate::Signer::load(
            &config.profile_certificate_file,
            &config.profile_private_key_file,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::AppleProfileSigner))?;
        let push = push::Push::load(&config, now)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleApns))?;
        let challenge_key = webhook_key(&config.challenge_webhook)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleChallengeWebhook))?;
        let notify_key = webhook_key(&config.notify_webhook)
            .map_err(|_| Error::Configuration(ConfigIssue::AppleNotifyWebhook))?;
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
            push_ready: std::sync::atomic::AtomicBool::new(true),
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
            .map_err(|_| Error::Configuration(ConfigIssue::SecretContents))?,
    );
    if secret.len() < 32 {
        return Err(Error::Configuration(ConfigIssue::SecretContents));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CertificateLevel {
    Healthy,
    RenewSoon,
    Critical,
    Expired,
}
#[derive(Clone, Copy, serde::Serialize)]
pub(super) struct CertificateHealth {
    purpose: &'static str,
    level: CertificateLevel,
    remaining_days: u64,
}
impl CertificateHealth {
    fn new(purpose: &'static str, expires: u64, now: i64) -> Self {
        let remaining = expires.saturating_sub(now.max(0) as u64);
        let level = if now <= 0 || expires <= now as u64 {
            CertificateLevel::Expired
        } else if remaining <= 7 * 86400 {
            CertificateLevel::Critical
        } else if remaining <= 30 * 86400 {
            CertificateLevel::RenewSoon
        } else {
            CertificateLevel::Healthy
        };
        Self {
            purpose,
            level,
            remaining_days: remaining / 86400,
        }
    }
}
impl Apple {
    pub(super) fn certificate_health(&self, now: i64) -> [CertificateHealth; 3] {
        [
            CertificateHealth::new("scep_issuer", self.authority.expires(), now),
            CertificateHealth::new("profile_signer", self.signer.expires(), now),
            CertificateHealth::new("apns", self.push.expires, now),
        ]
    }
    pub(crate) fn ready(&self, now: i64) -> bool {
        if !self.push_ready.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        self.certificate_health(now)
            .iter()
            .all(|item| item.level != CertificateLevel::Expired)
    }
    pub(super) fn report_certificate_health(
        &self,
        now: i64,
        previous: &mut [Option<CertificateLevel>; 3],
    ) {
        for (item, last) in self.certificate_health(now).into_iter().zip(previous) {
            if *last != Some(item.level) && item.level != CertificateLevel::Healthy {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"apple_certificate_health","certificate":item})
                );
            }
            *last = Some(item.level);
        }
    }
}
#[cfg(test)]
mod health_tests {
    use super::*;
    #[test]
    fn certificate_health_warns_before_expiry_and_fails_closed_at_expiry() {
        for (remaining, level) in [
            (31 * 86400, CertificateLevel::Healthy),
            (30 * 86400, CertificateLevel::RenewSoon),
            (7 * 86400, CertificateLevel::Critical),
            (1, CertificateLevel::Critical),
            (0, CertificateLevel::Expired),
        ] {
            assert_eq!(
                CertificateHealth::new("fixture", 100 + remaining, 100).level,
                level
            );
        }
        assert_eq!(
            CertificateHealth::new("fixture", 100, 101).level,
            CertificateLevel::Expired
        );
        assert_eq!(
            CertificateHealth::new("fixture", 100, -1).level,
            CertificateLevel::Expired
        );
    }
}
