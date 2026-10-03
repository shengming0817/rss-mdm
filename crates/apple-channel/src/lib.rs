//! Apple MDM protocol, SCEP lifecycle and APNs transport.
mod agent_collection;
pub mod attempt;
mod checkin;
pub mod collection;
mod database;
pub mod enrollment;
mod error;
pub mod flow_store;
mod material;
mod native;
mod operations;
mod profiles;
mod protection;
pub mod push;
pub mod renewal;
mod webhook;
pub use database::Store;
pub use error::Error;
use rss_mdm_apple_mdm::{profile, protocol};
use rss_mdm_authorization_service as authorization;
use rss_mdm_certificate::apple as certificate;
use rss_mdm_execution_service as execution;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
use rss_mdm_registration_service::{device, enrollment as registration_enrollment};
use sha2::{Digest, Sha256};
use std::sync::Arc;
pub struct Config {
    pub management: Origin,
    pub scep_url: String,
    pub scep_provisioner: String,
    pub apns_topic: String,
    pub challenge_webhook: Webhook,
    pub notify_webhook: Webhook,
}
pub struct Origin {
    pub origin: String,
}
pub struct Webhook {
    pub id: String,
}
pub struct Apple {
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_identity: Option<rss_mdm_execution_service::agent_install::Identity>,
    pub(crate) config: Config,
    pub(crate) authority: certificate::AppleDeviceTrust,
    pub(crate) signer: certificate::ProfileSigner,
    pub(crate) push: push::Push,
    push_ready: std::sync::atomic::AtomicBool,
    pub(crate) challenge_key: ring::hmac::Key,
    pub(crate) notify_key: ring::hmac::Key,
    configuration: [u8; 32],
}
pub struct Health {
    pub push_available: bool,
    pub certificates: [CertificateHealth; 3],
}
impl Health {
    pub fn certificates_expired(&self) -> bool {
        self.certificates
            .iter()
            .any(|item| item.level == CertificateLevel::Expired)
    }
    pub fn is_ready(&self) -> bool {
        self.push_available && !self.certificates_expired()
    }
}
impl Apple {
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit independent native, CA, signer and webhook key owners"
    )]
    pub fn new(
        protection: Arc<rss_mdm_native_protection::Protector>,
        config: Config,
        authority: certificate::AppleDeviceTrust,
        signer: certificate::ProfileSigner,
        push: push::Push,
        challenge_key: ring::hmac::Key,
        notify_key: ring::hmac::Key,
        agent_identity: Option<rss_mdm_execution_service::agent_install::Identity>,
    ) -> Self {
        let configuration = Sha256::digest(
            serde_json::to_vec(&(
                "mdm.apple.enrollment/v1",
                &config.management.origin,
                &config.scep_url,
                &config.scep_provisioner,
                &config.apns_topic,
                &config.challenge_webhook.id,
                &config.notify_webhook.id,
                authority.issuer_fingerprint(),
            ))
            .expect("closed configuration"),
        )
        .into();
        Self {
            protection,
            agent_identity,
            config,
            authority,
            signer,
            push,
            push_ready: std::sync::atomic::AtomicBool::new(true),
            challenge_key,
            notify_key,
            configuration,
        }
    }
    pub(crate) fn access_rights(&self) -> i32 {
        8191
    }
}
pub fn browser_routes(app: Arc<HttpState>, envelope: boundary::Envelope) -> axum::Router {
    use axum::routing::post;
    boundary::wrap(
        axum::Router::new()
            .route(
                "/api/v3/enrollments/{id}/profile",
                post(enrollment::download),
            )
            .route("/native/apple/scep/challenge", post(enrollment::challenge))
            .route("/native/apple/scep/notify", post(enrollment::notify))
            .with_state(app)
            .layer(axum::extract::DefaultBodyLimit::max(128 * 1024)),
        envelope,
    )
}
pub fn router(app: Arc<HttpState>, envelope: boundary::Envelope) -> axum::Router {
    use axum::routing::put;
    boundary::wrap(
        axum::Router::new()
            .route("/checkin", put(checkin::checkin))
            .route("/mdm", put(checkin::manage))
            .route(
                "/api/agent/v5/managed-registrations",
                axum::routing::post(checkin::register_agent),
            )
            .with_state(app)
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        envelope,
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateLevel {
    Healthy,
    RenewSoon,
    Critical,
    Expired,
}
#[derive(Clone, Copy, serde::Serialize)]
pub struct CertificateHealth {
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
    pub fn certificate_health(&self, now: i64) -> [CertificateHealth; 3] {
        [
            CertificateHealth::new("scep_issuer", self.authority.expires(), now),
            CertificateHealth::new("profile_signer", self.signer.expires(), now),
            CertificateHealth::new("apns", self.push.expires, now),
        ]
    }
    pub fn health(&self, now: i64) -> Health {
        Health {
            push_available: self.push_ready.load(std::sync::atomic::Ordering::Relaxed),
            certificates: self.certificate_health(now),
        }
    }
    pub fn report_certificate_health(
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

pub struct HttpState {
    pub mount: crate::device::ChannelMount,
    pub audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    pub access: std::sync::Arc<crate::Store>,
    pub apple: Option<std::sync::Arc<crate::Apple>>,
    pub clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
    pub execution: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub credentials:
        std::sync::Arc<rss_mdm_registration_service::enrollment::credentials::Credentials>,
    pub devices: std::sync::Arc<crate::device::DeviceService>,
    pub identity: std::sync::Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub requests: std::sync::Arc<tokio::sync::Semaphore>,
}
impl HttpState {
    pub fn apple(&self) -> std::result::Result<&Arc<crate::Apple>, crate::Error> {
        self.apple.as_ref().ok_or(crate::Error::Unsupported)
    }
}

pub async fn retire_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: uuid::Uuid,
) -> Result<(), Error> {
    use crate::database::db;
    sqlx::query("UPDATE mdm_apple.devices SET state='retired',bootstrap=NULL WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.channels SET state='retired',material=NULL,material_digest=NULL,push_lease_until=NULL WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.profiles SET retired_at=coalesce(retired_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

pub(crate) async fn notify(c: &mut sqlx::PgConnection, work: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),$1)").bind(work).execute(c).await?;
    Ok(())
}
async fn wait(
    notify: &tokio::sync::Notify,
    stop: &tokio_util::sync::CancellationToken,
    nearest: Option<std::time::Duration>,
) {
    let recovery = std::time::Duration::from_secs(5);
    tokio::select! {biased;()=stop.cancelled()=>{},()=notify.notified()=>{},()=tokio::time::sleep(nearest.unwrap_or(recovery).min(recovery))=>{}}
}
#[cfg(test)]
#[path = "../tests/health.rs"]
mod health_tests;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod boundary;

/// Exact read/write privileges required from the host access role.
pub const ACCESS_ADMISSION_SQL: &str = include_str!("access-admission.sql");

#[cfg(feature = "integration")]
impl Apple {
    pub fn trust_fixture(&self) -> &certificate::AppleDeviceTrust {
        &self.authority
    }
    pub fn signer_expiration_fixture(&self) -> u64 {
        self.signer.expires()
    }
    pub fn push_fixture(&self) -> &push::Push {
        &self.push
    }
    pub fn challenge_signature_fixture(&self, body: &[u8]) -> ring::hmac::Tag {
        ring::hmac::sign(&self.challenge_key, body)
    }
}

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
