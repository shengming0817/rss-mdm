//! Apple MDM protocol, SCEP lifecycle and APNs transport.
pub mod account_enrollment;
mod agent_collection;
pub mod attempt;
mod checkin;
pub mod collection;
mod database;
pub mod ddm;
pub mod enrollment;
mod error;
mod evidence;
pub mod exchange;
pub mod flow_store;
mod material;
mod native;
mod operations;
mod profiles;
mod protection;
pub mod push;
pub mod renewal;
mod trust_installation;
mod webhook;
pub use database::Store;
pub use error::Error;
use rss_mdm_apple_mdm::{profile, protocol};
use rss_mdm_certificate::apple as certificate;
use rss_mdm_execution_service as execution;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
use rss_mdm_registration_service::{device, enrollment as registration_enrollment};
use sha2::{Digest, Sha256};
use std::sync::Arc;
pub struct Config {
    pub management: Origin,
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
    providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) account_keys:
        std::collections::BTreeMap<String, certificate::ManagedAccountTokenSigner>,
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
/// Canonical stable protocol identity, independent of issuer rotation.
pub fn protocol_identity(config: &Config) -> [u8; 32] {
    Sha256::digest(
        serde_json::to_vec(&(
            "mdm.apple.enrollment/v3",
            &config.management.origin,
            &config.apns_topic,
            &config.challenge_webhook.id,
            &config.notify_webhook.id,
        ))
        .expect("closed configuration"),
    )
    .into()
}
impl Apple {
    pub fn trust_certificates(
        &self,
    ) -> Result<Vec<rss_mdm_apple_mdm::profile::CertificatePayload>, Error> {
        use x509_cert::der::{Decode, EncodePem};
        self.authority
            .trust
            .certificates()
            .map_err(|_| Error::Conflict)?
            .into_iter()
            .map(|(root, der)| {
                let fingerprint = rss_mdm_device_trust::digest(&der);
                let content = if root {
                    der
                } else {
                    x509_cert::Certificate::from_der(&der)
                        .map_err(|_| Error::Malformed)?
                        .to_pem(x509_cert::der::pem::LineEnding::LF)
                        .map_err(|_| Error::Malformed)?
                        .into_bytes()
                };
                Ok(rss_mdm_apple_mdm::profile::CertificatePayload {
                    root,
                    fingerprint,
                    content,
                })
            })
            .collect()
    }
    pub fn device_trust(&self) -> &rss_mdm_device_trust::DeviceTrust {
        &self.authority.trust
    }
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
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
    ) -> Self {
        let configuration = protocol_identity(&config);
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
            providers,
            account_keys: Default::default(),
        }
    }
    pub fn with_account_keys(
        mut self,
        keys: std::collections::BTreeMap<String, certificate::ManagedAccountTokenSigner>,
    ) -> Self {
        self.account_keys = keys;
        self
    }
    pub(crate) async fn active_scep(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: &str,
    ) -> Result<(Vec<u8>, String, String), Error> {
        let trust = self.authority.trust.public().map_err(|_| Error::Conflict)?;
        let generation = trust
            .issuers
            .iter()
            .find(|g| g.mode == rss_mdm_agent_wire::pki::Mode::Active)
            .ok_or(Error::Conflict)?;
        rss_mdm_pki_service::signing::require_active_in(
            c,
            uuid::Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?,
            "apple",
            &generation.digest,
        )
        .await
        .map_err(|error| match error {
            rss_mdm_pki_service::Error::Conflict => Error::Conflict,
            _ => Error::Unavailable(crate::Failure::Database),
        })?;
        let url = self
            .providers
            .scep(&generation.digest)
            .map_err(|_| Error::Conflict)?
            .to_owned();
        let issuer = rss_mdm_device_trust::decode(&generation.certificate, 32768)
            .map_err(|_| Error::Conflict)?;
        use sha2::Digest;
        Ok((
            Sha256::digest(issuer).to_vec(),
            url,
            generation.provisioner.clone(),
        ))
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
                "/api/v1/enrollments/{id}/profile",
                post(enrollment::download),
            )
            .route("/api/v1/apple/scep/challenge", post(enrollment::challenge))
            .route("/api/v1/apple/scep/notify", post(enrollment::notify))
            .merge(account_enrollment::routes())
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
            .route(
                "/native/apple/ddm/assets/{operation}/{identifier}",
                axum::routing::get(ddm::asset),
            )
            .route("/mdm", put(checkin::manage))
            .route(
                "/api/v1/agent/enroll/native-grants",
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
        account_previous: &mut std::collections::BTreeMap<String, CertificateLevel>,
    ) {
        for (id, key) in &self.account_keys {
            let certificate = CertificateHealth::new("managed_account", key.expires(), now);
            if account_previous.insert(id.clone(), certificate.level) != Some(certificate.level)
                && certificate.level != CertificateLevel::Healthy
            {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"apple_certificate_health","keyId":id,"certificate":certificate})
                );
            }
        }
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
    pub authentication: account_enrollment::Authentication,
    pub account_authority:
        Arc<dyn rss_mdm_registration_service::enrollment::native::AccountAuthority>,
    pub agent_policy: Option<rss_mdm_registration_service::agent::Policy>,
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
    sqlx::query("UPDATE mdm_apple.account_flows SET revoked=true,material=NULL,profile=NULL WHERE tenant_id=$1::uuid AND enrollment=(SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2)")
        .bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.devices SET state='retired',bootstrap=NULL WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.channels SET state='retired',material=NULL,material_digest=NULL,push_lease_until=NULL WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.profiles SET retired_at=coalesce(retired_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.declarations SET retired_at=coalesce(retired_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
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
    pub fn scep_fixture(&self) -> Result<(String, String), Error> {
        let generation = self.authority.trust.active().map_err(|_| Error::Conflict)?;
        let url = self
            .providers
            .scep(&generation.digest)
            .map_err(|_| Error::Conflict)?;
        Ok((url.to_owned(), generation.provisioner))
    }
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

/// Forward migration for account-driven protocol state and general SCEP authority revision.
pub const ACCOUNT_ENROLLMENT_SQL: &str = include_str!("../schema/account-enrollment.sql");
