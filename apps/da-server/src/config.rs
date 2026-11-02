//! Process-local composition inputs. Private material is always read from protected files.
use crate::{Error, Result};

use rss_mdm_install_support::files::{read, secret};

use serde::{Deserialize, Serialize};

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: PathBuf,
}
impl Database {
    pub fn options(&self) -> Result<sqlx::postgres::PgConnectOptions> {
        if self.host.is_empty() || self.name.is_empty() || self.user.is_empty() || self.port == 0 {
            return Err(Error::Configuration);
        }
        Ok(sqlx::postgres::PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.name)
            .username(&self.user)
            .password(&secret(&self.password_file).map_err(|_| Error::Configuration)?)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(
                read(&self.ca_file, 1048576, false)
                    .map_err(|_| Error::Configuration)?
                    .to_vec(),
            ))
    }
    pub fn same_database(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port && self.name == other.name
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub instance: uuid::Uuid,
    pub tenant: uuid::Uuid,
    pub management_tenant: uuid::Uuid,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
}
impl Installation {
    pub fn validate(&self) -> Result<()> {
        if self.instance.is_nil()
            || self.tenant.is_nil()
            || self.management_tenant.is_nil()
            || self.epoch <= 0
        {
            return Err(Error::Configuration);
        }
        rss_transactional_messaging::fence::StorageIdentity::new(self.target, self.lineage)
            .map_err(|_| Error::Configuration)?;

        if self.tenant == self.management_tenant
            && self.epoch != rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub fn tenants(&self) -> Result<Vec<(rss_request_context::TenantId, i64)>> {
        self.validate()?;

        let mut v = vec![(
            rss_request_context::TenantId::parse(&self.tenant.to_string())
                .map_err(|_| Error::Configuration)?,
            self.epoch,
        )];

        if self.management_tenant != self.tenant {
            v.push((
                rss_request_context::TenantId::parse(&self.management_tenant.to_string())
                    .map_err(|_| Error::Configuration)?,
                rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH,
            ));
        }
        Ok(v)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Audit {
    Plain,
    Ledger { key_id: String, key_file: PathBuf },
}
impl Audit {
    pub fn ledger(&self) -> bool {
        matches!(self, Self::Ledger { .. })
    }
    pub fn integrity(&self) -> Result<rss_audit_postgres::Integrity> {
        match self {
            Self::Plain => Ok(rss_audit_postgres::Integrity::Plain),
            Self::Ledger { key_id, key_file } => {
                Ok(rss_audit_postgres::Integrity::Ledger(Arc::new(
                    rss_ledger::Authenticator::new(
                        rss_ledger::KeyId::parse(key_id).map_err(|_| Error::Configuration)?,
                        read(key_file, 4096, true)
                            .map_err(|_| Error::Configuration)?
                            .to_vec(),
                    )
                    .map_err(|_| Error::Configuration)?,
                )))
            }
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Protection {
    pub active_file: PathBuf,
    pub historical_files: Vec<PathBuf>,
    pub fingerprint_file: PathBuf,
}
impl Protection {
    pub fn load(&self) -> Result<Arc<rss_mdm_native_protection::Protector>> {
        if self.historical_files.len() > 15 {
            return Err(Error::Configuration);
        }
        let active = read(&self.active_file, 32, true).map_err(|_| Error::Configuration)?;

        let fingerprint =
            read(&self.fingerprint_file, 32, true).map_err(|_| Error::Configuration)?;

        let history = self
            .historical_files
            .iter()
            .map(|p| read(p, 32, true).map_err(|_| Error::Configuration))
            .collect::<Result<Vec<_>>>()?;

        rss_mdm_native_protection::Protector::with_fingerprint(
            &active,
            &history.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
            &fingerprint,
        )
        .map(Arc::new)
        .map_err(|_| Error::Configuration)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub listen: std::net::SocketAddr,
    pub origin: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
impl Listener {
    pub fn host(&self) -> Result<String> {
        let u = url::Url::parse(&self.origin).map_err(|_| Error::Configuration)?;

        if u.scheme() != "https"
            || u.domain().is_none()
            || u.origin().ascii_serialization() != self.origin
            || self.listen.port() == 0
        {
            return Err(Error::Configuration);
        }
        Ok(self.origin.trim_start_matches("https://").to_owned())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub listener: Listener,
    pub trust_file: PathBuf,
    pub providers: Vec<rss_mdm_pki_service::configuration::Provider>,
    pub certificate_days: u16,
    pub configuration_revision: Option<u64>,
    pub configuration_lifetime: std::num::NonZeroU32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub installation: Installation,
    pub database: Database,
    pub identity_database: Database,
    pub audit: Audit,
    pub browser: Listener,
    pub registration: Registration,
    pub protection: Protection,
    pub cursor_key_file: PathBuf,
    pub deployment_authorities: Vec<rss_mdm_device_access_runtime::platform::DeploymentAuthority>,
    pub platform_sso: Option<rss_mdm_device_access_runtime::platform::PlatformSso>,
    pub enterprise: Option<rss_mdm_device_access_runtime::enterprise::Deployment>,
    pub oidc: Option<Oidc>,
    pub recovery: Option<rss_mdm_recovery_credentials::configuration::Config>,
    #[serde(default)]
    pub reports: rss_mdm_device_access_postgres::reports::Limits,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;

        self.browser.host()?;

        self.registration.listener.host()?;

        if self.database.user != "da_access"
            || self.identity_database.user != "da_identity_runtime"
            || !self.database.same_database(&self.identity_database)
            || self.browser.listen == self.registration.listener.listen
        {
            return Err(Error::Configuration);
        }
        if self.registration.providers.is_empty()
            || self
                .registration
                .providers
                .iter()
                .any(|p| p.purpose != rss_mdm_agent_wire::pki::Purpose::DaDevice)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
pub fn load<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T> {
    if !p.is_absolute() {
        return Err(Error::Configuration);
    }
    serde_json::from_slice(&read(p, 1048576, true).map_err(|_| Error::Configuration)?)
        .map_err(|_| Error::Configuration)
}

impl Database {
    pub fn archive(
        &self,
    ) -> std::result::Result<
        rss_mdm_install_support::maintenance::archive::Database<'_>,
        crate::Error,
    > {
        Ok(rss_mdm_install_support::maintenance::archive::Database {
            options: self.options()?,
            host: &self.host,
            port: self.port,
            name: &self.name,
            user: &self.user,
            password_file: &self.password_file,
            ca_file: &self.ca_file,
            profile: rss_mdm_install_support::StorageProfile::Da,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    pub state_key_file: PathBuf,
    pub active_credential_key: String,
    pub credential_keys: std::collections::BTreeMap<String, PathBuf>,
    pub return_targets: std::collections::BTreeMap<String, String>,
    pub group_facts_max_age_seconds: i64,
}
impl Oidc {
    pub fn federation(
        &self,
        authority: rss_identity_postgres::Authority,
        origin: &str,
        instance: rss_identity_core::InstanceId,
    ) -> Result<rss_identity_postgres::Federation> {
        let key = |p: &Path| -> Result<[u8; 32]> {
            read(p, 32, true)
                .map_err(|_| Error::Configuration)?
                .as_slice()
                .try_into()
                .map_err(|_| Error::Configuration)
        };

        let keys = self
            .credential_keys
            .iter()
            .map(|(id, p)| Ok((id.clone(), key(p)?)))
            .collect::<Result<Vec<_>>>()?;

        let transport = rss_identity_oidc::HttpOidc::new(Vec::new(), Vec::new())
            .map_err(|_| Error::Configuration)?;

        rss_identity_postgres::Federation::new(
            rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
                .map_err(|_| Error::Configuration)?,
            authority,
            Arc::new(transport),
            rss_identity_core::federation::StateSigner::new(
                key(&self.state_key_file)?,
                &instance.to_string(),
            )
            .map_err(|_| Error::Configuration)?,
            rss_identity_postgres::FederationConfig {
                callback: format!("{origin}/api/v1/identity/oidc/callback"),
                credential_keys: Arc::new(
                    rss_identity_postgres::CredentialKeys::new(
                        self.active_credential_key.clone(),
                        keys,
                    )
                    .map_err(|_| Error::Configuration)?,
                ),
                targets: self.return_targets.clone(),
            },
        )
        .map_err(|_| Error::Identity)
    }
}
