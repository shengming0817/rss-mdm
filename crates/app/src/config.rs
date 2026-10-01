//! Configuration is read once; all changes require a process restart.
use crate::ConfigIssue;
use crate::{Error, authorization::identity_management::IdentityManagementGrant};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

/// Explicit persistence mode. The host owns key files and the pool lifecycle.
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditConfig {
    Plain,
    Ledger { key_id: String, key_file: PathBuf },
}
impl AuditConfig {
    pub(crate) fn mode(&self) -> crate::migration::AuditMode {
        match self {
            Self::Plain => crate::migration::AuditMode::Plain,
            Self::Ledger { .. } => crate::migration::AuditMode::Ledger,
        }
    }
    pub(crate) fn integrity(&self) -> Result<rss_audit_postgres::Integrity, Error> {
        match self {
            Self::Plain => Ok(rss_audit_postgres::Integrity::Plain),
            Self::Ledger { key_id, key_file } => {
                let key = read(key_file, 4096, true)?;
                let id = rss_ledger::KeyId::parse(key_id)
                    .map_err(|_| Error::Configuration(ConfigIssue::Audit))?;
                let auth = rss_ledger::Authenticator::new(id, key.to_vec())
                    .map_err(|_| Error::Configuration(ConfigIssue::Audit))?;
                Ok(rss_audit_postgres::Integrity::Ledger(Arc::new(auth)))
            }
        }
    }
}

#[derive(Deserialize)]
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
    pub fn options(&self) -> Result<PgConnectOptions, Error> {
        if self.host.is_empty() || self.name.is_empty() || self.user.is_empty() || self.port == 0 {
            return Err(Error::Configuration(ConfigIssue::DatabaseAddress));
        }
        Ok(PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.name)
            .username(&self.user)
            .password(
                &secret(&self.password_file)
                    .map_err(|_| Error::Configuration(ConfigIssue::DatabasePassword))?,
            )
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(
                read(&self.ca_file, 1024 * 1024, false)
                    .map_err(|_| Error::Configuration(ConfigIssue::DatabaseCa))?
                    .to_vec(),
            ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConfig {
    pub database: Database,
    pub installation: crate::migration::Installation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub instance_id: String,
    pub tenant_id: String,
    pub database: Database,
    pub audit_worker: Database,
    pub oidc: Option<crate::identity::OidcConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProtocols {
    #[serde(default, deserialize_with = "enabled")]
    pub apple: Option<crate::apple::config::Config>,
    #[serde(default, deserialize_with = "enabled")]
    pub windows: Option<crate::windows::WindowsConfig>,
}
fn enabled<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub audit: AuditConfig,
    pub listen: SocketAddr,
    pub product_origin: String,
    #[serde(default)]
    pub agent_installation: rss_mdm_flow_service::planning::policies::agent_install::Config,
    #[serde(default)]
    pub enrollment_entries: rss_mdm_flow_service::planning::policies::enrollment::Entries,
    pub trusted_gateway: std::net::IpAddr,
    pub identity: Identity,
    pub access_database: Database,
    pub runtime_database: Database,
    pub execution: ExecutionStorage,
    pub(crate) content: Option<rss_mdm_content_service::Config>,
    pub(crate) task_signing: Option<crate::task_signing::Config>,
    pub(crate) flow: crate::flow::Config,
    pub identity_management: Vec<IdentityManagementGrant>,
    pub native_protocols: NativeProtocols,
}
pub(crate) struct Compiled {
    pub config: Config,
    pub identity_management:
        Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
}
impl Config {
    pub(crate) fn compile(mut self) -> Result<Compiled, Error> {
        if !self.listen.ip().is_loopback() {
            return Err(Error::Configuration(ConfigIssue::Listen));
        }
        if self.access_database.user != "mdm_access" {
            return Err(Error::Configuration(ConfigIssue::AccessDatabase));
        }
        if self.runtime_database.user != "mdm_runtime"
            || self.runtime_database.host != self.access_database.host
            || self.runtime_database.port != self.access_database.port
            || self.runtime_database.name != self.access_database.name
        {
            return Err(Error::Configuration(ConfigIssue::RuntimeDatabase));
        }
        let product = https_url(&self.product_origin)
            .map_err(|_| Error::Configuration(ConfigIssue::ProductOrigin))?;
        if product.origin().ascii_serialization() != self.product_origin {
            return Err(Error::Configuration(ConfigIssue::ProductOrigin));
        }
        self.flow
            .publication
            .validate_hosted(&self.product_origin)?;
        let instance = rss_identity_core::InstanceId::parse(&self.identity.instance_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Instance))?;
        if instance.to_string() != self.identity.instance_id {
            return Err(Error::Configuration(ConfigIssue::Instance));
        }
        if self.identity.database.user != "mdm_identity_runtime"
            || self.identity.database.host != self.access_database.host
            || self.identity.database.port != self.access_database.port
            || self.identity.database.name != self.access_database.name
        {
            return Err(Error::Configuration(ConfigIssue::IdentityDatabase));
        }
        let worker = &self.identity.audit_worker;
        if worker.user != crate::identity_audit::ROLE
            || worker.host != self.identity.database.host
            || worker.port != self.identity.database.port
            || worker.name != self.identity.database.name
        {
            return Err(Error::Configuration(ConfigIssue::IdentityAuditDatabase));
        }
        let tenant = uuid::Uuid::parse_str(&self.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?;
        if tenant.is_nil() || tenant.to_string() != self.identity.tenant_id {
            return Err(Error::Configuration(ConfigIssue::Tenant));
        }
        if self.execution.database.user != "mdm_command_runtime"
            || self.execution.database.host != self.access_database.host
            || self.execution.database.port != self.access_database.port
            || self.execution.database.name != self.access_database.name
        {
            return Err(Error::Configuration(ConfigIssue::Execution));
        }
        self.flow.validate(&self.access_database)?;
        if let Some(windows) = &self.native_protocols.windows {
            windows.validate(self.listen)?;
        }
        if let Some(apple) = &self.native_protocols.apple {
            apple.validate(self.listen)?;
            if self.native_protocols.windows.as_ref().is_some_and(|w| {
                w.enrollment.listen == apple.management.listen
                    || w.management.listen == apple.management.listen
                    || w.enrollment.origin == apple.management.origin
                    || w.management.origin == apple.management.origin
            }) {
                return Err(Error::Configuration(ConfigIssue::AppleListeners));
            }
        }
        let identity_management =
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                &self.identity.tenant_id,
                &self.identity.instance_id,
                std::mem::take(&mut self.identity_management),
            )?;
        let worker = &self.identity.audit_worker;
        let runtime = &self.identity.database;
        if worker.password_file == runtime.password_file
            || secret(&worker.password_file)
                .map_err(|_| Error::Configuration(ConfigIssue::IdentityAuditDatabase))?
                == secret(&runtime.password_file)
                    .map_err(|_| Error::Configuration(ConfigIssue::IdentityAuditDatabase))?
        {
            return Err(Error::Configuration(ConfigIssue::IdentityAuditDatabase));
        }
        Ok(Compiled {
            config: self,
            identity_management: Arc::new(identity_management),
        })
    }
}
pub(crate) fn https_url(value: &str) -> Result<url::Url, Error> {
    let u = url::Url::parse(value).map_err(|_| Error::Configuration(ConfigIssue::Issuer))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::Configuration(ConfigIssue::Issuer));
    }
    Ok(u)
}
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, crate::ProcessError> {
    let bytes = read(path, 1024 * 1024, true)
        .map_err(|_| crate::ProcessError::ConfigFile(path.to_owned()))?;
    serde_json::from_slice(&bytes).map_err(|e| crate::ProcessError::ConfigJson {
        path: path.to_owned(),
        line: e.line(),
        column: e.column(),
    })
}
pub(crate) fn read(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Open without following symlinks; inspect the same opened file before reading secrets.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Configuration(ConfigIssue::FileAccess))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::Configuration(ConfigIssue::FileAccess))?;
    if !meta.is_file() || (private && meta.permissions().mode() & 0o077 != 0) {
        return Err(Error::Configuration(ConfigIssue::FileShape));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration(ConfigIssue::FileAccess))?;
    if bytes.len() as u64 > limit {
        return Err(Error::Configuration(ConfigIssue::FileSize));
    }
    Ok(bytes)
}
pub(crate) fn secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    let bytes = read(path, 16384, true)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Configuration(ConfigIssue::SecretEncoding))?
        .trim_end_matches('\n');
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(Error::Configuration(ConfigIssue::SecretContents));
    }
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
#[path = "../tests/config/unit.rs"]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStorage {
    pub database: Database,
}
