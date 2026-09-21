//! Configuration is read once; all changes require a process restart.
use crate::ConfigIssue;
use crate::{Error, access::IdentityManagementGrant};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

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
    pub oidc: Option<crate::identity::OidcConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub product_origin: String,
    pub trusted_gateway: std::net::IpAddr,
    pub identity: Identity,
    pub access_database: Database,
    pub runtime_database: Database,
    pub(crate) management: crate::management::Config,
    pub identity_management: Vec<IdentityManagementGrant>,
    pub windows: crate::windows::WindowsConfig,
}
pub(crate) struct Compiled {
    pub config: Config,
    pub identity_management: Arc<crate::access::IdentityManagementPolicy>,
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
        let tenant = uuid::Uuid::parse_str(&self.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?;
        if tenant.is_nil() || tenant.to_string() != self.identity.tenant_id {
            return Err(Error::Configuration(ConfigIssue::Tenant));
        }
        self.management.validate(&self.access_database)?;
        self.windows.validate(self.listen)?;
        let identity_management = crate::access::IdentityManagementPolicy::new(
            &self.identity.tenant_id,
            &self.identity.instance_id,
            std::mem::take(&mut self.identity_management),
        )?;
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
mod tests {
    use super::*;
    #[test]
    fn static_business_permissions_are_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/mdm-config.example.json"))
                .unwrap();
        value["bindings"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Config>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("bindings");
        value["identity_management"] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<Config>(value.clone())
                .unwrap()
                .compile()
                .is_ok()
        );
        value.as_object_mut().unwrap().remove("access_database");
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
    #[test]
    fn startup_configuration_diagnostics_identify_safe_fields() {
        for (pointer, value, field) in [
            ("/listen", serde_json::json!("0.0.0.0:8080"), "Listen"),
            (
                "/access_database/user",
                serde_json::json!("postgres"),
                "AccessDatabase",
            ),
            (
                "/product_origin",
                serde_json::json!("https://synthetic-secret@example.test"),
                "ProductOrigin",
            ),
            (
                "/identity/instance_id",
                serde_json::json!("synthetic-secret"),
                "Instance",
            ),
            (
                "/identity/database/user",
                serde_json::json!("postgres"),
                "IdentityDatabase",
            ),
            (
                "/identity/tenant_id",
                serde_json::json!("synthetic-secret"),
                "Tenant",
            ),
            (
                "/windows/enrollment/origin",
                serde_json::json!("http://synthetic-secret.example.test"),
                "WindowsListeners",
            ),
            (
                "/windows/management/origin",
                serde_json::json!("http://synthetic-secret.example.test"),
                "WindowsListeners",
            ),
        ] {
            let mut value_config: serde_json::Value =
                serde_json::from_str(include_str!("../../../fixtures/mdm-config.example.json"))
                    .unwrap();
            *value_config.pointer_mut(pointer).unwrap() = value;
            let config: Config = serde_json::from_value(value_config).unwrap();
            let error = match config.compile() {
                Err(error) => error,
                Ok(_) => panic!("invalid configuration accepted"),
            };
            let diagnostic = crate::ProcessError::at("startup.configuration", error).to_string();
            assert!(diagnostic.contains(field));
            assert!(!diagnostic.contains("synthetic-secret"));
        }
    }
    #[test]
    fn ca_inputs_reject_symlinks_directories_and_oversize() {
        let root = std::env::temp_dir().join(format!("mdm-ca-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let ca = root.join("ca");
        std::fs::write(&ca, b"public certificate").unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&ca, &alias).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let password = root.join("password");
        std::fs::write(&password, "fixture").unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut database = Database {
            host: "localhost".into(),
            port: 5432,
            name: "mdm".into(),
            user: "mdm_api".into(),
            password_file: password,
            ca_file: alias,
        };
        assert!(database.options().is_err());
        database.ca_file = root.clone();
        assert!(database.options().is_err());
        database.ca_file = ca.clone();
        std::fs::write(&ca, vec![0; 1024 * 1024 + 1]).unwrap();
        assert!(database.options().is_err());
        std::fs::write(&ca, b"public certificate").unwrap();
        assert!(database.options().is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
