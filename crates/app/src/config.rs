//! Configuration is read once; all changes require a process restart.
use crate::ConfigIssue;
use crate::{Error, access::Binding};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
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
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub origin: String,
    pub issuer: String,
    pub client_id: String,
    pub tenant_id: String,
    pub audience: String,
    pub oidc_secret_file: PathBuf,
    pub validation_secret_file: PathBuf,
    pub ca_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub product_origin: String,
    pub identity: Identity,
    pub database: Database,
    pub access_database: Database,
    pub bindings: Vec<Binding>,
}
pub(crate) struct Compiled {
    pub config: Config,
    pub policy: crate::access::Policy,
}
impl Config {
    pub(crate) fn compile(mut self) -> Result<Compiled, Error> {
        if !self.listen.ip().is_loopback() {
            return Err(Error::Configuration(ConfigIssue::Listen));
        }
        if self.database.user != "mdm_api" {
            return Err(Error::Configuration(ConfigIssue::DatabaseRole));
        }
        if self.access_database.user != "mdm_access"
            || self.access_database.host != self.database.host
            || self.access_database.port != self.database.port
            || self.access_database.name != self.database.name
        {
            return Err(Error::Configuration(ConfigIssue::AccessDatabase));
        }
        for (value, field) in [
            (&self.product_origin, ConfigIssue::ProductOrigin),
            (&self.identity.origin, ConfigIssue::IdentityOrigin),
        ] {
            let u = https_url(value).map_err(|_| Error::Configuration(field))?;
            if u.origin().ascii_serialization() != *value {
                return Err(Error::Configuration(field));
            }
        }
        let issuer = https_url(&self.identity.issuer)
            .map_err(|_| Error::Configuration(ConfigIssue::Issuer))?;
        let product = https_url(&self.product_origin)
            .map_err(|_| Error::Configuration(ConfigIssue::ProductOrigin))?;
        if issuer.host_str() == product.host_str() || self.identity.origin == self.product_origin {
            return Err(Error::Configuration(ConfigIssue::CookieAuthority));
        }
        let tenant = uuid::Uuid::parse_str(&self.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?;
        if tenant.is_nil() || tenant.to_string() != self.identity.tenant_id {
            return Err(Error::Configuration(ConfigIssue::Tenant));
        }
        let policy = crate::access::Policy::new(
            &self.identity.tenant_id,
            &self.identity.client_id,
            std::mem::take(&mut self.bindings),
        )?;
        Ok(Compiled {
            config: self,
            policy,
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
    fn enrollment_configuration_requires_explicit_permissions_and_store() {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/mdm-config.example.json"))
                .unwrap();
        let mut old = value.clone();
        old.as_object_mut().unwrap().remove("access_database");
        assert!(serde_json::from_value::<Config>(old).is_err());
        let mut old = value;
        old["bindings"][0]
            .as_object_mut()
            .unwrap()
            .remove("allow_enrollment");
        assert!(serde_json::from_value::<Config>(old).is_err());
    }
    #[test]
    fn cookie_authorities_cannot_share_a_hostname() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/mdm-config.example.json"))
                .unwrap();
        value["product_origin"] = serde_json::json!("https://identity.example.test:8443");
        let config: Config = serde_json::from_value(value).unwrap();
        assert!(config.compile().is_err());
    }
    #[test]
    fn startup_configuration_diagnostics_identify_safe_fields() {
        for (pointer, value, field) in [
            ("/listen", serde_json::json!("0.0.0.0:8080"), "Listen"),
            (
                "/database/user",
                serde_json::json!("postgres"),
                "DatabaseRole",
            ),
            (
                "/product_origin",
                serde_json::json!("https://synthetic-secret@example.test"),
                "ProductOrigin",
            ),
            (
                "/identity/origin",
                serde_json::json!("http://synthetic-secret.example.test"),
                "IdentityOrigin",
            ),
            (
                "/identity/issuer",
                serde_json::json!("http://synthetic-secret.example.test"),
                "Issuer",
            ),
            (
                "/identity/tenant_id",
                serde_json::json!("synthetic-secret"),
                "Tenant",
            ),
            ("/identity/client_id", serde_json::json!("*"), "ClientId"),
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
