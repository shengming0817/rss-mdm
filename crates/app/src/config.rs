//! Configuration is read once; all changes require a process restart.
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
            return Err(Error::Configuration);
        }
        Ok(PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.name)
            .username(&self.user)
            .password(&secret(&self.password_file)?)
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(&self.ca_file))
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
    pub bindings: Vec<Binding>,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.listen.ip().is_loopback() || self.database.user != "mdm_api" {
            return Err(Error::Configuration);
        }
        for value in [&self.product_origin, &self.identity.origin] {
            let u = https_url(value)?;
            if u.origin().ascii_serialization() != *value {
                return Err(Error::Configuration);
            }
        }
        https_url(&self.identity.issuer)?;
        if self.identity.origin == self.product_origin {
            return Err(Error::Configuration);
        }
        let tenant =
            uuid::Uuid::parse_str(&self.identity.tenant_id).map_err(|_| Error::Configuration)?;
        if tenant.is_nil() || tenant.to_string() != self.identity.tenant_id {
            return Err(Error::Configuration);
        }
        crate::access::Policy::new(
            &self.identity.tenant_id,
            &self.identity.client_id,
            self.bindings.clone(),
        )?;
        Ok(())
    }
}
pub(crate) fn https_url(value: &str) -> Result<url::Url, Error> {
    let u = url::Url::parse(value).map_err(|_| Error::Configuration)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(u)
}
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    serde_json::from_slice(&read(path, 1024 * 1024, true)?).map_err(|_| Error::Configuration)
}
pub(crate) fn read(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Open without following symlinks; inspect the same opened file before reading secrets.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Configuration)?;
    let meta = file.metadata().map_err(|_| Error::Configuration)?;
    if !meta.is_file() || (private && meta.permissions().mode() & 0o077 != 0) {
        return Err(Error::Configuration);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}
pub(crate) fn secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    let bytes = read(path, 16384, true)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Configuration)?
        .trim_end_matches('\n');
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(Error::Configuration);
    }
    Ok(Zeroizing::new(text.to_owned()))
}
