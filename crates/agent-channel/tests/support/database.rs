use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::path::PathBuf;
#[derive(serde::Deserialize)]
pub struct Database {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) name: String,
    pub(super) user: String,
    pub(super) ca_file: PathBuf,
    pub(super) password_file: PathBuf,
}
impl Database {
    pub fn options(&self) -> anyhow::Result<PgConnectOptions> {
        Ok(PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.name)
            .username(&self.user)
            .password(std::fs::read_to_string(&self.password_file)?.trim())
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(&self.ca_file))
    }
}
