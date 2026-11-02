//! Standalone DA composition. No MDM application or running device channel is required.
pub mod config;

pub mod host;

pub mod installation;

pub mod maintenance;

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("DA configuration rejected")]
    Configuration,
    #[error("DA storage or installation unavailable")]
    Storage,
    #[error("DA identity unavailable or rejected")]
    Identity,
    #[error("DA owner admission rejected")]
    Admission,
    #[error("DA lifecycle did not complete")]
    Lifecycle,
    #[error("DA operation result unknown")]
    Unknown,
}
pub type Result<T> = std::result::Result<T, Error>;

pub mod backup;

pub fn http_contract() -> Result<serde_json::Value> {
    rss_mdm_device_access_http::contract().map_err(|_| Error::Configuration)
}
