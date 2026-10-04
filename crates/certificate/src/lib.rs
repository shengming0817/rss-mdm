//! Purpose-bound certificate validation and signing; callers own enrollment state.
pub mod agent;
pub mod apple;
mod peer;
pub mod windows;
pub use peer::HandshakePeer;

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid certificate material")]
    Malformed,
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("certificate identity rejected")]
    Unauthorized,
    #[error("certificate intent mismatch")]
    Conflict,
    #[error("certificate expired or not yet valid")]
    Expired,
    #[error("certificate signing failed")]
    Signing,
}

impl From<rss_mdm_device_trust::Error> for Error {
    fn from(e: rss_mdm_device_trust::Error) -> Self {
        match e {
            rss_mdm_device_trust::Error::Malformed => Self::Malformed,
            rss_mdm_device_trust::Error::Unauthorized | rss_mdm_device_trust::Error::Revoked => {
                Self::Unauthorized
            }
            rss_mdm_device_trust::Error::Conflict => Self::Conflict,
            rss_mdm_device_trust::Error::Expired => Self::Expired,
        }
    }
}
