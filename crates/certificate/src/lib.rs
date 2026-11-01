//! Purpose-bound certificate validation and signing; callers own enrollment state.
pub mod apple;
pub mod bootstrap;
pub mod device_identity;
mod peer;
pub mod windows;
pub use peer::{ClientCertificateEvidence, GatewayConnection, GatewayOrigin};

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
