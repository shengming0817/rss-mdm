//! Asset-specific rejection and host projection.
#[derive(Clone, Debug, thiserror::Error)]
pub enum AssetError {
    #[error("operation requires the full authorized inventory scope")]
    RestrictedScope,
}

impl From<AssetError> for crate::Error {
    fn from(error: AssetError) -> Self {
        match error {
            AssetError::RestrictedScope => Self::Forbidden,
        }
    }
}
