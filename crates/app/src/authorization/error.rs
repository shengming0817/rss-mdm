#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum AuthorizationError {
    #[error("invalid authorization input")]
    Malformed,
    #[error("authentication proof expired")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("invalid persisted authorization")]
    Corrupt,
}
