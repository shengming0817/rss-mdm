//! Bounded Apple MDM wire codecs and the shipped device Profile format.
pub mod profile;
pub mod protocol;
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed Apple MDM payload")]
    Malformed,
    #[error("unsupported Apple MDM operation")]
    Unsupported,
    #[error("Apple Profile identity mismatch")]
    Conflict,
}
