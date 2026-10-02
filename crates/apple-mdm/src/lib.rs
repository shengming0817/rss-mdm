//! Bounded Apple MDM wire codecs and the shipped device Profile format.
pub mod applicability;
pub mod native;
pub mod profile;
pub mod protocol;
pub mod software;
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed Apple MDM payload")]
    Malformed,
    #[error("unsupported Apple MDM operation")]
    Unsupported,
    #[error("Apple Profile identity mismatch")]
    Conflict,
}

#[cfg(test)]
#[path = "../tests/software.rs"]
mod software_tests;
