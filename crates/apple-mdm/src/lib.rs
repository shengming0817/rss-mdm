//! Bounded Apple MDM wire codecs and the shipped device Profile format.
pub mod agent_install;
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

#[cfg(test)]
#[path = "../tests/agent_install.rs"]
mod agent_install_tests;
