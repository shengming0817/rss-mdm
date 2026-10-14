//! Collection range is immutable evidence; it is not the policy's target set.
use serde::{Deserialize, Serialize};
/// Exact namespace of collected values. Only device-wide projection is currently executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateScope {
    /// Complete device-wide namespace.
    Device,
    /// One explicitly identified user; never merged into device-wide facts.
    User {
        /// Stable account identity.
        identity: String,
    },
    /// One provider-specific namespace.
    Source {
        /// Stable provider identity.
        identity: String,
    },
    /// One stable volume identity, independent of drive letter.
    Volume {
        /// Stable volume identity.
        identity: String,
    },
    /// One explicit path prefix.
    Prefix {
        /// Exact path prefix.
        path: String,
    },
}
impl TemplateScope {
    /// Reject ranges that the current end-to-end storage/query path cannot distinguish safely.
    pub fn validate_executable(&self) -> Result<(), crate::Error> {
        if matches!(self, Self::Device) {
            Ok(())
        } else {
            Err(crate::Error::InvalidInput)
        }
    }
}
