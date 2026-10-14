//! Collection range is immutable evidence; it is not the policy's target set.
use serde::{Deserialize, Serialize};
/// Exact namespace of collected values. Device and authenticated Apple user namespaces are executable.
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
        match self {
            Self::Device => Ok(()),
            Self::User { identity }
                if identity.len() == 36
                    && identity.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
                    && identity != "00000000-0000-0000-0000-000000000000" =>
            {
                Ok(())
            }
            _ => Err(crate::Error::InvalidInput),
        }
    }
}
