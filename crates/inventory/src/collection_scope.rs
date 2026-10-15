//! Product-owned asset namespaces, independent of execution sessions and Policy targets.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
/// Approved application namespace, not an arbitrary filesystem traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationRoot {
    /// /Applications.
    Local,
    /// /System/Applications.
    System,
    /// Applications in the bound user's home.
    User,
}
/// Homebrew evidence kinds never establish application existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrewPackage {
    /// Installed formula evidence.
    Formula,
    /// Installed cask evidence.
    Cask,
}
/// Exact namespace of one field. Source, registration and epoch belong to its stream.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollectionScope {
    /// Device-wide facts.
    Device,
    /// Authenticated Apple MDM user channel identity, never a Unix UID.
    AppleUser {
        /// Canonical nonzero user UUID.
        identity: String,
    },
    /// One approved application root.
    MacosApplications {
        /// Stable root, independent of execution session.
        root: ApplicationRoot,
        /// Required only for the user's application root.
        uid: Option<u32>,
    },
    /// One user's package-manager enumeration.
    MacosBrew {
        /// Bound non-root local user.
        uid: u32,
        /// Exact canonical data prefix.
        prefix: String,
        /// Independent formula/cask namespace.
        package: BrewPackage,
        /// Sorted selectors; empty means all taps within this prefix.
        taps: BTreeSet<String>,
    },
}
impl CollectionScope {
    /// Reject malformed or unbound namespaces before accepting a definition.
    pub fn validate_executable(&self) -> crate::Result<()> {
        let valid = match self {
            Self::Device => true,
            Self::AppleUser { identity } => {
                identity.len() == 36
                    && identity.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
                    && identity != "00000000-0000-0000-0000-000000000000"
            }
            Self::MacosApplications {
                root: ApplicationRoot::User,
                uid: Some(uid),
            } => *uid > 0,
            Self::MacosApplications {
                root: ApplicationRoot::Local | ApplicationRoot::System,
                uid: None,
            } => true,
            Self::MacosApplications { .. } => false,
            Self::MacosBrew {
                uid, prefix, taps, ..
            } => {
                *uid > 0
                    && prefix.len() <= 4096
                    && prefix.starts_with('/')
                    && !prefix.chars().any(char::is_control)
                    && prefix[1..]
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != "..")
                    && taps.len() <= 64
                    && taps.iter().all(|tap| {
                        tap.len() <= 255
                            && tap.split('/').count() == 2
                            && tap.split('/').all(|p| {
                                !p.is_empty()
                                    && p != "."
                                    && p != ".."
                                    && p.bytes().all(|b| {
                                        b.is_ascii_lowercase()
                                            || b.is_ascii_digit()
                                            || b"._-".contains(&b)
                                    })
                            })
                    })
            }
        };
        if valid {
            Ok(())
        } else {
            Err(crate::Invalid::Value)
        }
    }
    /// Check the product producer that may assert this namespace.
    pub fn validate_source(&self, source: crate::Source) -> crate::Result<()> {
        self.validate_executable()?;
        if match self {
            Self::Device => source != crate::Source::Manual,
            Self::AppleUser { .. } => source == crate::Source::MdmApple,
            Self::MacosApplications { .. } | Self::MacosBrew { .. } => {
                source == crate::Source::AgentNative
            }
        } {
            Ok(())
        } else {
            Err(crate::Invalid::SourceNotAllowed)
        }
    }
    /// Canonical identity used by storage and signed read cursors.
    pub fn canonical(&self) -> crate::Result<String> {
        self.validate_executable()?;
        serde_json::to_string(self).map_err(|_| crate::Invalid::Encoding)
    }
}
