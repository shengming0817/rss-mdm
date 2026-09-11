//! Strict, bounded Windows MDM XML codecs. Parsed device identifiers are claims,
//! never authenticated identities. No I/O, scheduling or persistence is performed.
//!
//! ```
//! use rss_mdm_windows_mdm::{syncml::{self, Header, Message, Command, Item}, CodecLimits};
//! # fn main() -> rss_mdm_windows_mdm::Result<()> {
//! let message = Message {
//!     header: Header { session_id: 1, message_id: 1, target: "claimed-device".into(),
//!         source: "https://mdm.example.com/manage".into(), credential: None, meta: None },
//!     commands: vec![Command::Get { id: 1, meta: None, items: vec![Item {
//!         target: Some("./DevDetail/SwV".into()), source: None, meta: None, data: None,
//!     }] }], final_message: true,
//! };
//! let wire = syncml::encode(&message, &CodecLimits::default())?;
//! assert_eq!(syncml::decode(&wire, &CodecLimits::default())?, message);
//! # Ok(()) }
//! ```
pub mod provisioning;
pub mod soap;
pub mod syncml;
mod xml;

/// Errors contain only closed classifications, never XML or credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    MalformedXml,
    WrongNamespace,
    Structure,
    InvalidValue,
    Unsupported,
    LimitExceeded,
    UnexpectedOperation,
    ForbiddenXml,
    Duplicate,
}
impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MalformedXml => "malformed XML",
            Self::WrongNamespace => "wrong namespace",
            Self::Structure => "invalid protocol structure",
            Self::InvalidValue => "invalid protocol value",
            Self::Unsupported => "unsupported protocol behavior",
            Self::LimitExceeded => "codec budget exceeded",
            Self::UnexpectedOperation => "unexpected protocol operation",
            Self::ForbiddenXml => "forbidden XML construct",
            Self::Duplicate => "duplicate protocol field",
        })
    }
}
impl std::error::Error for CodecError {}
pub type Result<T> = std::result::Result<T, CodecError>;

/// Failure source for association APIs. No remote input is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationError {
    InvalidRequest(CodecError),
    InvalidExpected(CodecError),
    InvalidResponse(CodecError),
    Mismatch,
}
impl std::fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(e) => write!(f, "invalid local request: {e}"),
            Self::InvalidExpected(e) => write!(f, "invalid local expectation: {e}"),
            Self::InvalidResponse(e) => write!(f, "invalid remote response: {e}"),
            Self::Mismatch => f.write_str("protocol correlation mismatch"),
        }
    }
}
impl std::error::Error for CorrelationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(e) | Self::InvalidExpected(e) | Self::InvalidResponse(e) => {
                Some(e)
            }
            Self::Mismatch => None,
        }
    }
}
pub type CorrelationResult<T> = std::result::Result<T, CorrelationError>;

/// Per-message limits. All limits are enforced; zero means no capacity, not unlimited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecLimits {
    pub discovery_bytes: usize,
    pub xcep_bytes: usize,
    pub wstep_bytes: usize,
    pub syncml_bytes: usize,
    pub depth: usize,
    pub elements: usize,
    pub events: usize,
    pub attributes_per_element: usize,
    pub attributes: usize,
    pub namespace_bindings: usize,
    pub commands: usize,
    pub items: usize,
    pub identifier_bytes: usize,
    pub uri_bytes: usize,
    pub field_bytes: usize,
    pub binary_bytes: usize,
}
impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            discovery_bytes: 64 * 1024,
            xcep_bytes: 256 * 1024,
            wstep_bytes: 512 * 1024,
            syncml_bytes: 512 * 1024,
            depth: 32,
            elements: 4096,
            events: 16384,
            attributes_per_element: 32,
            attributes: 2048,
            namespace_bindings: 32,
            commands: 256,
            items: 1024,
            identifier_bytes: 128,
            uri_bytes: 2048,
            field_bytes: 64 * 1024,
            binary_bytes: 256 * 1024,
        }
    }
}
pub(crate) fn bound(n: usize, max: usize) -> Result<()> {
    if n > max {
        Err(CodecError::LimitExceeded)
    } else {
        Ok(())
    }
}
pub(crate) fn text(value: &str, max: usize, empty: bool) -> Result<()> {
    bound(value.len(), max)?;
    if (!empty && value.trim().is_empty()) || !value.chars().all(xml::legal_char) {
        return Err(CodecError::InvalidValue);
    }
    Ok(())
}
/// Sensitive protocol bytes/strings deliberately do not implement revealing Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(pub T);
impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
