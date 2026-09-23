#![deny(missing_docs)]
#![deny(clippy::cognitive_complexity)]
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
pub mod configuration;
pub mod provisioning;
pub mod soap;
pub mod syncml;
mod xml;

/// Errors contain only closed classifications, never XML or credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Input is not well-formed XML.
    MalformedXml,
    /// An element or attribute uses an unexpected namespace.
    WrongNamespace,
    /// Required protocol structure is missing or inconsistent.
    Structure,
    /// A value violates the field's supported syntax or range.
    InvalidValue,
    /// The wire feature is outside the supported protocol profile.
    Unsupported,
    /// A byte, depth, element, event, attribute, command or item budget was exceeded.
    LimitExceeded,
    /// The message action/body is not the expected operation.
    UnexpectedOperation,
    /// Input uses a prohibited XML construct, such as a DTD or processing instruction.
    ForbiddenXml,
    /// A field, identity or reference that must be unique is repeated.
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
/// Bounded codec result carrying a closed [`CodecError`].
pub type Result<T> = std::result::Result<T, CodecError>;

/// Failure source for association APIs. No remote input is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationError {
    /// The originating local request fails codec/profile validation.
    InvalidRequest(CodecError),
    /// The local expected-response state is invalid or exceeds its budgets.
    InvalidExpected(CodecError),
    /// The response is invalid or contains conflicting repeated coverage.
    InvalidResponse(CodecError),
    /// The valid response does not match the expected operation or correlation identities.
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
/// Association result distinguishing bad local inputs, bad responses and mismatches.
pub type CorrelationResult<T> = std::result::Result<T, CorrelationError>;

/// Per-message limits. All limits are enforced; zero means no capacity, not unlimited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecLimits {
    /// Maximum discovery message bytes and direct SOAP Fault encoding/decoding; default 64 KiB.
    /// [`soap::decode_response`] instead applies the originating operation's budget to Faults.
    pub discovery_bytes: usize,
    /// Maximum encoded/decoded XCEP policy message bytes; default 256 KiB.
    /// Also bounds Fault input for a GetPolicies request in [`soap::decode_response`].
    pub xcep_bytes: usize,
    /// Maximum encoded/decoded WSTEP enrollment message bytes; default 512 KiB.
    /// Also bounds Fault input for an Issue request in [`soap::decode_response`].
    pub wstep_bytes: usize,
    /// Maximum encoded/decoded SyncML message bytes; default 512 KiB.
    pub syncml_bytes: usize,
    /// Maximum XML element nesting depth; default 32.
    pub depth: usize,
    /// Maximum XML elements per message; default 4096.
    pub elements: usize,
    /// Maximum XML processing events per message; default 16384.
    pub events: usize,
    /// Maximum attributes on one element, including namespace declarations; default 32.
    pub attributes_per_element: usize,
    /// Maximum accumulated XML attributes per message; default 2048.
    pub attributes: usize,
    /// Maximum active namespace bindings; default 32.
    pub namespace_bindings: usize,
    /// Maximum SyncML commands; also bounds retained correlation messages/commands; default 256.
    pub commands: usize,
    /// Maximum accumulated protocol items; also bounds correlation target references; default 1024.
    pub items: usize,
    /// Maximum UTF-8 bytes in identifier-class text; default 128.
    pub identifier_bytes: usize,
    /// Maximum UTF-8 bytes in URI-class text; default 2048.
    pub uri_bytes: usize,
    /// Maximum UTF-8 bytes in general text fields; default 64 KiB.
    pub field_bytes: usize,
    /// Maximum decoded binary field or generated provisioning document bytes; default 256 KiB.
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
/// Debug-redacted protocol data with explicit access through the public inner value.
/// This wrapper neither encrypts nor zeroizes memory and does not validate its input.
/// Encoded output still contains the sensitive data; the caller owns disclosure and transport.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(
    /// Unprotected inner value; accessing or formatting it bypasses Debug redaction.
    pub T,
);
impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
