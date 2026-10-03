use rss_request_context::{Clock, Deadline};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Duration};

/// Closed diagnostics: never retain an SDK source, URL, key or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("invalid content storage input")]
    Input,
    #[error("content storage configuration or capability rejected")]
    Configuration,
    #[error("content storage access denied")]
    Denied,
    #[error("selected object or upload not found")]
    Missing,
    #[error("content storage condition conflict")]
    Conflict,
    #[error("content storage temporarily unavailable")]
    Transient,
    #[error("content storage integrity mismatch")]
    Integrity,
    #[error("content storage budget exhausted")]
    Budget,
    #[error("content storage concurrency exhausted")]
    Busy,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Per-call limits; copied cutoffs never extend a call. Byte limits bound payloads,
/// not cross-client stored-byte quotas (those belong to the content business owner).
#[derive(Clone)]
pub struct Budget {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) deadline: Deadline,
    pub(crate) idle: Duration,
    pub(crate) bytes: u64,
    pub(crate) pages: usize,
}
impl Budget {
    pub fn new(
        clock: Arc<dyn Clock>,
        timeout: Duration,
        idle: Duration,
        bytes: u64,
        pages: usize,
    ) -> Result<Self> {
        if timeout.is_zero() || idle.is_zero() || pages == 0 || pages > 10_000 {
            return Err(Error::Input);
        }
        Ok(Self {
            deadline: Deadline::from_timeout(clock.as_ref(), timeout).map_err(|_| Error::Input)?,
            clock,
            idle,
            bytes,
            pages,
        })
    }
}

/// Expected complete bytes, independent of provider ETag/composite checksum semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub length: u64,
    pub sha256: [u8; 32],
}

/// Namespace-relative target bound to one connection/bucket/namespace identity.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub(crate) scope: [u8; 32],
    pub(crate) key: String,
}
impl Target {
    pub fn relative_key(&self) -> &str {
        &self.key
    }
}
impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Target(<redacted>)")
    }
}

/// Unverified persisted coordinate. Restoration is not proof that an object exists.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub(crate) target: Target,
    pub(crate) version: String,
}
impl Object {
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}
impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Object(<redacted>)")
    }
}

/// Caller-selected operation association; the caller owns uniqueness and persistence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Write {
    pub(crate) target: Target,
    pub(crate) operation: String,
    pub(crate) content: Content,
}
impl Write {
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn content(&self) -> Content {
        self.content
    }
}
impl fmt::Debug for Write {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Write(<redacted>)")
    }
}

/// Durable host material for the original multipart upload; never substituted on recovery.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub(crate) write: Write,
    pub(crate) id: String,
}
impl Upload {
    pub fn write(&self) -> &Write {
        &self.write
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
impl fmt::Debug for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Upload(<redacted>)")
    }
}

/// Provider-observed part identity; SHA-256 is per-part, never a full-object hash.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Part {
    pub(crate) upload: Upload,
    pub(crate) number: i32,
    pub(crate) length: u64,
    pub(crate) etag: String,
    pub(crate) sha256: [u8; 32],
}
impl Part {
    pub fn number(&self) -> i32 {
        self.number
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn etag(&self) -> &str {
        &self.etag
    }
}
impl fmt::Debug for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Part")
            .field("number", &self.number)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// Produced only by complete byte verification. Not deserializable; reverify restored coordinates.
#[derive(Clone, Debug)]
pub struct Verified {
    pub(crate) object: Object,
    pub(crate) content: Content,
}
impl Verified {
    pub fn object(&self) -> &Object {
        &self.object
    }
    pub fn content(&self) -> Content {
        self.content
    }
}

/// HEAD facts are observed metadata, not complete-byte verification.
#[derive(Debug)]
pub struct Metadata {
    pub object: Object,
    pub length: u64,
    pub(crate) operation: Option<String>,
}

/// A confirmed write may still require verification; do not reupload on verification failure.
#[derive(Debug)]
pub enum Written {
    Verified(Verified),
    Unverified { object: Object, error: Error },
}
/// An uncertain effect must be reconciled with the caller's original target/handle.
#[derive(Debug)]
pub enum Mutation<T> {
    Confirmed(T),
    Unknown(Error),
}
/// An absent upload can have completed or been aborted; it is not a failed-write receipt.
#[derive(Debug)]
pub enum UploadState {
    Active(Vec<Part>),
    Absent,
}
/// Candidate discovery never selects an upload or proves an absent initiation did not happen.
#[derive(Debug)]
pub struct Candidates {
    pub ids: Vec<String>,
}
/// No current match is not proof of rollback; another version may have existed.
#[derive(Debug)]
pub enum Recovery {
    Matched(Written),
    Unresolved,
}

pub(crate) fn token(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Input);
    }
    Ok(())
}
pub(crate) fn relative(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(Error::Input);
    }
    Ok(())
}
pub(crate) fn version(value: &str) -> Result<()> {
    token(value, 1024)?;
    if value == "null" {
        return Err(Error::Configuration);
    }
    Ok(())
}
