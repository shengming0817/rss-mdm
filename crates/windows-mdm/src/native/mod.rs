//! Source-constrained Windows operations. Compilation is not authorization or proof of effect.
//! ref: Microsoft DDFv2Feb2026, pinned in ddf/upstream/source.json.
use crate::{
    Secret,
    syncml::{Command, Item, Meta},
};
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
mod generated;
pub mod admx;
mod decimal;
pub mod declared;
mod request;
mod resolved;
pub use resolved::{AuthorizationTarget, Prepared, Resolved};
pub mod receipt;
mod value;
pub mod verification;
pub use request::{Compiled, Execution, Object, Request};
mod xsd;

/// Native Windows management scope, independent of the node's permanent/dynamic lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Device management tree.
    Device,
    /// Enrolled user's management tree.
    User,
}
/// Authenticated target evidence supplied by the registration/observation owners.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// OS major, minor, build and servicing revision; absent means not observed.
    pub build: Option<[u32; 4]>,
    /// Native OS edition identifier; absent means not observed.
    pub edition: Option<u32>,
    /// Authorized target channel.
    pub scope: Scope,
    /// Cryptographically authenticated enrollment purpose, supplied by the channel owner.
    pub enrollment: Enrollment,
}
/// Enrollment identity bound by the registration owner; no implicit primary fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    /// Ordinary management registration.
    Primary,
    /// Independent certificate authenticated WinDC registration.
    LinkedCertificate,
}
/// Native operation, rather than a product purpose or brand.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    /// Query a node or enumerate an interior node.
    Get,
    /// Create a native node.
    Add,
    /// Replace a native value.
    Replace,
    /// Delete a node and its native subtree.
    Delete,
    /// Invoke a native action.
    Exec,
}
impl Verb {
    fn mask(self) -> u8 {
        match self {
            Self::Get => 1,
            Self::Add => 2,
            Self::Replace => 4,
            Self::Delete => 8,
            Self::Exec => 16,
        }
    }
}
/// Native input values. Values intentionally have no Debug implementation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Value {
    /// Native policy controls compiled from an official ADMX definition.
    Admx(admx::PolicyValue),
    /// Character data.
    Text(String),
    /// Integer data, including unsigned 32-bit DDF ranges.
    Integer(#[serde(with = "decimal")] i64),
    /// Boolean data.
    Boolean(bool),
    /// Decoded binary bytes, encoded once at the protocol boundary.
    Bytes(Vec<u8>),
    /// XML payload subject to its node's structural constraints.
    Xml(String),
    /// Native time value.
    Time(String),
}
/// Closed validation failures; no device or input data is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No official schema matches the requested native object.
    UnknownObject,
    /// Dynamic identity is incomplete or invalid.
    Identity,
    /// The native object belongs to a different management scope.
    Scope,
    /// Required target evidence has not been observed.
    MissingEvidence,
    /// The frozen definition does not support this target.
    Unsupported,
    /// The native schema does not permit this verb.
    OperationNotAllowed,
    /// A typed value violates the schema.
    Value,
    /// Source semantics require a native constraint adapter before dispatch.
    UnresolvedConstraint,
    /// A native object requires an Atomic group for this operation.
    AtomicRequired,
    /// A request exceeds the native codec's bounded input budget.
    Limit,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnknownObject => "unknown native object",
            Self::Identity => "invalid native identity",
            Self::Scope => "native scope mismatch",
            Self::MissingEvidence => "missing target evidence",
            Self::Unsupported => "unsupported native target",
            Self::OperationNotAllowed => "native operation not allowed",
            Self::Value => "invalid native value",
            Self::UnresolvedConstraint => "native constraint requires resolution",
            Self::Limit => "native input budget exceeded",
            Self::AtomicRequired => "native operation requires an atomic group",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Format {
    Text,
    Integer,
    Boolean,
    Base64,
    Binary,
    Xml,
    Node,
    Null,
    Time,
}
impl Format {
    fn wire(self) -> &'static str {
        match self {
            Self::Text => "chr",
            Self::Integer => "int",
            Self::Boolean => "bool",
            Self::Base64 => "b64",
            Self::Binary => "bin",
            Self::Xml => "xml",
            Self::Node => "node",
            Self::Null => "null",
            Self::Time => "time",
        }
    }
}
struct Constraint {
    kind: &'static str,
    values: &'static [&'static str],
    delimiter: Option<&'static str>,
    admx: Option<(&'static str, &'static str)>,
}
struct Node {
    path: &'static str,
    source: &'static str,
    stable_source: Option<&'static str>,
    preview: bool,
    bounded_branches: bool,
    certificate_builds: &'static [[u32; 4]],
    format: Format,
    access: u8,
    builds: &'static [[u32; 4]],
    editions: Option<&'static [&'static str]>,
    mime: &'static str,
    lifetime: &'static str,
    occurrence: &'static str,
    case: Option<&'static str>,
    atomic: bool,
    deprecated: Option<&'static str>,
    constraints: &'static [Constraint],
}

/// Native lifecycle metadata, retained independently of ACK or effect evidence.
pub struct Semantics {
    /// DDF permanent/dynamic node lifetime.
    pub lifetime: &'static str,
    /// DDF occurrence contract; request budgets still apply.
    pub occurrence: &'static str,
    /// Explicit source case sensitivity, if declared.
    pub case: Option<&'static str>,
    /// Whether the native node requires an Atomic group.
    pub atomic_required: bool,
    /// Deprecated build, or empty text for an undated deprecation; not a removal.
    pub deprecated: Option<&'static str>,
}

/// An immutable schema-checked operation, still requiring resource authorization at dispatch.
pub struct Operation {
    node: &'static Node,
    verb: Verb,
    uri: String,
    data: Option<Secret<String>>,
}
impl Operation {
    /// Resolve a frozen template and dynamic segments, then validate target and native input.
    pub fn compile(
        template: &str,
        segments: &[String],
        verb: Verb,
        value: Option<Value>,
        target: Context,
    ) -> Result<Self, Error> {
        let index = generated::NODES
            .binary_search_by_key(&template, |n| n.path)
            .map_err(|_| Error::UnknownObject)?;
        let node = &generated::NODES[index];
        let scope = if template.starts_with("./User/") {
            Scope::User
        } else {
            Scope::Device
        };
        if scope != target.scope {
            return Err(Error::Scope);
        }
        let uri = identity(template, segments)?;
        node.check(target)?;
        if node.access & verb.mask() == 0 {
            return Err(Error::OperationNotAllowed);
        }
        let data = value::compile(node, verb, value, target)?;
        Ok(Self {
            node,
            verb,
            uri,
            data: data.map(Secret),
        })
    }
    /// Canonical URI, including encoded dynamic identities.
    pub fn uri(&self) -> &str {
        &self.uri
    }
    /// Official Learn source digest used to select the stable applicability branches.
    pub fn applicability_source(&self) -> Option<&'static str> {
        self.node.stable_source
    }
    /// Frozen official source file; the source manifest owns its immutable digest.
    pub fn source(&self) -> &'static str {
        self.node.source
    }
    /// Native lifecycle requirements, independent of execution state.
    pub fn semantics(&self) -> Semantics {
        Semantics {
            lifetime: self.node.lifetime,
            occurrence: self.node.occurrence,
            case: self.node.case,
            atomic_required: self.node.atomic,
            deprecated: self.node.deprecated,
        }
    }
    /// Allocate a protocol command identity after the execution owner has authorized dispatch.
    /// Codec validation still rejects zero or duplicate IDs in the containing message.
    pub fn command(&self, id: u32) -> Command {
        let items = vec![Item {
            more_data: false,
            source: None,
            target: Some(self.uri.clone()),
            data: self.data.clone(),
            meta: self.data.as_ref().map(|_| Meta {
                format: Some(self.node.format.wire().into()),
                media_type: (!self.node.mime.is_empty()).then(|| self.node.mime.into()),
                ..Meta::default()
            }),
        }];
        match self.verb {
            Verb::Get => Command::Get {
                id,
                meta: None,
                items,
            },
            Verb::Add => Command::Add {
                id,
                meta: None,
                items,
            },
            Verb::Replace => Command::Replace {
                id,
                meta: None,
                items,
            },
            Verb::Delete => Command::Delete {
                id,
                meta: None,
                items,
            },
            Verb::Exec => Command::Exec {
                id,
                meta: None,
                items,
            },
        }
    }
}
impl Node {
    fn check(&self, target: Context) -> Result<(), Error> {
        let declared = self.path.contains("/Vendor/MSFT/DeclaredConfiguration");
        if declared != (target.enrollment == Enrollment::LinkedCertificate) {
            return Err(Error::Scope);
        }
        if self.preview && self.certificate_builds.is_empty() {
            return Err(Error::Unsupported);
        }
        let build = target.build.ok_or(Error::MissingEvidence)?;
        let edition = target.edition.ok_or(Error::MissingEvidence)?;
        let builds = if declared {
            self.certificate_builds
        } else {
            self.builds
        };
        if builds.is_empty() {
            return Err(Error::UnresolvedConstraint);
        }
        // A servicing revision applies to its branch, not every numerically newer build.
        if !builds.iter().any(|b| {
            b[0..2] == [10, 0]
                && build[0..2] == b[0..2]
                && if b[3] == 0 && !self.bounded_branches && !declared {
                    build[2] >= b[2]
                } else {
                    build[2] == b[2] && build[3] >= b[3]
                }
        }) {
            return Err(Error::Unsupported);
        }
        let editions = self.editions.ok_or(Error::UnresolvedConstraint)?;
        if !editions.iter().any(|raw| {
            raw.strip_prefix("0x")
                .and_then(|raw| u32::from_str_radix(raw, 16).ok())
                == Some(edition)
        }) {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}

fn identity(template: &str, segments: &[String]) -> Result<String, Error> {
    let mut values = segments.iter();
    let mut uri = String::new();
    for segment in template.split('/') {
        if !uri.is_empty() {
            uri.push('/');
        }
        if segment != "*" {
            uri.push_str(segment);
            continue;
        }
        let value = values.next().ok_or(Error::Identity)?;
        if value.is_empty()
            || matches!(value.as_str(), "." | ".." | "*")
            || value.chars().any(char::is_control)
        {
            return Err(Error::Identity);
        }
        if value.len() > 2048 {
            return Err(Error::Limit);
        }
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                uri.push(char::from(byte));
            } else {
                use std::fmt::Write;
                write!(uri, "%{byte:02X}").map_err(|_| Error::Identity)?;
            }
        }
    }
    if values.next().is_some() {
        return Err(Error::Identity);
    }
    if uri.len() > 2048 {
        return Err(Error::Limit);
    }
    Ok(uri)
}

pub(crate) fn known_node(template: &str) -> bool {
    generated::NODES
        .binary_search_by_key(&template, |node| node.path)
        .is_ok()
}
