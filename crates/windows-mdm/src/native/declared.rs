//! WinDC document identity and result semantics; a SyncML ACK never proves convergence.
//! ref: Microsoft declared-configuration-resource-access and declared-configuration-extensibility.
use super::{Error, Scope};
use crate::{
    CodecLimits,
    xml::{Input, Start},
};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Document identity is native to its linked registration and scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Document GUID supplied by the server.
    pub id: Uuid,
    /// Native device or enrolled-user context.
    pub scope: Scope,
    /// Server-supplied immutable document version.
    pub checksum: String,
    /// Scenario selected from the pinned official tables.
    pub scenario: String,
}
/// Native resource result facts, separate from document-level progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceResult {
    /// Exact native document or resource identity.
    pub identity: String,
    /// Native resource status, absent while no result is reported.
    pub status: Option<u16>,
    /// Native lifecycle state, independent of SyncML status.
    pub state: Option<u32>,
}
/// Parsed bounded native document. Values deliberately do not implement Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct Document {
    /// Exact native document or resource identity.
    pub identity: Identity,
    /// Requested resources or independently reported per-resource facts.
    pub resources: BTreeMap<String, ResourceValue>,
    /// Whether the document targets a native MI provider.
    pub dsc: bool,
}
/// A native value remains tied to the format declared by its official protocol position.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceValue {
    /// Native URI format, absent for MI provider parameters.
    pub format: Option<String>,
    /// Sensitive native value; never emitted by Debug.
    pub value: crate::Secret<String>,
}
/// Parsed result retains partial and infrastructure failures without inventing success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultDocument {
    /// Exact native document or resource identity.
    pub identity: Identity,
    /// Client-supplied result version; not a cryptographic authenticity proof.
    pub result_checksum: String,
    /// Native Set, Get, or Delete lifecycle.
    pub operation: String,
    /// Native lifecycle state, independent of SyncML status.
    pub state: u32,
    /// Requested resources or independently reported per-resource facts.
    pub resources: Vec<ResourceResult>,
}
fn malformed(_: crate::CodecError) -> Error {
    Error::Value
}
fn attr<'a>(start: &'a Start, name: &str) -> Result<&'a str, Error> {
    start
        .attr("", name)
        .filter(|v| !v.is_empty())
        .ok_or(Error::Value)
}
fn identity(start: &Start) -> Result<Identity, Error> {
    if attr(start, "schema")? != "1.0" {
        return Err(Error::Unsupported);
    }
    let scope = match attr(start, "context")? {
        "Device" | "device" => Scope::Device,
        "User" | "user" => Scope::User,
        _ => return Err(Error::Scope),
    };
    let scenario = attr(start, "osdefinedscenario")?;
    if !super::generated::DECLARED_SCENARIOS
        .iter()
        .any(|(name, _)| *name == scenario)
    {
        return Err(Error::Unsupported);
    }
    let checksum = attr(start, "checksum")?;
    if checksum.len() > 256 || checksum.chars().any(char::is_control) {
        return Err(Error::Value);
    }
    let id = Uuid::parse_str(attr(start, "id")?).map_err(|_| Error::Identity)?;
    if id.is_nil() {
        return Err(Error::Identity);
    }
    Ok(Identity {
        id,
        scope,
        checksum: checksum.into(),
        scenario: scenario.into(),
    })
}
fn root_attributes(start: &Start, result: bool) -> Result<(), Error> {
    let mut attrs = vec![
        ("", "schema"),
        ("", "context"),
        ("", "id"),
        ("", "checksum"),
        ("", "osdefinedscenario"),
    ];
    if result {
        attrs.extend([
            ("", "result_checksum"),
            ("", "result_timestamp"),
            ("", "operation"),
            ("", "state"),
        ]);
    }
    start.attrs(&attrs).map_err(malformed)
}
fn number<T: std::str::FromStr>(start: &Start, name: &str) -> Result<Option<T>, Error> {
    start
        .attr("", name)
        .map(|v| v.parse().map_err(|_| Error::Value))
        .transpose()
}
fn family(start: &Start, dsc: bool, result: bool) -> Result<String, Error> {
    let mut attrs = if dsc {
        vec![("", "namespace"), ("", "className"), ("", "classname")]
    } else {
        vec![("", "name")]
    };
    if result {
        attrs.extend([("", "state"), ("", "status")]);
    }
    start.attrs(&attrs).map_err(malformed)?;
    if dsc {
        if start.attr("", "className").is_some() && start.attr("", "classname").is_some() {
            return Err(Error::Value);
        }
        let class = start
            .attr("", "className")
            .or_else(|| start.attr("", "classname"))
            .ok_or(Error::Value)?;
        if class.is_empty()
            || class.len() > 256
            || !class
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::Value);
        }
        let namespace = attr(start, "namespace")?.replace('\\', "/");
        if namespace.len() > 256
            || !namespace
                .split('/')
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err(Error::Identity);
        }
        Ok(format!(
            "{}:{}",
            namespace.to_ascii_lowercase(),
            class.to_ascii_lowercase()
        ))
    } else {
        let name = attr(start, "name")?;
        if !name.starts_with("./Vendor/MSFT/")
            || name.split('/').count() != 4
            || name.contains(['<', '>', '%'])
            || name == "./Vendor/MSFT/DeclaredConfiguration"
        {
            return Err(Error::Identity);
        }
        Ok(name.into())
    }
}
fn member(start: &Start, family: &str, dsc: bool, result: bool) -> Result<String, Error> {
    let mut attrs = if dsc {
        vec![("", "name")]
    } else {
        vec![("", "path"), ("", "type")]
    };
    if result {
        attrs.extend([("", "status"), ("", "state")]);
    }
    start.attrs(&attrs).map_err(malformed)?;
    let path = attr(start, if dsc { "name" } else { "path" })?;
    if path.len() > 2048
        || path.starts_with('/')
        || path
            .split('/')
            .any(|s| s.is_empty() || matches!(s, "." | ".."))
    {
        return Err(Error::Identity);
    }
    if !dsc
        && !matches!(
            attr(start, "type")?,
            "chr" | "int" | "bool" | "b64" | "bin" | "xml" | "node" | "null" | "time"
        )
    {
        return Err(Error::Value);
    }
    if dsc {
        if !path.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::Identity);
        }
        Ok(format!(
            "{family}/{}/{}",
            start.name,
            path.to_ascii_lowercase()
        ))
    } else {
        Ok(format!("{family}/{path}"))
    }
}
impl Document {
    /// Parse the bounded official document grammar without external XML resolution.
    pub fn parse(xml: &str) -> Result<Self, Error> {
        let limits = CodecLimits::default();
        let mut input =
            Input::new(xml.as_bytes(), limits.object_bytes, &limits).map_err(malformed)?;
        let root = input
            .start("", "DeclaredConfiguration")
            .map_err(malformed)?;
        root_attributes(&root, false)?;
        let identity = identity(&root)?;
        let dsc = identity.scenario.starts_with("MSFTExtensibilityMIProvider");
        if dsc && identity.scope != Scope::Device {
            return Err(Error::Scope);
        }
        let family_tag = if dsc { "DSC" } else { "CSP" };
        let mut resources = BTreeMap::new();
        let mut families = std::collections::BTreeSet::new();
        while input.is("", family_tag).map_err(malformed)? {
            let start = input.start("", family_tag).map_err(malformed)?;
            let family = family(&start, dsc, false)?;
            if dsc && !families.insert(family.clone()) {
                return Err(Error::Identity);
            }
            while input
                .is("", if dsc { "Key" } else { "URI" })
                .map_err(malformed)?
                || (dsc && input.is("", "Value").map_err(malformed)?)
            {
                let tag = if !dsc {
                    "URI"
                } else if input.is("", "Key").map_err(malformed)? {
                    "Key"
                } else {
                    "Value"
                };
                let start = input.start("", tag).map_err(malformed)?;
                let key = member(&start, &family, dsc, false)?;
                let value = input
                    .content("", tag, limits.object_bytes, true)
                    .map_err(malformed)?;
                if resources
                    .insert(
                        key,
                        ResourceValue {
                            format: start.attr("", "type").map(str::to_owned),
                            value: crate::Secret(value),
                        },
                    )
                    .is_some()
                {
                    return Err(Error::Identity);
                }
                if resources.len() > limits.items {
                    return Err(Error::Limit);
                }
            }
            input.end("", family_tag).map_err(malformed)?;
        }
        input.end("", "DeclaredConfiguration").map_err(malformed)?;
        input.finish().map_err(malformed)?;
        if resources.is_empty()
            || dsc
                && families.iter().any(|family| {
                    !resources
                        .keys()
                        .any(|k| k.starts_with(&format!("{family}/Key/")))
                })
        {
            return Err(Error::Value);
        }
        Ok(Self {
            identity,
            resources,
            dsc,
        })
    }
}
impl ResultDocument {
    /// Parse the bounded official document grammar without external XML resolution.
    pub fn parse(xml: &str) -> Result<Self, Error> {
        let limits = CodecLimits::default();
        let mut input =
            Input::new(xml.as_bytes(), limits.object_bytes, &limits).map_err(malformed)?;
        let root = input
            .start("", "DeclaredConfigurationResult")
            .map_err(malformed)?;
        root_attributes(&root, true)?;
        let identity = identity(&root)?;
        let state = number(&root, "state")?.ok_or(Error::Value)?;
        if !matches!(state,0..=3|10..=11|20..=21|40|60..=63|70..=72|80..=82) {
            return Err(Error::Value);
        }
        let operation = attr(&root, "operation")?.to_owned();
        if !matches!(operation.as_str(), "Set" | "Get" | "Delete") {
            return Err(Error::Value);
        }
        let result_checksum = attr(&root, "result_checksum")?.to_owned();
        if result_checksum.len() > 256 {
            return Err(Error::Limit);
        }
        let dsc = identity.scenario.starts_with("MSFTExtensibilityMIProvider");
        let family_tag = if dsc { "DSC" } else { "CSP" };
        let mut resources = BTreeMap::new();
        let mut families = std::collections::BTreeSet::new();
        while input.is("", family_tag).map_err(malformed)? {
            let start = input.start("", family_tag).map_err(malformed)?;
            let family = family(&start, dsc, true)?;
            if dsc && !families.insert(family.clone()) {
                return Err(Error::Identity);
            }
            let inherited_status = number(&start, "status")?;
            let inherited_state = number(&start, "state")?;
            if inherited_status.is_some_and(|v| v != 200)
                || inherited_state.is_some_and(|v| v != state)
            {
                return Err(Error::Value);
            }
            while input
                .is("", if dsc { "Key" } else { "URI" })
                .map_err(malformed)?
                || (dsc && input.is("", "Value").map_err(malformed)?)
            {
                let tag = if !dsc {
                    "URI"
                } else if input.is("", "Key").map_err(malformed)? {
                    "Key"
                } else {
                    "Value"
                };
                let start = input.start("", tag).map_err(malformed)?;
                let key = member(&start, &family, dsc, true)?;
                let value = ResourceResult {
                    identity: key.clone(),
                    status: number(&start, "status")?.or(inherited_status),
                    state: number(&start, "state")?.or(inherited_state),
                };
                input
                    .content("", tag, limits.object_bytes, true)
                    .map_err(malformed)?;
                if resources.insert(key, value).is_some() {
                    return Err(Error::Identity);
                }
                if resources.len() > limits.items {
                    return Err(Error::Limit);
                }
            }
            input.end("", family_tag).map_err(malformed)?;
        }
        input
            .end("", "DeclaredConfigurationResult")
            .map_err(malformed)?;
        input.finish().map_err(malformed)?;
        Ok(Self {
            identity,
            result_checksum,
            operation,
            state,
            resources: resources.into_values().collect(),
        })
    }
    /// Success requires the original identity/version and every requested resource.
    pub fn converged(&self, desired: &Document, operation: &str) -> bool {
        let success = match operation {
            "Set" => 60,
            "Delete" => 70,
            "Get" => 80,
            _ => return false,
        };
        self.identity == desired.identity
            && self.operation == operation
            && self.state == success
            && self.resources.len() == desired.resources.len()
            && self.resources.iter().all(|r| {
                desired.resources.contains_key(&r.identity)
                    && r.status == Some(200)
                    && r.state == Some(success)
            })
    }
}

/// A WinDC summary is a trigger to retrieve full results, never convergence evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Document identity within the linked enrollment.
    pub id: Uuid,
    /// Native target context.
    pub scope: Scope,
    /// Server document version echoed by the client.
    pub checksum: String,
    /// Client result version to retrieve.
    pub result_checksum: String,
    /// Native document progress.
    pub state: u32,
}
/// Parse the native 1224 summary, including an empty current document set.
pub fn summaries(xml: &str) -> Result<Vec<Summary>, Error> {
    let limits = CodecLimits::default();
    let mut input = Input::new(xml.as_bytes(), limits.object_bytes, &limits).map_err(malformed)?;
    let root = input
        .start("", "DeclaredConfigurations")
        .map_err(malformed)?;
    root.attrs(&[("", "schema")]).map_err(malformed)?;
    if attr(&root, "schema")? != "1.0" {
        return Err(Error::Unsupported);
    }
    let mut documents = BTreeMap::new();
    while input.is("", "DeclaredConfiguration").map_err(malformed)? {
        let start = input
            .start("", "DeclaredConfiguration")
            .map_err(malformed)?;
        start
            .attrs(&[
                ("", "context"),
                ("", "id"),
                ("", "checksum"),
                ("", "result_checksum"),
                ("", "state"),
            ])
            .map_err(malformed)?;
        let scope = match attr(&start, "context")? {
            "Device" | "device" => Scope::Device,
            "User" | "user" => Scope::User,
            _ => return Err(Error::Scope),
        };
        let id = Uuid::parse_str(attr(&start, "id")?).map_err(|_| Error::Identity)?;
        if id.is_nil() {
            return Err(Error::Identity);
        }
        let checksum = attr(&start, "checksum")?.to_owned();
        let result_checksum = attr(&start, "result_checksum")?.to_owned();
        if checksum.len() > 256 || result_checksum.len() > 256 {
            return Err(Error::Limit);
        }
        let state = number(&start, "state")?.ok_or(Error::Value)?;
        if !matches!(state,0..=3|10..=11|20..=21|40|60..=63|70..=72|80..=82) {
            return Err(Error::Value);
        }
        if documents
            .insert(
                (scope, id),
                Summary {
                    id,
                    scope,
                    checksum,
                    result_checksum,
                    state,
                },
            )
            .is_some()
        {
            return Err(Error::Identity);
        }
        if documents.len() > limits.items {
            return Err(Error::Limit);
        }
        input.end("", "DeclaredConfiguration").map_err(malformed)?;
    }
    input.end("", "DeclaredConfigurations").map_err(malformed)?;
    input.finish().map_err(malformed)?;
    Ok(documents.into_values().collect())
}

impl Document {
    /// Validate embedded CSP values using the same generated schema as ordinary native operations.
    pub fn requests(&self, operation: super::Verb) -> Result<Vec<super::Request>, Error> {
        if self.dsc {
            return Err(Error::OperationNotAllowed);
        }
        let inventory = operation == super::Verb::Get;
        self.resources
            .iter()
            .map(|(uri, resource)| {
                let value = if inventory || operation == super::Verb::Delete {
                    None
                } else {
                    Some(match resource.format.as_deref().ok_or(Error::Value)? {
                        "chr" => super::Value::Text(resource.value.0.clone()),
                        "xml" => super::Value::Xml(resource.value.0.clone()),
                        "int" => super::Value::Integer(
                            resource.value.0.parse().map_err(|_| Error::Value)?,
                        ),
                        "bool" => super::Value::Boolean(match resource.value.0.as_str() {
                            "true" | "1" => true,
                            "false" | "0" => false,
                            _ => return Err(Error::Value),
                        }),
                        "b64" | "bin" => {
                            use base64::Engine;
                            super::Value::Bytes(
                                base64::engine::general_purpose::STANDARD
                                    .decode(&resource.value.0)
                                    .map_err(|_| Error::Value)?,
                            )
                        }
                        "time" => super::Value::Time(resource.value.0.clone()),
                        _ => return Err(Error::UnresolvedConstraint),
                    })
                };
                super::Request::from_uri(uri, operation, value, self.identity.scope)
            })
            .collect()
    }
}

/// Frozen servicing support for certificate-linked discovery; client claims are not identity proof.
pub fn certificate_supported(build: [u32; 4]) -> bool {
    super::generated::NODES
        .iter()
        .find(|n| {
            n.path
                == "./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document"
        })
        .is_some_and(|n| {
            n.certificate_builds
                .iter()
                .any(|b| build[..3] == b[..3] && build[3] >= b[3])
        })
}
