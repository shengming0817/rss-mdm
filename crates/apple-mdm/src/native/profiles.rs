//! Multi-object native Profile composition. Ownership and installation belong to the channel.
//! ref: Apple TopLevel.yaml, CommonPayloadKeys.yaml and individual payload definitions.
use super::{Error, Kind, Payload, ProfilePayload, Target, generated, input::Fields};
use crate::applicability::Channel;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// One payload with native identity, shared metadata and its generated schema fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PayloadInput {
    /// Official payload schema path; PayloadType alone is not unique in Apple's definitions.
    pub schema: String,
    /// Native PayloadIdentifier, stable across updates.
    pub identifier: String,
    /// Native PayloadUUID, independently versioned by the content owner.
    pub uuid: Uuid,
    /// Optional CommonPayloadKeys; identity/type/version keys are owned by the compiler.
    #[serde(default)]
    pub metadata: Fields,
    /// Payload-specific native fields.
    pub fields: Fields,
}
/// A profile content version. Resource versions are independent of Apple's fixed PayloadVersion=1.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileInput {
    /// Native profile identifier, which determines replacement versus a distinct object.
    pub identifier: String,
    /// Native profile UUID.
    pub uuid: Uuid,
    /// Optional TopLevel properties, excluding compiler-owned content/identity/scope keys.
    #[serde(default)]
    pub metadata: Fields,
    /// Ordered native payloads, each validated against its own schema.
    pub payloads: Vec<PayloadInput>,
}
impl std::fmt::Debug for ProfileInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppleProfileInput([REDACTED])")
    }
}
/// Native object evidence used to establish multi-object ownership claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileObject {
    /// Configuration for the envelope, or the actual native PayloadType.
    pub payload_type: String,
    /// Native identifier.
    pub identifier: String,
    /// Native UUID.
    pub uuid: Uuid,
    /// Whether the payload's official schema allows multiple instances in a scope.
    pub multiple: bool,
}
/// Compiled unsigned profile. CMS signing stays with the existing certificate/channel owner.
pub struct CompiledProfile {
    /// Exact native profile bytes.
    pub bytes: Vec<u8>,
    /// Profile and payload objects; an ACK does not prove their device effects.
    pub objects: Vec<ProfileObject>,
}
impl PayloadInput {
    /// Stable native type from the generated official schema; applicability is checked at dispatch.
    pub fn payload_type(&self) -> Result<&'static str, Error> {
        generated::DEFINITIONS
            .iter()
            .find(|d| d.kind == Kind::Profile && d.schema == self.schema)
            .map(|d| d.identity)
            .ok_or(Error::UnknownSchema)
    }
}
impl ProfileInput {
    /// Compare the complete returned manifest, never infer settings or compliance from its presence.
    /// Missing/encrypted content cannot establish that an earlier payload was replaced.
    pub fn observed(&self, report: &Dictionary) -> Result<bool, crate::Error> {
        let objects = self
            .payloads
            .iter()
            .map(|p| {
                Ok(ProfileObject {
                    payload_type: p
                        .payload_type()
                        .map_err(|_| crate::Error::Malformed)?
                        .into(),
                    identifier: p.identifier.clone(),
                    uuid: p.uuid,
                    multiple: true,
                })
            })
            .collect::<Result<Vec<_>, crate::Error>>()?;
        observed_manifest(report, &self.identifier, self.uuid, &objects)
    }

    /// Compile one scope-consistent profile and reject duplicate identities or singleton types.
    pub fn compile(&self, target: &Target<'_>) -> Result<CompiledProfile, Error> {
        identity(&self.identifier, self.uuid)?;
        if self.payloads.len() > 256 {
            return Err(Error::Limit);
        }
        let mut identifiers = BTreeSet::from([self.identifier.as_str()]);
        let mut uuids = BTreeSet::from([self.uuid]);
        let mut singleton_types = BTreeSet::new();
        let mut objects = vec![ProfileObject {
            payload_type: "Configuration".into(),
            identifier: self.identifier.clone(),
            uuid: self.uuid,
            multiple: true,
        }];
        let mut payloads = Vec::new();
        for input in &self.payloads {
            identity(&input.identifier, input.uuid)?;
            if !identifiers.insert(input.identifier.as_str()) || !uuids.insert(input.uuid) {
                return Err(Error::Constraint);
            }
            let payload = ProfilePayload::new(&input.schema, input.fields.to_plist()?, target)?;
            if !payload.allows_multiple() && !singleton_types.insert(payload.payload_type()) {
                return Err(Error::Constraint);
            }
            let mut metadata = envelope(
                &input.metadata,
                &input.identifier,
                input.uuid,
                payload.payload_type(),
            )?;
            validate_metadata("mdm/profiles/CommonPayloadKeys.yaml", &metadata, target)?;
            for (key, value) in payload.fields() {
                if metadata.insert(key.clone(), value.clone()).is_some() {
                    return Err(Error::Constraint);
                }
            }
            payloads.push(Value::Dictionary(metadata));
            objects.push(ProfileObject {
                payload_type: payload.payload_type().into(),
                identifier: input.identifier.clone(),
                uuid: input.uuid,
                multiple: payload.allows_multiple(),
            });
        }
        references(&payloads, &self.payloads, target)?;
        let mut document = envelope(&self.metadata, &self.identifier, self.uuid, "Configuration")?;
        if document.contains_key("EncryptedPayloadContent") {
            return Err(Error::Constraint);
        }
        insert(&mut document, "PayloadContent", Value::Array(payloads))?;
        insert(
            &mut document,
            "PayloadScope",
            Value::String(
                match target.context.channel {
                    Channel::Device => "System",
                    Channel::User => "User",
                }
                .into(),
            ),
        )?;
        validate_metadata("mdm/profiles/TopLevel.yaml", &document, target)?;
        let mut bytes = Vec::new();
        Value::Dictionary(document)
            .to_writer_xml(&mut bytes)
            .map_err(|_| Error::Encoding)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        Ok(CompiledProfile { bytes, objects })
    }
}
/// Compare a complete native payload manifest with retained compiled object identities.
/// The envelope is identified separately; compiled manifests may include its Configuration object.
pub fn observed_manifest(
    report: &Dictionary,
    identifier: &str,
    uuid: Uuid,
    objects: &[ProfileObject],
) -> Result<bool, crate::Error> {
    use crate::protocol::text;
    if !crate::profile::presence(report, identifier, uuid)? {
        return Ok(false);
    }
    let item = report
        .get("ProfileList")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .filter_map(Value::as_dictionary)
                .find(|d| d.get("PayloadIdentifier").and_then(Value::as_string) == Some(identifier))
        })
        .ok_or(crate::Error::Malformed)?;
    if item
        .get("IsEncrypted")
        .is_some_and(|v| v.as_boolean() != Some(false))
        || item
            .get("PayloadVersion")
            .and_then(Value::as_unsigned_integer)
            != Some(1)
    {
        return Err(crate::Error::Malformed);
    }
    let children = item
        .get("PayloadContent")
        .and_then(Value::as_array)
        .ok_or(crate::Error::Malformed)?;
    let mut identifiers = BTreeSet::from([identifier]);
    let mut uuids = BTreeSet::from([uuid]);
    let mut actual = BTreeSet::new();
    for value in children {
        let child = value.as_dictionary().ok_or(crate::Error::Malformed)?;
        let identifier = text(child, "PayloadIdentifier")?;
        let uuid =
            Uuid::parse_str(text(child, "PayloadUUID")?).map_err(|_| crate::Error::Malformed)?;
        if identifier.is_empty()
            || uuid.is_nil()
            || !identifiers.insert(identifier)
            || !uuids.insert(uuid)
            || child
                .get("PayloadVersion")
                .and_then(Value::as_unsigned_integer)
                != Some(1)
        {
            return Err(crate::Error::Malformed);
        }
        actual.insert((text(child, "PayloadType")?, identifier, uuid));
    }
    let expected = objects
        .iter()
        .filter(|p| p.uuid != uuid)
        .map(|p| (p.payload_type.as_str(), p.identifier.as_str(), p.uuid))
        .collect::<BTreeSet<_>>();
    Ok(actual == expected)
}

/// Closed evidence decision. Only Matched and Failed permit ownership updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Matched,
    Mismatched,
    Unknown,
    Failed,
}
/// One interpretation for live settlement and read-only queries.
pub fn verification(
    report: &Dictionary,
    identifier: &str,
    uuid: Uuid,
    present: bool,
    manifest: &[ProfileObject],
    failed: bool,
    previous: Option<&[ProfileObject]>,
) -> Verification {
    let actual = match crate::profile::presence(report, identifier, uuid) {
        Ok(value) => value,
        Err(crate::Error::Conflict) => return Verification::Mismatched,
        Err(_) => return Verification::Unknown,
    };
    let matched = if present {
        match observed_manifest(report, identifier, uuid, manifest) {
            Ok(value) => value,
            Err(_) => return Verification::Unknown,
        }
    } else {
        !actual
    };
    if matched {
        return Verification::Matched;
    }
    if failed && present && !actual {
        return Verification::Failed;
    }
    if failed
        && !present
        && previous
            .is_some_and(|old| matches!(observed_manifest(report, identifier, uuid, old), Ok(true)))
    {
        return Verification::Failed;
    }
    Verification::Mismatched
}

fn identity(identifier: &str, uuid: Uuid) -> Result<(), Error> {
    if uuid.is_nil()
        || identifier.trim().is_empty()
        || identifier.len() > 1024
        || identifier.chars().any(char::is_control)
    {
        Err(Error::Constraint)
    } else {
        Ok(())
    }
}
fn insert(fields: &mut Dictionary, name: &str, value: Value) -> Result<(), Error> {
    if fields.insert(name.into(), value).is_some() {
        Err(Error::Constraint)
    } else {
        Ok(())
    }
}
fn envelope(
    metadata: &Fields,
    identifier: &str,
    uuid: Uuid,
    payload_type: &str,
) -> Result<Dictionary, Error> {
    let mut fields = metadata.to_plist()?;
    for (key, value) in [
        ("PayloadIdentifier", Value::String(identifier.into())),
        ("PayloadUUID", Value::String(uuid.to_string())),
        ("PayloadType", Value::String(payload_type.into())),
        ("PayloadVersion", Value::Integer(1.into())),
    ] {
        insert(&mut fields, key, value)?;
    }
    Ok(fields)
}
fn validate_metadata(schema: &str, fields: &Dictionary, target: &Target<'_>) -> Result<(), Error> {
    let definition = generated::DEFINITIONS
        .iter()
        .find(|d| d.kind == Kind::Profile && d.schema == schema)
        .ok_or(Error::InvalidSchema)?;
    Payload::for_definition(definition, fields.clone(), target)?;
    Ok(())
}

/// Certificate references are UUID identities within this same scoped, ordered Profile.
fn references(
    payloads: &[Value],
    inputs: &[PayloadInput],
    target: &Target<'_>,
) -> Result<(), Error> {
    let certificates = payloads
        .iter()
        .filter_map(Value::as_dictionary)
        .filter_map(|d| {
            let kind = d.get("PayloadType")?.as_string()?;
            let id = Uuid::parse_str(d.get("PayloadUUID")?.as_string()?).ok()?;
            matches!(
                kind,
                "com.apple.security.pkcs1"
                    | "com.apple.security.pkcs12"
                    | "com.apple.security.root"
                    | "com.apple.security.pem"
                    | "com.apple.security.scep"
                    | "com.apple.ADCertificate.managed"
            )
            .then_some((id, kind))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    fn check(
        value: &Value,
        definition: &super::Definition,
        ids: &[usize],
        certificates: &std::collections::BTreeMap<Uuid, &str>,
        target_depth: usize,
        target: &Target<'_>,
    ) -> Result<(), Error> {
        if target_depth > 64 {
            return Err(Error::Limit);
        }
        match value {
            Value::Dictionary(values) => {
                for (key, value) in values {
                    // Arbitrary application dictionaries do not inherit native certificate semantics.
                    let Some(field) = ids
                        .iter()
                        .map(|id| &definition.fields[*id])
                        .find(|field| !field.wildcard && field.key == key)
                    else {
                        continue;
                    };
                    let identity = match key.as_str() {
                        "IdentityCertificateUUID"
                        | "AuthenticationCertificateUUID"
                        | "ResourcePayloadCertificateUUID"
                        | "DeviceCertificateUUID"
                        | "ControllerCertificateUUID"
                        | "AccessKeyTerminalIdentityUUID"
                        | "SMIMESigningCertificateUUID"
                        | "SMIMEEncryptionCertificateUUID" => Some(true),
                        "PayloadCertificateUUID" => Some(!matches!(
                            definition.identity,
                            "com.apple.security.certificatepreference" | "com.apple.MCX.FileVault2"
                        )),
                        "CertificateUUID" => Some(false),
                        _ => None,
                    };
                    let anchors = matches!(
                        key.as_str(),
                        "DeviceCACertificateUUIDs"
                            | "ControllerCACertificateUUIDs"
                            | "PayloadCertificateAnchorUUID"
                            | "CertificateAnchorUUID"
                            | "LeaderPayloadCertificateAnchorUUID"
                            | "MemberPayloadCertificateAnchorUUID"
                            | "ServerURLPinningCertificateUUIDs"
                            | "CheckInURLPinningCertificateUUIDs"
                            | "AccessKeyReaderIssuerCertificateUUID"
                    );
                    if identity.is_some() || anchors {
                        let values: Vec<&Value> = match value {
                            Value::Array(items) => items.iter().collect(),
                            _ => vec![value],
                        };
                        for value in values {
                            let id = Uuid::parse_str(value.as_string().ok_or(Error::Field)?)
                                .map_err(|_| Error::Constraint)?;
                            let kind = certificates.get(&id).ok_or(Error::Constraint)?;
                            let is_identity = matches!(
                                *kind,
                                "com.apple.security.pkcs12"
                                    | "com.apple.security.scep"
                                    | "com.apple.ADCertificate.managed"
                            );
                            if (identity == Some(true) && !is_identity) || (anchors && is_identity)
                            {
                                return Err(Error::Constraint);
                            }
                        }
                    }
                    let rule = field.active(target)?;
                    if !rule.children.is_empty() {
                        check(
                            value,
                            definition,
                            rule.children,
                            certificates,
                            target_depth + 1,
                            target,
                        )?;
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    for id in ids {
                        let field = &definition.fields[*id];
                        let rule = field.active(target)?;
                        if !rule.children.is_empty() {
                            check(
                                value,
                                definition,
                                rule.children,
                                certificates,
                                target_depth + 1,
                                target,
                            )?;
                        }
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
    for (value, input) in payloads.iter().zip(inputs) {
        let definition = generated::DEFINITIONS
            .iter()
            .find(|d| d.kind == Kind::Profile && d.schema == input.schema)
            .ok_or(Error::UnknownSchema)?;
        check(
            value,
            definition,
            definition.request,
            &certificates,
            0,
            target,
        )?;
    }
    Ok(())
}

/// Facts read under the registration lock; the rule itself has no persistence dependency.
pub struct History {
    pub terminal: bool,
    pub dispatched: bool,
    pub observed: bool,
    pub present: bool,
    pub uuid: Uuid,
}
pub fn can_reserve(history: &[History], uuid: Uuid, present: bool) -> bool {
    history
        .iter()
        .all(|old| old.terminal && (!old.dispatched || old.observed))
        && (present || history.iter().any(|old| old.present && old.uuid == uuid))
}
pub fn collides(objects: &[ProfileObject], other: &[ProfileObject], types: bool) -> bool {
    objects.iter().any(|new| {
        other.iter().any(|old| {
            new.uuid == old.uuid
                || new.identifier == old.identifier
                || (types
                    && new.payload_type == old.payload_type
                    && (!new.multiple || !old.multiple))
        })
    })
}

/// Import a bounded unsigned native profile with explicit official schema provenance.
/// PayloadType is not sufficient to disambiguate Apple's profile schema definitions.
pub fn from_native(
    bytes: &[u8],
    schemas: &[String],
    channel: Channel,
) -> Result<ProfileInput, Error> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| Error::Encoding)?;
    let root = value.as_dictionary().ok_or(Error::Field)?;
    let scope = if channel == Channel::Device {
        "System"
    } else {
        "User"
    };
    if root
        .get("PayloadScope")
        .and_then(Value::as_string)
        .unwrap_or("System")
        != scope
        || root.get("PayloadType").and_then(Value::as_string) != Some("Configuration")
        || root
            .get("PayloadVersion")
            .and_then(Value::as_unsigned_integer)
            != Some(1)
    {
        return Err(Error::Constraint);
    }
    let read_identity = |values: &Dictionary| -> Result<(String, Uuid), Error> {
        let id = values
            .get("PayloadIdentifier")
            .and_then(Value::as_string)
            .ok_or(Error::Field)?;
        let uuid = Uuid::parse_str(
            values
                .get("PayloadUUID")
                .and_then(Value::as_string)
                .ok_or(Error::Field)?,
        )
        .map_err(|_| Error::Field)?;
        identity(id, uuid)?;
        Ok((id.into(), uuid))
    };
    let children = root
        .get("PayloadContent")
        .and_then(Value::as_array)
        .ok_or(Error::Field)?;
    if children.len() != schemas.len() {
        return Err(Error::Constraint);
    }
    let common = generated::DEFINITIONS
        .iter()
        .find(|d| d.schema == "mdm/profiles/CommonPayloadKeys.yaml")
        .ok_or(Error::InvalidSchema)?;
    let identity_keys = [
        "PayloadIdentifier",
        "PayloadUUID",
        "PayloadType",
        "PayloadVersion",
    ];
    let mut payloads = Vec::new();
    for (child, schema) in children.iter().zip(schemas) {
        let child = child.as_dictionary().ok_or(Error::Field)?;
        let definition = generated::DEFINITIONS
            .iter()
            .find(|d| d.kind == Kind::Profile && d.schema == schema)
            .ok_or(Error::UnknownSchema)?;
        if matches!(
            definition.identity,
            "com.apple.mdm"
                | "com.apple.declarations"
                | "TopLevel"
                | "CommonPayloadKeys"
                | "Configuration"
        ) || child.get("PayloadType").and_then(Value::as_string) != Some(definition.identity)
            || child
                .get("PayloadVersion")
                .and_then(Value::as_unsigned_integer)
                != Some(1)
        {
            return Err(Error::Constraint);
        }
        let (identifier, uuid) = read_identity(child)?;
        let mut metadata = Dictionary::new();
        let mut fields = Dictionary::new();
        for (name, value) in child {
            if identity_keys.contains(&name.as_str()) {
                continue;
            }
            if common.request.iter().any(|i| common.fields[*i].key == name) {
                metadata.insert(name.clone(), value.clone());
            } else {
                fields.insert(name.clone(), value.clone());
            }
        }
        payloads.push(PayloadInput {
            schema: schema.clone(),
            identifier,
            uuid,
            metadata: Fields::from_plist(&metadata)?,
            fields: Fields::from_plist(&fields)?,
        });
    }
    let (identifier, uuid) = read_identity(root)?;
    let metadata: Dictionary = root
        .iter()
        .filter(|(name, _)| {
            !identity_keys.contains(&name.as_str())
                && !["PayloadContent", "PayloadScope"].contains(&name.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(ProfileInput {
        identifier,
        uuid,
        metadata: Fields::from_plist(&metadata)?,
        payloads,
    })
}
/// DDM takeover requires the exact ordered native structure; presence alone is insufficient.
pub fn same_structure(left: &[ProfileObject], right: &[ProfileObject]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a.identifier == b.identifier && a.uuid == b.uuid && a.payload_type == b.payload_type
        })
}

/// Takeover observes the managed profile's ordered structure, including complete payload content.
pub fn observed_structure(
    report: &Dictionary,
    objects: &[ProfileObject],
) -> Result<bool, crate::Error> {
    let root = objects.first().ok_or(crate::Error::Malformed)?;
    if !observed_manifest(report, &root.identifier, root.uuid, objects)? {
        return Ok(false);
    }
    let profile = report
        .get("ProfileList")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().filter_map(Value::as_dictionary).find(|p| {
                p.get("PayloadIdentifier").and_then(Value::as_string) == Some(&root.identifier)
            })
        })
        .ok_or(crate::Error::Malformed)?;
    if profile.get("IsManaged").and_then(Value::as_boolean) != Some(true) {
        return Ok(false);
    }
    let children = profile
        .get("PayloadContent")
        .and_then(Value::as_array)
        .ok_or(crate::Error::Malformed)?;
    Ok(children.iter().zip(&objects[1..]).all(|(value, expected)| {
        value.as_dictionary().is_some_and(|v| {
            v.get("PayloadType").and_then(Value::as_string) == Some(&expected.payload_type)
                && v.get("PayloadIdentifier").and_then(Value::as_string)
                    == Some(&expected.identifier)
                && v.get("PayloadUUID")
                    .and_then(Value::as_string)
                    .and_then(|v| Uuid::parse_str(v).ok())
                    == Some(expected.uuid)
        })
    }))
}
