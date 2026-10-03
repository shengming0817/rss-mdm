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
        use crate::protocol::text;
        if !crate::profile::presence(report, &self.identifier, self.uuid)? {
            return Ok(false);
        }
        let item = report
            .get("ProfileList")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().filter_map(Value::as_dictionary).find(|d| {
                    d.get("PayloadIdentifier").and_then(Value::as_string) == Some(&self.identifier)
                })
            })
            .ok_or(crate::Error::Malformed)?;
        if item
            .get("IsEncrypted")
            .is_some_and(|v| v.as_boolean() != Some(false))
        {
            return Err(crate::Error::Malformed);
        }
        let children = item
            .get("PayloadContent")
            .and_then(Value::as_array)
            .ok_or(crate::Error::Malformed)?;
        let mut identifiers = BTreeSet::new();
        let mut uuids = BTreeSet::from([self.uuid]);
        let mut actual = BTreeSet::new();
        for value in children {
            let child = value.as_dictionary().ok_or(crate::Error::Malformed)?;
            let identifier = text(child, "PayloadIdentifier")?;
            let uuid = Uuid::parse_str(text(child, "PayloadUUID")?)
                .map_err(|_| crate::Error::Malformed)?;
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
        let expected = self
            .payloads
            .iter()
            .map(|p| {
                Ok((
                    p.payload_type().map_err(|_| crate::Error::Malformed)?,
                    p.identifier.as_str(),
                    p.uuid,
                ))
            })
            .collect::<Result<BTreeSet<_>, crate::Error>>()?;
        Ok(actual == expected)
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
