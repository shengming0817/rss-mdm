//! Structurally validated native Apple payloads. Validation grants no execution authority.
//! Dispatch adapters additionally own operation-specific prerequisites, resource references,
//! cross-object constraints, recovery and interpretation of external effects.
//! ref: apple/device-management docs/schema.md, pinned by schema/upstream/sources.json.
use crate::applicability::{Channel, Context, Enrollment, EnrollmentRule, Support, Version};
use plist::{Dictionary, Value};

#[rustfmt::skip]
mod generated;
pub mod ddm;
mod decimal;
pub mod evidence;
pub mod input;
mod json;
pub mod outcome;
pub mod profiles;
pub mod request;
mod semantics;
mod validation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Atom {
    String,
    Integer,
    Real,
    Boolean,
    Date,
    Data,
    Array,
    Dictionary,
    Any,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Command,
    Checkin,
    Profile,
    Declaration,
    Credential,
    Status,
    Protocol,
    Error,
}

#[derive(Clone, Copy)]
pub struct Source {
    pub path: &'static str,
    pub sha256: &'static str,
}

#[derive(Clone, Copy)]
pub(super) struct Conditions {
    introduced: Option<&'static str>,
    removed: Option<&'static str>,
    access_rights: Option<&'static str>,
    beta: Option<bool>,
    device_channel: Option<bool>,
    user_channel: Option<bool>,
    supervised: Option<bool>,
    automated_enrollment: Option<bool>,
    user_approved: Option<bool>,
    multiple: Option<bool>,
    user_enrollment: Option<&'static str>,
    enrollments: &'static [&'static str],
    scopes: &'static [&'static str],
}
impl Conditions {
    const INHERIT: Self = Self {
        introduced: None,
        removed: None,
        access_rights: None,
        beta: None,
        device_channel: None,
        user_channel: None,
        supervised: None,
        automated_enrollment: None,
        user_approved: None,
        multiple: None,
        user_enrollment: None,
        enrollments: &[],
        scopes: &[],
    };
    fn inherit(self, parent: Self) -> Self {
        Self {
            introduced: self.introduced.or(parent.introduced),
            removed: self.removed.or(parent.removed),
            access_rights: self.access_rights.or(parent.access_rights),
            beta: self.beta.or(parent.beta),
            device_channel: self.device_channel.or(parent.device_channel),
            user_channel: self.user_channel.or(parent.user_channel),
            supervised: self.supervised.or(parent.supervised),
            automated_enrollment: self.automated_enrollment.or(parent.automated_enrollment),
            user_approved: self.user_approved.or(parent.user_approved),
            multiple: self.multiple.or(parent.multiple),
            user_enrollment: self.user_enrollment.or(parent.user_enrollment),
            enrollments: if self.enrollments.is_empty() {
                parent.enrollments
            } else {
                self.enrollments
            },
            scopes: if self.scopes.is_empty() {
                parent.scopes
            } else {
                self.scopes
            },
        }
    }
    fn check(self, target: &Target<'_>) -> Result<(), Error> {
        if target
            .context
            .version
            .is_some_and(|version| version.components()[0] < 15)
        {
            return Err(Error::Unsupported);
        }
        if self.introduced == Some("n/a") {
            return Err(Error::Unsupported);
        }
        let introduced = self.introduced.ok_or(Error::InvalidSchema)?;
        let mut support = Support::since(introduced).map_err(|_| Error::InvalidSchema)?;
        support.removed = self
            .removed
            .map(Version::parse)
            .transpose()
            .map_err(|_| Error::InvalidSchema)?;
        support.beta = self.beta.unwrap_or(false);
        support.device_channel = self.device_channel.unwrap_or(true);
        support.user_channel = self.user_channel.unwrap_or(true);
        support.supervised = self.supervised.unwrap_or(false);
        support.automated_enrollment = self.automated_enrollment.unwrap_or(false);
        support.user_approved = self.user_approved.unwrap_or(false);
        support.enrollment = match self.user_enrollment {
            Some("forbidden") => EnrollmentRule::DeviceOnly,
            Some("required") => EnrollmentRule::UserOnly,
            Some("allowed") | None => EnrollmentRule::Any,
            Some("ignored") => EnrollmentRule::DeviceOnly,
            _ => return Err(Error::InvalidSchema),
        };
        support
            .check(target.context)
            .map_err(Error::Applicability)?;
        let scope = match target.context.channel {
            Channel::Device => "system",
            Channel::User => "user",
        };
        if !self.scopes.is_empty() && !self.scopes.contains(&scope) {
            return Err(Error::Unsupported);
        }
        if !self.enrollments.is_empty() {
            let enrollment = match target.context.enrollment {
                Enrollment::User => "user",
                Enrollment::Device => "device",
            };
            if !(self.enrollments.contains(&enrollment)
                || (target.context.enrollment == Enrollment::Device
                    && self.enrollments.contains(&"supervised")
                    && target.context.supervised == Some(true)))
            {
                return Err(Error::Unsupported);
            }
        }
        if let Some(right) = self.access_rights
            && !["n/a", "None"].contains(&right)
            && !target.access_rights.contains(&right)
        {
            return Err(Error::AccessRight);
        }
        Ok(())
    }
}

pub(super) struct Field {
    key: &'static str,
    wildcard: bool,
    variants: &'static [Variant<FieldRule>],
}
pub(super) struct FieldRule {
    atom: Atom,
    required: bool,
    conditions: Conditions,
    children: &'static [usize],
    range: &'static [&'static str],
    min: Option<&'static str>,
    max: Option<&'static str>,
    format: Option<&'static str>,
    value_type: Option<&'static str>,
    min_items: Option<&'static str>,
    max_items: Option<&'static str>,
    asset_types: &'static [&'static str],
    asset_content_types: &'static [&'static str],
}
pub(super) struct Definition {
    kind: Kind,
    identity: &'static str,
    schema: &'static str,
    availability: &'static [Variant<Availability>],
    fields: &'static [Field],
    request: &'static [usize],
    response: &'static [usize],
}

pub(super) struct Availability {
    conditions: Conditions,
    source: Source,
}
pub(super) struct Variant<T> {
    from: [u32; 3],
    before: Option<[u32; 3]>,
    value: T,
}
fn select<'a, T>(variants: &'a [Variant<T>], target: &Target<'_>) -> Result<&'a T, Error> {
    let version = target
        .context
        .version
        .ok_or(Error::Applicability(
            crate::applicability::Rejection::MissingEvidence(
                crate::applicability::Condition::Version,
            ),
        ))?
        .components();
    variants
        .iter()
        .find(|v| version >= v.from && v.before.is_none_or(|end| version < end))
        .map(|v| &v.value)
        .ok_or(Error::Unsupported)
}
impl Definition {
    fn active(&self, target: &Target<'_>) -> Result<&Availability, Error> {
        select(self.availability, target)
    }
}
impl Field {
    fn active(&self, target: &Target<'_>) -> Result<&FieldRule, Error> {
        select(self.variants, target)
    }
}

/// Actual platform facts and granted MDM protocol rights supplied by the channel owner.
pub struct Target<'a> {
    pub context: &'a Context,
    pub access_rights: &'a [&'a str],
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("unknown native Apple schema")]
    UnknownSchema,
    #[error("native schema does not apply to this target")]
    Unsupported,
    #[error("native prerequisite rejected: {0}")]
    Applicability(crate::applicability::Rejection),
    #[error("required MDM access right is absent")]
    AccessRight,
    #[error("invalid compiled native schema")]
    InvalidSchema,
    #[error("native field is missing, unknown, or has the wrong type")]
    Field,
    #[error("native field violates its value constraint")]
    Constraint,
    #[error("native payload exceeds its budget")]
    Limit,
    #[error("native payload encoding failed")]
    Encoding,
}

#[derive(Clone)]
struct Payload {
    definition: &'static Definition,
    conditions: Conditions,
    source: Source,
    fields: Dictionary,
    context: Context,
}
impl Payload {
    fn new(
        kind: Kind,
        identity: &str,
        fields: Dictionary,
        target: &Target<'_>,
    ) -> Result<Self, Error> {
        let mut matching = generated::DEFINITIONS
            .iter()
            .filter(|s| s.kind == kind && s.identity == identity);
        let definition = matching.next().ok_or(Error::UnknownSchema)?;
        if matching.next().is_some() {
            return Err(Error::InvalidSchema);
        }
        Self::for_definition(definition, fields, target)
    }
    fn for_definition(
        definition: &'static Definition,
        fields: Dictionary,
        target: &Target<'_>,
    ) -> Result<Self, Error> {
        let active = definition.active(target)?;
        let mut admission = active.conditions;
        // DeviceInformation defines protocol access per requested query, not one
        // synthetic "Special Case" right on the command envelope.
        if definition.kind == Kind::Command && definition.identity == "DeviceInformation" {
            admission.access_rights = None;
        }
        admission.check(target)?;
        validation::dictionary(definition, definition.request, &fields, target)?;
        semantics::check(definition.kind, definition.identity, &fields)?;
        Ok(Self {
            definition,
            conditions: active.conditions,
            source: active.source,
            fields,
            context: target.context.clone(),
        })
    }
}

/// A schema-checked MDM command body; UUID and RequestType are owned by the encoder.
#[derive(Clone)]
pub struct Command(Payload);
impl Command {
    pub fn new(request_type: &str, fields: Dictionary, target: &Target<'_>) -> Result<Self, Error> {
        if request_type == "RunScript" {
            return Err(Error::Unsupported);
        }
        outcome::prerequisites(request_type, &fields, target.context)?;
        Payload::new(Kind::Command, request_type, fields, target).map(Self)
    }
    pub fn request_type(&self) -> &'static str {
        self.0.definition.identity
    }
    pub fn source(&self) -> Source {
        self.0.source
    }
    pub fn encode(&self, uuid: uuid::Uuid) -> Result<Vec<u8>, Error> {
        if uuid.is_nil() {
            return Err(Error::Constraint);
        }
        let mut command = self.0.fields.clone();
        command.insert(
            "RequestType".into(),
            Value::String(self.request_type().into()),
        );
        let mut envelope = Dictionary::new();
        envelope.insert("CommandUUID".into(), Value::String(uuid.to_string()));
        envelope.insert("Command".into(), Value::Dictionary(command));
        let mut bytes = Vec::new();
        Value::Dictionary(envelope)
            .to_writer_xml(&mut bytes)
            .map_err(|_| Error::Encoding)?;
        Ok(bytes)
    }
    /// Checks the command-specific response after the channel verifies UUID/status/identity.
    pub fn validate_response(&self, fields: &Dictionary, target: &Target<'_>) -> Result<(), Error> {
        if target.context.channel != self.0.context.channel
            || target.context.enrollment != self.0.context.enrollment
        {
            return Err(Error::Unsupported);
        }
        // Bind late receipts to the originally compiled OS evidence; current rights
        // are checked again, so the frozen command cannot retain revoked access.
        let target = Target {
            context: &self.0.context,
            access_rights: target.access_rights,
        };
        validation::dictionary(
            self.0.definition,
            self.0.definition.request,
            &self.0.fields,
            &target,
        )?;
        if self.request_type() == "DeviceInformation" {
            let requested = self
                .0
                .fields
                .get("Queries")
                .and_then(Value::as_array)
                .ok_or(Error::InvalidSchema)?;
            if let Some(answers) = fields.get("QueryResponses").and_then(Value::as_dictionary)
                && answers.keys().any(|key| {
                    !requested
                        .iter()
                        .any(|query| query.as_string() == Some(key.as_str()))
                })
            {
                return Err(Error::Constraint);
            }
        }
        validation::dictionary(
            self.0.definition,
            self.0.definition.response,
            fields,
            &target,
        )
    }
}

/// A DDM payload, independent of its declaration Identifier/ServerToken envelope.
#[derive(Clone)]
pub struct DeclarationPayload(Payload);
impl DeclarationPayload {
    pub fn new(
        declaration_type: &str,
        fields: Dictionary,
        target: &Target<'_>,
    ) -> Result<Self, Error> {
        if !declaration_type.starts_with("com.apple.") {
            return Err(Error::UnknownSchema);
        }
        Payload::new(Kind::Declaration, declaration_type, fields, target).map(Self)
    }
    pub fn declaration_type(&self) -> &'static str {
        self.0.definition.identity
    }
    pub fn fields(&self) -> &Dictionary {
        &self.0.fields
    }
    pub fn source(&self) -> Source {
        self.0.source
    }
}

/// A Profile payload is selected by its source schema because Apple reuses PayloadType.
#[derive(Clone)]
pub struct ProfilePayload(Payload);
impl ProfilePayload {
    pub fn new(schema: &str, fields: Dictionary, target: &Target<'_>) -> Result<Self, Error> {
        let definition = generated::DEFINITIONS
            .iter()
            .find(|d| {
                d.kind == Kind::Profile
                    && d.schema == schema
                    && !matches!(
                        d.identity,
                        "Configuration" | "TopLevel" | "CommonPayloadKeys"
                    )
            })
            .ok_or(Error::UnknownSchema)?;
        Payload::for_definition(definition, fields, target).map(Self)
    }
    pub fn payload_type(&self) -> &'static str {
        self.0.definition.identity
    }
    pub fn fields(&self) -> &Dictionary {
        &self.0.fields
    }
    pub fn source(&self) -> Source {
        self.0.source
    }
    pub fn allows_multiple(&self) -> bool {
        self.0.conditions.multiple.unwrap_or(false)
    }
}

#[cfg(test)]
#[path = "../../tests/native_schema.rs"]
mod tests;
