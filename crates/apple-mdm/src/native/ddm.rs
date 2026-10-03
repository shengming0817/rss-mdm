//! Native DDM documents and synchronization manifests, independent of command ACK state.
//! ref: Apple declarative/protocol/{tokensresponse,declarationitemsresponse}.yaml.
use super::{DeclarationPayload, Error, Target, input::Fields};
mod status;
use base64::Engine;
use plist::Value as Plist;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub use status::{DeclarationStatus, StatusReport, Validity};
mod projection;
pub use projection::{
    PROJECTION_BYTES, Projection, ProjectionState, ReportEvidence, StatusProjection, project,
};
mod assets;
pub use assets::{AssetBinding, AssetInput, LegacyProfile, bind_assets, legacy_profiles};
use std::collections::BTreeMap;

/// Apple's four native declaration families.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationKind {
    /// Activation predicates and configuration references.
    Activation,
    /// Native configuration payload.
    Configuration,
    /// Asset metadata and content supply.
    Asset,
    /// Management properties.
    Management,
}
impl DeclarationKind {
    fn of(declaration_type: &str) -> Result<Self, Error> {
        match declaration_type.split('.').nth(2) {
            Some("activation") => Ok(Self::Activation),
            Some("configuration") => Ok(Self::Configuration),
            Some("asset") => Ok(Self::Asset),
            Some("management") => Ok(Self::Management),
            _ => Err(Error::UnknownSchema),
        }
    }
    /// Native endpoint path component.
    pub fn path(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Configuration => "configuration",
            Self::Asset => "asset",
            Self::Management => "management",
        }
    }
    fn manifest_key(self) -> &'static str {
        match self {
            Self::Activation => "Activations",
            Self::Configuration => "Configurations",
            Self::Asset => "Assets",
            Self::Management => "Management",
        }
    }
}
/// Declaration input with an immutable native identity and typed payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeclarationInput {
    /// Native identifier, unique across all four kinds within the target scope.
    pub identifier: String,
    /// Official declaration Type.
    pub declaration_type: String,
    /// Native payload fields.
    pub payload: Fields,
}
impl std::fmt::Debug for DeclarationInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppleDeclarationInput([REDACTED])")
    }
}
struct Reference {
    id: String,
    kind: DeclarationKind,
    types: &'static [&'static str],
    content_types: &'static [&'static str],
}
/// Immutable validated native document. A token denotes content, not activation or effect.
pub struct Declaration {
    identifier: String,
    declaration_type: String,
    kind: DeclarationKind,
    server_token: String,
    payload: Value,
    references: Vec<Reference>,
    channel: crate::applicability::Channel,
}
impl DeclarationInput {
    /// Compile native payload and bind its token to both content and the server-owned input version.
    pub fn compile(&self, input_version: &str, target: &Target<'_>) -> Result<Declaration, Error> {
        identifier(&self.identifier)?;
        internal_identity(input_version)?;
        let payload =
            DeclarationPayload::new(&self.declaration_type, self.payload.to_plist()?, target)?;
        if self.declaration_type == "com.apple.configuration.management.status-subscriptions" {
            for item in payload
                .fields()
                .get("StatusItems")
                .and_then(Plist::as_array)
                .ok_or(Error::Field)?
            {
                let name = item
                    .as_dictionary()
                    .and_then(|i| i.get("Name"))
                    .and_then(Plist::as_string)
                    .ok_or(Error::Field)?;
                let definition = super::generated::DEFINITIONS
                    .iter()
                    .find(|d| d.kind == super::Kind::Status && d.identity == name)
                    .ok_or(Error::UnknownSchema)?;
                definition.active(target)?.conditions.check(target)?;
            }
        }
        let kind = DeclarationKind::of(payload.declaration_type())?;
        let mut references = Vec::new();
        if self.declaration_type == "com.apple.activation.simple"
            && let Some(items) = payload
                .fields()
                .get("StandardConfigurations")
                .and_then(Plist::as_array)
        {
            for value in items {
                references.push(Reference {
                    id: value.as_string().ok_or(Error::Constraint)?.into(),
                    kind: DeclarationKind::Configuration,
                    types: &[],
                    content_types: &[],
                });
            }
        }
        collect_references(&payload, target, &mut references)?;
        let native_payload = to_json(&Plist::Dictionary(payload.fields().clone()))?;
        let server_token = digest(&json!([
            "apple.declaration/v1",
            input_version,
            self.identifier,
            self.declaration_type,
            native_payload
        ]))?;
        Ok(Declaration {
            identifier: self.identifier.clone(),
            declaration_type: self.declaration_type.clone(),
            kind,
            server_token,
            payload: native_payload,
            references,
            channel: target.context.channel,
        })
    }
}
impl Declaration {
    /// Native declaration identifier.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
    /// Exact content/version token.
    pub fn server_token(&self) -> &str {
        &self.server_token
    }
    /// Native declaration family.
    pub fn kind(&self) -> DeclarationKind {
        self.kind
    }
    /// Native JSON body for one authenticated declaration endpoint.
    pub fn document(&self) -> Value {
        json!({"Identifier": self.identifier, "Type": self.declaration_type, "ServerToken": self.server_token, "Payload": self.payload})
    }
}
/// A single authenticated scope's declaration snapshot; persistence remains with Apple channel.
pub struct DeclarationSet {
    declarations: BTreeMap<String, Declaration>,
    token: String,
}
impl DeclarationSet {
    /// Validate references and compute one order-independent synchronization token.
    /// The caller's scope identity binds tenant, registration generation and device/user channel.
    pub fn new(scope_identity: &str, declarations: Vec<Declaration>) -> Result<Self, Error> {
        internal_identity(scope_identity)?;
        if declarations.len() > 4096 {
            return Err(Error::Limit);
        }
        let mut values = BTreeMap::new();
        let channel = declarations.first().map(|d| d.channel);
        for declaration in declarations {
            if Some(declaration.channel) != channel
                || values
                    .insert(declaration.identifier.clone(), declaration)
                    .is_some()
            {
                return Err(Error::Constraint);
            }
        }
        for declaration in values.values() {
            for reference in &declaration.references {
                let target = values.get(&reference.id).ok_or(Error::Constraint)?;
                if target.kind != reference.kind
                    || !reference.types.is_empty()
                        && !reference.types.contains(&target.declaration_type.as_str())
                {
                    return Err(Error::Constraint);
                }
                if !reference.content_types.is_empty()
                    && !target
                        .payload
                        .get("Reference")
                        .and_then(|r| r.get("ContentType"))
                        .and_then(Value::as_str)
                        .is_some_and(|t| reference.content_types.contains(&t))
                {
                    return Err(Error::Constraint);
                }
            }
        }
        let versions = values
            .values()
            .map(|d| (&d.identifier, &d.server_token))
            .collect::<Vec<_>>();
        let token = digest(&json!(["apple.declarations/v1", scope_identity, versions]))?;
        Ok(Self {
            declarations: values,
            token,
        })
    }
    /// Native tokens response, without a fabricated command UUID or ACK.
    pub fn tokens(&self) -> Value {
        json!({"SyncTokens": {"DeclarationsToken": self.token}})
    }
    /// Native declaration-items response. All four arrays are present, including when empty.
    pub fn manifest(&self) -> Value {
        let mut lists =
            json!({"Activations": [], "Configurations": [], "Assets": [], "Management": []});
        for declaration in self.declarations.values() {
            if let Some(list) = lists[declaration.kind.manifest_key()].as_array_mut() {
                list.push(json!({"Identifier": declaration.identifier, "ServerToken": declaration.server_token}));
            }
        }
        json!({"Declarations": lists, "DeclarationsToken": self.token})
    }
    /// Resolve a native path only in its declared family; removed/wrong-kind objects are absent.
    pub fn declaration(&self, kind: DeclarationKind, id: &str) -> Option<Value> {
        self.declarations
            .get(id)
            .filter(|d| d.kind == kind)
            .map(Declaration::document)
    }
}
fn identifier(value: &str) -> Result<(), Error> {
    if value.len() > 64 {
        return Err(Error::Constraint);
    }
    internal_identity(value)
}
fn internal_identity(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(Error::Constraint)
    } else {
        Ok(())
    }
}
fn digest(value: &Value) -> Result<String, Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| Error::Encoding)?)
    ))
}
fn to_json(value: &Plist) -> Result<Value, Error> {
    Ok(match value {
        Plist::String(v) => json!(v),
        Plist::Boolean(v) => json!(v),
        Plist::Integer(v) => {
            if let Some(v) = v.as_unsigned() {
                json!(v)
            } else {
                json!(v.as_signed().ok_or(Error::Constraint)?)
            }
        }
        Plist::Real(v) if v.is_finite() => json!(v),
        Plist::Date(v) => json!(v.to_xml_format()),
        Plist::Data(v) => json!(base64::engine::general_purpose::STANDARD.encode(v)),
        Plist::Array(values) => Value::Array(values.iter().map(to_json).collect::<Result<_, _>>()?),
        Plist::Dictionary(values) => Value::Object(
            values
                .iter()
                .map(|(k, v)| Ok((k.clone(), to_json(v)?)))
                .collect::<Result<_, Error>>()?,
        ),
        _ => return Err(Error::Constraint),
    })
}

fn collect_references(
    payload: &DeclarationPayload,
    target: &Target<'_>,
    output: &mut Vec<Reference>,
) -> Result<(), Error> {
    let definition = payload.0.definition;
    let parent = definition.active(target)?.conditions;
    for (key, value) in payload.fields() {
        let field = definition
            .request
            .iter()
            .map(|id| &definition.fields[*id])
            .find(|f| f.key == key)
            .or_else(|| {
                definition
                    .request
                    .iter()
                    .map(|id| &definition.fields[*id])
                    .find(|f| f.key == "ANY")
            })
            .ok_or(Error::InvalidSchema)?;
        field_references(definition, field, value, target, parent, 0, output)?;
    }
    Ok(())
}
fn field_references(
    d: &super::Definition,
    field: &super::Field,
    value: &Plist,
    target: &Target<'_>,
    parent: super::Conditions,
    depth: usize,
    output: &mut Vec<Reference>,
) -> Result<(), Error> {
    if depth > 64 {
        return Err(Error::Limit);
    }
    let rule = field.active(target)?;
    let conditions = rule.conditions.inherit(parent);
    if !rule.asset_types.is_empty() {
        output.push(Reference {
            id: value.as_string().ok_or(Error::Constraint)?.into(),
            kind: DeclarationKind::Asset,
            types: rule.asset_types,
            content_types: rule.asset_content_types,
        });
    }
    match value {
        Plist::Dictionary(values) if !rule.children.is_empty() => {
            for (key, value) in values {
                let child = rule
                    .children
                    .iter()
                    .map(|id| &d.fields[*id])
                    .find(|f| f.key == key)
                    .or_else(|| {
                        rule.children
                            .iter()
                            .map(|id| &d.fields[*id])
                            .find(|f| f.key == "ANY")
                    })
                    .ok_or(Error::InvalidSchema)?;
                field_references(d, child, value, target, conditions, depth + 1, output)?;
            }
        }
        Plist::Array(values) if !rule.children.is_empty() => {
            for value in values {
                let child = rule
                    .children
                    .iter()
                    .map(|id| &d.fields[*id])
                    .find(|field| {
                        super::validation::check_field(
                            d,
                            field,
                            value,
                            target,
                            conditions,
                            depth + 1,
                        )
                        .is_ok()
                    })
                    .ok_or(Error::InvalidSchema)?;
                field_references(d, child, value, target, conditions, depth + 1, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}
