//! Report interpretation retains native validity separately from activation and command receipts.
//! ref: Apple declarative/protocol/statusreport.yaml; status/management.declarations.yaml.
use super::{DeclarationKind, Error, Target};
use crate::native::{self, Kind, Payload};
use plist::Dictionary;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Apple's validity vocabulary is not a Boolean and does not establish compliance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Validity {
    Unknown,
    Invalid,
    Valid,
}
/// A single native report, never promoted to current state without matching its ServerToken.
pub struct DeclarationStatus {
    pub kind: DeclarationKind,
    pub identifier: String,
    pub server_token: String,
    pub active: bool,
    pub validity: Validity,
    pub reasons: Vec<Value>,
}
/// Validated wire report. The channel persists evidence and owns full/delta reconciliation.
pub struct StatusReport {
    full: bool,
    items: BTreeMap<String, Value>,
    errors: Vec<Value>,
}
impl StatusReport {
    /// Decode the nested native status namespaces using their official generated leaf schemas.
    pub fn decode(bytes: &[u8], target: &Target<'_>) -> Result<Self, Error> {
        let raw = native::json::decode(bytes)?;
        let raw = raw.as_object().ok_or(Error::Field)?;
        let namespace = raw
            .get("StatusItems")
            .and_then(Value::as_object)
            .ok_or(Error::Field)?;
        // Validate the native envelope independently; status leaves retain JSON null.
        let mut envelope = raw.clone();
        envelope.insert("StatusItems".into(), Value::Object(Map::new()));
        let fields = native::json::plist(&Value::Object(envelope))?;
        Payload::new(
            Kind::Protocol,
            "StatusReport",
            fields.into_dictionary().ok_or(Error::Field)?,
            target,
        )?;
        let full = raw
            .get("FullReport")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let errors = raw
            .get("Errors")
            .and_then(Value::as_array)
            .ok_or(Error::Field)?
            .clone();
        let mut items = BTreeMap::new();
        flatten("", namespace, target, &mut items, 0)?;
        let report = Self {
            full,
            items,
            errors,
        };
        report.declarations()?;
        Ok(report)
    }
    pub fn full_report(&self) -> bool {
        self.full
    }
    pub fn items(&self) -> &BTreeMap<String, Value> {
        &self.items
    }
    pub fn errors(&self) -> &[Value] {
        &self.errors
    }
    /// Return native declaration reports, preserving old tokens for evidence and late-report handling.
    pub fn declarations(&self) -> Result<Vec<DeclarationStatus>, Error> {
        let Some(value) = self.items.get("management.declarations") else {
            return Ok(vec![]);
        };
        if value.is_null() {
            return Ok(vec![]);
        }
        let groups = value.as_object().ok_or(Error::Field)?;
        let mut reports = Vec::new();
        let mut identifiers = BTreeSet::new();
        for (key, kind) in [
            ("activations", DeclarationKind::Activation),
            ("configurations", DeclarationKind::Configuration),
            ("assets", DeclarationKind::Asset),
            ("management", DeclarationKind::Management),
        ] {
            for value in groups
                .get(key)
                .and_then(Value::as_array)
                .ok_or(Error::Field)?
            {
                let item = value.as_object().ok_or(Error::Field)?;
                let text = |key| item.get(key).and_then(Value::as_str).ok_or(Error::Field);
                let identifier = text("identifier")?;
                super::identifier(identifier)?;
                let server_token = text("server-token")?;
                super::identifier(server_token)?;
                if !identifiers.insert(identifier) {
                    return Err(Error::Constraint);
                }
                reports.push(DeclarationStatus {
                    kind,
                    identifier: identifier.into(),
                    server_token: server_token.into(),
                    active: item
                        .get("active")
                        .and_then(Value::as_bool)
                        .ok_or(Error::Field)?,
                    validity: match text("valid")? {
                        "unknown" => Validity::Unknown,
                        "invalid" => Validity::Invalid,
                        "valid" => Validity::Valid,
                        _ => return Err(Error::Constraint),
                    },
                    reasons: item
                        .get("reasons")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default(),
                });
            }
        }
        Ok(reports)
    }
}
fn flatten(
    prefix: &str,
    values: &Map<String, Value>,
    target: &Target<'_>,
    out: &mut BTreeMap<String, Value>,
    depth: usize,
) -> Result<(), Error> {
    if depth > 16 {
        return Err(Error::Limit);
    }
    for (key, value) in values {
        if key.is_empty() || key.contains('.') {
            return Err(Error::Field);
        }
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let mut definitions = native::generated::DEFINITIONS
            .iter()
            .filter(|d| d.kind == Kind::Status);
        if let Some(d) = definitions.clone().find(|d| d.identity == path) {
            d.active(target)?.conditions.check(target)?;
            if !value.is_null() {
                validate_leaf(d, &path, value, target)?;
            }
            out.insert(path.clone(), value.clone());
        } else if definitions.any(|d| d.identity.starts_with(&format!("{path}."))) {
            flatten(
                &path,
                value.as_object().ok_or(Error::Field)?,
                target,
                out,
                depth + 1,
            )?;
        } else {
            return Err(Error::UnknownSchema);
        }
    }
    Ok(())
}

fn validate_leaf(
    d: &'static native::Definition,
    path: &str,
    value: &Value,
    target: &Target<'_>,
) -> Result<(), Error> {
    let mut fields = Dictionary::new();
    if let Some(child) = incremental_item(d, target)? {
        let objects = value.as_array().ok_or(Error::Field)?;
        let mut identifiers = BTreeSet::new();
        let child_rule = child.active(target)?;
        for object in objects {
            let object = object.as_object().ok_or(Error::Field)?;
            let identifier = object
                .get("identifier")
                .and_then(Value::as_str)
                .ok_or(Error::Field)?;
            if identifier.is_empty() || identifier.len() > 1024 || !identifiers.insert(identifier) {
                return Err(Error::Constraint);
            }
            let removed = object
                .get("_removed")
                .map(|v| v.as_bool().ok_or(Error::Field))
                .transpose()?
                .unwrap_or(false);
            // Apple's native array contract allows bounded unknown extension keys. They
            // remain in the raw report but cannot bypass validation of any known field.
            let known: Map<String, Value> = object
                .iter()
                .filter(|(key, _)| {
                    child_rule
                        .children
                        .iter()
                        .any(|&i| d.fields[i].key == key.as_str())
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if removed {
                if known
                    .keys()
                    .any(|k| !["identifier", "_removed"].contains(&k.as_str()))
                {
                    return Err(Error::Constraint);
                }
                continue;
            }
            fields.insert(
                path.into(),
                native::json::plist(&Value::Array(vec![Value::Object(known)]))?,
            );
            let converted = native::json::fields(d, d.request, &fields, target)?;
            Payload::for_definition(d, converted, target)?;
        }
        fields.insert(path.into(), plist::Value::Array(vec![]));
    } else {
        fields.insert(path.into(), native::json::plist(value)?);
    }
    let converted = native::json::fields(d, d.request, &fields, target)?;
    Payload::for_definition(d, converted, target)?;
    Ok(())
}
pub(super) fn incremental_item<'a>(
    d: &'a native::Definition,
    target: &Target<'_>,
) -> Result<Option<&'a native::Field>, Error> {
    let Some(&root) = d.request.first() else {
        return Err(Error::InvalidSchema);
    };
    let rule = d.fields[root].active(target)?;
    if rule.atom != native::Atom::Array || rule.children.len() != 1 {
        return Ok(None);
    }
    let child = &d.fields[rule.children[0]];
    let child_rule = child.active(target)?;
    Ok((child_rule.atom == native::Atom::Dictionary
        && ["identifier", "_removed"].iter().all(|name| {
            child_rule
                .children
                .iter()
                .any(|&i| d.fields[i].key == *name)
        }))
    .then_some(child))
}
