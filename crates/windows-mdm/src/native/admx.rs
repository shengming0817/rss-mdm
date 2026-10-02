//! Native ADMX-backed policy values; all element identities come from fixed official templates.
//! ref: Microsoft understanding-admx-backed-policies, Text/MultiText/List/Enum/Decimal/Boolean.
use super::{Context, Error, Scope, generated};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Enabled/disabled ADMX state. Not configured uses the native Delete operation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValue {
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// Exact parameter IDs and typed values. Disabled policies must have no parameters.
    pub elements: BTreeMap<String, Data>,
}
/// Typed ADMX input controls. Debug is deliberately unavailable for sensitive policy data.
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Data {
    /// Native enum choice that deletes a registry value; encoding requires verified device support.
    Delete,
    /// Text or string-valued enumeration.
    Text(String),
    /// Decimal or integer-valued enumeration.
    Integer(#[serde(with = "super::decimal")] u64),
    /// Boolean control.
    Boolean(bool),
    /// REG_MULTI_SZ strings; callers cannot inject the native delimiter.
    MultiText(Vec<String>),
    /// Explicit native registry name/value pairs for an ADMX list control.
    List(Vec<(String, String)>),
}
pub(super) struct AdmxPolicy {
    pub file: &'static str,
    pub name: &'static str,
    pub from: u32,
    pub until: u32,
    pub class: &'static str,
    pub elements: &'static [AdmxElement],
}
pub(super) struct AdmxElement {
    pub id: &'static str,
    pub kind: &'static str,
    pub min: u64,
    pub max: u64,
    pub max_length: u64,
    pub choices: &'static [AdmxChoice],
}
pub(super) enum AdmxChoice {
    Integer(u64),
    Text(&'static str),
    Delete,
}

pub(super) fn compile(
    file: &str,
    name: &str,
    value: PolicyValue,
    target: Context,
) -> Result<String, Error> {
    let build = target.build.ok_or(Error::MissingEvidence)?[2];
    let policy = generated::POLICIES
        .iter()
        .find(|p| p.file == file && p.name == name && build >= p.from && build < p.until)
        .ok_or(Error::Unsupported)?;
    if matches!(
        (policy.class, target.scope),
        ("Machine", Scope::User) | ("User", Scope::Device)
    ) {
        return Err(Error::Scope);
    }
    if !value.enabled {
        return if value.elements.is_empty() {
            Ok("<disabled/>".into())
        } else {
            Err(Error::Value)
        };
    }
    // Policy CSP requires the complete control set, including controls marked optional in GPEdit.
    if value.elements.len() != policy.elements.len() {
        return Err(Error::Value);
    }
    let mut out = String::from("<enabled/>");
    for element in policy.elements {
        let input = value.elements.get(element.id).ok_or(Error::Value)?;
        let data = element.encode(input)?;
        use std::fmt::Write;
        write!(
            out,
            "<data id=\"{}\" value=\"{}\"/>",
            attribute(element.id)?,
            attribute(&data)?
        )
        .map_err(|_| Error::Value)?;
        if out.len() > 64 * 1024 {
            return Err(Error::Limit);
        }
    }
    Ok(out)
}

impl AdmxElement {
    fn encode(&self, input: &Data) -> Result<String, Error> {
        let value = match (self.kind, input) {
            ("enum", Data::Delete)
                if self.choices.iter().any(|c| matches!(c, AdmxChoice::Delete)) =>
            {
                return Err(Error::UnresolvedConstraint);
            }
            ("text", Data::Text(v)) => v.clone(),
            ("decimal", Data::Integer(v)) if (self.min..=self.max).contains(v) => v.to_string(),
            ("boolean", Data::Boolean(v)) => v.to_string(),
            ("enum", Data::Integer(v))
                if self
                    .choices
                    .iter()
                    .any(|c| matches!(c, AdmxChoice::Integer(n) if n == v)) =>
            {
                v.to_string()
            }
            ("enum", Data::Text(v))
                if self
                    .choices
                    .iter()
                    .any(|c| matches!(c, AdmxChoice::Text(s) if s == v)) =>
            {
                v.clone()
            }
            ("multiText", Data::MultiText(values)) => join(values.iter().map(String::as_str))?,
            ("list", Data::List(values)) => {
                let mut keys = BTreeSet::new();
                if values
                    .iter()
                    .any(|(name, _)| name.is_empty() || !keys.insert(name))
                {
                    return Err(Error::Value);
                }
                join(
                    values
                        .iter()
                        .flat_map(|(name, value)| [name.as_str(), value.as_str()]),
                )?
            }
            _ => return Err(Error::Value),
        };
        if value.len() > 64 * 1024 || value.encode_utf16().count() as u64 > self.max_length {
            return Err(Error::Limit);
        }
        Ok(value)
    }
}
fn join<'a>(values: impl Iterator<Item = &'a str>) -> Result<String, Error> {
    let mut out = String::new();
    for (index, value) in values.enumerate() {
        if index >= 2048 || value.len() > 64 * 1024 {
            return Err(Error::Limit);
        }
        if value.contains('\u{f000}') {
            return Err(Error::Value);
        }
        if index > 0 {
            out.push('\u{f000}');
        }
        if out.len().saturating_add(value.len()) > 64 * 1024 {
            return Err(Error::Limit);
        }
        out.push_str(value);
    }
    Ok(out)
}
fn attribute(value: &str) -> Result<String, Error> {
    crate::text(value, 64 * 1024, true).map_err(|_| Error::Value)?;
    Ok(quick_xml::escape::escape(value)
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
        .replace('\t', "&#9;"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lists_cannot_inject_native_delimiters_and_xml_controls() {
        assert!(join(["one", "two"].into_iter()).is_ok());
        assert_eq!(join(["one\u{f000}two"].into_iter()), Err(Error::Value));
        assert_eq!(attribute("<\"&\n").unwrap(), "&lt;&quot;&amp;&#10;");
        assert!(attribute("\0").is_err());
    }
}
