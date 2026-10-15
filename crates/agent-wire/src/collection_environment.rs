//! Authenticated collection executor evidence; no server-domain dependencies.
use crate::runtime::WireError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Authenticated, current endpoint evidence, separate from administrator-authored requirements.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionEnvironment {
    /// Exact edition, absent when not observed.
    #[serde(deserialize_with = "required_option")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<String>"
    )]
    #[schemars(extend("minLength" = 1, "maxLength" = 128, "pattern" = "^[a-zA-Z0-9_.-]+$"))]
    pub edition: Option<String>,
    /// Installed controlled tool versions.
    #[schemars(extend("maxProperties" = 16, "propertyNames" = serde_json::json!({"minLength":1,"maxLength":128,"pattern":"^[a-zA-Z0-9_.-]+$"}), "additionalProperties" = serde_json::json!({"type":"string","minLength":1,"maxLength":64,"pattern":"^[0-9]+(\\.[0-9]+){0,3}$"})))]
    pub tools: BTreeMap<String, String>,
    /// Explicit native engine contracts; empty means no native execution support.
    pub native_engines: crate::runtime::NativeEngines,
}
fn numeric(value: &str) -> Option<[u32; 4]> {
    let mut out = [0; 4];
    if value.is_empty() || value.len() > 64 || value.split('.').count() > 4 {
        return None;
    }
    for (i, part) in value.split('.').enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[i] = part.parse().ok()?;
    }
    Some(out)
}
fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
impl CollectionEnvironment {
    /// Validate bounded current evidence before persisting it.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.native_engines.values().any(|v| *v != 1)
            || self.edition.as_ref().is_some_and(|v| !token(v))
            || self.tools.len() > 16
            || self
                .tools
                .iter()
                .any(|(k, v)| !token(k) || numeric(v).is_none())
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

fn required_option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
