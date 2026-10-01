//! Canonical typed Observation value; source identity comes from the authenticated stream.
use crate::{FieldDefinition, Invalid, Result, Scalar};
use serde::{Deserialize, Serialize};
/// Definitive per-field outcome. Failed/missing attempts never delete a last-known fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CollectedValue {
    /// Typed value validated against the frozen field version.
    Value(Scalar),
    /// Explicit legal null.
    Null,
    /// Explicit removal of this source's field; never inferred from failure.
    Deleted,
    /// Collector explicitly cannot provide this field.
    Unsupported,
}
impl CollectedValue {
    /// Encode only the current schema after checking its frozen field definition.
    pub fn encode(&self, definition: &FieldDefinition) -> Result<Vec<u8>> {
        self.validate(definition)?;
        serde_json::to_vec(self).map_err(|_| Invalid::Encoding)
    }
    /// Decode only the current typed schema; no legacy scalar/text fallback.
    pub fn decode(definition: &FieldDefinition, bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Invalid::Encoding)?;
        value.validate(definition)?;
        Ok(value)
    }
    fn validate(&self, definition: &FieldDefinition) -> Result<()> {
        match self {
            Self::Value(v) => definition.validate_scalar(v),
            Self::Null if !definition.nullable => Err(Invalid::TypeMismatch),
            _ => Ok(()),
        }
    }
}
