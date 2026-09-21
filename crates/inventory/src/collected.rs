//! Current internal Observation payload. It does not change the device protocol.
use crate::{FieldKey, Invalid, Result};
use serde::{Deserialize, Serialize};
/// A definitive collected outcome; ordinary failed/partial attempts remain quality evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CollectedValue {
    /// Valid nonempty standard text.
    Known(String),
    /// The existing channel explicitly cannot implement the requested field Get.
    Unsupported,
}
impl CollectedValue {
    /// Encode the current closed payload after validating its catalog field.
    pub fn encode(&self, field: FieldKey) -> Result<Vec<u8>> {
        self.validate(field)?;
        serde_json::to_vec(self).map_err(|_| Invalid)
    }
    /// Decode only the current payload; no legacy text fallback.
    pub fn decode(field: FieldKey, bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
        value.validate(field)?;
        Ok(value)
    }
    fn validate(&self, field: FieldKey) -> Result<()> {
        if field.is_manual() || matches!(self,Self::Known(s) if !field.validate(s)) {
            Err(Invalid)
        } else {
            Ok(())
        }
    }
}
