//! Persisted execution evidence uses its real Agent or native owner, including null/omission semantics.
use rss_mdm_agent_wire::runtime as w;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RunResult {
    Unmanage(Unmanage),
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Unmanage {
    pub unmanage_outcome: w::UnmanageOutcome,
}

impl RunResult {
    pub(crate) fn effect(&self) -> Option<&'static str> {
        None
    }
}

/// Real summary projection; diagnostic streams and collection values never enter serialization.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct SummaryResult(Summary);
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum Summary {
    Unmanage(WithDiagnostics<Unmanage>),
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
struct WithDiagnostics<T> {
    #[serde(flatten)]
    result: T,
    diagnostics: (),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticsSummary {
    pub duration_ms: u64,
    pub executed_at: i64,
    pub failure: Option<w::TaskFailure>,
}
impl From<&w::TaskDiagnostics> for DiagnosticsSummary {
    fn from(value: &w::TaskDiagnostics) -> Self {
        Self {
            duration_ms: value.duration_ms(),
            executed_at: value.executed_at(),
            failure: value.failure(),
        }
    }
}
impl<'de> Deserialize<'de> for SummaryResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        // Retain the existing recursive privacy boundary, then reject unknown core structure.
        fn strip(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(fields) => {
                    for key in ["output", "native", "stdout", "stderr"] {
                        fields.remove(key);
                    }
                    for value in fields.values_mut() {
                        strip(value);
                    }
                }
                serde_json::Value::Array(items) => {
                    for value in items {
                        strip(value);
                    }
                }
                _ => (),
            }
        }
        strip(&mut value);
        serde_json::from_value(value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}
