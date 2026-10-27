//! Persisted execution evidence uses its real Agent or native owner, including null/omission semantics.
use rss_mdm_agent_wire::runtime as w;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RunResult {
    Script(w::ScriptRunResult),
    AgentCollection(AgentCollection),
    NativeCollection(NativeCollection),
    Software(Software),
    NativeSoftware(NativeSoftware),
    Access(w::AccessResult),
    Credential(w::CredentialResult),
    CredentialRecovery(CredentialRecovery),
    Unmanage(Unmanage),
    Enrollment(Enrollment),
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollection {
    pub native: Option<w::NativeCollectionResult>,
    pub queries: BTreeMap<String, NativeQuerySummary>,
    pub plan_digest: [u8; 32],
    pub output_reference: w::ScriptOutputReference,
    pub trusted: bool,
    pub received_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeQuerySummary {
    pub query_digest: [u8; 32],
    pub collected_at: i64,
    pub status: w::NativeQueryStatus,
    pub enumeration_complete: bool,
    pub row_count: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCollection {
    pub collection_run: Uuid,
    pub result: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Software<E = w::SoftwareTaskResult> {
    pub intent: w::SoftwareTaskIntent,
    pub definition_digest: [u8; 32],
    pub evidence: E,
    pub effect: w::SelfServiceSoftwareEffect,
    pub effect_observed_at: Option<i64>,
    pub effect_received_at: i64,
    pub received_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "effect",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeSoftware {
    NotStarted {
        operation: Uuid,
    },
    Verified {
        operation: Uuid,
        effect_observed_at: i64,
        effect_received_at: i64,
    },
    Unknown {
        operation: Uuid,
        protocol: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Unmanage {
    pub unmanage_outcome: w::UnmanageOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    pub entry_outcome: w::EnrollmentEntryOutcome,
}
impl RunResult {
    pub(crate) fn effect(&self) -> Option<&'static str> {
        Some(match self {
            Self::Software(value) => match value.effect {
                w::SelfServiceSoftwareEffect::Verified => "verified",
                w::SelfServiceSoftwareEffect::Failed => "failed",
                w::SelfServiceSoftwareEffect::WaitingReboot => "waiting_reboot",
                w::SelfServiceSoftwareEffect::Unknown => "unknown",
            },
            Self::NativeSoftware(value) => match value {
                NativeSoftware::NotStarted { .. } => "not_started",
                NativeSoftware::Verified { .. } => "verified",
                NativeSoftware::Unknown { .. } => "unknown",
            },
            Self::CredentialRecovery(value) => match value.effect {
                w::CredentialRecoveryOutcome::NotAttempted => "not_attempted",
                w::CredentialRecoveryOutcome::Unchanged => "unchanged",
                w::CredentialRecoveryOutcome::Applied => "applied",
            },
            _ => return None,
        })
    }
}

/// Real summary projection; diagnostic streams and collection values never enter serialization.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct SummaryResult(Summary);
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum Summary {
    Script(ScriptSummary),
    AgentCollection(WithDiagnostics<AgentCollectionSummary>),
    NativeCollection(WithDiagnostics<NativeCollection>),
    Software(Software<w::SoftwareTaskResult<DiagnosticsSummary>>),
    NativeSoftware(WithDiagnostics<NativeSoftware>),
    Access(WithDiagnostics<w::AccessResult>),
    Credential(WithDiagnostics<w::CredentialResult>),
    CredentialRecovery(WithDiagnostics<CredentialRecovery>),
    Unmanage(WithDiagnostics<Unmanage>),
    Enrollment(WithDiagnostics<Enrollment>),
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
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScriptSummary {
    collected_at: i64,
    received_at: i64,
    exit_code: Option<i32>,
    quality: w::OutputQuality,
    schema_valid: bool,
    budget_valid: bool,
    output_reference: Option<w::ScriptOutputReference>,
    diagnostics: DiagnosticsSummary,
    trusted: bool,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentCollectionSummary {
    queries: BTreeMap<String, NativeQuerySummary>,
    plan_digest: [u8; 32],
    output_reference: w::ScriptOutputReference,
    trusted: bool,
    received_at: i64,
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

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRecovery {
    pub effect: w::CredentialRecoveryOutcome,
    pub recovered_by_task: Uuid,
    pub recovered_by_attempt: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn summary(value: RunResult) -> serde_json::Value {
        let mut raw = serde_json::to_value(value).unwrap();
        if raw.get("evidence").is_none() && raw.get("diagnostics").is_none() {
            raw["diagnostics"] = serde_json::Value::Null;
        }
        serde_json::to_value(serde_json::from_value::<SummaryResult>(raw).unwrap()).unwrap()
    }
    #[test]
    fn native_summary_keeps_sql_null_and_omitted_native_software_fields() {
        let operation = Uuid::new_v4();
        let value = summary(RunResult::NativeSoftware(NativeSoftware::NotStarted {
            operation,
        }));
        assert_eq!(
            value,
            json!({"operation":operation,"effect":"not_started","diagnostics":null})
        );
        let value = summary(RunResult::NativeCollection(NativeCollection {
            collection_run: operation,
            result: "failed".into(),
            reason: "complete".into(),
        }));
        assert_eq!(
            value,
            json!({"collectionRun":operation,"result":"failed","reason":"complete","diagnostics":null})
        );
        assert!(
            serde_json::from_value::<SummaryResult>(
                json!({"operation":operation,"effect":"future","diagnostics":null})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<RunResult>(json!({"unknownResult":{}})).is_err());
    }
    #[test]
    fn script_summary_removes_streams_and_resource_output_but_preserves_timing() {
        let value = summary(RunResult::Script(w::ScriptRunResult {
            collected_at: 1,
            received_at: 2,
            exit_code: Some(0),
            quality: w::OutputQuality::Complete,
            schema_valid: true,
            budget_valid: true,
            output: json!({"private":"value"}),
            output_reference: None,
            diagnostics: w::TaskDiagnostics::new(
                "secret output".into(),
                "secret error".into(),
                7,
                1,
                None,
            )
            .unwrap(),
            trusted: true,
        }));
        assert!(value.get("output").is_none());
        assert_eq!(
            value["diagnostics"],
            json!({"durationMs":7,"executedAt":1,"failure":null})
        );
        assert!(!value.to_string().contains("secret"));
    }
}
