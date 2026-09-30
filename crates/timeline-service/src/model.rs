use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed timeline query")]
    Malformed,
    #[error("timeline cursor does not match this query")]
    Conflict,
    #[error("timeline storage unavailable")]
    Storage,
    #[error("timeline source integrity failure")]
    Integrity,
    #[error("timeline operation deadline")]
    Deadline,
    #[error("timeline authorization rejected")]
    Forbidden,
}
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        let category = match &error {
            sqlx::Error::Database(_) => "database",
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode",
            sqlx::Error::RowNotFound => "missing",
            _ => "provider",
        };
        eprintln!(
            "{}",
            serde_json::json!({"event":"timeline_storage_failure","category":category,"code":error.as_database_error().and_then(|e|e.code())})
        );
        Self::Storage
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(_: rss_mdm_audit_integration::Error) -> Self {
        Self::Integrity
    }
}
/// Filters apply to the persisted recording time, inclusively from and exclusively until.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub device: Option<String>,
    pub operation_id: Option<Uuid>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}
impl Query {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=200).contains(&self.limit.unwrap_or(50))
            || self.operation_id.is_some_and(|v| v.is_nil())
            || self.from.is_some_and(|v| v < 0)
            || self.until.is_some_and(|v| v < 0)
            || self.from.zip(self.until).is_some_and(|(a, b)| a >= b)
            || self.cursor.as_ref().is_some_and(|v| v.len() > 4096)
            || [&self.device, &self.actor, &self.action]
                .into_iter()
                .flatten()
                .any(|v| !identifier(v))
            || self
                .outcome
                .as_deref()
                .is_some_and(|v| !matches!(v, "succeeded" | "denied" | "failed" | "unknown"))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> Self {
        let mut q = self.clone();
        q.cursor = None;
        q.limit = None;
        q
    }
}
pub(crate) fn identifier(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control)
}
/// Only explicit safe fields are returned. Audit outcome is not device-effect proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactView {
    pub source: String,
    pub event_id: String,
    pub position: u64,
    pub recorded_at: i64,
    pub observed_at: i64,
    pub actor_kind: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub device_id: Option<String>,
    pub operation_id: Option<Uuid>,
    pub related_operation_ids: Vec<Uuid>,
    pub request_id: Option<Uuid>,
    pub registration_id: Option<Uuid>,
    pub registration_request_id: Option<Uuid>,
    pub instance_id: Option<Uuid>,
    pub audit_outcome: String,
    pub phase: String,
    pub execution_state: Option<String>,
    pub effect: String,
    pub request_write_outcome: Option<String>,
    pub supported: bool,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub indexed_through: Option<u64>,
    pub source_through: Option<u64>,
    /// Source positions are indexed; this does not prove lifecycle or association completeness.
    pub complete: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub items: Vec<FactView>,
    pub next_cursor: Option<String>,
    pub coverage: Coverage,
}
