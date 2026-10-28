use crate::Error;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
/// Stable task result shape consumed by Inventory and its scheduling participant.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobAccepted {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status_url: String,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub struct TaskRead {
    pub task: Uuid,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub processed: u64,
    pub members: u64,
    pub failure: Option<String>,
    pub failure_detail: Option<TaskDiagnostic>,
    pub replacement_task: Option<Uuid>,
}

/// Durable task diagnostic emitted by the existing scheduling owner.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskDiagnostic {
    GroupInputPending,
}
