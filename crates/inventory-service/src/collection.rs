//! Native collection is the durable product intake; RSS owns receipts and projection.
pub mod agent;
pub mod channel;
pub mod enterprise;
pub mod read;
use crate::{Error, Failure};
pub use rss_mdm_inventory::{CollectionProgress as Attempts, FieldAttempt, NativeValue, Quality};
use rss_observation::Body;
#[cfg(test)]
use rss_observation::Id;
use serde::{Deserialize, Serialize};

pub mod store;
pub use store::{DurableReport, Run, terminate};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunResult {
    Pending,
    Snapshot,
    Partial,
    Failed,
}
impl RunResult {
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "snapshot" => Ok(Self::Snapshot),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            _ => Err(corrupt()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Complete,
    MessageBudget,
    Timeout,
    Superseded,
    Revoked,
}
impl FinishReason {
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "complete" => Ok(Self::Complete),
            "message_budget" => Ok(Self::MessageBudget),
            "timeout" => Ok(Self::Timeout),
            "superseded" => Ok(Self::Superseded),
            "revoked" => Ok(Self::Revoked),
            _ => Err(corrupt()),
        }
    }
}

fn corrupt() -> Error {
    Error::Unavailable(Failure::Database)
}

#[cfg(test)]
#[path = "../tests/collection.rs"]
mod tests;

#[derive(Clone, Debug, thiserror::Error)]
pub enum CollectionError {
    #[error("report correlation or value conflict")]
    CorrelationConflict,
}
