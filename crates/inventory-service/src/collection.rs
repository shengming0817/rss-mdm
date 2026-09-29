//! Native collection is the durable product intake; RSS owns receipts and projection.
pub mod admission;
pub mod agent;
pub mod enterprise;
pub mod read;
use crate::{Error, Failure};
use rss_mdm_inventory::FieldKey;
use rss_observation::{Body, Change, Id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod store;
pub use store::{DurableReport, Run, terminate};

const FIELD_COUNT: usize = FieldKey::OBSERVED_COUNT;
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    #[default]
    Pending,
    Success,
    Unsupported,
    Failed,
    Invalid,
    Missing,
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldAttempt {
    pub status: Option<u16>,
    pub quality: Quality,
    pub received_at: Option<i64>,
    pub value: Option<String>,
    value_digest: Option<String>,
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempts {
    pub fields: [FieldAttempt; FIELD_COUNT],
}
pub enum NativeValue {
    Value(String),
    Invalid,
    Missing,
    Failed,
}
impl Attempts {
    pub fn native(values: [NativeValue; FIELD_COUNT], received_at: i64) -> Self {
        let mut attempts = Self::default();
        for ((field, key), value) in attempts
            .fields
            .iter_mut()
            .zip(FieldKey::observed())
            .zip(values)
        {
            field.received_at = Some(received_at);
            field.quality = match value {
                NativeValue::Value(value) if key.validate(&value) => {
                    field.value_digest = Some(format!("{:x}", Sha256::digest(value.as_bytes())));
                    field.value = Some(value);
                    Quality::Success
                }
                NativeValue::Value(_) | NativeValue::Invalid => Quality::Invalid,
                NativeValue::Missing => Quality::Missing,
                NativeValue::Failed => Quality::Failed,
            };
        }
        attempts
    }

    /// Interpret validated canonical inventory facts, independent of the reporting protocol.
    pub fn reported(body: &Body, received_at: i64) -> Result<Self, Error> {
        let mut attempts = Self::default();
        match body {
            Body::Snapshot(changes) | Body::Partial(changes) => {
                for change in changes {
                    let index = FieldKey::observed()
                        .position(|key| key.as_str() == change.key().as_str())
                        .ok_or(Error::Malformed)?;
                    let field = FieldKey::observed().nth(index).ok_or(Error::Malformed)?;
                    let value = rss_mdm_inventory::CollectedValue::decode(
                        field,
                        change.value().ok_or(Error::Malformed)?,
                    )
                    .map_err(|_| Error::Malformed)?;
                    match value {
                        rss_mdm_inventory::CollectedValue::Known(value) => {
                            attempts.status(index, 200)?;
                            attempts.value(index, value)?;
                        }
                        rss_mdm_inventory::CollectedValue::Unsupported => {
                            attempts.status(index, 501)?
                        }
                        _ => return Err(Error::Malformed),
                    }
                    attempts.fields[index].received_at = Some(received_at);
                }
            }
            Body::Failed { .. } => {
                for field in &mut attempts.fields {
                    field.status = Some(500);
                    field.quality = Quality::Failed;
                    field.received_at = Some(received_at);
                }
            }
            _ => return Err(Error::Malformed),
        }
        attempts.finish();
        Ok(attempts)
    }
    pub fn observe_status(
        &mut self,
        field: FieldKey,
        code: u16,
        received_at: i64,
    ) -> Result<(), CollectionError> {
        let index = FieldKey::observed()
            .position(|key| key == field)
            .ok_or(CollectionError::CorrelationConflict)?;
        self.status(index, code)?;
        self.fields[index].received_at = Some(received_at);
        Ok(())
    }
    pub fn observe_value(
        &mut self,
        field: FieldKey,
        value: String,
        received_at: i64,
    ) -> Result<(), CollectionError> {
        let index = FieldKey::observed()
            .position(|key| key == field)
            .ok_or(CollectionError::CorrelationConflict)?;
        self.value(index, value)?;
        self.fields[index].received_at = Some(received_at);
        Ok(())
    }

    fn status(&mut self, index: usize, code: u16) -> Result<(), CollectionError> {
        let field = &mut self.fields[index];
        if field.status.is_some_and(|old| old != code)
            || (!(200..300).contains(&code) && field.value_digest.is_some())
        {
            return Err(CollectionError::CorrelationConflict);
        }
        field.status = Some(code);
        self.refresh(index);
        Ok(())
    }
    fn value(&mut self, index: usize, value: String) -> Result<(), CollectionError> {
        let field = &mut self.fields[index];
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        if field
            .value_digest
            .as_ref()
            .is_some_and(|old| old != &digest)
            || field.status.is_some_and(|code| !(200..300).contains(&code))
        {
            return Err(CollectionError::CorrelationConflict);
        }
        field.value_digest = Some(digest);
        field.value = FieldKey::observed()
            .nth(index)
            .expect("collection field index")
            .validate(&value)
            .then_some(value);
        self.refresh(index);
        Ok(())
    }
    fn refresh(&mut self, index: usize) {
        let field = &mut self.fields[index];
        field.quality = if field.status == Some(501) {
            Quality::Unsupported
        } else if field.status.is_some_and(|code| !(200..300).contains(&code)) {
            Quality::Failed
        } else if field.value_digest.is_some() && field.value.is_none() {
            Quality::Invalid
        } else if field.status.is_some() && field.value.is_some() {
            Quality::Success
        } else {
            Quality::Pending
        };
    }
    pub fn complete(&self) -> bool {
        self.fields.iter().all(|f| f.quality != Quality::Pending)
    }
    fn finish(&mut self) {
        for field in &mut self.fields {
            if field.quality == Quality::Pending {
                field.quality = Quality::Missing;
            }
        }
    }
    fn body(&self) -> Option<Body> {
        if self
            .fields
            .iter()
            .all(|f| f.received_at.is_none() && f.status.is_none() && f.value_digest.is_none())
        {
            return None;
        }
        let changes: Vec<_> = self
            .fields
            .iter()
            .zip(FieldKey::observed())
            .filter_map(|(field, key)| {
                let outcome = if field.quality == Quality::Unsupported {
                    Some(rss_mdm_inventory::CollectedValue::Unsupported)
                } else {
                    field
                        .value
                        .as_ref()
                        .map(|value| rss_mdm_inventory::CollectedValue::Known(value.clone()))
                };
                outcome.map(|value| {
                    Change::upsert(
                        Id::new(key.as_str()).expect("static field"),
                        value.encode(key).expect("validated collection outcome"),
                    )
                })
            })
            .collect();
        Some(
            if self
                .fields
                .iter()
                .all(|field| matches!(field.quality, Quality::Success | Quality::Unsupported))
            {
                Body::Snapshot(changes)
            } else if changes.is_empty() {
                Body::Failed {
                    code: Id::new("collection_failed").expect("static reason"),
                }
            } else {
                Body::Partial(changes)
            },
        )
    }
}

fn corrupt() -> Error {
    Error::Unavailable(Failure::Database)
}

#[cfg(test)]
#[path = "../tests/collection.rs"]
mod tests;

/// Server-authored quality evidence for one fixed enterprise field.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnterpriseAttempt {
    pub field: FieldKey,
    pub quality: Quality,
    pub received_at: i64,
    pub task_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum CollectionError {
    #[error("report correlation or value conflict")]
    CorrelationConflict,
}
