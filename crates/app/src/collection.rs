//! Windows collection is the durable product intake; RSS owns receipts and projection.
use crate::{Error, Failure};
use rss_mdm_inventory::FieldKey;
use rss_observation::{Body, Change, Id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
mod store;
pub(crate) use store::{
    DurableReport, Run, accept, create, revalidate, terminate, terminate_session,
};

const FIELD_COUNT: usize = FieldKey::OBSERVED_COUNT;
fn uri(key: FieldKey) -> &'static str {
    match key {
        FieldKey::Model => "./DevInfo/Mod",
        FieldKey::OsVersion => "./DevDetail/SwV",
        _ => unreachable!("collection only uses observed catalog entries"),
    }
}
fn field_index(command: u32, first: u32) -> Option<usize> {
    command
        .checked_sub(first)
        .map(|offset| offset as usize)
        .filter(|index| *index < FIELD_COUNT)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunResult {
    Pending,
    Snapshot,
    Partial,
    Failed,
}
impl RunResult {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
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
pub(crate) enum FinishReason {
    Complete,
    MessageBudget,
    Timeout,
    Superseded,
    Revoked,
}
impl FinishReason {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
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
pub(crate) enum Quality {
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
pub(crate) struct FieldAttempt {
    pub status: Option<u16>,
    pub quality: Quality,
    pub received_at: Option<i64>,
    value: Option<String>,
    value_digest: Option<String>,
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attempts {
    pub fields: [FieldAttempt; FIELD_COUNT],
}
impl Attempts {
    fn status(&mut self, index: usize, code: u16) -> Result<(), Error> {
        let field = &mut self.fields[index];
        if field.status.is_some_and(|old| old != code)
            || (!(200..300).contains(&code) && field.value_digest.is_some())
        {
            return Err(Error::Conflict);
        }
        field.status = Some(code);
        self.refresh(index);
        Ok(())
    }
    fn value(&mut self, index: usize, value: String) -> Result<(), Error> {
        let field = &mut self.fields[index];
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        if field
            .value_digest
            .as_ref()
            .is_some_and(|old| old != &digest)
            || field.status.is_some_and(|code| !(200..300).contains(&code))
        {
            return Err(Error::Conflict);
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
    fn complete(&self) -> bool {
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
            .all(|f| f.status.is_none() && f.value_digest.is_none())
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
    fn apply(
        &mut self,
        correlated: &rss_mdm_windows_mdm::syncml::Correlated,
        message: u32,
        first: u32,
        received_at: i64,
    ) -> Result<(), Error> {
        for status in &correlated.statuses {
            if status.command_id == 0 {
                continue;
            }
            // Only Get statuses affect collection. Other sent command acknowledgements are harmless.
            if status.message_id == message
                && let Some(index) = field_index(status.command_id, first)
            {
                self.status(index, status.code)?;
                self.fields[index].received_at = Some(received_at);
            }
        }
        for result in &correlated.results {
            if !result.explicit_message_ref
                || !result.explicit_command_ref
                || result.reference.message_id != message
            {
                return Err(Error::Conflict);
            }
            let index = field_index(result.reference.command_id, first).ok_or(Error::Conflict)?;
            if result.reference.uri
                != uri(FieldKey::observed()
                    .nth(index)
                    .expect("collection field index"))
            {
                return Err(Error::Conflict);
            }
            self.value(index, result.value.0.clone())?;
            self.fields[index].received_at = Some(received_at);
        }
        Ok(())
    }
}

fn corrupt() -> Error {
    Error::Unavailable(Failure::AccessStore)
}

#[cfg(test)]
mod tests;
