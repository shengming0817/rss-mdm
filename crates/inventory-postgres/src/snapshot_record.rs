//! Stored columns shared by ordinary provider reads and composed snapshot queries.
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;

pub(crate) struct Record(pub Value);
impl Record {
    pub fn try_get<'a, T: Deserialize<'a>, I: AsRef<str>>(&'a self, key: I) -> Result<T> {
        T::deserialize(
            self.0
                .get(key.as_ref())
                .context("missing snapshot column")?,
        )
        .context("invalid snapshot column")
    }
    pub fn observed(row: &sqlx::postgres::PgRow) -> Result<Self> {
        let mut value = serde_json::Map::new();
        for key in [
            "scope",
            "field",
            "field_scope",
            "source",
            "registration",
            "epoch",
            "batch_id",
            "coverage",
            "definition",
            "state",
        ] {
            value.insert(key.into(), json!(row.try_get::<String, _>(key)?));
        }
        for key in [
            "value",
            "value_version",
            "last_known",
            "last_known_version",
            "last_known_batch",
        ] {
            value.insert(key.into(), json!(row.try_get::<Option<String>, _>(key)?));
        }
        for key in [
            "observed_at",
            "received_at",
            "last_known_observed",
            "last_known_received",
        ] {
            value.insert(key.into(), json!(row.try_get::<Option<i64>, _>(key)?));
        }
        Ok(Self(Value::Object(value)))
    }
    pub fn manual(row: sqlx::postgres::PgRow) -> Result<Self> {
        Ok(Self(
            json!({"device":row.try_get::<String,_>("device")?,"field":row.try_get::<String,_>("field")?,"revision":row.try_get::<i64,_>("revision")?,"fact":row.try_get::<Value,_>("fact")?,"value_version":row.try_get::<Option<String>,_>("value_version")?,"last_known_version":row.try_get::<Option<String>,_>("last_known_version")?}),
        ))
    }
}
