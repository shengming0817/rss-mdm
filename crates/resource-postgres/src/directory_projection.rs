//! Resource's typed metadata projection; shared storage owns CAS and digest execution.
use crate::STORAGE;
use rss_transactional_messaging_postgres::PgError;
use serde_json::Value;
pub(crate) fn from_record(record: &crate::core::directory::Record) -> Result<Value, PgError> {
    let mut presentation: crate::core::Presentation = STORAGE.json(
        "directory metadata",
        serde_json::from_value(Value::Object(record.presentation.clone())),
    )?;
    presentation.extensions.clear();
    let mut value = STORAGE.json("directory projection", serde_json::to_value(record))?;
    value["presentation"] =
        STORAGE.json("directory metadata", serde_json::to_value(presentation))?;
    Ok(value)
}
