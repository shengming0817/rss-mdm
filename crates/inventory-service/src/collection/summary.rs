//! Collection display metadata excludes observed values and ordinal quality entries.
use rss_mdm_inventory::{CollectionDefinition, FieldKey, Quality};
use serde::Deserialize;
use std::collections::BTreeMap;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    pub definition: CollectionDefinition,
    pub fields: BTreeMap<FieldKey, Field>,
    pub finished: bool,
    pub complete_coverage: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Field {
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub quality: Quality,
    pub received_at: Option<i64>,
    pub item_count: usize,
    pub invalid_items: usize,
}
impl Summary {
    pub fn decode(bytes: &str) -> Result<Self, crate::Error> {
        let value: Self = serde_json::from_str(bytes).map_err(|_| super::corrupt())?;
        if value.fields.len() != value.definition.fields().len() {
            return Err(super::corrupt());
        }
        for (key, field) in &value.fields {
            value.definition.field(*key).map_err(|_| super::corrupt())?;
            if field.invalid_items > field.item_count {
                return Err(super::corrupt());
            }
        }
        Ok(value)
    }

    pub fn coverage_complete(&self) -> bool {
        self.finished
            && self.complete_coverage
            && self.fields.values().all(|f| {
                matches!(
                    f.quality,
                    Quality::Success | Quality::Unsupported | Quality::Deleted
                )
            })
    }
}
