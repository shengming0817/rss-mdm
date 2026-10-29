use super::*;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use uuid::Uuid;
/// Extraction is fixed with the imported document, never a mutable mapping program.
#[derive(Clone, Default, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Extraction {
    #[serde(default)]
    pub records: Option<String>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Import {
    /// Arbitrary bounded JSON data. No field grants software execution or publication authority.
    #[schemars(with = "Value", extend("x-rss-extension" = "Complete bounded source JSON, retained without software interpretation"))]
    pub document: Box<RawValue>,
    #[serde(default)]
    pub extraction: Extraction,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub source: String,
    pub revision: i64,
    /// Digest of the received JSON value's UTF-8 bytes, without a claim of upstream authenticity.
    pub document_sha256: [u8; 32],
    pub entry_count: i64,
    pub imported_at: i64,
    pub extraction: Extraction,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    #[serde(flatten)]
    pub snapshot: Snapshot,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDetail {
    #[serde(flatten)]
    pub snapshot: Snapshot,
    #[schemars(with = "Value", extend("x-rss-extension" = "Complete bounded current source JSON"))]
    pub document: Box<RawValue>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub entry_id: Uuid,
    pub source: String,
    pub revision: i64,
    pub package_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetail {
    #[serde(flatten)]
    pub entry: Entry,
    pub document_sha256: [u8; 32],
    #[schemars(with = "Value", extend("x-rss-extension" = "Owned copy of the selected source JSON; callers persist and edit their own data"))]
    pub data: Box<RawValue>,
}
#[derive(Serialize)]
pub(super) struct IndexEntry {
    pub id: Uuid,
    pub byte_offset: i64,
    pub byte_length: i64,
    pub package_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}
pub(super) struct Prepared {
    pub document: Box<RawValue>,
    pub digest: [u8; 32],
    pub extraction: Extraction,
    pub entries: Value,
    pub entry_count: i64,
}
fn pointer(value: &str) -> Result<Vec<String>, Error> {
    if value.len() > 4096 || value.contains('\0') || (!value.is_empty() && !value.starts_with('/'))
    {
        return Err(invalid());
    }
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value[1..]
        .split('/')
        .map(|token| {
            let mut result = String::new();
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c == '~' {
                    result.push(match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(invalid()),
                    });
                } else {
                    result.push(c);
                }
            }
            Ok(result)
        })
        .collect()
}
/// Traverse borrowed raw values: numbers and unused data never pass through f64 or JSONB.
struct Child<'a>(&'a str);
impl<'de> Visitor<'de> for Child<'_> {
    type Value = Option<&'de RawValue>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON container")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut selected = None;
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value::<&RawValue>()?;
            if key == self.0 {
                selected = Some(value);
            }
        }
        Ok(selected)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let wanted = if self.0.is_empty()
            || (self.0.len() > 1 && self.0.starts_with('0'))
            || !self.0.bytes().all(|c| c.is_ascii_digit())
        {
            None
        } else {
            self.0.parse::<usize>().ok()
        };
        let mut selected = None;
        let mut position = 0;
        while let Some(value) = seq.next_element::<&RawValue>()? {
            if wanted == Some(position) {
                selected = Some(value);
            }
            position += 1;
        }
        Ok(selected)
    }
}
fn select<'a>(mut value: &'a RawValue, path: &[String]) -> Result<Option<&'a RawValue>, Error> {
    for token in path {
        if !matches!(value.get().as_bytes().first(), Some(b'{' | b'[')) {
            return Ok(None);
        }
        let mut reader = serde_json::Deserializer::from_str(value.get());
        let selected = serde::Deserializer::deserialize_any(&mut reader, Child(token))
            .map_err(|_| invalid())?;
        let Some(selected) = selected else {
            return Ok(None);
        };
        value = selected;
    }
    Ok(Some(value))
}
struct Records;
impl<'de> Visitor<'de> for Records {
    type Value = Vec<&'de RawValue>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a bounded JSON record array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut records = Vec::new();
        while let Some(value) = seq.next_element::<&RawValue>()? {
            if records.len() == MAX_ENTRIES {
                return Err(serde::de::Error::custom("source record budget exceeded"));
            }
            records.push(value);
        }
        Ok(records)
    }
}
fn field(record: &RawValue, path: Option<&Vec<String>>) -> Result<Option<String>, Error> {
    let Some(path) = path else {
        return Ok(None);
    };
    let Some(value) = select(record, path)? else {
        return Ok(None);
    };
    // Reject oversized descriptive values before allocating their decoded string.
    if !value.get().starts_with('"') || value.get().len() > 6 * 4096 + 2 {
        return Ok(None);
    }
    let text: String = serde_json::from_str(value.get()).map_err(|_| invalid())?;
    Ok((text.len() <= 4096 && !text.is_empty() && !text.contains('\0')).then_some(text))
}
impl Import {
    pub(super) fn prepare(self) -> Result<Prepared, Error> {
        if self.document.get().len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        let package = self
            .extraction
            .package_id
            .as_deref()
            .map(pointer)
            .transpose()?;
        let name = self.extraction.name.as_deref().map(pointer).transpose()?;
        let version = self
            .extraction
            .version
            .as_deref()
            .map(pointer)
            .transpose()?;
        let selected = if let Some(p) = &self.extraction.records {
            select(&self.document, &pointer(p)?)?.unwrap_or(&self.document)
        } else {
            &self.document
        };
        let records: Vec<&RawValue> = if selected.get().starts_with('[') {
            serde::Deserializer::deserialize_seq(
                &mut serde_json::Deserializer::from_str(selected.get()),
                Records,
            )
            .map_err(|_| invalid())?
        } else {
            vec![selected]
        };
        if records.len() > MAX_ENTRIES {
            return Err(invalid());
        }
        let mut entries = Vec::with_capacity(records.len());
        let mut index_budget = MAX_REQUEST_BYTES;
        for record in records {
            let entry = IndexEntry {
                id: Uuid::new_v4(),
                byte_offset: 0,
                byte_length: record.get().len() as i64,
                package_id: field(record, package.as_ref())?,
                name: field(record, name.as_ref())?,
                version: field(record, version.as_ref())?,
            };
            // Conservative encoded-index budget, checked before retaining each derived row.
            let cost = 256
                + [&entry.package_id, &entry.name, &entry.version]
                    .into_iter()
                    .flatten()
                    .map(|s| s.len() * 6)
                    .sum::<usize>();
            index_budget = index_budget.checked_sub(cost).ok_or_else(invalid)?;
            let offset = (record.get().as_ptr() as usize)
                .checked_sub(self.document.get().as_ptr() as usize)
                .ok_or_else(invariant)?;
            if self.document.get().get(offset..offset + record.get().len()) != Some(record.get()) {
                return Err(invariant());
            }
            entries.push(IndexEntry {
                byte_offset: offset as i64,
                ..entry
            });
        }
        let digest = Sha256::digest(self.document.get().as_bytes()).into();
        Ok(Prepared {
            document: self.document,
            digest,
            extraction: self.extraction,
            entry_count: entries.len() as i64,
            entries: serde_json::to_value(entries).map_err(|_| invalid())?,
        })
    }
}
