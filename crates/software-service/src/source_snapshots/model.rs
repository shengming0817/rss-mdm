use super::*;
use serde::{Deserialize, Serialize};
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
    #[schemars(extend("x-rss-extension" = "Complete bounded source JSON, retained without software interpretation"))]
    pub document: Value,
    #[serde(default)]
    pub extraction: Extraction,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub source: String,
    pub revision: i64,
    /// Digest of the serialized JSON value; not a claim about original whitespace or authenticity.
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
    #[schemars(extend("x-rss-extension" = "Complete bounded current source JSON"))]
    pub document: Value,
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
    #[schemars(extend("x-rss-extension" = "Owned copy of the selected source JSON; callers persist and edit their own data"))]
    pub data: Value,
}
#[derive(Serialize)]
pub(super) struct IndexEntry {
    pub id: Uuid,
    pub path: Vec<String>,
    pub package_id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}
pub(super) struct Prepared {
    pub document: Value,
    pub digest: [u8; 32],
    pub extraction: Extraction,
    pub entries: Value,
    pub entry_count: i64,
}
fn pointer(value: &str) -> Result<Vec<String>, Error> {
    if value.len() > 4096 || (!value.is_empty() && !value.starts_with('/')) {
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
fn field(record: &Value, pointer: Option<&str>) -> Option<String> {
    record
        .pointer(pointer?)
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 4096 && !s.is_empty() && !s.contains('\0'))
        .map(str::to_owned)
}
impl Import {
    pub(super) fn prepare(self) -> Result<Prepared, Error> {
        let mut path = Vec::new();
        for value in [
            &self.extraction.package_id,
            &self.extraction.name,
            &self.extraction.version,
        ]
        .into_iter()
        .flatten()
        {
            pointer(value)?;
        }
        let selected = if let Some(p) = &self.extraction.records {
            let selected_path = pointer(p)?;
            if let Some(value) = self.document.pointer(p) {
                path = selected_path;
                value
            } else {
                &self.document
            }
        } else {
            &self.document
        };
        let size = selected.as_array().map_or(1, Vec::len);
        if size > MAX_ENTRIES {
            return Err(invalid());
        }
        let mut entries = Vec::with_capacity(size);
        let mut append = |record: &Value, path: Vec<String>| {
            entries.push(IndexEntry {
                id: Uuid::new_v4(),
                path,
                package_id: field(record, self.extraction.package_id.as_deref()),
                name: field(record, self.extraction.name.as_deref()),
                version: field(record, self.extraction.version.as_deref()),
            });
        };
        if let Some(values) = selected.as_array() {
            for (index, value) in values.iter().enumerate() {
                let mut path = path.clone();
                path.push(index.to_string());
                append(value, path);
            }
        } else {
            append(selected, path);
        }
        let bytes = serde_json::to_vec(&self.document).map_err(|_| invalid())?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        let digest = Sha256::digest(bytes).into();
        Ok(Prepared {
            document: self.document,
            digest,
            extraction: self.extraction,
            entry_count: entries.len() as i64,
            entries: serde_json::to_value(entries).map_err(|_| invalid())?,
        })
    }
}
