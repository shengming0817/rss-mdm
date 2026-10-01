//! Immutable collection coverage shared by all device executors.
use crate::{Catalog, CollectedValue, FieldDefinition, FieldKey, Invalid, Result, Source};
use rss_observation::{Batch, Coverage, Id, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Definition {
    dataset: String,
    version: String,
    source: Source,
    fields: Vec<FieldDefinition>,
}
/// Frozen source and field definitions for one published collector version.
/// Constructing this value validates structure; the caller still owns tenant/device authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Definition", into = "Definition")]
pub struct CollectionDefinition(Definition);
impl TryFrom<Definition> for CollectionDefinition {
    type Error = Invalid;
    fn try_from(value: Definition) -> Result<Self> {
        Self::new(&value.dataset, &value.version, value.source, value.fields)
    }
}
impl From<CollectionDefinition> for Definition {
    fn from(value: CollectionDefinition) -> Self {
        value.0
    }
}
impl CollectionDefinition {
    /// Bind a finite unique field set to one device source and immutable definition version.
    pub fn new(
        dataset: &str,
        version: impl ToString,
        source: Source,
        mut fields: Vec<FieldDefinition>,
    ) -> Result<Self> {
        Id::new(dataset).map_err(|_| Invalid::Value)?;
        let version = version.to_string();
        Id::new(&version).map_err(|_| Invalid::Value)?;
        if dataset.len() > 128
            || version.len() > 128
            || source == Source::Manual
            || fields.is_empty()
            || fields.len() > 128
        {
            return Err(Invalid::Value);
        }
        Catalog::new(fields.clone())?;
        if fields.iter().any(|f| !f.sources.contains_key(&source)) {
            return Err(Invalid::SourceNotAllowed);
        }
        fields.sort_by_key(|f| f.key);
        Ok(Self(Definition {
            dataset: dataset.into(),
            version,
            source,
            fields,
        }))
    }
    /// Dataset selected by the product stream owner.
    pub fn dataset(&self) -> &str {
        &self.0.dataset
    }
    /// Exact source; never inferred from user-supplied field names.
    pub fn source(&self) -> Source {
        self.0.source
    }
    /// Immutable definition number.
    pub fn version(&self) -> &str {
        &self.0.version
    }
    /// Canonical unique field order, also used for completeness reporting.
    pub fn fields(&self) -> &[FieldDefinition] {
        &self.0.fields
    }
    /// Resolve a field only within this frozen coverage.
    pub fn field(&self, key: FieldKey) -> Result<&FieldDefinition> {
        self.0
            .fields
            .iter()
            .find(|f| f.key == key)
            .ok_or(Invalid::UnknownField)
    }
    /// Exact content identity includes schemas, sources and all definition constraints.
    pub fn fingerprint(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.0).map_err(|_| Invalid::Encoding)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    /// Observation validates the same coverage on every batch and replay.
    pub fn coverage(&self) -> Result<Coverage> {
        let id = |v: &str| Id::new(v).map_err(|_| Invalid::Value);
        Ok(Coverage::new(
            id(self.dataset())?,
            id(self.version())?,
            id(&self.fingerprint()?)?,
            id("typed-fields-v2")?,
        ))
    }
    /// Validate authenticated stream coordinates against this definition.
    pub fn validate_scope(&self, scope: &Scope) -> Result<()> {
        if scope.source().as_str() != self.source().as_str()
            || scope.dataset().as_str() != self.dataset()
        {
            return Err(Invalid::SourceNotAllowed);
        }
        Ok(())
    }
    /// Validate exact coverage and typed values; empty full snapshots are legitimate.
    pub fn validate(&self, batch: &Batch) -> Result<()> {
        if batch.coverage() != &self.coverage()? {
            return Err(Invalid::Evidence);
        }
        let mut fields = BTreeSet::new();
        for change in batch.body().changes() {
            let key = FieldKey::parse(change.key().as_str())?;
            let field = self.field(key)?;
            if !fields.insert(key) {
                return Err(Invalid::DuplicateField);
            }
            if let Some(value) = change.value() {
                CollectedValue::decode(field, value)?;
            }
        }
        Ok(())
    }
}

/// Product result reference carried by Observation. The referenced result is immutable and tenant scoped.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionReference {
    format: u8,
    digest: String,
}
impl CollectionReference {
    /// Freeze a complete reference event; field completeness belongs to the referenced result.
    pub fn batch(
        id: Id,
        sequence: u64,
        at: rss_contract::Timepoint,
        definition: &CollectionDefinition,
        digest: String,
    ) -> Result<Batch> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Invalid::Evidence);
        }
        let bytes =
            serde_json::to_vec(&Self { format: 1, digest }).map_err(|_| Invalid::Encoding)?;
        Batch::new(
            id,
            sequence,
            at,
            definition.coverage()?,
            rss_observation::Body::Snapshot(vec![rss_observation::Change::upsert(
                Id::new("collection_result").map_err(|_| Invalid::Value)?,
                bytes,
            )]),
        )
        .map_err(|_| Invalid::Evidence)
    }
    /// Read only the current result-reference envelope and exact frozen coverage.
    pub fn from_batch(definition: &CollectionDefinition, batch: &Batch) -> Result<Self> {
        let rss_observation::Body::Snapshot(changes) = batch.body() else {
            return Err(Invalid::Evidence);
        };
        if changes.len() != 1
            || changes[0].key().as_str() != "collection_result"
            || batch.coverage() != &definition.coverage()?
        {
            return Err(Invalid::Evidence);
        }
        let bytes = changes[0].value().ok_or(Invalid::Evidence)?;
        if bytes.len() > 256 {
            return Err(Invalid::Evidence);
        }
        let reference: Self = serde_json::from_slice(bytes).map_err(|_| Invalid::Encoding)?;
        if reference.format != 1
            || reference.digest.len() != 64
            || !reference
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Invalid::Evidence);
        }
        Ok(reference)
    }
    /// Exact SHA-256 of the canonical immutable result bytes.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
