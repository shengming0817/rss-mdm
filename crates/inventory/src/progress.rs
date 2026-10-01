//! Bounded per-field progress. A value without successful protocol confirmation is not a fact.
use crate::{CollectedValue, CollectionDefinition, FieldKey, Invalid, Result};
use rss_observation::{Body, Change, Id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Quality of one expected field in one frozen collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    /// Not attempted or not confirmed.
    Pending,
    /// Confirmed typed value, including explicit null.
    Success,
    /// Explicit unsupported response.
    Unsupported,
    /// Execution or protocol failure.
    Failed,
    /// Output violated the frozen schema.
    Invalid,
    /// No confirmed result before termination.
    Missing,
    /// Explicit source tombstone.
    Deleted,
}
/// Provenance and validated output for a single field; inspect through CollectionProgress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldAttempt {
    /// Optional native protocol response status.
    pub status: Option<u16>,
    /// Current quality, independently checked during restoration.
    pub quality: Quality,
    /// Last server receipt time, never a TTL.
    pub received_at: Option<i64>,
    value: Option<CollectedValue>,
    digest: Option<String>,
    confirmed: bool,
    terminal: Option<Quality>,
    items: Vec<Quality>,
}
impl FieldAttempt {
    /// Original row order and validation result, without untrusted values.
    pub fn items(&self) -> &[Quality] {
        &self.items
    }
}
impl Default for FieldAttempt {
    fn default() -> Self {
        Self {
            status: None,
            quality: Quality::Pending,
            received_at: None,
            value: None,
            digest: None,
            confirmed: false,
            terminal: None,
            items: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    definition: CollectionDefinition,
    fields: BTreeMap<FieldKey, FieldAttempt>,
    finished: bool,
    complete_coverage: bool,
}
/// All expected fields share one definition. No positional slots or implicit field membership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Document", into = "Document")]
pub struct CollectionProgress(Document);
impl From<CollectionProgress> for Document {
    fn from(v: CollectionProgress) -> Self {
        v.0
    }
}
impl TryFrom<Document> for CollectionProgress {
    type Error = Invalid;
    fn try_from(v: Document) -> Result<Self> {
        if v.fields.len() != v.definition.fields().len() {
            return Err(Invalid::Evidence);
        }
        for (key, f) in &v.fields {
            let definition = v.definition.field(*key)?;
            if matches!(&f.value,Some(CollectedValue::Value(crate::Scalar::Array(values))) if values.len()!=f.items.len())
            {
                return Err(Invalid::Evidence);
            }
            if !f.items.is_empty() {
                let crate::ValueType::Array { max_items, .. } = &definition.value_type else {
                    return Err(Invalid::Evidence);
                };
                if f.items.len() > *max_items as usize
                    || f.items
                        .iter()
                        .any(|q| !matches!(q, Quality::Success | Quality::Invalid))
                {
                    return Err(Invalid::Evidence);
                }
                match &f.value {
                    Some(CollectedValue::Value(crate::Scalar::Array(values)))
                        if values.len() == f.items.len()
                            && f.items.iter().all(|q| *q == Quality::Success) =>
                    {
                        ()
                    }
                    None if f.terminal == Some(Quality::Invalid)
                        && f.items.contains(&Quality::Invalid) =>
                    {
                        ()
                    }
                    _ => return Err(Invalid::Evidence),
                }
            }
            if let Some(value) = &f.value {
                let bytes = value.encode(definition)?;
                if f.digest.as_deref() != Some(format!("{:x}", Sha256::digest(bytes)).as_str()) {
                    return Err(Invalid::Evidence);
                }
            }
            if f.terminal.is_some_and(|q| {
                !matches!(
                    q,
                    Quality::Missing | Quality::Failed | Quality::Invalid | Quality::Deleted
                )
            }) || (f.terminal.is_some() && (f.value.is_some() || f.confirmed))
            {
                return Err(Invalid::Evidence);
            }
            if f.received_at
                .is_some_and(|at| rss_contract::Timepoint::try_from(at).is_err())
                || f.digest
                    .as_ref()
                    .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
                || f.quality != quality(f, v.finished)
            {
                return Err(Invalid::Evidence);
            }
        }
        Ok(Self(v))
    }
}
fn quality(f: &FieldAttempt, finished: bool) -> Quality {
    if let Some(terminal) = f.terminal {
        return terminal;
    }
    if f.confirmed && f.value == Some(CollectedValue::Deleted) {
        return Quality::Deleted;
    }
    if f.status == Some(501) || (f.confirmed && f.value == Some(CollectedValue::Unsupported)) {
        Quality::Unsupported
    } else if f.status.is_some_and(|c| !(200..300).contains(&c)) {
        Quality::Failed
    } else if f.digest.is_some() && f.value.is_none() {
        Quality::Invalid
    } else if f.confirmed && f.value.is_some() {
        Quality::Success
    } else if finished {
        Quality::Missing
    } else {
        Quality::Pending
    }
}
impl CollectionProgress {
    /// Allocate exactly the fields in the frozen definition.
    pub fn new(definition: CollectionDefinition) -> Self {
        let fields = definition
            .fields()
            .iter()
            .map(|f| (f.key, FieldAttempt::default()))
            .collect();
        Self(Document {
            definition,
            fields,
            finished: false,
            complete_coverage: true,
        })
    }
    /// Frozen source, schemas and coverage.
    pub fn definition(&self) -> &CollectionDefinition {
        &self.0.definition
    }
    /// Canonical per-field quality; callers cannot change the membership or cached state.
    pub fn fields(&self) -> &BTreeMap<FieldKey, FieldAttempt> {
        &self.0.fields
    }
    /// Record a correlated protocol status. Conflicting retries fail atomically.
    pub fn observe_status(&mut self, key: FieldKey, code: u16, at: i64) -> Result<()> {
        rss_contract::Timepoint::try_from(at).map_err(|_| Invalid::Time)?;
        if self.0.finished || !(100..600).contains(&code) {
            return Err(Invalid::State);
        }
        let f = self.0.fields.get_mut(&key).ok_or(Invalid::UnknownField)?;
        if f.terminal.is_some()
            || f.status.is_some_and(|old| old != code)
            || (!(200..300).contains(&code) && f.digest.is_some())
        {
            return Err(Invalid::Evidence);
        }
        f.status = Some(code);
        f.confirmed = (200..300).contains(&code);
        f.received_at = Some(at);
        f.quality = quality(f, false);
        Ok(())
    }
    /// Retain typed output only when valid; record bounded invalid quality otherwise.
    pub fn observe_value(&mut self, key: FieldKey, value: CollectedValue, at: i64) -> Result<()> {
        rss_contract::Timepoint::try_from(at).map_err(|_| Invalid::Time)?;
        if self.0.finished {
            return Err(Invalid::State);
        }
        let definition = self.0.definition.field(key)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| Invalid::Encoding)?;
        let previous = self
            .0
            .fields
            .get(&key)
            .and_then(|f| f.value.as_ref())
            .map(|v| v.encode(definition))
            .transpose()?
            .map_or(0, |v| v.len());
        if self
            .value_bytes()?
            .saturating_sub(previous)
            .saturating_add(bytes.len())
            > 16 * 1024 * 1024
        {
            return Err(Invalid::Value);
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let f = self.0.fields.get_mut(&key).ok_or(Invalid::UnknownField)?;
        if f.terminal.is_some()
            || f.digest.as_ref().is_some_and(|old| old != &digest)
            || f.status.is_some_and(|c| !(200..300).contains(&c))
        {
            return Err(Invalid::Evidence);
        }
        f.value = value.encode(definition).ok().map(|_| value);
        f.items = match &f.value {
            Some(CollectedValue::Value(crate::Scalar::Array(items))) => {
                vec![Quality::Success; items.len()]
            }
            _ => Vec::new(),
        };
        f.digest = Some(digest);
        f.received_at = Some(at);
        f.quality = quality(f, false);
        Ok(())
    }
    /// Whether all expected fields have a definitive result.
    pub fn complete(&self) -> bool {
        self.0
            .fields
            .values()
            .all(|f| f.quality != Quality::Pending)
    }
    /// Stop accepting results; outstanding fields become Missing, never deletion.
    pub fn finish(&mut self) {
        self.0.finished = true;
        for f in self.0.fields.values_mut() {
            f.quality = quality(f, true)
        }
    }
    /// Record native parsing failure without treating it as a missing value or protocol success.
    pub fn observe_invalid(&mut self, key: FieldKey, at: i64) -> Result<()> {
        rss_contract::Timepoint::try_from(at).map_err(|_| Invalid::Time)?;
        let field = self.0.fields.get_mut(&key).ok_or(Invalid::UnknownField)?;
        if self.0.finished || field.value.is_some() || field.terminal.is_some() {
            return Err(Invalid::Evidence);
        }
        field.confirmed = false;
        field.received_at = Some(at);
        field.terminal = Some(Quality::Invalid);
        field.quality = quality(field, false);
        Ok(())
    }
    /// Retain row-level validation failures while preserving the prior trusted field as a whole.
    pub fn observe_invalid_items(
        &mut self,
        key: FieldKey,
        items: Vec<Quality>,
        at: i64,
    ) -> Result<()> {
        let crate::ValueType::Array { max_items, .. } = &self.0.definition.field(key)?.value_type
        else {
            return Err(Invalid::TypeMismatch);
        };
        if items.len() > *max_items as usize
            || !items.contains(&Quality::Invalid)
            || items
                .iter()
                .any(|q| !matches!(q, Quality::Success | Quality::Invalid))
        {
            return Err(Invalid::Evidence);
        }
        self.observe_invalid(key, at)?;
        self.0
            .fields
            .get_mut(&key)
            .ok_or(Invalid::UnknownField)?
            .items = items;
        Ok(())
    }
    /// Encoded values currently retained, for the native adapter's aggregate budget.
    pub fn value_bytes(&self) -> Result<usize> {
        self.0
            .fields
            .iter()
            .try_fold(0usize, |total, (key, field)| {
                let bytes = field
                    .value
                    .as_ref()
                    .map(|v| v.encode(self.0.definition.field(*key)?))
                    .transpose()?
                    .map_or(0, |v| v.len());
                total.checked_add(bytes).ok_or(Invalid::Value)
            })
    }
    /// Emit only confirmed outcomes. Failure or missing values cannot create a full snapshot.
    pub fn body(&self) -> Result<Option<Body>> {
        if self.0.fields.values().all(|f| f.received_at.is_none()) {
            return Ok(None);
        }
        let complete = self.0.complete_coverage
            && self.0.fields.values().all(|f| {
                matches!(
                    f.quality,
                    Quality::Success | Quality::Unsupported | Quality::Deleted
                )
            });
        let mut changes = Vec::new();
        for (key, f) in &self.0.fields {
            let value = match f.quality {
                Quality::Success => f.value.as_ref(),
                Quality::Unsupported => Some(&CollectedValue::Unsupported),
                Quality::Deleted if !complete => Some(&CollectedValue::Deleted),
                _ => None,
            };
            if let Some(value) = value {
                changes.push(Change::upsert(
                    Id::new(key.as_str()).map_err(|_| Invalid::Value)?,
                    value.encode(self.0.definition.field(*key)?)?,
                ));
            }
        }
        Ok(Some(if complete {
            Body::Snapshot(changes)
        } else if changes.is_empty()
            && self
                .0
                .fields
                .values()
                .any(|f| matches!(f.quality, Quality::Failed | Quality::Invalid))
        {
            Body::Failed {
                code: Id::new("collection_failed").map_err(|_| Invalid::Value)?,
            }
        } else {
            Body::Partial(changes)
        }))
    }
}

/// Native adapter outcome; protocol decoders own scalar parsing, not the asset resolver.
pub enum NativeValue {
    /// Typed native value or explicit unsupported/null.
    Value(CollectedValue),
    /// Per-row results from a malformed list; no partial list replaces trusted facts.
    InvalidItems(Vec<Quality>),
    /// Response did not match the expected schema.
    Invalid,
    /// Expected field was absent.
    Missing,
    /// Native command failed.
    Failed,
}
impl CollectionProgress {
    /// Capture native responses using registered identities, never positional field slots.
    pub fn native(
        definition: CollectionDefinition,
        mut values: BTreeMap<FieldKey, NativeValue>,
        at: i64,
    ) -> Result<Self> {
        let mut result = Self::new(definition);
        for key in values.keys() {
            result.0.definition.field(*key)?;
        }
        let keys: Vec<_> = result.0.fields.keys().copied().collect();
        for key in keys {
            match values.remove(&key).unwrap_or(NativeValue::Missing) {
                NativeValue::Value(value) => {
                    match result.observe_value(key, value, at) {
                        Ok(()) => (),
                        Err(Invalid::Value) => {
                            result.observe_invalid(key, at)?;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    let f = result.0.fields.get_mut(&key).ok_or(Invalid::UnknownField)?;
                    f.confirmed = true;
                    f.quality = quality(f, false);
                }
                NativeValue::InvalidItems(items) => result.observe_invalid_items(key, items, at)?,
                other => {
                    rss_contract::Timepoint::try_from(at).map_err(|_| Invalid::Time)?;
                    let f = result.0.fields.get_mut(&key).ok_or(Invalid::UnknownField)?;
                    f.received_at = Some(at);
                    f.terminal = Some(match other {
                        NativeValue::Invalid => Quality::Invalid,
                        NativeValue::Failed => Quality::Failed,
                        _ => Quality::Missing,
                    });
                    f.quality = quality(f, false);
                }
            }
        }
        result.finish();
        Ok(result)
    }
    /// Read quality from an already verified report; full absence and explicit deletes remain distinct from failure.
    pub fn reported(definition: CollectionDefinition, body: &Body, at: i64) -> Result<Self> {
        let mut values = BTreeMap::new();
        for change in body.changes() {
            let key = FieldKey::parse(change.key().as_str())?;
            let field = definition.field(key)?;
            if values
                .insert(
                    key,
                    match change.value() {
                        Some(bytes) => NativeValue::Value(CollectedValue::decode(field, bytes)?),
                        None => NativeValue::Missing,
                    },
                )
                .is_some()
            {
                return Err(Invalid::DuplicateField);
            }
        }
        if matches!(body, Body::Failed { .. }) {
            values = definition
                .fields()
                .iter()
                .map(|f| (f.key, NativeValue::Failed))
                .collect();
        }
        let mut result = Self::native(definition, values, at)?;
        result.0.complete_coverage = matches!(body, Body::Snapshot(_));
        for (key, f) in &mut result.0.fields {
            if (matches!(body, Body::Snapshot(_))
                && !body
                    .changes()
                    .iter()
                    .any(|c| c.key().as_str() == key.as_str()))
                || body
                    .changes()
                    .iter()
                    .any(|c| c.key().as_str() == key.as_str() && c.value().is_none())
            {
                f.terminal = Some(Quality::Deleted);
                f.quality = Quality::Deleted;
            }
        }
        Ok(result)
    }
}

impl NativeValue {
    /// Validate each mapped list row and duplicate identities without accepting a partial snapshot.
    pub fn list(field: &crate::FieldDefinition, rows: Vec<Result<crate::Scalar>>) -> Result<Self> {
        let crate::ValueType::Array { items, max_items } = &field.value_type else {
            return Err(Invalid::TypeMismatch);
        };
        if rows.len() > *max_items as usize {
            return Ok(Self::Invalid);
        }
        let mut quality = Vec::with_capacity(rows.len());
        let mut values = Vec::with_capacity(rows.len());
        let mut identities = BTreeMap::new();
        for (index, row) in rows.into_iter().enumerate() {
            let value = row.and_then(|v| items.validate_value(&v).map(|_| v));
            quality.push(if value.is_ok() {
                Quality::Success
            } else {
                Quality::Invalid
            });
            if let Ok(value) = value {
                if let (Some(key), crate::Scalar::Object(properties)) = (&field.item_key, &value) {
                    let identity = properties.get(key).ok_or(Invalid::Value)?;
                    if let Some(previous) = identities.insert(identity.clone(), index) {
                        quality[previous] = Quality::Invalid;
                        quality[index] = Quality::Invalid;
                    }
                }
                values.push(value);
            }
        }
        if quality.contains(&Quality::Invalid) {
            Ok(Self::InvalidItems(quality))
        } else {
            Ok(Self::Value(CollectedValue::Value(
                field.canonical_value(crate::Scalar::Array(values))?,
            )))
        }
    }
}
