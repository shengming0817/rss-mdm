//! Array summaries retain value identity without materializing their items.
use crate::{
    Evidence, FieldDefinition, FieldKey, Invalid, Result, Source, UnknownReason, ValueType,
};
use serde::{Deserialize, Serialize};

/// One immutable array value. Equality compares canonical values, not storage locations.
#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrayValue {
    /// Immutable storage version bound by the query cursor.
    pub version: String,
    /// Ordinal item count.
    pub count: usize,
    /// Full canonical Scalar byte count.
    pub bytes: usize,
    /// SHA-256 of the full canonical Scalar bytes.
    pub digest: String,
}
impl PartialEq for ArrayValue {
    fn eq(&self, other: &Self) -> bool {
        (self.count, self.bytes, &self.digest) == (other.count, other.bytes, &other.digest)
    }
}
/// Field state whose known value is metadata, never a synthetic empty array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArrayState {
    /// An indeterminate observation with its original reason.
    Unknown {
        /// Closed observation reason.
        reason: UnknownReason,
    },
    /// Immutable version metadata.
    Known(ArrayValue),
    /// Explicit null.
    Null,
    /// No current fact.
    Missing,
    /// Source does not support the field.
    Unsupported,
    /// Source tombstone.
    Deleted,
    /// Equal-priority sources disagree.
    Conflict,
}
/// Retained metadata with the evidence belonging to that value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrayKnownValue {
    /// Immutable value.
    pub value: ArrayValue,
    /// Original observation evidence.
    pub evidence: Evidence,
}
/// A current array observation, without its item bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrayFact {
    /// Current field state.
    pub state: ArrayState,
    /// Prior known value, independently addressed.
    pub last_known: Option<ArrayKnownValue>,
    /// Current source evidence.
    pub evidence: Evidence,
}
/// Endpoint-specific source identity for associated views.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointArrayFact {
    /// Owning endpoint.
    pub endpoint: String,
    /// Source fact.
    pub fact: ArrayFact,
}
/// Resolved array summaries for one endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedArray {
    /// Catalog field.
    pub field: FieldKey,
    /// Resolved current state.
    pub state: ArrayState,
    /// Retained source metadata.
    pub sources: Vec<ArrayFact>,
}
/// Resolved array summaries across an explicitly authorized association.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedDeviceArray {
    /// Catalog field.
    pub field: FieldKey,
    /// Resolved current state.
    pub state: ArrayState,
    /// Endpoint-qualified source metadata.
    pub sources: Vec<EndpointArrayFact>,
}
fn validate_value(definition: &FieldDefinition, value: &ArrayValue) -> Result<()> {
    let ValueType::Array { max_items, .. } = &definition.value_type else {
        return Err(Invalid::Value);
    };
    let hash = |text: &str| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if value.count > *max_items as usize
        || value.bytes < 27
        || !hash(&value.version)
        || !hash(&value.digest)
        || value.count == 0 && value.bytes != 27
    {
        return Err(Invalid::Value);
    }
    Ok(())
}
fn state(definition: &FieldDefinition, sources: &[&ArrayFact]) -> Result<ArrayState> {
    definition.validate()?;
    if !matches!(definition.value_type, ValueType::Array { .. }) {
        return Err(Invalid::Value);
    }
    for fact in sources {
        crate::assets::validate_evidence(definition, &fact.evidence)?;
        if sources
            .first()
            .is_some_and(|first| first.evidence.scope != fact.evidence.scope)
        {
            return Err(Invalid::Evidence);
        }
        match &fact.state {
            ArrayState::Known(value) => validate_value(definition, value)?,
            ArrayState::Null if !definition.nullable => return Err(Invalid::State),
            ArrayState::Missing | ArrayState::Conflict => return Err(Invalid::State),
            ArrayState::Unsupported if fact.evidence.source == Source::Manual => {
                return Err(Invalid::State);
            }
            _ => {}
        }
        if let Some(old) = &fact.last_known {
            validate_value(definition, &old.value)?;
            crate::assets::validate_evidence(definition, &old.evidence)?;
            let e = &fact.evidence;
            let previous = &old.evidence;
            if (
                &e.scope,
                e.source,
                &e.registration,
                e.registration_generation,
                &e.epoch,
                &e.dataset,
            ) != (
                &previous.scope,
                previous.source,
                &previous.registration,
                previous.registration_generation,
                &previous.epoch,
                &previous.dataset,
            ) {
                return Err(Invalid::Evidence);
            }
        }
    }
    let selectable = |s: &&ArrayFact| {
        matches!(
            s.state,
            ArrayState::Known(_) | ArrayState::Null | ArrayState::Unknown { .. }
        )
    };
    let priority = sources
        .iter()
        .copied()
        .filter(selectable)
        .filter_map(|s| definition.sources.get(&s.evidence.source))
        .min();
    let values = sources
        .iter()
        .copied()
        .filter(selectable)
        .filter(|s| definition.sources.get(&s.evidence.source) == priority)
        .map(|s| &s.state)
        .collect::<Vec<_>>();
    Ok(match values.first() {
        Some(_)
            if values
                .iter()
                .any(|v| matches!(v, ArrayState::Unknown { .. })) =>
        {
            ArrayState::Unknown {
                reason: if values.iter().any(|v| {
                    matches!(
                        v,
                        ArrayState::Unknown {
                            reason: UnknownReason::UnorderedConflict
                        }
                    )
                }) {
                    UnknownReason::UnorderedConflict
                } else {
                    UnknownReason::NativeStatus
                },
            }
        }
        Some(first) if values.iter().any(|v| v != first) => ArrayState::Conflict,
        Some(first) => (*first).clone(),
        None if sources.iter().any(|s| s.state == ArrayState::Deleted) => ArrayState::Deleted,
        None if sources.iter().any(|s| s.state == ArrayState::Unsupported) => {
            ArrayState::Unsupported
        }
        None => ArrayState::Missing,
    })
}
/// Apply the existing source-priority and conservative unknown/conflict policy to metadata.
pub fn resolve_array(
    definition: &FieldDefinition,
    mut sources: Vec<ArrayFact>,
) -> Result<ResolvedArray> {
    if sources.len() > 128 {
        return Err(Invalid::SourceLimit);
    }
    sources.sort_by(|a, b| {
        (a.evidence.source, &a.evidence.dataset).cmp(&(b.evidence.source, &b.evidence.dataset))
    });
    if sources.windows(2).any(|s| {
        (s[0].evidence.source, &s[0].evidence.dataset)
            == (s[1].evidence.source, &s[1].evidence.dataset)
    }) {
        return Err(Invalid::DuplicateSource);
    }
    let state = state(definition, &sources.iter().collect::<Vec<_>>())?;
    Ok(ResolvedArray {
        field: definition.key,
        state,
        sources,
    })
}
/// Resolve separately qualified endpoint facts without collapsing their source identities.
pub fn resolve_device_array(
    definition: &FieldDefinition,
    mut sources: Vec<EndpointArrayFact>,
) -> Result<ResolvedDeviceArray> {
    if sources.len() > 256 {
        return Err(Invalid::SourceLimit);
    }
    if sources.iter().any(|s| {
        s.endpoint.is_empty() || s.endpoint.len() > 256 || s.endpoint.chars().any(char::is_control)
    }) {
        return Err(Invalid::Evidence);
    }
    sources.sort_by(|a, b| {
        (
            &a.endpoint,
            a.fact.evidence.source,
            &a.fact.evidence.dataset,
        )
            .cmp(&(
                &b.endpoint,
                b.fact.evidence.source,
                &b.fact.evidence.dataset,
            ))
    });
    if sources.windows(2).any(|s| {
        (
            &s[0].endpoint,
            s[0].fact.evidence.source,
            &s[0].fact.evidence.dataset,
        ) == (
            &s[1].endpoint,
            s[1].fact.evidence.source,
            &s[1].fact.evidence.dataset,
        )
    }) {
        return Err(Invalid::DuplicateSource);
    }
    let state = state(
        definition,
        &sources.iter().map(|s| &s.fact).collect::<Vec<_>>(),
    )?;
    Ok(ResolvedDeviceArray {
        field: definition.key,
        state,
        sources,
    })
}
