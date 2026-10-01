//! Source normalization is product policy, independent of storage and Group.
use crate::{FieldDefinition, FieldKey, Invalid, Kind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Explicitly typed asset scalar. Times are UTC Unix seconds, never validity windows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Scalar {
    /// Nonblank bounded text.
    String(String),
    /// Signed integer.
    Integer(i64),
    /// Finite numeric observation.
    Number(ordered_float::NotNan<f64>),
    /// Ordered bounded collection.
    Array(Vec<Scalar>),
    /// Declared structured attributes.
    Object(BTreeMap<String, Scalar>),
    /// Boolean value, including false.
    Boolean(bool),
    /// UTC Unix seconds.
    Time(i64),
}
impl Scalar {
    /// Declared scalar kind.
    pub fn kind(&self) -> Kind {
        match self {
            Self::String(_) => Kind::String,
            Self::Integer(_) => Kind::Integer,
            Self::Number(_) => Kind::Number,
            Self::Array(_) => Kind::Array,
            Self::Object(_) => Kind::Object,
            Self::Boolean(_) => Kind::Boolean,
            Self::Time(_) => Kind::Time,
        }
    }
    /// Validate bounded text and the canonical time range.
    pub fn validate(&self) -> Result<()> {
        fn visit(value: &Scalar, depth: usize, nodes: &mut usize, bytes: &mut usize) -> Result<()> {
            *nodes += 1;
            if depth > 5 || *nodes > 200000 {
                return Err(Invalid::Value);
            }
            match value {
                Scalar::String(s) => {
                    *bytes = bytes.checked_add(s.len()).ok_or(Invalid::Value)?;
                    if s.chars().any(|c| c == '\0') || *bytes > 16 * 1024 * 1024 {
                        return Err(Invalid::Value);
                    }
                }
                Scalar::Number(n) if !n.into_inner().is_finite() => return Err(Invalid::Value),
                Scalar::Time(t) if rss_contract::Timepoint::try_from(*t).is_err() => {
                    return Err(Invalid::Time);
                }
                Scalar::Array(values) => {
                    for v in values {
                        visit(v, depth + 1, nodes, bytes)?
                    }
                }
                Scalar::Object(values) => {
                    for (key, v) in values {
                        *bytes += key.len();
                        visit(v, depth + 1, nodes, bytes)?
                    }
                }
                _ => (),
            }
            Ok(())
        }
        visit(self, 0, &mut 0, &mut 0)
    }
}
/// Field state. None of these states is inferred from elapsed time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum State {
    /// Explicit typed value.
    Known(Scalar),
    /// Explicit legal null.
    Null,
    /// No fact has been supplied.
    Missing,
    /// Collector cannot produce this field.
    Unsupported,
    /// Explicitly removed from this source.
    Deleted,
    /// Current sources disagree.
    Conflict,
}
/// Provenance supplied by the trusted product boundary, never authority by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    /// Closed source selected by the product adapter.
    pub source: crate::Source,
    /// Collector dataset identity; absent only for management assignments.
    pub dataset: Option<String>,
    /// Current device registration; absent for Manual.
    pub registration: Option<String>,
    /// Registration generation resolved by the host; absent on Manual and raw provider reads.
    pub registration_generation: Option<u64>,
    /// Source epoch; absent for Manual.
    pub epoch: Option<String>,
    /// Immutable batch or operation identity.
    pub snapshot_id: String,
    /// Observation/assignment time.
    pub observed_at: i64,
    /// Server reception time.
    pub received_at: i64,
    /// Management actor for Manual; absent for device facts.
    pub actor: Option<String>,
}
/// Retained value together with the provenance of that value, not a later deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnownValue {
    /// Typed last-known value.
    pub value: Scalar,
    /// Its original provenance.
    pub evidence: Evidence,
}
/// One current source fact with retained last-known value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFact {
    /// Explicit current source state.
    pub state: State,
    /// Last known typed value, retained across deletion.
    pub last_known: Option<KnownValue>,
    /// Trusted input provenance.
    pub evidence: Evidence,
}
/// One canonical resolved field, preserving every source for explanation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedField {
    /// Catalog key.
    pub field: FieldKey,
    /// Resolved state consumed by all product views.
    pub state: State,
    /// Stable source order with original provenance and last-known values.
    pub sources: Vec<SourceFact>,
}
/// Resolve current, authorized source facts. The caller must bind registration and epoch.
/// Tombstones never erase another source; equal values coalesce and unequal values conflict.
pub fn resolve(
    definition: &FieldDefinition,
    mut sources: Vec<SourceFact>,
) -> Result<ResolvedField> {
    if sources.len() > 128 {
        return Err(Invalid::SourceLimit);
    }
    definition.validate()?;
    for fact in &sources {
        validate_evidence(definition, &fact.evidence)?;
        match &fact.state {
            State::Known(v) => definition.validate_scalar(v)?,
            State::Null if !definition.nullable => return Err(Invalid::State),
            State::Missing | State::Conflict => return Err(Invalid::State),
            State::Unsupported if fact.evidence.source == crate::Source::Manual => {
                return Err(Invalid::State);
            }
            _ => {}
        }
        if let Some(v) = &fact.last_known {
            definition.validate_scalar(&v.value)?;
            validate_evidence(definition, &v.evidence)?;
            let e = &fact.evidence;
            let old = &v.evidence;
            // The historical actor and operation must remain the original ones.
            if (
                e.source.as_str(),
                &e.registration,
                e.registration_generation,
                &e.epoch,
                &e.dataset,
            ) != (
                old.source.as_str(),
                &old.registration,
                old.registration_generation,
                &old.epoch,
                &old.dataset,
            ) {
                return Err(Invalid::Evidence);
            }
        }
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
    let selected_priority = sources
        .iter()
        .filter(|s| matches!(s.state, State::Known(_) | State::Null))
        .filter_map(|s| definition.sources.get(&s.evidence.source))
        .min()
        .copied();
    let values: Vec<_> = sources
        .iter()
        .filter(|s| {
            matches!(s.state, State::Known(_) | State::Null)
                && definition.sources.get(&s.evidence.source).copied() == selected_priority
        })
        .map(|s| match &s.state {
            State::Known(value) => definition.canonical_value(value.clone()).map(State::Known),
            state => Ok(state.clone()),
        })
        .collect::<Result<Vec<_>>>()?;
    let state = match values.first() {
        Some(first) if values.iter().any(|v| v != first) => State::Conflict,
        Some(first) => first.clone(),
        None if sources.iter().any(|s| s.state == State::Deleted) => State::Deleted,
        None if sources.iter().any(|s| s.state == State::Unsupported) => State::Unsupported,
        None => State::Missing,
    };
    Ok(ResolvedField {
        field: definition.key,
        state,
        sources,
    })
}

fn validate_evidence(definition: &FieldDefinition, e: &Evidence) -> Result<()> {
    let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
    if !definition.sources.contains_key(&e.source) {
        return Err(Invalid::SourceNotAllowed);
    }
    if !bounded(&e.snapshot_id)
        || rss_contract::Timepoint::try_from(e.observed_at).is_err()
        || rss_contract::Timepoint::try_from(e.received_at).is_err()
        || if e.source == crate::Source::Manual {
            e.dataset.is_some()
                || e.registration.is_some()
                || e.registration_generation.is_some()
                || e.epoch.is_some()
                || e.actor.as_ref().is_none_or(|s| !bounded(s))
        } else {
            e.dataset.as_ref().is_none_or(|s| !bounded(s))
                || e.registration.as_ref().is_none_or(|s| !bounded(s))
                || e.epoch.as_ref().is_none_or(|s| !bounded(s))
                || e.actor.is_some()
                || e.registration_generation == Some(0)
        }
    {
        return Err(Invalid::Evidence);
    }
    Ok(())
}
