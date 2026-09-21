//! Source normalization is product policy, independent of storage and Group.
use crate::{FieldKey, Invalid, Kind, Result};
use serde::{Deserialize, Serialize};
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
            Self::Boolean(_) => Kind::Boolean,
            Self::Time(_) => Kind::Time,
        }
    }
    /// Validate bounded text and the canonical time range.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::String(s)
                if s.trim().is_empty() || s.len() > 256 || s.chars().any(char::is_control) =>
            {
                Err(Invalid)
            }
            Self::Time(t) if rss_contract::Timepoint::try_from(*t).is_err() => Err(Invalid),
            _ => Ok(()),
        }
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
    pub source: String,
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
pub fn resolve(field: FieldKey, mut sources: Vec<SourceFact>) -> Result<ResolvedField> {
    if sources.len() > 2 {
        return Err(Invalid);
    }
    let manual = field.definition().manual;
    for fact in &sources {
        let e = &fact.evidence;
        if if manual {
            !field.definition().sources.contains(&e.source.as_str())
                || e.registration.is_some()
                || e.epoch.is_some()
                || e.actor.as_ref().is_none_or(|a| a.is_empty())
        } else {
            !field.definition().sources.contains(&e.source.as_str())
                || e.registration.as_ref().is_none_or(|s| s.is_empty())
                || e.epoch.as_ref().is_none_or(|s| s.is_empty())
        } {
            return Err(Invalid);
        }
        if e.snapshot_id.is_empty()
            || e.snapshot_id.len() > 256
            || rss_contract::Timepoint::try_from(e.observed_at).is_err()
            || rss_contract::Timepoint::try_from(e.received_at).is_err()
        {
            return Err(Invalid);
        }
        match &fact.state {
            State::Known(v) => field.validate_scalar(v)?,
            State::Null if !manual => return Err(Invalid),
            State::Conflict => return Err(Invalid),
            _ => {}
        }
        if let Some(v) = &fact.last_known {
            field.validate_scalar(&v.value)?;
        }
    }
    sources.sort_by(|a, b| a.evidence.source.cmp(&b.evidence.source));
    if sources
        .windows(2)
        .any(|s| s[0].evidence.source == s[1].evidence.source)
    {
        return Err(Invalid);
    }
    let values: Vec<_> = sources
        .iter()
        .filter(|s| matches!(s.state, State::Known(_) | State::Null))
        .map(|s| s.state.clone())
        .collect();
    let state = match values.first() {
        Some(first) if values.iter().any(|v| v != first) => State::Conflict,
        Some(first) => first.clone(),
        None if sources.iter().any(|s| s.state == State::Deleted) => State::Deleted,
        None if sources.iter().any(|s| s.state == State::Unsupported) => State::Unsupported,
        None => State::Missing,
    };
    Ok(ResolvedField {
        field,
        state,
        sources,
    })
}
