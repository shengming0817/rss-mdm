#![deny(missing_docs)]
//! Inventory field policy, independent of storage and fixture authorization.
//!
//! [`coverage`] identifies the fixed device-basics contract. [`validate`] checks
//! batch coverage and values without changing the batch, reading storage or
//! authenticating its producer. Observation owns stream ordering and completeness;
//! the product adapter owns trusted device/source binding and persistence.
use rss_observation::{Batch, Coverage, Error, ErrorKind, Id};

/// Observation dataset name selected by the Inventory projection.
pub const DATASET: &str = "inventory";

mod assets;
mod collected;
pub use collected::CollectedValue;
mod catalog;
mod source;
pub use assets::{Evidence, KnownValue, ResolvedField, Scalar, SourceFact, State, resolve};
pub use catalog::{DICTIONARY, FieldDefinition, FieldKey, Kind, Operator};
pub use source::{Channel, ReportSource, Source};
/// Closed value-free validation categories; no field values or provider text are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Field identifier is outside the fixed catalog.
    UnknownField,
    /// Source identifier is outside the trusted vocabulary.
    UnknownSource,
    /// Scalar and catalog kinds differ.
    TypeMismatch,
    /// A scalar violates its bounded value rules.
    Value,
    /// A scalar timestamp is outside the canonical UTC range.
    Time,
    /// State is not accepted from this kind of producer.
    State,
    /// Provenance is malformed or not bound to the same source coordinates.
    Evidence,
    /// The catalog does not permit this producer for the field.
    SourceNotAllowed,
    /// More than one fact uses the same source.
    DuplicateSource,
    /// Source count exceeds the fixed catalog budget.
    SourceLimit,
    /// The closed payload cannot be encoded or decoded.
    Encoding,
}
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category = match self {
            Self::UnknownField => "unknown field",
            Self::UnknownSource => "unknown source",
            Self::TypeMismatch => "type mismatch",
            Self::Value => "invalid value",
            Self::Time => "invalid time",
            Self::State => "invalid state",
            Self::Evidence => "invalid evidence",
            Self::SourceNotAllowed => "source not allowed",
            Self::DuplicateSource => "duplicate source",
            Self::SourceLimit => "source limit",
            Self::Encoding => "invalid encoding",
        };
        f.write_str(category)
    }
}
impl std::error::Error for Invalid {}
/// Product asset policy result.
pub type Result<T> = std::result::Result<T, Invalid>;

/// Return fixed `device-basics` / `2` / `model-os` / `typed-v2` coverage identities.
/// Construction performs no I/O and makes no assertion about a particular report.
pub fn coverage() -> Coverage {
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(id("device-basics"), id("2"), id("model-os"), id("typed-v2"))
}

/// Validate the fixed coverage, known field keys and closed typed outcomes.
/// Rejects unknown keys, mismatched coverage, legacy text, malformed payloads or values failing
/// [`FieldKey::validate`] with `rss_observation::ErrorKind::InvalidInput`.
/// Deletions carry no value to validate. Does not mutate or authenticate the batch.
pub fn validate(batch: &Batch) -> std::result::Result<(), Error> {
    let fields = if batch.coverage() == &coverage() {
        FieldKey::OBSERVED.to_vec()
    } else {
        vec![
            FieldKey::ENTERPRISE
                .into_iter()
                .find(|field| batch.coverage() == &enterprise_coverage(*field))
                .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?,
        ]
    };
    for change in batch.body().changes() {
        let field = fields
            .iter()
            .copied()
            .find(|key| key.as_str() == change.key().as_str())
            .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?;
        if let Some(value) = change.value() {
            CollectedValue::decode(field, value)
                .map_err(|_| Error::from(ErrorKind::InvalidInput))?;
        }
    }
    Ok(())
}

/// Each fixed enterprise field has its own snapshot scope and coverage.
pub fn enterprise_coverage(field: FieldKey) -> Coverage {
    assert!(field.is_enterprise(), "enterprise field required");
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(
        id("enterprise-task"),
        id("1"),
        id(field.as_str()),
        id("typed-v1"),
    )
}
/// Validate the exact source/dataset pair and return its sole coverage.
pub fn scope_coverage(scope: &rss_observation::Scope) -> Result<Coverage> {
    if scope.dataset().as_str() == DATASET {
        ReportSource::parse(scope.source().as_str())?;
        return Ok(coverage());
    }
    let field = FieldKey::parse(scope.dataset().as_str())?;
    let source = Source::parse(scope.source().as_str())?;
    if !field.is_enterprise() || !field.definition().sources.contains(&source) {
        return Err(Invalid::SourceNotAllowed);
    }
    Ok(enterprise_coverage(field))
}
/// The finite datasets owned by a trusted producer.
pub fn datasets(source: Source) -> &'static [&'static str] {
    match source {
        Source::AgentBuiltin | Source::MdmWindows => &[DATASET],
        Source::AgentScript => &[
            "custom.corporate_agent.version",
            "custom.corporate_agent.healthy",
        ],
        Source::AgentOsquery => &["custom.osquery.version"],
        Source::Manual => &[],
    }
}
