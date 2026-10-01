#![deny(missing_docs)]
//! Inventory field policy, independent of storage and fixture authorization.
//!
//! Published collection definitions bind coverage and values. Observation owns
//! stream ordering and completeness;
//! the product adapter owns trusted device/source binding and persistence.

/// Observation dataset name selected by the Inventory projection.
pub const DATASET: &str = "inventory";

mod channels;
pub use channels::{AgentInstallation, MdmEnrollment};
mod assets;
mod collected;
pub use collected::CollectedValue;
/// Immutable seed definitions for the one product catalog.
pub mod builtin;
mod catalog;
mod collection;
pub use collection::{CollectionDefinition, CollectionReference};
mod source;
pub use assets::{Evidence, KnownValue, ResolvedField, Scalar, SourceFact, State, resolve};
pub use catalog::{
    Catalog, DICTIONARY, FieldDefinition, FieldKey, FieldPath, Kind, Operator, Platform,
    Sensitivity, ValueType,
};
pub use source::{Channel, ReportSource, Source};
/// Closed value-free validation categories; no field values or provider text are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Duplicate field definition or value within the same snapshot.
    DuplicateField,
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
            Self::DuplicateField => "duplicate field",
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

mod progress;
pub use progress::{CollectionProgress, FieldAttempt, NativeValue, Quality};
