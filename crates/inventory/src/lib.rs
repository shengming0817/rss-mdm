#![deny(missing_docs)]
//! Inventory field policy, independent of storage and fixture authorization.
//!
//! Published collection definitions bind coverage and values. Observation owns
//! stream ordering and completeness;
//! the product adapter owns trusted device/source binding and persistence.

/// Observation dataset name selected by the Inventory projection.
pub const DATASET: &str = "inventory";

mod channels;
mod cut;
pub use cut::{AssetCut, InvalidAssetCut};
mod hardware;
mod software;
pub use channels::{AgentInstallation, MdmEnrollment};
pub use hardware::{normalize_hardware_uuid, normalize_serial_number};
mod array;
mod assets;
pub use array::{
    ArrayFact, ArrayKnownValue, ArrayState, ArrayValue, EndpointArrayFact, ResolvedArray,
    ResolvedDeviceArray, resolve_array, resolve_device_array,
};
mod collected;
pub use collected::{CollectedValue, UnknownReason};
/// Immutable seed definitions for the one product catalog.
pub mod builtin;
mod catalog;
mod retention;
mod telemetry;
mod time_series;
pub use retention::RetentionPolicy;
pub use time_series::{
    RetentionReference, TelemetryAggregation, TelemetryDimension, TelemetryKind, TimeSeriesBinding,
};
mod collection;
pub use collection::{CollectionDefinition, CollectionField, CollectionReference};
mod source;
pub use assets::{
    EndpointSourceFact, Evidence, KnownValue, ResolvedDeviceField, ResolvedField, Scalar,
    ScalarBudget, SourceFact, State, resolve, resolve_device,
};
pub use catalog::{
    Catalog, DICTIONARY, FieldDefinition, FieldKey, FieldPath, Kind, Operator, Platform, Property,
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

mod collection_scope;
pub use collection_scope::{ApplicationRoot, BrewPackage, CollectionScope, LocalAccountIdentity};

/// JSON projection of the fixed Observation dependency's existing Coverage serializer.
/// ref: rss crates/observation/src/{identity,report}.rs@3de9b9eb7c43fad5ed39a02e41a035464224d3fb
pub fn coverage_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let id = serde_json::json!({"type":"string", "minLength":1, "maxLength":256, "pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"});
    schemars::json_schema!({"type":"object", "properties":{
        "id":id, "version":id, "definition":id, "format":id
    }, "required":["id","version","definition","format"], "additionalProperties":false})
}
