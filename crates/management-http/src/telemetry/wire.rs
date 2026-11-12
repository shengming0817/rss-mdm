//! The management query wire owns its JSON representation, independently of RSS storage.
//! ref: rss crates/timeseries/src/{definition,model,query,value}.rs@aa7d4d72a06046691a07237c63a336d8100e9900.
use crate::decimal::{DecimalI64, DecimalI128, DecimalU64, DecimalU128, PositiveU64};
use rss_mdm_telemetry_service::query as service;
use rss_timeseries as ts;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
};

macro_rules! wire_enum {
    ($name:ident, $($variant:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all="camelCase")]
        pub(super) enum $name { $($variant),+ }
        impl From<ts::$name> for $name {
            fn from(value: ts::$name) -> Self { match value { $(ts::$name::$variant => Self::$variant),+ } }
        }
        impl From<$name> for ts::$name {
            fn from(value: $name) -> Self { match value { $($name::$variant => Self::$variant),+ } }
        }
    }
}
wire_enum!(QueryMode, History, Latest);
wire_enum!(
    AggregateOp,
    Min,
    Max,
    Sum,
    Count,
    Mean,
    Increase,
    Rate,
    Timeline,
    Transitions,
    Coverage
);
wire_enum!(NumberKind, I64, U64, F64);
wire_enum!(Temporality, Cumulative, Delta);

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HistoryRequest {
    device: String,
    field: String,
    resource: String,
    start_micros: DecimalI64,
    end_micros: DecimalI64,
    max_points: NonZeroU32,
    mode: QueryMode,
    after: Option<String>,
}
impl From<HistoryRequest> for service::HistoryRequest {
    fn from(v: HistoryRequest) -> Self {
        Self {
            device: v.device,
            field: v.field,
            resource: v.resource,
            start_micros: v.start_micros.0,
            end_micros: v.end_micros.0,
            max_points: v.max_points,
            mode: v.mode.into(),
            after: v.after,
        }
    }
}
#[derive(Deserialize, JsonSchema)]
#[serde(
    tag = "coverage",
    content = "maxHoldMicros",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum CoveragePolicy {
    ObservedOnly,
    HoldLast(PositiveU64),
}
impl From<CoveragePolicy> for ts::CoveragePolicy {
    fn from(v: CoveragePolicy) -> Self {
        match v {
            CoveragePolicy::ObservedOnly => Self::ObservedOnly,
            CoveragePolicy::HoldLast(n) => Self::HoldLast(n.0),
        }
    }
}
#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AggregateRequest {
    query: HistoryRequest,
    definition_version: PositiveU64,
    source: rss_mdm_inventory::Source,
    epoch: uuid::Uuid,
    dimensions: BTreeMap<String, String>,
    resolution_micros: PositiveU64,
    operation: AggregateOp,
    coverage: CoveragePolicy,
    max_gap_micros: Option<PositiveU64>,
}
impl From<AggregateRequest> for service::AggregateRequest {
    fn from(v: AggregateRequest) -> Self {
        Self {
            query: v.query.into(),
            definition_version: v.definition_version.0,
            source: v.source,
            epoch: v.epoch,
            dimensions: v.dimensions,
            resolution_micros: v.resolution_micros.0,
            operation: v.operation.into(),
            coverage: v.coverage.into(),
            max_gap_micros: v.max_gap_micros.map(|v| v.0),
        }
    }
}

#[derive(Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
struct Id(
    #[schemars(
        length(min = 1, max = 256),
        regex(pattern = r"^[^\u0000-\u001f\u007f-\u009f]*$")
    )]
    String,
);
impl From<&ts::Id> for Id {
    fn from(v: &ts::Id) -> Self {
        Self(v.as_str().into())
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    #[schemars(with = "uuid::Uuid")]
    tenant: String,
    namespace: Id,
}
impl From<&ts::Scope> for Scope {
    fn from(v: &ts::Scope) -> Self {
        Self {
            tenant: v.tenant().to_string(),
            namespace: v.namespace().into(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Stream {
    scope: Scope,
    source: Id,
    generation: Id,
}
impl From<&ts::Stream> for Stream {
    fn from(v: &ts::Stream) -> Self {
        Self {
            scope: v.scope().into(),
            source: v.source().into(),
            generation: v.generation().into(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Metric {
    Gauge {
        number: NumberKind,
    },
    Counter {
        number: NumberKind,
        temporality: Temporality,
    },
    Bool,
    State {
        #[schemars(length(min = 1, max = 256))]
        members: BTreeSet<Id>,
    },
}
impl From<&ts::Metric> for Metric {
    fn from(v: &ts::Metric) -> Self {
        match v {
            ts::Metric::Gauge { number } => Self::Gauge {
                number: (*number).into(),
            },
            ts::Metric::Counter {
                number,
                temporality,
            } => Self::Counter {
                number: (*number).into(),
                temporality: (*temporality).into(),
            },
            ts::Metric::Bool => Self::Bool,
            ts::Metric::State { members } => Self::State {
                members: members.iter().map(Into::into).collect(),
            },
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DimensionRules {
    #[schemars(length(max = 64))]
    allowed: BTreeSet<Id>,
    #[schemars(length(max = 64))]
    required: BTreeSet<Id>,
    #[schemars(range(max = 64))]
    max_count: u16,
    #[schemars(range(min = 1, max = 256))]
    max_value_bytes: u16,
    #[schemars(range(min = 1, max = 32768))]
    max_total_bytes: u32,
}
impl From<&ts::DimensionRules> for DimensionRules {
    fn from(v: &ts::DimensionRules) -> Self {
        Self {
            allowed: v.allowed.iter().map(Into::into).collect(),
            required: v.required.iter().map(Into::into).collect(),
            max_count: v.max_count,
            max_value_bytes: v.max_value_bytes,
            max_total_bytes: v.max_total_bytes,
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Definition {
    scope: Scope,
    key: Id,
    version: PositiveU64,
    unit: Id,
    metric: Metric,
    dimensions: DimensionRules,
}
impl From<&ts::Definition> for Definition {
    fn from(v: &ts::Definition) -> Self {
        let v = v.spec();
        Self {
            scope: (&v.scope).into(),
            key: (&v.key).into(),
            version: std::num::NonZeroU64::new(v.version)
                .expect("validated definition version")
                .into(),
            unit: (&v.unit).into(),
            metric: (&v.metric).into(),
            dimensions: (&v.dimensions).into(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Series {
    definition: Definition,
    subject: Id,
    resource: Id,
    dimensions: BTreeMap<String, Id>,
}
impl From<&ts::Series> for Series {
    fn from(v: &ts::Series) -> Self {
        Self {
            definition: v.definition().into(),
            subject: v.subject().into(),
            resource: v.resource().into(),
            dimensions: v
                .dimensions()
                .iter()
                .map(|(k, v)| (k.as_str().into(), v.into()))
                .collect(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Interval {
    start: DecimalI64,
    end: DecimalI64,
}
impl From<ts::Interval> for Interval {
    fn from(v: ts::Interval) -> Self {
        Self {
            start: v.start().micros().into(),
            end: v.end().micros().into(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum Number {
    I64(DecimalI64),
    U64(DecimalU64),
    F64(f64),
}
impl From<ts::Number> for Number {
    fn from(v: ts::Number) -> Self {
        match v {
            ts::Number::I64(v) => Self::I64(v.into()),
            ts::Number::U64(v) => Self::U64(v.into()),
            ts::Number::F64(v) => Self::F64(v.get()),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum Value {
    Number(Number),
    Bool(bool),
    State(Id),
}
impl From<&ts::Value> for Value {
    fn from(v: &ts::Value) -> Self {
        match v {
            ts::Value::Number(v) => Self::Number((*v).into()),
            ts::Value::Bool(v) => Self::Bool(*v),
            ts::Value::State(v) => Self::State(v.into()),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(
    tag = "quality",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum Reading {
    Valid(Value),
    Missing,
    Failed,
}
impl From<&ts::Reading> for Reading {
    fn from(v: &ts::Reading) -> Self {
        match v {
            ts::Reading::Valid(v) => Self::Valid(v.into()),
            ts::Reading::Missing => Self::Missing,
            ts::Reading::Failed => Self::Failed,
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sample {
    stream: Stream,
    series: Series,
    id: Id,
    sequence: DecimalU64,
    observed_at: DecimalI64,
    interval: Option<Interval>,
    reading: Reading,
}
impl From<ts::Sample> for Sample {
    fn from(v: ts::Sample) -> Self {
        let v = v.input();
        Self {
            stream: (&v.stream).into(),
            series: (&v.series).into(),
            id: (&v.id).into(),
            sequence: v.sequence.into(),
            observed_at: v.observed_at.micros().into(),
            interval: v.interval.map(Into::into),
            reading: (&v.reading).into(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(tag = "selection", rename_all = "camelCase", deny_unknown_fields)]
enum Selection {
    Exact {
        stream: Stream,
        series: Series,
    },
    Resource {
        scope: Scope,
        subject: Id,
        resource: Id,
        keys: BTreeSet<Id>,
    },
}
impl From<ts::Selection> for Selection {
    fn from(v: ts::Selection) -> Self {
        match v {
            ts::Selection::Exact { stream, series } => Self::Exact {
                stream: (&stream).into(),
                series: (&series).into(),
            },
            ts::Selection::Resource {
                scope,
                subject,
                resource,
                keys,
            } => Self::Resource {
                scope: (&scope).into(),
                subject: (&subject).into(),
                resource: (&resource).into(),
                keys: keys.iter().map(Into::into).collect(),
            },
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Unavailable {
    selection: Selection,
    window: Interval,
    reason: service::UnavailableCause,
}
impl From<service::Unavailable> for Unavailable {
    fn from(v: service::Unavailable) -> Self {
        Self {
            selection: v.selection.into(),
            window: v.window.into(),
            reason: v.reason,
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HistoryRow {
    sample: Sample,
    received_at: DecimalI64,
    live_source: bool,
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LatestRow {
    sample: Sample,
    received_at: DecimalI64,
    effective_source: bool,
    source_conflict: bool,
}
#[derive(Serialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum History {
    History {
        rows: Vec<HistoryRow>,
        unavailable: Vec<Unavailable>,
        next: Option<String>,
        retired: bool,
    },
    Latest {
        rows: Vec<LatestRow>,
        unavailable: Vec<Unavailable>,
        next: Option<String>,
        retired: bool,
    },
}
impl From<service::History> for History {
    fn from(v: service::History) -> Self {
        match v {
            service::History::History {
                rows,
                unavailable,
                next,
                retired,
            } => Self::History {
                rows: rows
                    .into_iter()
                    .map(|v| HistoryRow {
                        sample: v.sample.into(),
                        received_at: v.received_at.into(),
                        live_source: v.live_source,
                    })
                    .collect(),
                unavailable: unavailable.into_iter().map(Into::into).collect(),
                next,
                retired,
            },
            service::History::Latest {
                rows,
                unavailable,
                next,
                retired,
            } => Self::Latest {
                rows: rows
                    .into_iter()
                    .map(|v| LatestRow {
                        sample: v.sample.into(),
                        received_at: v.received_at.into(),
                        effective_source: v.effective_source,
                        source_conflict: v.source_conflict,
                    })
                    .collect(),
                unavailable: unavailable.into_iter().map(Into::into).collect(),
                next,
                retired,
            },
        }
    }
}

#[derive(Serialize, JsonSchema)]
enum Sum {
    I128(DecimalI128),
    U128(DecimalU128),
    F64(f64),
}
impl From<ts::Sum> for Sum {
    fn from(v: ts::Sum) -> Self {
        match v {
            ts::Sum::I128(v) => Self::I128(v.into()),
            ts::Sum::U128(v) => Self::U128(v.into()),
            ts::Sum::F64(v) => Self::F64(v.get()),
        }
    }
}
#[derive(Serialize, JsonSchema)]
enum StateValue {
    Bool(bool),
    State(Id),
}
impl From<&ts::StateValue> for StateValue {
    fn from(v: &ts::StateValue) -> Self {
        match v {
            ts::StateValue::Bool(v) => Self::Bool(*v),
            ts::StateValue::State(v) => Self::State(v.into()),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StateSegment {
    value: StateValue,
    window: Interval,
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Transition {
    at: DecimalI64,
    from: StateValue,
    to: StateValue,
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StateDuration {
    value: StateValue,
    micros: DecimalU64,
}
#[derive(Serialize, JsonSchema)]
enum AggregateValue {
    Number(Number),
    Sum(Sum),
    Count(DecimalU64),
    Mean {
        sum: Sum,
        count: PositiveU64,
    },
    Rate {
        increase: Sum,
        duration_micros: PositiveU64,
    },
    StateSegments(Vec<StateSegment>),
    Transitions(Vec<Transition>),
    StateCoverage(Vec<StateDuration>),
    Missing,
}
impl From<ts::AggregateValue> for AggregateValue {
    fn from(v: ts::AggregateValue) -> Self {
        match v {
            ts::AggregateValue::Number(v) => Self::Number(v.into()),
            ts::AggregateValue::Sum(v) => Self::Sum(v.into()),
            ts::AggregateValue::Count(v) => Self::Count(v.into()),
            ts::AggregateValue::Mean { sum, count } => Self::Mean {
                sum: sum.into(),
                count: count.into(),
            },
            ts::AggregateValue::Rate {
                increase,
                duration_micros,
            } => Self::Rate {
                increase: increase.into(),
                duration_micros: duration_micros.into(),
            },
            ts::AggregateValue::StateSegments(v) => Self::StateSegments(
                v.into_iter()
                    .map(|v| StateSegment {
                        value: (&v.value).into(),
                        window: v.window.into(),
                    })
                    .collect(),
            ),
            ts::AggregateValue::Transitions(v) => Self::Transitions(
                v.into_iter()
                    .map(|v| Transition {
                        at: v.at.micros().into(),
                        from: (&v.from).into(),
                        to: (&v.to).into(),
                    })
                    .collect(),
            ),
            ts::AggregateValue::StateCoverage(v) => Self::StateCoverage(
                v.into_iter()
                    .map(|v| StateDuration {
                        value: (&v.value).into(),
                        micros: v.micros.into(),
                    })
                    .collect(),
            ),
            ts::AggregateValue::Missing => Self::Missing,
        }
    }
}
#[derive(Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
enum Completeness {
    Gaps,
    Overlap,
    ResetBoundary,
    Boundary,
}
impl From<ts::Completeness> for Completeness {
    fn from(v: ts::Completeness) -> Self {
        match v {
            ts::Completeness::Gaps => Self::Gaps,
            ts::Completeness::Overlap => Self::Overlap,
            ts::Completeness::ResetBoundary => Self::ResetBoundary,
            ts::Completeness::Boundary => Self::Boundary,
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AggregateBucket {
    window: Interval,
    value: AggregateValue,
    valid_samples: DecimalU64,
    covered_micros: DecimalU64,
    completeness: BTreeSet<Completeness>,
}
impl From<ts::AggregateBucket> for AggregateBucket {
    fn from(v: ts::AggregateBucket) -> Self {
        Self {
            window: v.window.into(),
            value: v.value.into(),
            valid_samples: v.valid_samples.into(),
            covered_micros: v.covered_micros.into(),
            completeness: v.completeness.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Aggregate {
    buckets: Vec<AggregateBucket>,
    unavailable: Vec<Unavailable>,
    resolution_micros: PositiveU64,
    refreshed_through: Option<DecimalI64>,
    next: Option<String>,
}
impl From<service::Aggregate> for Aggregate {
    fn from(v: service::Aggregate) -> Self {
        Self {
            buckets: v.buckets.into_iter().map(Into::into).collect(),
            unavailable: v.unavailable.into_iter().map(Into::into).collect(),
            resolution_micros: v.resolution_micros.into(),
            refreshed_through: v.refreshed_through.map(Into::into),
            next: v.next,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
