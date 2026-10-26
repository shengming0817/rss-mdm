//! Narrow schema adapters for the fixed RSS types serialized by the actual HTTP inputs.
//! No replacement DTO or execution model is defined here. Serde seam tests own drift detection.
//! ref: rss crates/timeseries/src/{definition,model,query,aggregate,value}.rs@3de9b9eb7c43fad5ed39a02e41a035464224d3fb
use rss_timeseries::{AggregateOp, CoveragePolicy, QueryMode};
use schemars::{Schema, SchemaGenerator};
use serde_json::{Value, json};

fn object(fields: &[(&str, Value)]) -> Value {
    json!({"type":"object", "properties":fields.iter().map(|(k,v)|((*k).to_owned(),v.clone())).collect::<serde_json::Map<_,_>>(),
        "required":fields.iter().map(|(k,_)|*k).collect::<Vec<_>>(), "additionalProperties":false})
}
fn id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"})
}
fn positive() -> Value {
    json!({"type":"integer","format":"uint64","minimum":1})
}
fn scope() -> Value {
    object(&[
        ("tenant", json!({"type":"string","format":"uuid"})),
        ("namespace", id()),
    ])
}
pub(crate) fn query_mode(_: &mut SchemaGenerator) -> Schema {
    let names = [QueryMode::History, QueryMode::Latest].map(|mode| match mode {
        QueryMode::History | QueryMode::Latest => {
            serde_json::to_value(mode).expect("RSS query mode")
        }
    });
    schemars::json_schema!({"type":"string","enum":names})
}
pub(crate) fn aggregate_op(_: &mut SchemaGenerator) -> Schema {
    use AggregateOp::*;
    let names = [
        Min,
        Max,
        Sum,
        Count,
        Mean,
        Increase,
        Rate,
        Timeline,
        Transitions,
        Coverage,
    ]
    .map(|op| match op {
        Min | Max | Sum | Count | Mean | Increase | Rate | Timeline | Transitions | Coverage => {
            serde_json::to_value(op).expect("RSS aggregate operation")
        }
    });
    schemars::json_schema!({"type":"string","enum":names})
}
pub(crate) fn coverage(_: &mut SchemaGenerator) -> Schema {
    fn branch(value: CoveragePolicy) -> Value {
        let encoded = serde_json::to_value(value).expect("RSS coverage policy");
        let mut fields = vec![("coverage", json!({"const":encoded["coverage"]}))];
        match value {
            CoveragePolicy::ObservedOnly => (),
            CoveragePolicy::HoldLast(_) => fields.push(("maxHoldMicros", positive())),
        }
        let mut schema = object(&fields);
        // This external enum's Serde declaration does not deny unknown object fields.
        schema
            .as_object_mut()
            .expect("object")
            .remove("additionalProperties");
        schema
    }
    schemars::json_schema!({"oneOf":[branch(CoveragePolicy::ObservedOnly),branch(CoveragePolicy::HoldLast(std::num::NonZeroU64::new(1).expect("positive")))]})
}
pub(crate) fn stream(_: &mut SchemaGenerator) -> Schema {
    object(&[("scope", scope()), ("source", id()), ("generation", id())])
        .try_into()
        .expect("schema")
}
fn metric() -> Value {
    use rss_timeseries::{Metric, NumberKind, Temporality};
    let number = json!({"type":"string","enum":[NumberKind::I64,NumberKind::U64,NumberKind::F64]});
    let make = |metric: Metric| {
        let encoded = serde_json::to_value(&metric).expect("RSS metric");
        let mut fields = vec![("kind", json!({"const":encoded["kind"]}))];
        match metric {
            Metric::Gauge { .. } => fields.push(("number", number.clone())),
            Metric::Counter { .. } => {
                fields.push(("number", number.clone()));
                fields.push((
                    "temporality",
                    json!({"type":"string","enum":[Temporality::Cumulative,Temporality::Delta]}),
                ));
            }
            Metric::Bool => (),
            Metric::State { .. } => fields.push((
                "members",
                json!({"type":"array","items":id(),"uniqueItems":true,"minItems":1,"maxItems":256}),
            )),
        }
        object(&fields)
    };
    json!({"oneOf":[make(Metric::Gauge{number:NumberKind::I64}),make(Metric::Counter{number:NumberKind::I64,temporality:Temporality::Cumulative}),make(Metric::Bool),make(Metric::State{members:Default::default()})]})
}
pub(crate) fn series(_: &mut SchemaGenerator) -> Schema {
    let ids = json!({"type":"array","items":id(),"uniqueItems":true,"maxItems":64});
    let dimensions = object(&[
        ("allowed", ids.clone()),
        ("required", ids),
        (
            "maxCount",
            json!({"type":"integer","minimum":0,"maximum":64}),
        ),
        (
            "maxValueBytes",
            json!({"type":"integer","minimum":1,"maximum":256}),
        ),
        (
            "maxTotalBytes",
            json!({"type":"integer","minimum":1,"maximum":32768}),
        ),
    ]);
    let definition = object(&[
        ("scope", scope()),
        ("key", id()),
        ("version", positive()),
        ("unit", id()),
        ("metric", metric()),
        ("dimensions", dimensions),
    ]);
    object(&[("definition",definition),("subject",id()),("resource",id()),
        ("dimensions",json!({"type":"object","propertyNames":id(),"additionalProperties":id(),"maxProperties":64}))]).try_into().expect("schema")
}
pub(crate) fn summary(generator: &mut SchemaGenerator) -> Schema {
    let mut schema = object(&[
        ("stream", stream(generator).to_value()),
        ("series", series(generator).to_value()),
        (
            "resolution",
            json!({"type":"integer","format":"uint64","minimum":1,"maximum":i64::MAX}),
        ),
        ("coverage", coverage(generator).to_value()),
        ("maxGap", json!({"anyOf":[positive(),{"type":"null"}]})),
    ]);
    if generator.contract().is_deserialize() {
        schema["required"]
            .as_array_mut()
            .expect("required keys")
            .retain(|v| v != "maxGap");
    }
    schema.try_into().expect("schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_timeseries::{
        Definition, DefinitionSpec, DimensionRules, Id, Metric, NumberKind, Scope, Series, Stream,
        SummarySpec, Temporality,
    };
    use schemars::generate::SchemaSettings;
    use std::num::NonZeroU64;

    #[test]
    fn fixed_rss_serializers_match_the_schema_for_every_metric_kind() {
        let scope = Scope::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            Id::new("mdm.telemetry").unwrap(),
        );
        let stream = Stream::new(
            scope.clone(),
            Id::new("agent.script").unwrap(),
            Id::new("epoch").unwrap(),
        );
        let cases = [
            (
                Metric::Gauge {
                    number: NumberKind::I64,
                },
                None,
            ),
            (
                Metric::Gauge {
                    number: NumberKind::U64,
                },
                None,
            ),
            (
                Metric::Gauge {
                    number: NumberKind::F64,
                },
                None,
            ),
            (
                Metric::Counter {
                    number: NumberKind::I64,
                    temporality: Temporality::Cumulative,
                },
                NonZeroU64::new(10),
            ),
            (
                Metric::Counter {
                    number: NumberKind::U64,
                    temporality: Temporality::Delta,
                },
                NonZeroU64::new(10),
            ),
            (Metric::Bool, None),
            (
                Metric::State {
                    members: [Id::new("on").unwrap()].into(),
                },
                None,
            ),
        ];
        let mut output = SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator();
        let output_schema = summary(&mut output).to_value();
        let output_validator = jsonschema::validator_for(&output_schema).unwrap();
        for (metric, max_gap) in cases {
            let definition = Definition::new(DefinitionSpec {
                scope: scope.clone(),
                key: Id::new("cpu").unwrap(),
                version: 1,
                unit: Id::new("count").unwrap(),
                metric,
                dimensions: DimensionRules {
                    allowed: Default::default(),
                    required: Default::default(),
                    max_count: 0,
                    max_value_bytes: 1,
                    max_total_bytes: 1,
                },
            })
            .unwrap();
            let series = Series::new(
                definition,
                Id::new("device").unwrap(),
                Id::new("resource").unwrap(),
                Default::default(),
            )
            .unwrap();
            let spec = SummarySpec::new(
                stream.clone(),
                series,
                NonZeroU64::new(10).unwrap(),
                CoveragePolicy::ObservedOnly,
                max_gap,
            )
            .unwrap();
            let value = serde_json::to_value(spec).unwrap();
            assert!(output_validator.is_valid(&value), "{value}");
            serde_json::from_value::<SummarySpec>(value.clone()).unwrap();
            let mut unknown = value.clone();
            unknown["series"]["definition"]["metric"]["kind"] = "future".into();
            assert!(!output_validator.is_valid(&unknown));
            assert!(serde_json::from_value::<SummarySpec>(unknown).is_err());
            if max_gap.is_none() {
                let mut omitted = value;
                omitted.as_object_mut().unwrap().remove("maxGap");
                assert!(!output_validator.is_valid(&omitted));
                let input_schema = summary(
                    &mut SchemaSettings::draft2020_12()
                        .for_deserialize()
                        .into_generator(),
                )
                .to_value();
                assert!(
                    jsonschema::validator_for(&input_schema)
                        .unwrap()
                        .is_valid(&omitted)
                );
                serde_json::from_value::<SummarySpec>(omitted).unwrap();
            }
        }
    }
}

pub(crate) fn opaque_id(_: &mut SchemaGenerator) -> Schema {
    Schema::try_from(id()).expect("RSS ID schema")
}
pub(crate) fn maintenance_block(_: &mut SchemaGenerator) -> Schema {
    use rss_timeseries::MaintenanceBlock::*;
    let values = [
        PendingWrite,
        Cutoff,
        DirtySummary,
        RestoreWindow,
        ReplayGuarantee,
        StreamOpen,
        RetainedData,
    ]
    .map(|reason| match reason {
        PendingWrite | Cutoff | DirtySummary | RestoreWindow | ReplayGuarantee | StreamOpen
        | RetainedData => serde_json::to_value(reason).expect("RSS maintenance block"),
    });
    schemars::json_schema!({"type":"string","enum":values})
}

fn timestamp() -> Value {
    json!({"type":"integer","format":"int64","minimum":0,"maximum":i64::MAX})
}
pub(crate) fn interval(_: &mut SchemaGenerator) -> Schema {
    object(&[("start", timestamp()), ("end", timestamp())])
        .try_into()
        .expect("interval schema")
}
fn external_variant(name: &str, value: Value) -> Value {
    object(&[(name, value)])
}
fn numeric(generator: &mut SchemaGenerator) -> Value {
    let variants = [
        ("i64", generator.subschema_for::<i64>().to_value()),
        ("u64", generator.subschema_for::<u64>().to_value()),
        ("f64", generator.subschema_for::<f64>().to_value()),
    ]
    .into_iter()
    .map(|(name, value)| object(&[("type", json!({"const":name})), ("value", value)]))
    .collect::<Vec<_>>();
    json!({"oneOf":variants})
}
pub(crate) fn sample(generator: &mut SchemaGenerator) -> Schema {
    let values = json!({"oneOf":[
        object(&[("type",json!({"const":"number"})),("value",numeric(generator))]),
        object(&[("type",json!({"const":"bool"})),("value",json!({"type":"boolean"}))]),
        object(&[("type",json!({"const":"state"})),("value",id())])
    ]});
    let reading = json!({"oneOf":[object(&[("quality",json!({"const":"valid"})),("value",values)]),object(&[("quality",json!({"const":"missing"}))]),object(&[("quality",json!({"const":"failed"}))])]});
    let mut value = object(&[
        ("stream", stream(generator).to_value()),
        ("series", series(generator).to_value()),
        ("id", id()),
        ("sequence", generator.subschema_for::<u64>().to_value()),
        ("observedAt", timestamp()),
        (
            "interval",
            json!({"anyOf":[interval(generator),{"type":"null"}]}),
        ),
        ("reading", reading),
    ]);
    if generator.contract().is_deserialize() {
        value["required"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v != "interval");
    }
    value.try_into().expect("sample schema")
}
pub(crate) fn selection(generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"oneOf":[
        object(&[("selection",json!({"const":"exact"})),("stream",stream(generator).to_value()),("series",series(generator).to_value())]),
        object(&[("selection",json!({"const":"resource"})),("scope",scope()),("subject",id()),("resource",id()),("keys",json!({"type":"array","items":id(),"uniqueItems":true}))])
    ]})
}
pub(crate) fn aggregate_buckets(generator: &mut SchemaGenerator) -> Schema {
    let sum = json!({"oneOf":[external_variant("I128",generator.subschema_for::<i128>().to_value()),external_variant("U128",generator.subschema_for::<u128>().to_value()),external_variant("F64",generator.subschema_for::<f64>().to_value())]});
    let state = json!({"oneOf":[external_variant("Bool",json!({"type":"boolean"})),external_variant("State",id())]});
    let array = |value: Value| json!({"type":"array","items":value});
    let value = json!({"oneOf":[
        external_variant("Number",numeric(generator)),external_variant("Sum",sum.clone()),external_variant("Count",generator.subschema_for::<u64>().to_value()),
        external_variant("Mean",object(&[("sum",sum.clone()),("count",positive())])),
        external_variant("Rate",object(&[("increase",sum),("duration_micros",positive())])),
        external_variant("StateSegments",array(object(&[("value",state.clone()),("window",interval(generator).to_value())]))),
        external_variant("Transitions",array(object(&[("at",timestamp()),("from",state.clone()),("to",state.clone())]))),
        external_variant("StateCoverage",array(object(&[("value",state),("micros",generator.subschema_for::<u64>().to_value())]))),
        {"type":"string","const":"Missing"}
    ]});
    use rss_timeseries::Completeness;
    let completeness = json!({"type":"array","uniqueItems":true,"items":{"type":"string","enum":[Completeness::Gaps,Completeness::Overlap,Completeness::ResetBoundary,Completeness::Boundary]}});
    array(object(&[
        ("window", interval(generator).to_value()),
        ("value", value),
        ("valid_samples", generator.subschema_for::<u64>().to_value()),
        (
            "covered_micros",
            generator.subschema_for::<u64>().to_value(),
        ),
        ("completeness", completeness),
    ]))
    .try_into()
    .expect("aggregate schema")
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use rss_timeseries::{
        AggregateBucket, AggregateValue as A, Completeness, FiniteF64, Interval, Number,
        StateDuration, StateSegment, StateValue, Sum, Timestamp, Transition,
    };
    use std::num::NonZeroU64;
    fn window() -> Interval {
        Interval::new(Timestamp::new(1).unwrap(), Timestamp::new(10).unwrap()).unwrap()
    }
    fn bucket(value: A) -> AggregateBucket {
        AggregateBucket {
            window: window(),
            value,
            valid_samples: 2,
            covered_micros: 9,
            completeness: [
                Completeness::Gaps,
                Completeness::Overlap,
                Completeness::ResetBoundary,
                Completeness::Boundary,
            ]
            .into(),
        }
    }
    #[test]
    fn aggregate_serializer_matches_every_actual_variant_and_rejects_unknown_core() {
        let mut generator = schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator();
        let schema = aggregate_buckets(&mut generator).to_value();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let state = StateValue::State(rss_timeseries::Id::new("ready").unwrap());
        for value in [
            A::Number(Number::I64(i64::MIN)),
            A::Number(Number::U64(u64::MAX)),
            A::Number(Number::F64(FiniteF64::new(0.5).unwrap())),
            A::Sum(Sum::I128(-1)),
            A::Sum(Sum::U128(1)),
            A::Sum(Sum::F64(FiniteF64::new(0.25).unwrap())),
            A::Count(0),
            A::Mean {
                sum: Sum::I128(9),
                count: NonZeroU64::new(2).unwrap(),
            },
            A::Rate {
                increase: Sum::U128(9),
                duration_micros: NonZeroU64::new(10).unwrap(),
            },
            A::StateSegments(vec![StateSegment {
                value: state.clone(),
                window: window(),
            }]),
            A::Transitions(vec![Transition {
                at: Timestamp::new(5).unwrap(),
                from: StateValue::Bool(false),
                to: StateValue::Bool(true),
            }]),
            A::StateCoverage(vec![StateDuration {
                value: state,
                micros: 9,
            }]),
            A::Missing,
        ] {
            let value = serde_json::to_value(vec![bucket(value)]).unwrap();
            assert!(validator.is_valid(&value), "{value}");
            let mut unknown = value.clone();
            unknown[0]["value"] = json!({"Future":{}});
            assert!(!validator.is_valid(&unknown));
            let mut missing = value;
            missing[0].as_object_mut().unwrap().remove("covered_micros");
            assert!(!validator.is_valid(&missing));
        }
    }
    #[test]
    fn aggregate_http_payload_serializes_128_bit_totals_without_a_value_intermediate() {
        for value in [Sum::I128(i128::MIN), Sum::U128(u128::MAX)] {
            let payload = crate::query::Aggregate {
                buckets: vec![bucket(A::Sum(value))],
                unavailable: vec![],
                resolution_micros: NonZeroU64::new(10).unwrap(),
                refreshed_through: None,
                next: None,
            };
            let encoded = serde_json::to_string(&payload).unwrap();
            let exact = match value {
                Sum::I128(v) => v.to_string(),
                Sum::U128(v) => v.to_string(),
                _ => unreachable!(),
            };
            assert!(encoded.contains(&format!(":{exact}}}")), "{encoded}");
        }
    }
}
