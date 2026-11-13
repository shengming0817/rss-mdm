use super::*;
use serde_json::json;
use std::num::NonZeroU64;
fn schema(path: &str, request: bool) -> serde_json::Value {
    let doc = rss_mdm_http_contract::artifact::document([(
        "browser",
        super::super::routes(None).into_endpoints(),
    )])
    .unwrap();
    let endpoint = doc["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["path"] == path)
        .unwrap();
    let body = if request {
        &endpoint["request"]["body"]
    } else {
        &endpoint["responses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["status"] == 200)
            .unwrap()["body"]
    };
    doc["schemas"][body["schema"]["schemaId"].as_str().unwrap()].clone()
}
fn sample(number: ts::Number) -> ts::Sample {
    let scope = ts::Scope::new(
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        ts::Id::new("telemetry").unwrap(),
    );
    let definition = ts::Definition::new(ts::DefinitionSpec {
        scope: scope.clone(),
        key: ts::Id::new("metric").unwrap(),
        version: u64::MAX,
        unit: ts::Id::new("count").unwrap(),
        metric: ts::Metric::Gauge {
            number: number.kind(),
        },
        dimensions: ts::DimensionRules {
            allowed: Default::default(),
            required: Default::default(),
            max_count: 0,
            max_value_bytes: 1,
            max_total_bytes: 1,
        },
    })
    .unwrap();
    ts::Sample::new(ts::SampleInput {
        stream: ts::Stream::new(
            scope,
            ts::Id::new("source").unwrap(),
            ts::Id::new("generation").unwrap(),
        ),
        series: ts::Series::new(
            definition,
            ts::Id::new("device").unwrap(),
            ts::Id::new("resource").unwrap(),
            Default::default(),
        )
        .unwrap(),
        id: ts::Id::new("sample").unwrap(),
        sequence: u64::MAX,
        observed_at: ts::Timestamp::new(i64::MAX - 1).unwrap(),
        interval: None,
        reading: ts::Reading::Valid(ts::Value::Number(number)),
    })
    .unwrap()
}
#[test]
fn mounted_history_and_latest_project_integer_values_and_coordinates() {
    let validator = jsonschema::validator_for(&schema("/telemetry/history", false)).unwrap();
    for (number, expected) in [
        (ts::Number::I64(i64::MIN), json!(i64::MIN.to_string())),
        (ts::Number::U64(u64::MAX), json!(u64::MAX.to_string())),
        (
            ts::Number::F64(ts::FiniteF64::new(0.5).unwrap()),
            json!(0.5),
        ),
    ] {
        for latest in [false, true] {
            let response = if latest {
                service::History::Latest {
                    rows: vec![service::LatestRow {
                        sample: sample(number),
                        received_at: i64::MAX,
                        effective_source: true,
                        source_conflict: false,
                    }],
                    unavailable: vec![],
                    next: None,
                    retired: false,
                }
            } else {
                service::History::History {
                    rows: vec![service::HistoryRow {
                        sample: sample(number),
                        received_at: i64::MAX,
                        live_source: true,
                    }],
                    unavailable: vec![],
                    next: Some("cursor".into()),
                    retired: false,
                }
            };
            let value = serde_json::to_value(History::from(response)).unwrap();
            assert!(validator.is_valid(&value), "{value}");
            assert_eq!(
                value["rows"][0]["sample"]["reading"]["value"]["value"]["value"],
                expected
            );
            assert_eq!(value["rows"][0]["sample"]["sequence"], u64::MAX.to_string());
            assert_eq!(
                value["rows"][0]["sample"]["series"]["definition"]["version"],
                u64::MAX.to_string()
            );
            assert_eq!(value["rows"][0]["receivedAt"], i64::MAX.to_string());
            let mut bad = value.clone();
            bad["rows"][0]["sample"]["sequence"] = json!(1);
            assert!(!validator.is_valid(&bad));
            let mut bad = value;
            bad["rows"][0]["sample"]["reading"]["quality"] = json!("future");
            assert!(!validator.is_valid(&bad));
        }
    }
}
#[test]
fn all_aggregate_branches_preserve_statistics_and_string_boundaries() {
    let validator = jsonschema::validator_for(&schema("/telemetry/aggregate", false)).unwrap();
    let window = ts::Interval::new(
        ts::Timestamp::new(1).unwrap(),
        ts::Timestamp::new(i64::MAX).unwrap(),
    )
    .unwrap();
    let state = ts::StateValue::Bool(true);
    let n = NonZeroU64::new(u64::MAX).unwrap();
    for (value, expected) in [
        (
            ts::AggregateValue::Number(ts::Number::I64(i64::MIN)),
            json!({"Number":{"type":"i64","value":i64::MIN.to_string()}}),
        ),
        (
            ts::AggregateValue::Sum(ts::Sum::I128(i128::MIN)),
            json!({"Sum":{"I128":i128::MIN.to_string()}}),
        ),
        (
            ts::AggregateValue::Sum(ts::Sum::I128(i128::MAX)),
            json!({"Sum":{"I128":i128::MAX.to_string()}}),
        ),
        (
            ts::AggregateValue::Sum(ts::Sum::U128(u128::MAX)),
            json!({"Sum":{"U128":u128::MAX.to_string()}}),
        ),
        (
            ts::AggregateValue::Sum(ts::Sum::F64(ts::FiniteF64::new(0.5).unwrap())),
            json!({"Sum":{"F64":0.5}}),
        ),
        (
            ts::AggregateValue::Count(u64::MAX),
            json!({"Count":u64::MAX.to_string()}),
        ),
        (
            ts::AggregateValue::Mean {
                sum: ts::Sum::I128(i128::MIN),
                count: n,
            },
            json!({"Mean":{"sum":{"I128":i128::MIN.to_string()},"count":u64::MAX.to_string()}}),
        ),
        (
            ts::AggregateValue::Rate {
                increase: ts::Sum::U128(u128::MAX),
                duration_micros: n,
            },
            json!({"Rate":{"increase":{"U128":u128::MAX.to_string()},"duration_micros":u64::MAX.to_string()}}),
        ),
        (
            ts::AggregateValue::StateSegments(vec![ts::StateSegment {
                value: state.clone(),
                window,
            }]),
            json!({"StateSegments":[{"value":{"Bool":true},"window":{"start":"1","end":i64::MAX.to_string()}}]}),
        ),
        (
            ts::AggregateValue::Transitions(vec![ts::Transition {
                at: window.end(),
                from: state.clone(),
                to: state.clone(),
            }]),
            json!({"Transitions":[{"at":i64::MAX.to_string(),"from":{"Bool":true},"to":{"Bool":true}}]}),
        ),
        (
            ts::AggregateValue::StateCoverage(vec![ts::StateDuration {
                value: state,
                micros: u64::MAX,
            }]),
            json!({"StateCoverage":[{"value":{"Bool":true},"micros":u64::MAX.to_string()}]}),
        ),
        (ts::AggregateValue::Missing, json!("Missing")),
    ] {
        let response = service::Aggregate {
            buckets: vec![ts::AggregateBucket {
                window,
                value,
                valid_samples: u64::MAX,
                covered_micros: u64::MAX,
                completeness: [ts::Completeness::Boundary].into(),
            }],
            unavailable: vec![service::Unavailable {
                selection: ts::Selection::Exact {
                    stream: sample(ts::Number::I64(0)).input().stream.clone(),
                    series: sample(ts::Number::I64(0)).input().series.clone(),
                },
                window,
                reason: service::UnavailableCause::Pruned,
            }],
            resolution_micros: n,
            refreshed_through: Some(i64::MAX),
            next: None,
        };
        let value = serde_json::to_value(Aggregate::from(response)).unwrap();
        assert!(validator.is_valid(&value), "{value}");
        assert_eq!(value["buckets"][0]["value"], expected);
        assert_eq!(value["buckets"][0]["valid_samples"], u64::MAX.to_string());
        assert_eq!(value["buckets"][0]["covered_micros"], u64::MAX.to_string());
        assert_eq!(
            value["unavailable"][0]["selection"]["series"]["definition"]["version"],
            u64::MAX.to_string()
        );
        assert_eq!(value["resolutionMicros"], u64::MAX.to_string());
        assert_eq!(value["refreshedThrough"], i64::MAX.to_string());
    }
}
#[test]
fn mounted_requests_require_canonical_strings_including_nested_coverage() {
    let value = json!({"device":"11111111-2222-4333-8444-555555555555","field":"field","resource":"device","startMicros":"0","endMicros":i64::MAX.to_string(),"maxPoints":10,"mode":"history"});
    let request: service::HistoryRequest = serde_json::from_value::<HistoryRequest>(value.clone())
        .unwrap()
        .into();
    assert_eq!(request.end_micros, i64::MAX);
    let h = jsonschema::validator_for(&schema("/telemetry/history", true)).unwrap();
    assert!(h.is_valid(&value));
    let value = json!({"query":value,"definitionVersion":u64::MAX.to_string(),"source":rss_mdm_inventory::Source::AgentNative,"epoch":"11111111-1111-4111-8111-111111111111","dimensions":{},"resolutionMicros":"1","operation":"mean","coverage":{"coverage":"holdLast","maxHoldMicros":u64::MAX.to_string()},"maxGapMicros":"2"});
    let a = jsonschema::validator_for(&schema("/telemetry/aggregate", true)).unwrap();
    assert!(a.is_valid(&value));
    let request: service::AggregateRequest =
        serde_json::from_value::<AggregateRequest>(value.clone())
            .unwrap()
            .into();
    assert_eq!(request.definition_version.get(), u64::MAX);
    assert_eq!(
        request.coverage,
        ts::CoveragePolicy::HoldLast(NonZeroU64::new(u64::MAX).unwrap())
    );
    for pointer in [
        "/query/startMicros",
        "/definitionVersion",
        "/resolutionMicros",
        "/coverage/maxHoldMicros",
        "/maxGapMicros",
    ] {
        for invalid in [json!(1), json!("01"), json!("18446744073709551616")] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = invalid;
            assert!(serde_json::from_value::<AggregateRequest>(bad.clone()).is_err());
            assert!(!a.is_valid(&bad), "{bad}");
        }
    }
}
