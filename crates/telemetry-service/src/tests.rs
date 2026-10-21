use super::*;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_inventory as d;
use rss_mdm_resource::*;
use rss_timeseries::{Id, Scope, Stream};
pub(super) fn fields() -> Vec<d::FieldDefinition> {
    vec![d::FieldDefinition {
        key: d::FieldKey::parse("custom.load").unwrap(),
        version: 1,
        value_type: d::ValueType::Integer,
        nullable: false,
        manual: false,
        sources: [(d::Source::AgentNative, 0)].into(),
        platforms: [d::Platform::Windows].into(),
        sensitivity: d::Sensitivity::Standard,
        unit: Some("percent".into()),
        searchable: true,
        item_key: None,
        time_series: Some(d::TimeSeriesBinding {
            kind: d::TelemetryKind::Gauge,
            value_path: vec![],
            interval_start_path: None,
            dimensions: Default::default(),
            aggregations: [d::TelemetryAggregation::Mean].into(),
            retention: d::RetentionReference {
                key: "standard".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    }]
}
pub(super) fn references(fields: &[d::FieldDefinition]) -> Vec<TelemetryFieldReference> {
    fields
        .iter()
        .map(|f| TelemetryFieldReference {
            key: f.key.as_str().into(),
            version: f.version,
        })
        .collect()
}
pub(super) fn profile(projection: TelemetryProjection) -> TelemetryProfile {
    TelemetryProfile::new(TelemetryProfileSpec {
        parameters: Default::default(),
        template: TelemetryTemplate {
            resource: "collector".into(),
            version: "one".into(),
            variant: "windows".into(),
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
        },
        fields: references(&fields()),
        projection,
        sample_millis: 1000,
        upload_millis: 10000,
        budget: TelemetryBudget {
            points: 64,
            bytes: 65536,
            resources: 1,
            execution_millis: 100,
            output_bytes: 4096,
        },
        boost: None,
        backfill_seconds: 3600,
        metadata: Default::default(),
    })
    .unwrap()
}
pub(super) fn input() -> w::TelemetryUpload {
    w::TelemetryUpload {
        binding: "a".repeat(64),
        batch_id: uuid::Uuid::new_v4(),
        policy: uuid::Uuid::new_v4(),
        policy_version: uuid::Uuid::new_v4(),
        observations: vec![w::TelemetryObservation {
            id: uuid::Uuid::new_v4(),
            sequence: 3,
            observed_at: 2_000_000,
            values: [(
                w::FieldKey::parse("custom.load").unwrap(),
                w::TelemetryReading::Valid {
                    value: w::Scalar::Integer(9007199254740993),
                    interval_start: None,
                },
            )]
            .into(),
        }],
    }
}
fn stream() -> Stream {
    Stream::new(
        Scope::new(
            TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            Id::new("mdm.telemetry").unwrap(),
        ),
        Id::new("registration:agent.native").unwrap(),
        Id::new("epoch").unwrap(),
    )
}
#[test]
fn replay_keeps_sample_identity_and_large_integer_exact_across_batch_ids() {
    let definitions = fields();
    let profile = profile(TelemetryProjection::History);
    let first = input();
    let a = samples::prepare(
        &profile,
        &definitions,
        &first,
        stream(),
        "device",
        3_000_000,
    )
    .unwrap()
    .unwrap();
    let mut second = first.clone();
    second.batch_id = uuid::Uuid::new_v4();
    let b = samples::prepare(
        &profile,
        &definitions,
        &second,
        stream(),
        "device",
        4_000_000,
    )
    .unwrap()
    .unwrap();
    assert_eq!(a.samples(), b.samples());
    assert_ne!(a.id(), b.id());
    assert_eq!(
        a.samples()[0].input().reading,
        rss_timeseries::Reading::Valid(rss_timeseries::Value::Number(rss_timeseries::Number::I64(
            9007199254740993
        )))
    );
    assert_eq!(a.samples()[0].input().observed_at.micros(), 2_000_000);
}
#[test]
fn three_destinations_validate_input_and_do_not_turn_failure_into_zero() {
    for mode in [
        TelemetryProjection::Current,
        TelemetryProjection::History,
        TelemetryProjection::Both,
    ] {
        let definitions = fields();
        let profile = profile(mode);
        let mut point = input();
        point.observations[0].values.values_mut().for_each(|v| {
            *v = w::TelemetryReading::Failed {
                interval_start: None,
                context: None,
            }
        });
        let batch = samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000,
        )
        .unwrap();
        if mode == TelemetryProjection::Current {
            assert!(batch.is_none());
        } else {
            assert_eq!(
                batch.unwrap().samples()[0].input().reading,
                rss_timeseries::Reading::Failed
            );
        }
        point.observations[0].observed_at = 4_000_000;
        assert!(matches!(
            samples::prepare(
                &profile,
                &definitions,
                &point,
                stream(),
                "device",
                3_000_000
            ),
            Err(crate::Error::Invalid)
        ));
    }
}
#[test]
fn unknown_fields_and_expired_backfill_fail_before_durable_admission() {
    let definitions = fields();
    let profile = profile(TelemetryProjection::Both);
    let mut point = input();
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            4_000_000_000
        )
        .is_err()
    );
    point.observations[0].values.insert(
        w::FieldKey::parse("custom.unknown").unwrap(),
        w::TelemetryReading::Missing {
            interval_start: None,
            context: None,
        },
    );
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000
        )
        .is_err()
    );
}
#[test]
fn counter_requires_explicit_nonnegative_interval_and_reset_boundary() {
    let mut definitions = fields();
    let mut spec = profile(TelemetryProjection::History).spec().clone();
    let binding = definitions[0].time_series.as_mut().unwrap();
    binding.kind = d::TelemetryKind::CumulativeCounter;
    binding.aggregations = [d::TelemetryAggregation::Rate].into();
    spec.fields = references(&definitions);
    failed_current_needs_no_historical_context(&definitions, &spec);
    let profile = TelemetryProfile::new(spec).unwrap();
    let mut point = input();
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000
        )
        .is_err()
    );
    for reading in point.observations[0].values.values_mut() {
        if let w::TelemetryReading::Valid { interval_start, .. } = reading {
            *interval_start = Some(1_000_000);
        }
    }
    let batch = samples::prepare(
        &profile,
        &definitions,
        &point,
        stream(),
        "device",
        3_000_000,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        batch.samples()[0].input().interval.unwrap().width_micros(),
        1_000_000
    );
    point.observations[0].values.values_mut().for_each(|v| {
        *v = w::TelemetryReading::Valid {
            value: w::Scalar::Integer(-1),
            interval_start: Some(1_000_000),
        }
    });
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000
        )
        .is_err()
    );
}

#[test]
fn independent_counters_keep_each_fields_reset_and_missing_does_not_invent_interval() {
    let mut definitions = fields();
    let mut spec = profile(TelemetryProjection::History).spec().clone();
    let binding = definitions[0].time_series.as_mut().unwrap();
    binding.kind = d::TelemetryKind::CumulativeCounter;
    binding.aggregations = [d::TelemetryAggregation::Rate].into();
    let mut other = definitions[0].clone();
    other.key = d::FieldKey::parse("custom.other").unwrap();
    definitions.push(other);
    spec.budget.resources = 2;
    spec.fields = references(&definitions);
    let profile = TelemetryProfile::new(spec).unwrap();
    let mut point = input();
    point.observations[0].values.insert(
        w::FieldKey::parse("custom.load").unwrap(),
        w::TelemetryReading::Valid {
            value: w::Scalar::Integer(10),
            interval_start: Some(500_000),
        },
    );
    point.observations[0].values.insert(
        w::FieldKey::parse("custom.other").unwrap(),
        w::TelemetryReading::Valid {
            value: w::Scalar::Integer(2),
            interval_start: Some(1_500_000),
        },
    );
    let batch = samples::prepare(
        &profile,
        &definitions,
        &point,
        stream(),
        "device",
        3_000_000,
    )
    .unwrap()
    .unwrap();
    let intervals: std::collections::BTreeMap<_, _> = batch
        .samples()
        .iter()
        .map(|v| {
            (
                v.input().series.definition().spec().key.as_str(),
                v.input().interval.unwrap().start().micros(),
            )
        })
        .collect();
    assert_eq!(intervals["custom.load"], 500_000);
    assert_eq!(intervals["custom.other"], 1_500_000);
    point.observations[0].values.values_mut().for_each(|v| {
        *v = w::TelemetryReading::Failed {
            interval_start: None,
            context: None,
        }
    });
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000
        )
        .is_err()
    );
    for reading in point.observations[0].values.values_mut() {
        *reading = w::TelemetryReading::Failed {
            interval_start: Some(500_000),
            context: None,
        };
    }
    let failures = samples::prepare(
        &profile,
        &definitions,
        &point,
        stream(),
        "device",
        3_000_000,
    )
    .unwrap()
    .unwrap();
    assert_eq!(failures.samples().len(), 2);
    assert!(
        failures
            .samples()
            .iter()
            .all(|s| s.input().reading == rss_timeseries::Reading::Failed)
    );
}

#[test]
fn array_counters_use_declared_per_resource_reset_paths() {
    let mut definitions = fields();
    let mut spec = profile(TelemetryProjection::History).spec().clone();
    let field = &mut definitions[0];
    field.value_type = d::ValueType::Array {
        items: Box::new(d::ValueType::Object {
            properties: [
                (
                    "key".into(),
                    d::ValueType::String {
                        max_length: 16,
                        allow_empty: false,
                    },
                ),
                ("count".into(), d::ValueType::Integer),
                ("reset".into(), d::ValueType::Integer),
            ]
            .into(),
        }),
        max_items: 2,
    };
    field.item_key = Some("key".into());
    let binding = field.time_series.as_mut().unwrap();
    binding.kind = d::TelemetryKind::CumulativeCounter;
    binding.aggregations = [d::TelemetryAggregation::Rate].into();
    binding.value_path = vec!["count".into()];
    binding.interval_start_path = Some(vec!["reset".into()]);
    binding.max_resources = 2;
    spec.budget.resources = 2;
    spec.fields = references(&definitions);
    failed_current_needs_no_historical_context(&definitions, &spec);
    let profile = TelemetryProfile::new(spec).unwrap();
    let mut point = input();
    let item = |key: &str, reset| {
        w::Scalar::Object(
            [
                ("key".into(), w::Scalar::String(key.into())),
                ("count".into(), w::Scalar::Integer(9)),
                ("reset".into(), w::Scalar::Integer(reset)),
            ]
            .into(),
        )
    };
    point.observations[0].values.insert(
        w::FieldKey::parse("custom.load").unwrap(),
        w::TelemetryReading::Valid {
            value: w::Scalar::Array(vec![item("a", 500_000), item("b", 1_500_000)]),
            interval_start: None,
        },
    );
    let batch = samples::prepare(
        &profile,
        &definitions,
        &point,
        stream(),
        "device",
        3_000_000,
    )
    .unwrap()
    .unwrap();
    let starts: std::collections::BTreeSet<_> = batch
        .samples()
        .iter()
        .map(|v| v.input().interval.unwrap().start().micros())
        .collect();
    assert_eq!(starts, [500_000, 1_500_000].into());
    assert_ne!(
        batch.samples()[0].input().series.resource(),
        batch.samples()[1].input().series.resource()
    );
    point.observations[0].values.insert(
        w::FieldKey::parse("custom.load").unwrap(),
        w::TelemetryReading::Valid {
            value: w::Scalar::Array(vec![item("a", 2_500_000)]),
            interval_start: None,
        },
    );
    assert!(
        samples::prepare(
            &profile,
            &definitions,
            &point,
            stream(),
            "device",
            3_000_000
        )
        .is_err()
    );
}

#[test]
fn current_destination_encoding_is_bounded_even_when_the_wire_body_fits() {
    let mut definitions = fields();
    let mut spec = profile(TelemetryProjection::Current).spec().clone();
    let seed = definitions[0].clone();
    definitions = (0..32)
        .map(|index| {
            let mut field = seed.clone();
            field.key = d::FieldKey::parse(&format!("custom.large_{index}")).unwrap();
            field.value_type = d::ValueType::String {
                max_length: 65536,
                allow_empty: false,
            };
            field.unit = None;
            field.time_series = None;
            field
        })
        .collect();
    spec.budget.resources = 32;
    spec.budget.bytes = 4 * 1024 * 1024;
    spec.budget.output_bytes = 4 * 1024 * 1024;
    spec.fields = references(&definitions);
    let profile = TelemetryProfile::new(spec).unwrap();
    let mut point = input();
    point.observations[0].values = profile
        .spec()
        .fields
        .iter()
        .map(|f| {
            (
                w::FieldKey::parse(f.key.as_str()).unwrap(),
                w::TelemetryReading::Valid {
                    value: w::Scalar::String("a".repeat(50_000)),
                    interval_start: None,
                },
            )
        })
        .collect();
    assert!(serde_json::to_vec(&point).unwrap().len() < 4 * 1024 * 1024);
    let mut accepted = crate::admission::Accepted {
        tenant: "11111111-1111-4111-8111-111111111111".into(),
        device: "device".into(),
        registration: uuid::Uuid::new_v4(),
        credential: uuid::Uuid::new_v4(),
        generation: 1,
        source: rss_mdm_inventory::Source::AgentNative,
        epoch: uuid::Uuid::new_v4(),
        received_at: 3_000_000,
        profile,
        fields: definitions,
        input: point,
    };
    assert!(accepted.history().unwrap().is_none());
    assert!(crate::current::prepare(&accepted).is_err());
    let mut smaller = accepted.profile.spec().clone();
    smaller.fields.truncate(16);
    accepted.fields.truncate(16);
    accepted.input.observations[0].values.retain(|key, _| {
        smaller
            .fields
            .iter()
            .any(|f| f.key.as_str() == key.as_str())
    });
    accepted.profile = TelemetryProfile::new(smaller).unwrap();
    assert_eq!(crate::current::prepare(&accepted).unwrap().1.len(), 1);
}

#[test]
fn query_recovery_errors_remain_client_actionable() {
    use crate::Error;
    use rss_timeseries::Error as Backend;
    assert!(matches!(
        Error::from(Backend::InvalidCursor),
        Error::Invalid
    ));
    assert!(matches!(
        Error::from(Backend::HistoryExpired),
        Error::Conflict
    ));
    assert!(matches!(
        Error::from(Backend::Unsupported),
        Error::Unsupported
    ));
    assert!(matches!(Error::from(Backend::Unauthorized), Error::Denied));
    assert!(matches!(Error::from(Backend::Unavailable), Error::Storage));
}

// The same conversion serves admission and delivery; verify both projections at that owner.
fn failed_current_needs_no_historical_context(
    definitions: &[d::FieldDefinition],
    spec: &TelemetryProfileSpec,
) {
    for mode in [
        TelemetryProjection::Current,
        TelemetryProjection::History,
        TelemetryProjection::Both,
    ] {
        let mut spec = spec.clone();
        spec.projection = mode;
        let profile = TelemetryProfile::new(spec).unwrap();
        let mut point = input();
        for value in point.observations[0].values.values_mut() {
            *value = w::TelemetryReading::Failed {
                interval_start: None,
                context: None,
            };
        }
        let accepted = crate::admission::Accepted {
            tenant: "11111111-1111-4111-8111-111111111111".into(),
            device: "device".into(),
            registration: uuid::Uuid::new_v4(),
            credential: uuid::Uuid::new_v4(),
            generation: 1,
            source: d::Source::AgentNative,
            epoch: uuid::Uuid::new_v4(),
            received_at: 3_000_000,
            profile,
            fields: definitions.to_vec(),
            input: point,
        };
        if mode == TelemetryProjection::Current {
            assert!(accepted.history().unwrap().is_none());
            let (_, batches) = crate::current::prepare(&accepted).unwrap();
            assert!(matches!(
                batches[0].body(),
                rss_observation::Body::Failed { .. }
            ));
            let mut invalid = accepted;
            invalid.input.observations[0].observed_at = 4_000_000;
            assert!(invalid.history().is_err());
            invalid.input.observations[0].observed_at = 2_000_000;
            invalid.input.observations[0]
                .values
                .values_mut()
                .for_each(|v| {
                    *v = w::TelemetryReading::Valid {
                        value: w::Scalar::Boolean(true),
                        interval_start: None,
                    }
                });
            assert!(invalid.history().is_err());
        } else {
            assert!(accepted.history().is_err());
        }
    }
}
