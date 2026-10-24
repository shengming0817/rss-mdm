use rss_mdm_inventory::*;
fn field() -> FieldDefinition {
    FieldDefinition {
        key: FieldKey::parse("custom.cpu.load").unwrap(),
        version: 1,
        value_type: ValueType::Integer,
        nullable: false,
        manual: false,
        sources: [(Source::AgentNative, 0)].into(),
        platforms: [Platform::Windows, Platform::Macos].into(),
        sensitivity: Sensitivity::Standard,
        unit: Some("percent".into()),
        searchable: true,
        item_key: None,
        time_series: Some(TimeSeriesBinding {
            kind: TelemetryKind::Gauge,
            value_path: vec![],
            interval_start_path: None,
            dimensions: Default::default(),
            aggregations: [TelemetryAggregation::Mean].into(),
            retention: RetentionReference {
                key: "standard".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    }
}
#[test]
fn catalog_binding_drives_public_rss_semantics_without_recompiling_metric_keys() {
    let field = field();
    field.validate().unwrap();
    let scope = rss_timeseries::Scope::new(
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        rss_timeseries::Id::new("mdm.telemetry").unwrap(),
    );
    let definition = field.time_series_definition(scope).unwrap();
    assert_eq!(definition.spec().key.as_str(), "custom.cpu.load");
    assert_eq!(definition.spec().unit.as_str(), "percent");
    assert_eq!(
        definition.spec().metric,
        rss_timeseries::Metric::Gauge {
            number: rss_timeseries::NumberKind::I64
        }
    );
    let mut wrong = field.clone();
    wrong.time_series.as_mut().unwrap().kind = TelemetryKind::State;
    assert!(wrong.validate().is_err());
    let mut manual = field;
    manual.sources = [(Source::Manual, 0)].into();
    manual.manual = true;
    assert!(manual.validate().is_err());
}
#[test]
fn counter_semantics_and_aggregate_permissions_cannot_be_reinterpreted() {
    let old = field();
    let mut new = old.clone();
    new.version = 2;
    new.time_series.as_mut().unwrap().kind = TelemetryKind::CumulativeCounter;
    assert!(new.validate().is_err());
    new.time_series.as_mut().unwrap().aggregations = [TelemetryAggregation::Rate].into();
    new.validate().unwrap();
    assert!(!new.time_series_extends(&old));
    let mut retained = old.clone();
    retained.version = 2;
    retained.time_series.as_mut().unwrap().retention.revision = 2;
    assert!(retained.time_series_extends(&old));
    retained.time_series = None;
    assert!(!retained.time_series_extends(&old));
}
#[test]
fn structured_metrics_require_stable_resource_keys_and_finite_dimensions() {
    let mut field = field();
    field.value_type = ValueType::Array {
        items: Box::new(ValueType::Object {
            properties: [
                (
                    "disk".into(),
                    ValueType::String {
                        max_length: 64,
                        allow_empty: false,
                    },
                ),
                ("used".into(), ValueType::Integer),
                (
                    "class".into(),
                    ValueType::Enum {
                        values: ["ssd".into(), "hdd".into()].into(),
                    },
                ),
            ]
            .into(),
        }),
        max_items: 16,
    };
    let binding = field.time_series.as_mut().unwrap();
    binding.value_path = vec!["used".into()];
    binding.max_resources = 16;
    binding.dimensions.insert(
        "class".into(),
        TelemetryDimension {
            path: vec!["class".into()],
            values: ["ssd".into(), "hdd".into()].into(),
        },
    );
    assert!(field.validate().is_err());
    field.item_key = Some("disk".into());
    field.validate().unwrap();
    field
        .time_series
        .as_mut()
        .unwrap()
        .dimensions
        .get_mut("class")
        .unwrap()
        .values
        .insert("unregistered".into());
    assert!(field.validate().is_err());
}

#[test]
fn retention_versions_bound_restore_and_summary_lifetimes_without_asset_ttl() {
    let mut policy = RetentionPolicy {
        key: "standard".into(),
        revision: 1,
        raw_seconds: 86400,
        summary_seconds: 604800,
        restore_seconds: 3600,
    };
    policy.validate().unwrap();
    policy.restore_seconds = 86401;
    assert!(policy.validate().is_err());
    policy.restore_seconds = 3600;
    policy.summary_seconds = 86399;
    assert!(policy.validate().is_err());
    policy.summary_seconds = 604800;
    policy.revision = 0;
    assert!(policy.validate().is_err());
}

#[test]
fn compatible_business_versions_widen_bounds_without_changing_scalar_kind() {
    let old = ValueType::Enum {
        values: ["up".into(), "down".into()].into(),
    };
    let new = ValueType::Enum {
        values: ["up".into(), "down".into(), "degraded".into()].into(),
    };
    assert!(new.extends(&old));
    assert!(!old.extends(&new));
    assert!(!ValueType::Number.extends(&ValueType::Integer));
    let old = ValueType::Record {
        properties: [(
            "reading".into(),
            Property {
                value_type: ValueType::Integer,
                required: true,
            },
        )]
        .into(),
    };
    let mut new = old.clone();
    if let ValueType::Record { properties } = &mut new {
        properties.insert(
            "label".into(),
            Property {
                value_type: ValueType::String {
                    max_length: 64,
                    allow_empty: false,
                },
                required: false,
            },
        );
    }
    assert!(new.extends(&old));
    assert!(!old.extends(&new));
}

#[test]
fn object_can_widen_to_optional_record_without_losing_old_values() {
    let old = ValueType::Object {
        properties: [("provisioned".into(), ValueType::Boolean)].into(),
    };
    let mut properties: std::collections::BTreeMap<String, Property> = [
        (
            "provisioned".into(),
            Property {
                value_type: ValueType::Boolean,
                required: false,
            },
        ),
        (
            "native".into(),
            Property {
                value_type: ValueType::Integer,
                required: false,
            },
        ),
    ]
    .into();
    let new = ValueType::Record {
        properties: properties.clone(),
    };
    assert!(new.extends(&old));
    assert!(
        new.decode_json(&serde_json::json!({"provisioned":true}))
            .is_ok()
    );
    assert!(new.decode_json(&serde_json::json!({"native":2})).is_ok());
    properties.get_mut("native").unwrap().required = true;
    assert!(!ValueType::Record { properties }.extends(&old));
    assert!(!old.extends(&new));
}
