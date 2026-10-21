//! Native performance publication and endpoint capability negotiation use the real product seam.
use super::*;

pub(super) async fn published_cpu(f: &mut Fixture) -> Result<()> {
    use rss_mdm_inventory as d;
    let field = d::FieldDefinition {
        key: d::FieldKey::parse("custom.performance.cpu")?,
        version: 1,
        value_type: d::ValueType::Number,
        nullable: false,
        manual: false,
        sources: [(d::Source::AgentNative, 0)].into(),
        platforms: [d::Platform::Macos].into(),
        sensitivity: d::Sensitivity::Standard,
        unit: Some("percent".into()),
        searchable: false,
        item_key: None,
        time_series: Some(d::TimeSeriesBinding {
            kind: d::TelemetryKind::Gauge,
            value_path: vec![],
            interval_start_path: None,
            dimensions: Default::default(),
            aggregations: [d::TelemetryAggregation::Mean].into(),
            retention: d::RetentionReference {
                key: "telemetry_test".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    };
    put(&mut f.author,&f.router,"/api/v1/asset-fields/custom.performance.cpu",json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":field}})).await?;
    let budget = wire::NativeBudget {
        timeout_seconds: 1,
        output_bytes: 4096,
        max_rows: 1,
    };
    let plan = wire::NativeCollectionPlan::new(wire::NativePlanSpec {
        version: 1,
        scope: rss_mdm_agent_wire::CollectionScope::Device,
        queries: [(
            "cpu".into(),
            wire::NativeQuery {
                version: 1,
                definition: wire::NativeQueryDefinition::MacosPerformance {
                    section: wire::PerformanceSection::Cpu,
                },
                cardinality: wire::NativeCardinality::ExactlyOne,
                instance_keys: vec![],
                budget,
            },
        )]
        .into(),
        budget,
    })?;
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
        applicability: Default::default(),
        plan: plan.clone(),
        mappings: [(
            field.key.as_str().into(),
            r::AgentCollectionMapping {
                query: "cpu".into(),
                mapping: r::ValueMapping {
                    pointer: "/busy_percent".into(),
                    conversion: r::Conversion::Identity,
                    columns: Default::default(),
                },
                missing: r::NativeMissing::Missing,
                counter_normalization: None,
            },
        )]
        .into(),
    })?;
    let template = Uuid::new_v4();
    publish(
        f,
        template,
        "agent_collection",
        serde_json::to_value(&definition)?,
        &definition.canonical(),
    )
    .await?;
    let profile = r::TelemetryProfile::new(r::TelemetryProfileSpec {
        template: r::TelemetryTemplate {
            resource: template.to_string(),
            version: "v1".into(),
            variant: "default".into(),
            platform: r::Platform::MacOS,
            architecture: r::Architecture::Aarch64,
        },
        parameters: Default::default(),
        fields: vec![r::TelemetryFieldReference {
            key: field.key.as_str().into(),
            version: 1,
        }],
        projection: r::TelemetryProjection::History,
        sample_millis: 5000,
        upload_millis: 10000,
        budget: r::TelemetryBudget {
            points: 4,
            bytes: 65536,
            resources: 1,
            execution_millis: 1000,
            output_bytes: 4096,
        },
        boost: None,
        backfill_seconds: 3600,
    })?;
    let profile_id = Uuid::new_v4();
    publish(
        f,
        profile_id,
        "telemetry_profile",
        serde_json::to_value(&profile)?,
        &profile.canonical(),
    )
    .await?;
    let scope = Uuid::new_v4();
    f.scope(scope, json!([{"kind":"device","id":case_device_id()}]))
        .await?;
    let policy = Uuid::new_v4();
    let policy = post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
    let path = format!(
        "/api/v1/agent/runtime/telemetry/configurations/{}/{}",
        policy["id"].as_str().unwrap(),
        policy["versionId"].as_str().unwrap()
    );
    directory(f, &policy, false).await?;
    let (status, _) =
        agent_call(&f.router, Method::GET, &path, Some(case_credential()), None).await?;
    ensure!(
        status == StatusCode::SERVICE_UNAVAILABLE,
        "missing native engine received executable configuration"
    );
    announce(f, json!({"macos.performance":1})).await?;
    directory(f, &policy, true).await?;
    let (status, signed) =
        agent_call(&f.router, Method::GET, &path, Some(case_credential()), None).await?;
    ensure!(
        status == StatusCode::OK,
        "native configuration: {status} {signed}"
    );
    let signed: wire::SignedTelemetryConfiguration = serde_json::from_value(signed)?;
    use base64::Engine;
    use ring::signature::KeyPair;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, f.key.public_key().as_ref())
        .verify(
            &signed.configuration.signing_bytes(&signed.key_id)?,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?,
        )
        .map_err(|_| anyhow::anyhow!("native configuration signature"))?;
    let config = signed.configuration;
    ensure!(matches!(config.source, wire::Source::AgentNative));
    let wire::TelemetryCollector::Native {
        plan: actual,
        mappings,
    } = &config.collector
    else {
        anyhow::bail!("native configuration downgraded to script")
    };
    ensure!(serde_json::to_value(actual)? == serde_json::to_value(&plan)? && mappings.len() == 1);
    let mapping = &mappings[field.key.as_str()];
    ensure!(
        mapping.query == "cpu"
            && mapping.mapping.pointer == "/busy_percent"
            && mapping.mapping.conversion == wire::TelemetryConversion::Identity
            && mapping.mapping.columns.is_empty()
    );
    let now = f.planning.clock.unix_seconds()? * 1_000_000;
    let batch = Uuid::new_v4();
    let body = json!({"batchId":batch,"policy":policy["id"],"policyVersion":policy["versionId"],"binding":config.binding,"observations":[{"id":Uuid::new_v4(),"sequence":1,"observedAt":now-1_000_000,"values":{"custom.performance.cpu":{"quality":"valid","value":{"kind":"number","value":25.5},"intervalStart":null}}}]});
    let (status, receipt) = agent_call(
        &f.router,
        Method::POST,
        "/api/v1/agent/runtime/telemetry/batches",
        Some(case_credential()),
        Some(body),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED,
        "native upload: {status} {receipt}"
    );
    published(
        &f.router,
        &format!("/api/v1/agent/runtime/telemetry/batches/{batch}"),
    )
    .await?;
    let history = post(&mut f.author,&f.router,"/api/v1/telemetry/history",json!({"device":case_device_id(),"field":field.key,"resource":"device","startMicros":now-2_000_000,"endMicros":now+1_000_000,"maxPoints":4,"mode":"history","after":null})).await?;
    ensure!(
        history["rows"].as_array().is_some_and(|v| v.len() == 1),
        "native history: {history}"
    );
    let sample: rss_timeseries::Sample =
        serde_json::from_value(history["rows"][0]["sample"].clone())?;
    ensure!(
        sample.input().reading
            == rss_timeseries::Reading::Valid(rss_timeseries::Value::Number(
                rss_timeseries::Number::F64(rss_timeseries::FiniteF64::new(25.5)?)
            )),
        "native reading changed"
    );
    published_network(f).await?;
    announce(f, json!({})).await?;
    Ok(())
}

async fn publish(
    f: &mut Fixture,
    id: Uuid,
    kind: &str,
    definition: Value,
    bytes: &[u8],
) -> Result<()> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    resource(
        &mut f.author,
        &f.router,
        id,
        0,
        json!({"action":"create","kind":kind}),
    )
    .await?;
    resource(&mut f.author,&f.router,id,1,json!({"action":"version","version":"v1","kind":kind,"variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":kind,"artifact":{"reference":"native-performance","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(upload(&f.author, &f.router, id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    Ok(())
}

async fn announce(f: &Fixture, engines: Value) -> Result<()> {
    let (status,result) = agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(json!({"wireVersion":1,"executionContext":software_execution::context(software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":engines},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(
        status == StatusCode::OK,
        "native engine announcement: {status} {result}"
    );
    Ok(())
}

async fn directory(f: &Fixture, policy: &Value, supported: bool) -> Result<()> {
    let (status, result) = agent_call(
        &f.router,
        Method::GET,
        "/api/v1/agent/runtime/telemetry/configurations",
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && result["assignments"]
                .as_array()
                .is_some_and(
                    |items| items.iter().any(|item| item["policy"] == policy["id"]
                        && item["version"] == policy["versionId"]
                        && item["supported"] == supported)
                ),
        "native capability directory: {status} {result}"
    );
    Ok(())
}

async fn published_network(f: &mut Fixture) -> Result<()> {
    use rss_mdm_inventory as d;
    let field = d::FieldDefinition {
        key: d::FieldKey::parse("custom.performance.network_received")?,
        version: 1,
        value_type: d::ValueType::Array {
            items: Box::new(d::ValueType::Object {
                properties: [
                    (
                        "id".into(),
                        d::ValueType::String {
                            max_length: 128,
                            allow_empty: false,
                        },
                    ),
                    ("received".into(), d::ValueType::Integer),
                    ("interval_start".into(), d::ValueType::Integer),
                ]
                .into(),
            }),
            max_items: 4,
        },
        nullable: false,
        manual: false,
        sources: [(d::Source::AgentNative, 0)].into(),
        platforms: [d::Platform::Macos].into(),
        sensitivity: d::Sensitivity::Standard,
        unit: Some("bytes".into()),
        searchable: false,
        item_key: Some("id".into()),
        time_series: Some(d::TimeSeriesBinding {
            kind: d::TelemetryKind::CumulativeCounter,
            value_path: vec!["received".into()],
            interval_start_path: Some(vec!["interval_start".into()]),
            dimensions: Default::default(),
            aggregations: [d::TelemetryAggregation::Increase].into(),
            retention: d::RetentionReference {
                key: "telemetry_test".into(),
                revision: 1,
            },
            max_resources: 4,
        }),
    };
    put(&mut f.author, &f.router, "/api/v1/asset-fields/custom.performance.network_received", json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":field}})).await?;
    let budget = wire::NativeBudget {
        timeout_seconds: 1,
        output_bytes: 4096,
        max_rows: 4,
    };
    let plan = wire::NativeCollectionPlan::new(wire::NativePlanSpec {
        version: 1,
        scope: rss_mdm_agent_wire::CollectionScope::Device,
        budget,
        queries: [(
            "network".into(),
            wire::NativeQuery {
                version: 1,
                definition: wire::NativeQueryDefinition::MacosPerformance {
                    section: wire::PerformanceSection::Network,
                },
                cardinality: wire::NativeCardinality::List,
                instance_keys: vec!["id".into()],
                budget,
            },
        )]
        .into(),
    })?;
    let column = |pointer: &str, conversion| r::ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    };
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
        applicability: Default::default(),
        plan,
        mappings: [(
            field.key.as_str().into(),
            r::AgentCollectionMapping {
                query: "network".into(),
                missing: r::NativeMissing::Missing,
                counter_normalization: Some(wire::NativeCounterNormalization::LocalCumulativeV1),
                mapping: r::ValueMapping {
                    pointer: String::new(),
                    conversion: r::Conversion::Identity,
                    columns: [
                        ("id".into(), column("/id", r::Conversion::Identity)),
                        (
                            "received".into(),
                            column("/received_bytes", r::Conversion::Integer),
                        ),
                    ]
                    .into(),
                },
            },
        )]
        .into(),
    })?;
    // The owner check must reject a marker on another metric kind or a generated path
    // that collides with the source key, before any executable configuration is issued.
    let mapping = &definition.spec().mappings[field.key.as_str()];
    rss_mdm_inventory_service::collection::native::validate_agent_mapping(
        &field,
        &definition,
        mapping,
    )?;
    let mut unmarked = mapping.clone();
    unmarked.counter_normalization = None;
    ensure!(
        rss_mdm_inventory_service::collection::native::validate_agent_mapping(
            &field,
            &definition,
            &unmarked
        )
        .is_err()
    );
    let mut invalid = field.clone();
    invalid.time_series.as_mut().unwrap().kind = d::TelemetryKind::Gauge;
    ensure!(
        rss_mdm_inventory_service::collection::native::validate_agent_mapping(
            &invalid,
            &definition,
            mapping
        )
        .is_err()
    );
    invalid = field.clone();
    invalid.time_series.as_mut().unwrap().interval_start_path = Some(vec!["received".into()]);
    ensure!(
        rss_mdm_inventory_service::collection::native::validate_agent_mapping(
            &invalid,
            &definition,
            mapping
        )
        .is_err()
    );
    let template = Uuid::new_v4();
    publish(
        f,
        template,
        "agent_collection",
        serde_json::to_value(&definition)?,
        &definition.canonical(),
    )
    .await?;
    let profile = r::TelemetryProfile::new(r::TelemetryProfileSpec {
        template: r::TelemetryTemplate {
            resource: template.to_string(),
            version: "v1".into(),
            variant: "default".into(),
            platform: r::Platform::MacOS,
            architecture: r::Architecture::Aarch64,
        },
        parameters: Default::default(),
        fields: vec![r::TelemetryFieldReference {
            key: field.key.as_str().into(),
            version: 1,
        }],
        projection: r::TelemetryProjection::History,
        sample_millis: 5000,
        upload_millis: 10000,
        budget: r::TelemetryBudget {
            points: 16,
            bytes: 65536,
            resources: 4,
            execution_millis: 1000,
            output_bytes: 4096,
        },
        boost: None,
        backfill_seconds: 3600,
    })?;
    let profile_id = Uuid::new_v4();
    publish(
        f,
        profile_id,
        "telemetry_profile",
        serde_json::to_value(&profile)?,
        &profile.canonical(),
    )
    .await?;
    let scope = Uuid::new_v4();
    f.scope(scope, json!([{"kind":"device","id":case_device_id()}]))
        .await?;
    let policy = post(&mut f.author, &f.router, &format!("/api/v1/policies/{}", Uuid::new_v4()), json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
    let path = format!(
        "/api/v1/agent/runtime/telemetry/configurations/{}/{}",
        policy["id"].as_str().unwrap(),
        policy["versionId"].as_str().unwrap()
    );
    // The CPU case already announced macos.performance:1. This refusal therefore
    // isolates the new capability, rather than a missing native engine.
    directory(f, &policy, false).await?;
    ensure!(
        agent_call(&f.router, Method::GET, &path, Some(case_credential()), None)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let tenant = case_tenant();
    let credential = case_credential();
    let original = pg(&format!(
        "SELECT b.capabilities FROM mdm_agent.bindings b JOIN mdm_access.credentials c ON c.tenant_id=b.tenant_id AND c.registration=b.registration WHERE c.tenant_id='{tenant}' AND c.locator='{credential}'"
    ))?;
    let mut capabilities: Vec<String> = serde_json::from_str(original.trim())?;
    capabilities.push("telemetry.counter.local.v1".into());
    let encoded = serde_json::to_string(&capabilities)?;
    pg(&format!(
        "UPDATE mdm_agent.bindings b SET capabilities='{encoded}' FROM mdm_access.credentials c WHERE c.tenant_id=b.tenant_id AND c.registration=b.registration AND c.tenant_id='{tenant}' AND c.locator='{credential}'"
    ))?;
    directory(f, &policy, true).await?;
    let (status, signed) =
        agent_call(&f.router, Method::GET, &path, Some(case_credential()), None).await?;
    ensure!(
        status == StatusCode::OK,
        "counter config: {status} {signed}"
    );
    let signed: wire::SignedTelemetryConfiguration = serde_json::from_value(signed)?;
    use base64::Engine;
    use ring::signature::KeyPair;
    let public = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        f.key.public_key().as_ref(),
    );
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?;
    public
        .verify(
            &signed.configuration.signing_bytes(&signed.key_id)?,
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("network signature"))?;
    let wire::TelemetryCollector::Native { mappings, .. } = &signed.configuration.collector else {
        anyhow::bail!("native collector missing")
    };
    ensure!(
        mappings[field.key.as_str()].counter_normalization
            == Some(wire::NativeCounterNormalization::LocalCumulativeV1)
    );
    let mut altered = signed.configuration.clone();
    if let wire::TelemetryCollector::Native { mappings, .. } = &mut altered.collector {
        mappings
            .get_mut(field.key.as_str())
            .unwrap()
            .counter_normalization = None;
    }
    match altered.signing_bytes(&signed.key_id) {
        Ok(bytes) => ensure!(
            public.verify(&bytes, &signature).is_err(),
            "normalization marker was not signed"
        ),
        Err(_) => {}
    }
    network_readings(f, &policy, &signed.configuration, &field).await?;
    pg(&format!(
        "UPDATE mdm_agent.bindings b SET capabilities='{}' FROM mdm_access.credentials c WHERE c.tenant_id=b.tenant_id AND c.registration=b.registration AND c.tenant_id='{tenant}' AND c.locator='{credential}'",
        original.trim()
    ))?;
    Ok(())
}

async fn network_readings(
    f: &mut Fixture,
    policy: &Value,
    config: &wire::TelemetryConfiguration,
    field: &rss_mdm_inventory::FieldDefinition,
) -> Result<()> {
    let now = f.planning.clock.unix_seconds()? * 1_000_000;
    let start = (now / 10_000_000 - 1) * 10_000_000;
    let interface = wire::Scalar::String("interface:stable-id".into());
    let resource = format!("item:{:x}", Sha256::digest(serde_json::to_vec(&interface)?));
    for (sequence, count) in [(1, None), (2, Some(10)), (3, Some(25))] {
        let item = json!({"kind":"object","value":{"id":interface,"interval_start":{"kind":"integer","value":start},"received":{"kind":"integer","value":count.unwrap_or(0)}}});
        let rows = json!({"kind":"array","value":[item]});
        let reading = match count {
            Some(_) => json!({"quality":"valid","value":rows,"intervalStart":null}),
            None => json!({"quality":"missing","context":rows,"intervalStart":null}),
        };
        let batch = Uuid::new_v4();
        let body = json!({"batchId":batch,"policy":policy["id"],"policyVersion":policy["versionId"],"binding":config.binding,"observations":[{"id":Uuid::new_v4(),"sequence":sequence,"observedAt":start+sequence*1_000_000,"values":{field.key.as_str():reading}}]});
        let (status, result) = agent_call(
            &f.router,
            Method::POST,
            "/api/v1/agent/runtime/telemetry/batches",
            Some(case_credential()),
            Some(body),
        )
        .await?;
        ensure!(
            status == StatusCode::ACCEPTED,
            "network readings: {status} {result}"
        );
        published(
            &f.router,
            &format!("/api/v1/agent/runtime/telemetry/batches/{batch}"),
        )
        .await?;
    }
    let query = json!({"device":case_device_id(),"field":field.key,"resource":resource,"startMicros":start,"endMicros":start+10_000_000,"maxPoints":4,"mode":"history","after":null});
    let history = post(
        &mut f.author,
        &f.router,
        "/api/v1/telemetry/history",
        query.clone(),
    )
    .await?;
    let rows = history["rows"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing history"))?;
    ensure!(rows.len() == 3, "network history: {history}");
    let samples = rows
        .iter()
        .map(|row| serde_json::from_value::<rss_timeseries::Sample>(row["sample"].clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(samples[0].input().reading == rss_timeseries::Reading::Missing);
    for (sample, count) in samples[1..].iter().zip([10, 25]) {
        ensure!(
            sample.input().reading
                == rss_timeseries::Reading::Valid(rss_timeseries::Value::Number(
                    rss_timeseries::Number::I64(count)
                ))
        );
        ensure!(
            sample
                .input()
                .interval
                .is_some_and(|interval| interval.start().micros() == start)
        );
    }
    let sample = &samples[1];
    let spec = rss_timeseries::SummarySpec::new(
        sample.input().stream.clone(),
        sample.input().series.clone(),
        std::num::NonZeroU64::new(10_000_000).unwrap(),
        rss_timeseries::CoveragePolicy::ObservedOnly,
        std::num::NonZeroU64::new(10_000_000),
    )?;
    settle(
        &mut f.author,
        &f.router,
        &rss_mdm_telemetry_service::maintenance::Request {
            id: Uuid::new_v4(),
            device: case_device_id().into(),
            field: field.key.as_str().into(),
            resource,
            start_micros: start,
            end_micros: start + 10_000_000,
            action: rss_mdm_telemetry_service::maintenance::Action::Recompute { spec },
        },
    )
    .await?;
    let aggregate = post(&mut f.author, &f.router, "/api/v1/telemetry/aggregate", json!({"query":query,"definitionVersion":1,"registration":config.registration_id,"source":"agent.native","epoch":config.source_epoch,"dimensions":{},"resolutionMicros":10_000_000,"operation":"increase","coverage":{"coverage":"observedOnly"},"maxGapMicros":10_000_000})).await?;
    let buckets: Vec<rss_timeseries::AggregateBucket> =
        serde_json::from_value(aggregate["buckets"].clone())?;
    ensure!(buckets.len() == 1, "network increase: {aggregate}");
    ensure!(
        matches!(
            buckets[0].value,
            rss_timeseries::AggregateValue::Sum(rss_timeseries::Sum::I128(15))
        ),
        "network increase: {aggregate}"
    );
    Ok(())
}
