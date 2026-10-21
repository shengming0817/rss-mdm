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
