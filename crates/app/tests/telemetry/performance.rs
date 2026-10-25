//! Native performance publication and endpoint capability negotiation use the real product seam.
use super::*;
use anyhow::Context;

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
            rss_mdm_agent_wire::runtime::AgentCollectionMapping {
                query: "cpu".into(),
                mapping: rss_mdm_agent_wire::runtime::ValueMapping {
                    pointer: "/busy_percent".into(),
                    conversion: rss_mdm_agent_wire::runtime::Conversion::Identity,
                    columns: Default::default(),
                },
                missing: rss_mdm_agent_wire::runtime::NativeMissing::Missing,
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
    let signed = native_configuration(f, &path).await?;
    use base64::Engine;
    use ring::signature::KeyPair;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, f.key.public_key().as_ref())
        .verify(
            &signed.configuration.signing_bytes(&signed.key_id)?,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?,
        )
        .map_err(|_| anyhow::anyhow!("native configuration signature"))?;
    let config = signed.configuration;
    ensure!(config.resource_digest.iter().any(|b| *b != 0));
    let mut altered = config.clone();
    altered.resource_digest[0] ^= 1;
    ensure!(
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            f.key.public_key().as_ref()
        )
        .verify(
            &altered.signing_bytes(&signed.key_id)?,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signed.signature)?
        )
        .is_err()
    );

    ensure!(matches!(config.source, wire::Source::AgentNative));
    let wire::TelemetryCollector::Native {
        plan: actual,
        plan_digest,
        mappings,
    } = &config.collector
    else {
        anyhow::bail!("native configuration downgraded to script")
    };
    ensure!(*plan_digest == actual.digest());
    ensure!(serde_json::to_value(actual)? == serde_json::to_value(&plan)? && mappings.len() == 1);
    let mapping = &mappings[field.key.as_str()];
    ensure!(
        mapping.query == "cpu"
            && mapping.mapping.pointer == "/busy_percent"
            && mapping.mapping.conversion == wire::Conversion::Identity
            && mapping.mapping.columns.is_empty()
    );
    cpu_reading(f, &policy, &config, &field).await?;
    published_network(f, config.registration_id).await?;
    scoped_configuration_reader(f, &policy).await?;
    announce(f, json!({})).await?;
    Ok(())
}

async fn cpu_reading(
    f: &mut Fixture,
    policy: &Value,
    config: &wire::TelemetryConfiguration,
    field: &rss_mdm_inventory::FieldDefinition,
) -> Result<()> {
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
    let (status, summary) = f
        .author
        .clone()
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v1/devices/{}/telemetry-configurations",
                case_device_id()
            ),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "management configurations: {status} {summary}"
    );
    let rows = summary["configurations"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing configuration summaries"))?;
    let assignments = result["assignments"].as_array().unwrap();
    ensure!(
        rows.len() == assignments.len(),
        "management/Agent directory count differs"
    );
    for assignment in assignments {
        ensure!(
            rows.iter()
                .any(|row| row["policyId"] == assignment["policy"]
                    && row["policyVersionId"] == assignment["version"]
                    && row["supported"] == assignment["supported"]),
            "management/Agent admission differs"
        );
    }
    ensure!(
        summary["device"] == case_device_id()
            && summary["registration"]["id"].is_string()
            && summary["registration"]["generation"]
                .as_i64()
                .is_some_and(|v| v > 0)
            && summary["evaluatedAtMicros"].as_i64().is_some_and(|v| v > 0)
    );
    for row in rows {
        let keys = row.as_object().unwrap();
        ensure!(
            keys.len() == 10
                && keys.contains_key("resource")
                && keys.contains_key("source")
                && keys.contains_key("projection")
                && keys.contains_key("sampleMillis")
                && keys.contains_key("normalSampleMillis")
                && keys.contains_key("boostExpiresAt")
                && keys.contains_key("uploadMillis"),
            "unexpected summary fields: {keys:?}"
        );
    }
    Ok(())
}

async fn published_network(f: &mut Fixture, registration: Uuid) -> Result<()> {
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
    let column = |pointer: &str, conversion| rss_mdm_agent_wire::runtime::ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    };
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
        applicability: Default::default(),
        plan,
        mappings: [(
            field.key.as_str().into(),
            rss_mdm_agent_wire::runtime::AgentCollectionMapping {
                query: "network".into(),
                missing: rss_mdm_agent_wire::runtime::NativeMissing::Missing,
                counter_normalization: Some(wire::NativeCounterNormalization::LocalCumulativeV1),
                mapping: rss_mdm_agent_wire::runtime::ValueMapping {
                    pointer: String::new(),
                    conversion: rss_mdm_agent_wire::runtime::Conversion::Identity,
                    columns: [
                        (
                            "id".into(),
                            column("/id", rss_mdm_agent_wire::runtime::Conversion::Identity),
                        ),
                        (
                            "received".into(),
                            column(
                                "/received_bytes",
                                rss_mdm_agent_wire::runtime::Conversion::Integer,
                            ),
                        ),
                    ]
                    .into(),
                },
            },
        )]
        .into(),
    })?;
    // One published template intentionally carries both fields, while profiles select one.
    let mut mixed = definition.spec().clone();
    let mut plan = mixed.plan.spec().clone();
    plan.queries.insert(
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
    );
    mixed.plan = wire::NativeCollectionPlan::new(plan)?;
    mixed.mappings.insert(
        "custom.performance.cpu".into(),
        rss_mdm_agent_wire::runtime::AgentCollectionMapping {
            query: "cpu".into(),
            mapping: column(
                "/busy_percent",
                rss_mdm_agent_wire::runtime::Conversion::Identity,
            ),
            missing: rss_mdm_agent_wire::runtime::NativeMissing::Missing,
            counter_normalization: None,
        },
    );
    let definition = r::AgentCollectionDefinition::new(mixed)?;
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
    let mut cpu_profile = profile.spec().clone();
    cpu_profile.fields = vec![r::TelemetryFieldReference {
        key: "custom.performance.cpu".into(),
        version: 1,
    }];
    let cpu_profile = r::TelemetryProfile::new(cpu_profile)?;
    let cpu_profile_id = Uuid::new_v4();
    publish(
        f,
        cpu_profile_id,
        "telemetry_profile",
        serde_json::to_value(&cpu_profile)?,
        &cpu_profile.canonical(),
    )
    .await?;
    let cpu_policy = post(&mut f.author, &f.router, &format!("/api/v1/policies/{}", Uuid::new_v4()), json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":cpu_profile_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
    directory(f, &cpu_policy, true).await?;
    let cpu_path = format!(
        "/api/v1/agent/runtime/telemetry/configurations/{}/{}",
        cpu_policy["id"].as_str().unwrap(),
        cpu_policy["versionId"].as_str().unwrap()
    );
    let (status, cpu_config) = agent_call(
        &f.router,
        Method::GET,
        &cpu_path,
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "mixed template CPU-only config requires unrelated counter capability: {status} {cpu_config}"
    );
    let cpu_config: wire::SignedTelemetryConfiguration = serde_json::from_value(cpu_config)?;
    let wire::TelemetryCollector::Native { mappings, .. } = &cpu_config.configuration.collector
    else {
        anyhow::bail!("CPU-only collector missing")
    };
    ensure!(
        mappings.len() == 1 && mappings.contains_key("custom.performance.cpu"),
        "unselected counter leaked into CPU config"
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
    let original = enable_counter_capability(registration)?;
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
    if let Ok(bytes) = altered.signing_bytes(&signed.key_id) {
        ensure!(
            public.verify(&bytes, &signature).is_err(),
            "normalization marker was not signed"
        );
    }
    network_readings(f, &policy, &signed.configuration, &field).await?;
    set_capabilities(registration, &original)?;
    Ok(())
}

// Capability changes are fixture prerequisites, scoped to the registration learned
// from an authenticated, verified configuration; credential strings are not locators.
fn enable_counter_capability(registration: Uuid) -> Result<String> {
    let tenant = case_tenant();
    let original = pg(&format!(
        "SELECT capabilities FROM mdm_agent.bindings WHERE tenant_id='{tenant}' AND registration='{registration}'"
    ))?;
    let original = original.trim();
    ensure!(
        !original.is_empty(),
        "missing capability fixture for {registration}"
    );
    let mut capabilities: Vec<String> = serde_json::from_str(original)?;
    capabilities.push("telemetry.counter.local.v1".into());
    set_capabilities(registration, &serde_json::to_string(&capabilities)?)?;
    Ok(original.to_owned())
}

fn set_capabilities(registration: Uuid, capabilities: &str) -> Result<()> {
    let tenant = case_tenant();
    let capabilities = capabilities.replace('\'', "''");
    let updated = pg(&format!(
        "WITH updated AS (UPDATE mdm_agent.bindings SET capabilities='{capabilities}' WHERE tenant_id='{tenant}' AND registration='{registration}' RETURNING registration) SELECT count(*) FROM updated"
    ))?;
    ensure!(
        updated.trim() == "1",
        "capability fixture must update one binding: {updated}"
    );
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

// Hold publication and prove the waiting configuration read has not acquired authorization.
async fn configuration_publication_first<T>(
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    use sqlx::Connection;
    let mut observer =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut hold = observer.begin().await?;
    crate::Database::configure_transaction(&mut hold, case_tenant()).await?;
    rss_mdm_inventory_postgres::lock_watermark_in(
        &mut hold,
        rss_request_context::TenantId::parse(case_tenant())?,
    )
    .await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_flow_runtime' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%mdm.lock_asset_watermark%')").fetch_one(&mut *hold).await?;
                    if waiting { break; }
                    sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                    tokio::task::yield_now().await;
                }
                let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2363))").bind(format!("{}:{}",case_tenant(),INSTANCE)).fetch_one(&mut *hold).await?;
                ensure!(free,"telemetry configuration reader acquired authorization before publication");
                Ok::<_,anyhow::Error>(())
            }).await;
        hold.rollback().await?;
        observed.context("telemetry configuration reader must actually wait for publication")??;
        Ok::<_, anyhow::Error>(())
    };
    let (response, released) = tokio::join!(operation, release);
    released?;
    observer.close().await?;
    response
}

// A separate reader's rule changes cannot invalidate published configuration authority.
async fn scoped_configuration_reader(f: &mut Fixture, policy: &Value) -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut administrator = Browser::default();
    ensure!(administrator.login(&f.router, "admin").await? == StatusCode::OK);
    let login = format!("telemetry-reader-{}", Uuid::new_v4());
    let accounts = format!("/api/v1/identity/tenants/{}/accounts", case_tenant());
    let (status, account) = administrator
        .call(
            &f.router,
            Method::POST,
            &accounts,
            Some(json!({"login":login,"password":identity::PASSWORD})),
        )
        .await?;
    ensure!(
        status == StatusCode::CREATED,
        "independent configuration reader creation failed"
    );
    let subject = account["principalId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("reader principal missing"))?;
    let mut reader = Browser::default();
    let (status, _) = reader
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/identity/tenants/{}/login", case_tenant()),
            Some(json!({"login":login,"password":identity::PASSWORD})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "independent configuration reader login failed"
    );
    let mut grants = identity::device_grants(Some(case_device_id()), &["inventory_read"])?;
    for operation in [Permission::PolicyRead, Permission::ResourceRead] {
        grants.push(Grant {
            operation,
            scope: Scope::Tenant,
        });
    }
    identity::set_grants(case_tenant(), subject, grants.clone()).await?;
    let endpoint = format!(
        "/api/v1/devices/{}/telemetry-configurations",
        case_device_id()
    );
    let (status, summary) =
        configuration_publication_first(reader.call(&f.router, Method::GET, &endpoint, None))
            .await?;
    ensure!(
        status == StatusCode::OK
            && summary["configurations"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["policyId"] == policy["id"]
                    && row["policyVersionId"] == policy["versionId"])),
        "device-scoped reader could not see configuration: {status} {summary}"
    );
    let (status, denied) = reader
        .call(
            &f.router,
            Method::GET,
            "/api/v1/devices/not-authorized/telemetry-configurations",
            None,
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN && denied.get("configurations").is_none());
    for permission in [
        Permission::PolicyRead,
        Permission::ResourceRead,
        Permission::InventoryRead,
    ] {
        identity::set_grants(
            case_tenant(),
            subject,
            grants
                .iter()
                .filter(|g| g.operation != permission)
                .cloned()
                .collect(),
        )
        .await?;
        let (status, denied) = reader.call(&f.router, Method::GET, &endpoint, None).await?;
        ensure!(
            status == StatusCode::FORBIDDEN && denied.get("configurations").is_none(),
            "configuration metadata survived {permission:?} revocation"
        );
    }
    identity::set_grants(case_tenant(), subject, grants).await?;
    let path = format!("/api/v1/policies/{}", policy["id"].as_str().unwrap());
    let disabled = post(
        &mut f.author,
        &f.router,
        &path,
        json!({
            "operationId":Uuid::new_v4(), "expectedRevision":policy["revision"],
            "input":{"action":"put","enabled":false,"definition":policy["definition"]}
        }),
    )
    .await?;
    let (status, summary) = reader.call(&f.router, Method::GET, &endpoint, None).await?;
    ensure!(
        status == StatusCode::OK
            && summary["configurations"]
                .as_array()
                .is_some_and(|rows| rows.iter().all(|row| row["policyId"] != disabled["id"])),
        "disabled policy remained current"
    );
    // The original publisher's untouched rule still authorizes its other configurations.
    let (status, directory) = agent_call(
        &f.router,
        Method::GET,
        "/api/v1/agent/runtime/telemetry/configurations",
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && directory["assignments"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
        "reader revocation invalidated the publisher's other assignments"
    );
    Ok(())
}

async fn configuration_lock_order(f: &Fixture, path: &str) -> Result<()> {
    use sqlx::Connection;
    let options = crate::device::test_support::options("postgres")?;
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    let mut observer = sqlx::PgConnection::connect_with(&options).await?;
    let mut reader = sqlx::PgConnection::connect_with(&options).await?;
    let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut owner)
        .await?;
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut reader)
        .await?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    rss_mdm_inventory_postgres::lock_watermark_in(&mut tx, tenant).await?;
    let parts = path.rsplit('/').take(2).collect::<Vec<_>>();
    let version = Uuid::parse_str(parts[0])?;
    let policy = Uuid::parse_str(parts[1])?;
    let planning = f.planning.clone();
    let task = tokio::spawn(async move {
        let mut tx = reader.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        let result = rss_mdm_flow_service::planning::policies::telemetry::resolve_on(
            &planning,
            &mut tx,
            case_device_id(),
            policy,
            version,
        )
        .await;
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(result?)
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                .bind(owner_pid)
                .bind(reader_pid)
                .fetch_one(&mut observer)
                .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    // Reader cannot hold authority while waiting for this publisher's watermark.
    let instance = f.base["identity"]["instance_id"]
        .as_str()
        .context("identity instance")?;
    tokio::time::timeout(
        Duration::from_secs(1),
        rss_mdm_authorization_service::store::lock(&mut tx, case_tenant(), instance),
    )
    .await??;
    tx.rollback().await?;
    let frozen = task.await??;
    ensure!(
        !frozen.grants.is_empty(),
        "lock-order witness did not resolve a real profile"
    );
    Ok(())
}

async fn native_configuration(
    f: &Fixture,
    path: &str,
) -> Result<wire::SignedTelemetryConfiguration> {
    configuration_lock_order(f, path).await?;
    let (status, signed) =
        agent_call(&f.router, Method::GET, path, Some(case_credential()), None).await?;
    ensure!(
        status == StatusCode::OK,
        "native configuration: {status} {signed}"
    );
    Ok(serde_json::from_value(signed)?)
}
