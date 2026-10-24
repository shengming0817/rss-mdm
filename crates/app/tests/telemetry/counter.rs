//! Counter gaps and sensitive access are product seams, not a provider arithmetic matrix.
use super::*;

async fn published_counter(f: &mut Fixture) -> Result<(Uuid, rss_mdm_inventory::FieldDefinition)> {
    use rss_mdm_inventory as d;
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventorySensitiveRead,
        scope: crate::authorization::Scope::Tenant,
    });
    identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    let field = d::FieldDefinition {
        key: d::FieldKey::parse("custom.telemetry_counter")?,
        version: 1,
        value_type: d::ValueType::Record {
            properties: [(
                "count".into(),
                d::Property {
                    required: true,
                    value_type: d::ValueType::Integer,
                },
            )]
            .into(),
        },
        nullable: false,
        manual: false,
        sources: [(d::Source::AgentScript, 0)].into(),
        platforms: [d::Platform::Macos].into(),
        sensitivity: d::Sensitivity::Sensitive,
        unit: Some("bytes".into()),
        searchable: false,
        item_key: None,
        time_series: Some(d::TimeSeriesBinding {
            kind: d::TelemetryKind::CumulativeCounter,
            value_path: vec!["count".into()],
            interval_start_path: None,
            dimensions: Default::default(),
            aggregations: [d::TelemetryAggregation::Rate].into(),
            retention: d::RetentionReference {
                key: "telemetry_test".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    };
    let field_path = "/api/v1/asset-fields/custom.telemetry_counter";
    put(&mut f.author,&f.router,field_path,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":field}})).await?;
    let script = Uuid::new_v4();
    let bytes = b"#!/bin/sh\nprintf '{\"counter\":{\"count\":10}}\\n'\n";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    resource(
        &mut f.author,
        &f.router,
        script,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"counter":{"type":"object","properties":{"count":{"type":"integer"}},"required":["count"],"additionalProperties":false}},"required":["counter"],"additionalProperties":false},"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":{"custom.telemetry_counter":{"pointer":"/counter","conversion":{"kind":"identity"},"columns":{}}}},"timeoutSeconds":1,"outputBytes":4096,"maxRows":1});
    resource(&mut f.author,&f.router,script,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"counter","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(upload(&f.author, &f.router, script, bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        script,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let profile = r::TelemetryProfile::new(r::TelemetryProfileSpec {
        template: r::TelemetryTemplate {
            resource: script.to_string(),
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
            points: 64,
            bytes: 65536,
            resources: 1,
            execution_millis: 1000,
            output_bytes: 4096,
        },
        boost: None,
        backfill_seconds: 3600,
    })?;
    let id = Uuid::new_v4();
    let bytes = profile.canonical();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    resource(
        &mut f.author,
        &f.router,
        id,
        0,
        json!({"action":"create","kind":"telemetry_profile"}),
    )
    .await?;
    let version = json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"version","version":"v1","kind":"telemetry_profile","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"telemetry_profile","artifact":{"reference":"counter-profile","length":bytes.len(),"sha256":digest},"definition":profile}}]}});
    let mut invalid = version.clone();
    invalid["operationId"] = json!(Uuid::new_v4());
    invalid["input"]["variants"][0]["declaration"]["definition"]["fields"][0]["version"] =
        json!(999);
    ensure!(
        f.author
            .call(
                &f.router,
                Method::POST,
                &format!("/api/v1/resources/{id}"),
                Some(invalid)
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let mut budget_invalid = version.clone();
    budget_invalid["operationId"] = json!(Uuid::new_v4());
    budget_invalid["input"]["variants"][0]["declaration"]["definition"]["budget"]["executionMillis"] =
        json!(500);
    ensure!(
        f.author
            .call(
                &f.router,
                Method::POST,
                &format!("/api/v1/resources/{id}"),
                Some(budget_invalid)
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    // Both commands meet the real catalog/reference lock concurrently. Retirement
    // must not pass an already published collector reference or a new Profile.
    let mut retiring = f.author.clone();
    let resource_path = format!("/api/v1/resources/{id}");
    let (publication,retired)=tokio::join!(
        f.author.call(&f.router,Method::POST,&resource_path,Some(version)),
        retiring.call(&f.router,Method::PUT,field_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}})))
    );
    let publication = publication?;
    let retired = retired?;
    ensure!(
        publication.0 == StatusCode::OK && retired.0 == StatusCode::CONFLICT,
        "publication/retirement race: {publication:?} {retired:?}"
    );
    ensure!(upload(&f.author, &f.router, id, &bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let references = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{field_path}/references"),
            None,
        )
        .await?;
    ensure!(
        references.0 == StatusCode::OK
            && references.1["asset"]["impact"]["telemetryProfiles"]
                .as_i64()
                .is_some_and(|v| v > 0),
        "profile reference: {references:?}"
    );
    ensure!(f.author.call(&f.router,Method::PUT,field_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}}))).await?.0==StatusCode::CONFLICT);
    Ok((id, field))
}

pub(super) async fn quality_and_sensitive_reads(f: &mut Fixture) -> Result<()> {
    use rss_mdm_inventory as d;
    let (id, field) = published_counter(f).await?;
    let scope = Uuid::from_u128(case::id("telemetry-counter-scope"));
    let policy = Uuid::new_v4();
    let policy=post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"telemetry_profile","resource":{"id":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"}}}}})).await?;
    let (status, signed) = agent_call(
        &f.router,
        Method::GET,
        &format!(
            "/api/v1/agent/runtime/telemetry/configurations/{}/{}",
            policy["id"].as_str().unwrap(),
            policy["versionId"].as_str().unwrap()
        ),
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "counter config: {status} {signed}"
    );
    let config: wire::SignedTelemetryConfiguration = serde_json::from_value(signed)?;
    let now = f.planning.clock.unix_seconds()? * 1_000_000;
    let start = (now / 10_000_000 - 1) * 10_000_000;
    upload_counter_readings(f, &policy, &config, &field, start).await?;
    let query = json!({"device":case_device_id(),"field":field.key,"resource":"device","startMicros":start,"endMicros":start+10_000_000,"maxPoints":64,"mode":"history","after":null});
    let history = post(
        &mut f.author,
        &f.router,
        "/api/v1/telemetry/history",
        query.clone(),
    )
    .await?;
    ensure!(history["rows"].as_array().is_some_and(|r| r.len() == 3));
    let sample: rss_timeseries::Sample =
        serde_json::from_value(history["rows"][0]["sample"].clone())?;
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
            resource: "device".into(),
            start_micros: start,
            end_micros: start + 10_000_000,
            action: rss_mdm_telemetry_service::maintenance::Action::Recompute { spec },
        },
    )
    .await?;
    let aggregate = json!({"query":query,"definitionVersion":1,"registration":config.configuration.registration_id,"source":d::Source::AgentScript,"epoch":config.configuration.source_epoch,"dimensions":{},"resolutionMicros":10_000_000,"operation":"rate","coverage":{"coverage":"observedOnly"},"maxGapMicros":10_000_000});
    let result = post(
        &mut f.author,
        &f.router,
        "/api/v1/telemetry/aggregate",
        aggregate.clone(),
    )
    .await?;
    ensure!(
        result["buckets"]
            .as_array()
            .is_some_and(|b| b.iter().any(|v| v["completeness"]
                .as_array()
                .is_some_and(|c| c.contains(&json!("Gaps"))))),
        "counter failure lost in summary: {result}"
    );
    f.grants
        .retain(|g| g.operation != crate::authorization::Permission::InventorySensitiveRead);
    identity::change_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    for (path, body) in [
        ("/api/v1/telemetry/history", query),
        ("/api/v1/telemetry/aggregate", aggregate),
    ] {
        ensure!(
            f.author
                .call(&f.router, Method::POST, path, Some(body))
                .await?
                .0
                == StatusCode::FORBIDDEN,
            "sensitive read permitted: {path}"
        );
    }
    Ok(())
}

async fn extension_replay(f: &Fixture, body: &Value) -> Result<()> {
    let path = "/api/v1/agent/runtime/telemetry/batches";
    let replay = agent_call(
        &f.router,
        Method::POST,
        path,
        Some(case_credential()),
        Some(body.clone()),
    )
    .await?;
    ensure!(replay.0 == StatusCode::ACCEPTED && replay.1["replayed"] == true);
    let mut changed = body.clone();
    changed["observations"][0]["values"]["custom.telemetry_counter"]["value"]["value"]["vendor_note"]
        ["value"] = json!("changed note");
    ensure!(
        agent_call(
            &f.router,
            Method::POST,
            path,
            Some(case_credential()),
            Some(changed.clone())
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    changed["batchId"] = json!(Uuid::new_v4());
    ensure!(
        agent_call(
            &f.router,
            Method::POST,
            path,
            Some(case_credential()),
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    Ok(())
}

async fn upload_counter_readings(
    f: &mut Fixture,
    policy: &Value,
    config: &wire::SignedTelemetryConfiguration,
    field: &rss_mdm_inventory::FieldDefinition,
    start: i64,
) -> Result<()> {
    let make = |reading: Value, offset: i64| json!({"batchId":Uuid::new_v4(),"policy":policy["id"],"policyVersion":policy["versionId"],"binding":config.configuration.binding,"observations":[{"id":Uuid::new_v4(),"sequence":offset,"observedAt":start+offset*1_000_000,"values":{"custom.telemetry_counter":reading}}]});
    for (offset, reading) in [
        (
            1,
            json!({"quality":"valid","value":{"kind":"object","value":{"count":{"kind":"integer","value":10},"vendor_note":{"kind":"string","value":"first raw note"}}},"intervalStart":start}),
        ),
        (
            2,
            json!({"quality":"failed","intervalStart":start,"context":null}),
        ),
        (
            3,
            json!({"quality":"valid","value":{"kind":"object","value":{"count":{"kind":"integer","value":20},"vendor_note":{"kind":"string","value":"second raw note"}}},"intervalStart":start}),
        ),
    ] {
        let body = make(reading, offset);
        let receipt = format!(
            "/api/v1/agent/runtime/telemetry/batches/{}",
            body["batchId"].as_str().unwrap()
        );
        ensure!(
            agent_call(
                &f.router,
                Method::POST,
                "/api/v1/agent/runtime/telemetry/batches",
                Some(case_credential()),
                Some(body.clone())
            )
            .await?
            .0 == StatusCode::ACCEPTED
        );
        published(&f.router, &receipt).await?;
        if offset == 1 {
            extension_replay(f, &body).await?;
        }
        if offset == 2 {
            let latest=post(&mut f.author,&f.router,"/api/v1/telemetry/history",json!({"device":case_device_id(),"field":field.key,"resource":"device","startMicros":start,"endMicros":start+10_000_000,"maxPoints":64,"mode":"latest","after":null})).await?;
            let sample: rss_timeseries::Sample =
                serde_json::from_value(latest["rows"][0]["sample"].clone())?;
            ensure!(
                sample.input().reading == rss_timeseries::Reading::Failed,
                "latest hid failure: {latest}"
            );
        }
    }
    Ok(())
}
