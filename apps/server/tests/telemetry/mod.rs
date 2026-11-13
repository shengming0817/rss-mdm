//! Exact management JSON across real TLS, live authorization and persisted PG summaries.
mod fixture;
mod http;
use crate::{authority_t2_support::Context, device_material_support as materials};
use anyhow::{Context as _, Result};
use fixture::{Fixture, SeedAuthority, deadline};
use rss_mdm_authorization_service::Permission;
use rss_mdm_inventory as inv;
use rss_timeseries::*;
use serde_json::{Value, json};
use std::{
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
};
use uuid::Uuid;

#[expect(
    clippy::cognitive_complexity,
    reason = "One legal fixture keeps definition, samples and durable summary on the same series coordinates"
)]
async fn seed(
    c: &Context,
    f: &Fixture,
    device: &rss_mdm_agent_wire::DeviceId,
    epoch: Uuid,
    key: &str,
    values: [Number; 2],
    counter: bool,
) -> Result<()> {
    let field = inv::FieldDefinition {
        key: inv::FieldKey::parse(key)?,
        version: 1,
        value_type: if matches!(values[0], Number::F64(_)) {
            inv::ValueType::Number
        } else {
            inv::ValueType::Integer
        },
        nullable: false,
        manual: false,
        sources: [(inv::Source::AgentNative, 0)].into(),
        platforms: [inv::Platform::Windows].into(),
        sensitivity: inv::Sensitivity::Standard,
        unit: Some("count".into()),
        searchable: true,
        item_key: None,
        time_series: Some(inv::TimeSeriesBinding {
            kind: if counter {
                inv::TelemetryKind::DeltaCounter
            } else {
                inv::TelemetryKind::Gauge
            },
            value_path: vec![],
            interval_start_path: None,
            dimensions: Default::default(),
            aggregations: if counter {
                [
                    inv::TelemetryAggregation::Sum,
                    inv::TelemetryAggregation::Rate,
                ]
                .into()
            } else {
                [
                    inv::TelemetryAggregation::Sum,
                    inv::TelemetryAggregation::Mean,
                    inv::TelemetryAggregation::Count,
                ]
                .into()
            },
            retention: inv::RetentionReference {
                key: "standard".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    };
    field.validate()?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    anyhow::ensure!(
        rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?,
        "field publication"
    );
    tx.commit().await?;
    let definition =
        field.time_series_definition(Scope::new(c.tenant, Id::new("mdm.telemetry")?))?;
    let series = Series::new(
        definition.clone(),
        Id::new(device.to_string())?,
        Id::new("device")?,
        Default::default(),
    )?;
    let stream = Stream::new(
        definition.spec().scope.clone(),
        Id::new(format!("{device}:agent.native"))?,
        Id::new(epoch.to_string())?,
    );
    let store = f.store(c).await?;
    let authority = SeedAuthority(c.tenant);
    let register = Authorized::<DefinitionMutation>::verify(
        &authority,
        DefinitionMutation::Register {
            definition,
            expected_latest: None,
        },
    )?;
    anyhow::ensure!(
        matches!(
            store.change(&register, deadline()).await?,
            Outcome::Accepted(_)
        ),
        "definition persisted"
    );
    let samples = values
        .into_iter()
        .enumerate()
        .map(|(i, value)| {
            let at = (i as i64 + 1) * 1_000_000;
            Sample::new(SampleInput {
                stream: stream.clone(),
                series: series.clone(),
                id: Id::new(format!("{key}-{i}"))?,
                sequence: i as u64,
                observed_at: Timestamp::new(at)?,
                interval: if counter {
                    Some(Interval::new(
                        Timestamp::new(at - 1_000_000)?,
                        Timestamp::new(at)?,
                    )?)
                } else {
                    None
                },
                reading: Reading::Valid(rss_timeseries::Value::Number(value)),
            })
        })
        .collect::<Result<Vec<_>, rss_timeseries::Error>>()?;
    let batch = Authorized::<Batch>::verify(
        &authority,
        Batch::new(stream.clone(), Id::new(key)?, samples)?,
    )?;
    anyhow::ensure!(
        matches!(store.write(&batch, deadline()).await?, Outcome::Accepted(_)),
        "batch persisted"
    );
    let spec = SummarySpec::new(
        stream,
        series,
        NonZeroU64::new(4_000_000).unwrap(),
        CoveragePolicy::ObservedOnly,
        if counter {
            NonZeroU64::new(4_000_000)
        } else {
            None
        },
    )?;
    let request = Authorized::<MaintenanceRequest>::verify(
        &authority,
        MaintenanceRequest::new(
            Id::new(format!("recompute-{key}"))?,
            MaintenanceAction::Recompute {
                spec,
                window: Interval::new(Timestamp::new(0)?, Timestamp::new(4_000_000)?)?,
            },
            MaintenanceBudget {
                rows: NonZeroU32::new(128).unwrap(),
                buckets: NonZeroU32::new(16).unwrap(),
            },
        )?,
    )?;
    let mut after = None;
    let mut complete = false;
    for _ in 0..8 {
        match store.step(&request, after.as_ref(), deadline()).await? {
            Outcome::Accepted(MaintenanceProgress::Complete { .. })
            | Outcome::Replay(MaintenanceProgress::Complete { .. }) => {
                complete = true;
                break;
            }
            Outcome::Accepted(MaintenanceProgress::More { next, .. })
            | Outcome::Replay(MaintenanceProgress::More { next, .. }) => after = Some(next),
            other => anyhow::bail!("recompute did not settle: {other:?}"),
        }
    }
    anyhow::ensure!(complete, "bounded recompute");
    store.close(deadline()).await?;
    Ok(())
}
fn query(device: &rss_mdm_agent_wire::DeviceId, field: &str) -> Value {
    json!({"device":device,"field":field,"resource":"device","startMicros":"0","endMicros":"4000000","maxPoints":16,"mode":"history"})
}
fn aggregate(
    device: &rss_mdm_agent_wire::DeviceId,
    field: &str,
    epoch: Uuid,
    operation: &str,
    counter: bool,
) -> Value {
    json!({"query":query(device,field),"definitionVersion":"1","source":inv::Source::AgentNative,"epoch":epoch,"dimensions":{},"resolutionMicros":"4000000","operation":operation,"coverage":{"coverage":"observedOnly"},"maxGapMicros":if counter{Some("4000000")}else{None}})
}
fn validator(path: &str) -> jsonschema::Validator {
    let document = rss_mdm_http_contract::artifact::document([(
        "browser",
        rss_mdm_management_http::telemetry::routes(None).into_endpoints(),
    )])
    .unwrap();
    let endpoint = document["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == path)
        .unwrap();
    let response = endpoint["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["status"] == 200)
        .unwrap();
    jsonschema::validator_for(
        &document["schemas"][response["body"]["schema"]["schemaId"].as_str().unwrap()],
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "T2: actual HTTPS query handlers preserve exact samples and reopened PG summaries under current tenant/device grants"]
async fn exact_integer_queries_and_live_authorization() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let result = async {
        let fixture = Fixture::open(&c).await?;
        let result = exercise(&c, &fixture).await;
        fixture::with_cleanup(result, fixture.close(&c).await)
    }
    .await;
    c.close().await;
    result
}
#[expect(
    clippy::cognitive_complexity,
    reason = "One HTTPS scenario checks exact values, continuation and live authorization against the same persisted data"
)]
async fn exercise(c: &Context, f: &Fixture) -> Result<()> {
    let (device, grant) = materials::seed_registration(c).await?;
    let principal = materials::authenticated_agent(
        c,
        grant,
        &device,
        vec![rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1],
    )
    .await?;
    let epoch = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,device,source,epoch,next_sequence,enabled) VALUES($1::uuid,$2,'agent.native',$3,0,true)").bind(c.tenant.to_string()).bind(device.into_uuid()).bind(epoch).execute(&mut *tx).await?;
    anyhow::ensure!(
        rss_mdm_inventory_postgres::publish_retention_policy_in(
            &mut tx,
            c.tenant,
            &inv::RetentionPolicy {
                key: "standard".into(),
                revision: 1,
                raw_seconds: 86400,
                summary_seconds: 86400,
                restore_seconds: 0,
            },
        )
        .await?,
        "retention policy seed"
    );
    tx.commit().await?;
    for (key, values, counter) in [
        ("custom.minimum", [Number::I64(i64::MIN); 2], false),
        ("custom.maximum", [Number::I64(i64::MAX); 2], false),
        ("custom.rate", [Number::I64(i64::MAX); 2], true),
        (
            "custom.float",
            [Number::F64(FiniteF64::new(0.5)?); 2],
            false,
        ),
    ] {
        seed(c, f, &device, epoch, key, values, counter)
            .await
            .with_context(|| format!("seed {key}"))?;
    }
    let account = c.account(&[Permission::InventoryRead]).await?;
    let service = f.service(c).await?;
    // The telemetry role revalidates primary credentials without native protocol column grants.
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&c.operator)
            .await?;
    let gap: rss_mdm_agent_wire::runtime::TelemetryGapReport = serde_json::from_value(json!({
        "reportId": Uuid::new_v4(),
        "deviceId": device,
        "createdAt": now,
        "gaps": [{"reason": "capacity", "count": 1, "first": now, "last": now}]
    }))?;
    let accepted = service.receive_gap(&principal, &gap, 0).await?;
    let recovered = service.gap_status(&principal, gap.report_id).await?;
    anyhow::ensure!(
        accepted.report_id == gap.report_id
            && !accepted.replayed
            && recovered.report_id == gap.report_id
            && recovered.replayed
            && recovered.received_at == accepted.received_at,
        "telemetry role admits the live primary credential and recovers its receipt"
    );
    let http = http::Http::open(
        c,
        service.clone(),
        Arc::new(c.authenticate(&account).await?),
    )
    .await?;
    let h = validator("/telemetry/history");
    let a = validator("/telemetry/aggregate");
    for (field, n) in [("custom.minimum", i64::MIN), ("custom.maximum", i64::MAX)] {
        let mut input = query(&device, field);
        input["maxPoints"] = json!(1);
        let first = http.post("/telemetry/history", input.clone()).await?;
        anyhow::ensure!(
            h.is_valid(&first) && first["rows"].as_array().is_some_and(|r| r.len() == 1),
            "first history page"
        );
        let expected = n.to_string();
        anyhow::ensure!(
            first["rows"][0]["sample"]["reading"]["value"]["value"]["value"].as_str()
                == Some(expected.as_str()),
            "exact string reading"
        );
        let cursor = first["next"].as_str().context("history continuation")?;
        input["after"] = json!(cursor);
        let second = http.post("/telemetry/history", input).await?;
        anyhow::ensure!(
            h.is_valid(&second)
                && second["rows"].as_array().is_some_and(|r| r.len() == 1)
                && first["rows"][0]["sample"]["id"] == format!("{field}-0")
                && second["rows"][0]["sample"]["id"] == format!("{field}-1"),
            "fixed continuation"
        );
        let mut latest = query(&device, field);
        latest["mode"] = json!("latest");
        let latest = http.post("/telemetry/history", latest).await?;
        anyhow::ensure!(
            h.is_valid(&latest) && latest["rows"].as_array().is_some_and(|r| r.len() == 1),
            "live latest"
        );
        anyhow::ensure!(
            latest["rows"][0]["effectiveSource"] == true,
            "live source selected"
        );
        for operation in ["sum", "mean"] {
            let value = http
                .post(
                    "/telemetry/aggregate",
                    aggregate(&device, field, epoch, operation, false),
                )
                .await?;
            anyhow::ensure!(
                a.is_valid(&value) && value["refreshedThrough"] == "4000000",
                "persisted summary/schema"
            );
            let value = &value["buckets"][0]["value"];
            let sum = if operation == "sum" {
                &value["Sum"]
            } else {
                anyhow::ensure!(value["Mean"]["count"] == "2", "mean denominator");
                &value["Mean"]["sum"]
            };
            anyhow::ensure!(
                sum["I128"] == (i128::from(n) * 2).to_string(),
                "exact wide statistic"
            );
        }
    }
    let rate = http
        .post(
            "/telemetry/aggregate",
            aggregate(&device, "custom.rate", epoch, "rate", true),
        )
        .await?;
    anyhow::ensure!(a.is_valid(&rate), "rate schema");
    anyhow::ensure!(
        rate["buckets"][0]["value"]["Rate"]["increase"]["I128"]
            == (i128::from(i64::MAX) * 2).to_string(),
        "rate numerator"
    );
    anyhow::ensure!(
        rate["buckets"][0]["value"]["Rate"]["duration_micros"] == "2000000",
        "rate duration"
    );
    let float = http
        .post(
            "/telemetry/aggregate",
            aggregate(&device, "custom.float", epoch, "mean", false),
        )
        .await?;
    anyhow::ensure!(
        float["buckets"][0]["value"]["Mean"]["sum"]["F64"] == 1.0,
        "f64 semantics"
    );
    let mut bad = query(&device, "custom.minimum");
    bad["startMicros"] = json!(0);
    anyhow::ensure!(
        http.call("/telemetry/history", bad).await?.0 == 400,
        "old number input rejected"
    );
    let no_read = c.account(&[Permission::GroupRead]).await?;
    let denied = http::Http::open(
        c,
        service.clone(),
        Arc::new(c.authenticate(&no_read).await?),
    )
    .await?;
    anyhow::ensure!(
        denied
            .call("/telemetry/history", query(&device, "custom.minimum"))
            .await?
            .0
            == 403,
        "permission boundary"
    );
    drop(denied);
    let foreign = Context::open("shared", &[]).await?;
    let foreign_account = foreign.account(&[Permission::InventoryRead]).await?;
    let foreign_http = http::Http::open(
        &foreign,
        service.clone(),
        Arc::new(foreign.authenticate(&foreign_account).await?),
    )
    .await?;
    let foreign_result = foreign_http
        .call("/telemetry/history", query(&device, "custom.minimum"))
        .await;
    drop(foreign_http);
    foreign.close().await;
    anyhow::ensure!(foreign_result?.0 == 403, "tenant binding");
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2 AND source='agent.native'").bind(c.tenant.to_string()).bind(device.into_uuid()).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut latest = query(&device, "custom.minimum");
    latest["mode"] = json!("latest");
    anyhow::ensure!(
        http.post("/telemetry/history", latest).await?["rows"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "retired source cannot supply latest"
    );
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(account.rule).execute(&mut *tx).await?;
    tx.commit().await?;
    anyhow::ensure!(
        http.call(
            "/telemetry/aggregate",
            aggregate(&device, "custom.minimum", epoch, "mean", false)
        )
        .await?
        .0 == 403,
        "live revoke"
    );
    drop(http);
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query(
        "UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(principal.credential())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    anyhow::ensure!(
        matches!(
            service.gap_status(&principal, gap.report_id).await,
            Err(rss_mdm_telemetry_service::Error::Denied)
        ),
        "revoked primary credential cannot recover the existing telemetry receipt"
    );
    drop(service);
    Ok(())
}
