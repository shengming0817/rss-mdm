//! One product definition and real PG series carry the complete admitted dimension/state sets.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
const KEY: &str = "custom.capacity_state";
fn states() -> BTreeSet<String> {
    (0..1024).map(|i| format!("s{i:04}")).collect()
}
fn dimensions() -> BTreeMap<String, String> {
    (0..1024)
        .map(|i| (format!("d{i:04}"), "v0000".into()))
        .collect()
}
#[expect(
    clippy::cognitive_complexity,
    reason = "one legal product definition binds expanded dimensions and State samples to the same persisted series"
)]
pub(super) async fn seed(
    c: &Context,
    f: &Fixture,
    device: &rss_mdm_agent_wire::DeviceId,
    epoch: Uuid,
) -> Result<SummarySpec> {
    let field = inv::FieldDefinition {
        key: inv::FieldKey::parse(KEY)?,
        version: 1,
        value_type: inv::ValueType::Object {
            properties: [
                ("value".into(), inv::ValueType::Enum { values: states() }),
                (
                    "dimension".into(),
                    inv::ValueType::String {
                        max_length: 256,
                        allow_empty: false,
                    },
                ),
            ]
            .into(),
        },
        nullable: false,
        manual: false,
        sources: [(inv::Source::AgentNative, 0)].into(),
        platforms: [inv::Platform::Windows].into(),
        sensitivity: inv::Sensitivity::Standard,
        unit: Some("state".into()),
        searchable: false,
        item_key: None,
        time_series: Some(inv::TimeSeriesBinding {
            kind: inv::TelemetryKind::State,
            value_path: vec!["value".into()],
            interval_start_path: None,
            dimensions: (0..1024)
                .map(|i| {
                    (
                        format!("d{i:04}"),
                        inv::TelemetryDimension {
                            path: vec!["dimension".into()],
                            values: if i == 0 {
                                (0..1024).map(|n| format!("v{n:04}")).collect()
                            } else {
                                ["v0000".into()].into()
                            },
                        },
                    )
                })
                .collect(),
            aggregations: [
                inv::TelemetryAggregation::Timeline,
                inv::TelemetryAggregation::Transitions,
            ]
            .into(),
            retention: inv::RetentionReference {
                key: "standard".into(),
                revision: 1,
            },
            max_resources: 1,
        }),
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    tx.commit().await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let restored = rss_mdm_inventory_postgres::field_version_in(&mut tx, c.tenant, field.key, 1)
        .await?
        .context("persisted capacity definition")?;
    assert_eq!(restored, field);
    assert_eq!(
        restored.time_series.as_ref().unwrap().dimensions["d0000"]
            .values
            .len(),
        1024
    );
    tx.rollback().await?;
    let definition =
        restored.time_series_definition(Scope::new(c.tenant, Id::new("mdm.telemetry")?))?;
    let series = Series::new(
        definition.clone(),
        Id::new(device.to_string())?,
        Id::new("device")?,
        dimensions()
            .into_iter()
            .map(|(k, v)| Ok((Id::new(k)?, Id::new(v)?)))
            .collect::<Result<_, rss_timeseries::Error>>()?,
    )?;
    let stream = Stream::new(
        definition.spec().scope.clone(),
        Id::new(format!("{device}:agent.native"))?,
        Id::new(epoch.to_string())?,
    );
    let spec = SummarySpec::new(
        stream.clone(),
        series.clone(),
        NonZeroU64::new(4_000_000).unwrap(),
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let store = f.store().await?;
    let authority = SeedAuthority(c.tenant);
    let register = Authorized::<DefinitionMutation>::verify(
        &authority,
        DefinitionMutation::Register {
            definition,
            expected_latest: None,
        },
    )?;
    assert!(matches!(
        store.change(&register, deadline()).await?,
        Outcome::Accepted(_)
    ));
    let samples = ["s0000", "s1023"]
        .into_iter()
        .enumerate()
        .map(|(i, state)| {
            Sample::new(SampleInput {
                stream: stream.clone(),
                series: series.clone(),
                id: Id::new(format!("capacity-{i}"))?,
                sequence: i as u64,
                observed_at: Timestamp::new((i as i64 + 1) * 1_000_000)?,
                interval: None,
                reading: Reading::Valid(rss_timeseries::Value::State(Id::new(state)?)),
            })
        })
        .collect::<Result<Vec<_>, rss_timeseries::Error>>()?;
    let batch = Authorized::<Batch>::verify(
        &authority,
        Batch::new(stream, Id::new("capacity")?, samples)?,
    )?;
    assert!(matches!(
        store.write(&batch, deadline()).await?,
        Outcome::Accepted(_)
    ));
    store.close(deadline()).await?;
    Ok(spec)
}
pub(super) async fn verify(
    http: &http::Http,
    device: &rss_mdm_agent_wire::DeviceId,
    schema: &jsonschema::Validator,
    epoch: Uuid,
    spec: &SummarySpec,
) -> Result<()> {
    for (mode, expected) in [
        ("history", vec!["s0000", "s1023"]),
        ("latest", vec!["s1023"]),
    ] {
        let mut input = query(device, KEY);
        input["mode"] = json!(mode);
        let value = http.post("/telemetry/history", input).await?;
        assert!(
            schema.is_valid(&value),
            "current capacity response must match the actual exported HTTP schema: {value}"
        );
        let rows = value["rows"].as_array().context("history rows")?;
        assert_eq!(rows.len(), expected.len());
        for (row, expected) in rows.iter().zip(expected) {
            let sample = &row["sample"];
            assert_eq!(sample["reading"]["value"]["value"], expected);
            assert_eq!(sample["series"]["dimensions"], json!(dimensions()));
            if mode == "latest" {
                let mut aggregate = aggregate(device, KEY, epoch, "timeline", false);
                aggregate["dimensions"] = json!(dimensions());
                let maintenance = json!({"id":Uuid::new_v4(), "device":device, "field":KEY, "resource":"device",
                    "startMicros":0, "endMicros":4000000, "action":{"action":"recompute","spec":spec}});
                assert!(serde_json::to_vec(&maintenance)?.len() > 16384);
                let progress = http
                    .post("/telemetry/maintenance", maintenance.clone())
                    .await?;
                assert_eq!(progress["state"], "complete");
                assert_eq!(
                    http.post("/telemetry/maintenance", maintenance).await?,
                    progress
                );
                let result = http.post("/telemetry/aggregate", aggregate.clone()).await?;
                anyhow::ensure!(
                    !result["buckets"]
                        .as_array()
                        .context("state buckets")?
                        .is_empty()
                );
                aggregate["dimensions"]["d0000"] = json!("unknown");
                assert_eq!(http.call("/telemetry/aggregate", aggregate).await?.0, 400);
            }
            let definition = &sample["series"]["definition"];
            assert_eq!(definition["metric"]["members"], json!(states()));
            let rules = &definition["dimensions"];
            assert_eq!(rules["allowed"].as_array().unwrap().len(), 1024);
            assert_eq!(rules["required"], rules["allowed"]);
            assert_eq!(rules["maxCount"], 1024);
            assert_eq!(rules["maxValueBytes"], 256);
            assert_eq!(rules["maxTotalBytes"], 32768);
        }
    }
    Ok(())
}
