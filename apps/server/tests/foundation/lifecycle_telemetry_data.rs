//! Product-owned reader material against the original installation and persisted RSS receipts.
use anyhow::{Context, Result, ensure};
use rss_mdm_telemetry_service::{
    backend::{Backend, SystemClock},
    selection,
};
use rss_request_context::{Deadline, TenantId};
use rss_timeseries::*;
use rss_timeseries_clickhouse::{ChOwner, ChStore};
use sqlx::Connection;
use std::{num::NonZeroU32, time::Duration};
use uuid::Uuid;

struct ScopeAuthority(TenantId);
impl Authority for ScopeAuthority {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error> {
        let scope = match access {
            Access::Definition(DefinitionMutation::Register { definition, .. }) => {
                &definition.spec().scope
            }
            Access::Write(batch) => batch.stream().scope(),
            Access::Query(query) => query.selection().scope(),
            Access::Receipt(receipt) => receipt.stream.scope(),
            _ => return Err(Error::Unauthorized),
        };
        if scope.tenant() == self.0 {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}
fn deadline() -> Deadline {
    Deadline::from_timeout(&SystemClock, Duration::from_secs(10)).unwrap()
}
async fn material(
    db: &crate::config::Database,
    config: &crate::config::Config,
    tenant: TenantId,
    installation: Uuid,
) -> Result<(selection::Reader, i64)> {
    let mut c = sqlx::PgConnection::connect_with(&db.options()?).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let selected = selection::load(&mut tx, tenant)
        .await?
        .context("explicit storage selection")?;
    ensure!(selected.resource_id == Some(installation));
    let reader = selected
        .reader(config.native_protector()?.as_ref(), tenant)?
        .context("current reader")?;
    tx.commit().await?;
    c.close().await?;
    Ok((reader, selected.revision))
}
struct Facts {
    definition: Authorized<DefinitionMutation>,
    batch: Authorized<Batch>,
    query: Authorized<Query>,
}
fn facts(tenant: TenantId, value: i64) -> Result<Facts> {
    let authority = ScopeAuthority(tenant);
    let scope = Scope::new(tenant, Id::new("mdm.telemetry")?);
    let definition = Definition::new(DefinitionSpec {
        scope: scope.clone(),
        key: Id::new("custom.shared")?,
        version: 1,
        unit: Id::new("count")?,
        metric: Metric::Gauge {
            number: NumberKind::I64,
        },
        dimensions: DimensionRules {
            allowed: Default::default(),
            required: Default::default(),
            max_count: 0,
            max_value_bytes: 1,
            max_total_bytes: 1,
        },
    })?;
    let stream = Stream::new(scope, Id::new("device:agent.native")?, Id::new("epoch")?);
    let series = Series::new(
        definition.clone(),
        Id::new("device")?,
        Id::new("device")?,
        Default::default(),
    )?;
    let mut samples = Vec::new();
    for sequence in 1..=2 {
        samples.push(Sample::new(SampleInput {
            stream: stream.clone(),
            series: series.clone(),
            id: Id::new(format!("sample-{sequence}"))?,
            sequence,
            observed_at: Timestamp::new(sequence as i64)?,
            interval: None,
            reading: Reading::Valid(Value::Number(Number::I64(value))),
        })?);
    }
    let limit = NonZeroU32::new(1).unwrap();
    let query = Query::new(
        Selection::Exact {
            stream: stream.clone(),
            series,
        },
        Interval::new(Timestamp::new(0)?, Timestamp::new(4)?)?,
        QueryBudget {
            max_series: limit,
            max_points: limit,
        },
        QueryMode::History,
    )?;
    Ok(Facts {
        definition: Authorized::<DefinitionMutation>::verify(
            &authority,
            DefinitionMutation::Register {
                definition,
                expected_latest: None,
            },
        )?,
        batch: Authorized::<Batch>::verify(
            &authority,
            Batch::new(stream, Id::new("installed-batch")?, samples)?,
        )?,
        query: Authorized::<Query>::verify(&authority, query)?,
    })
}
async fn publish(store: &ChStore<SystemClock>, facts: &Facts) -> Result<()> {
    ensure!(
        matches!(
            store.change(&facts.definition, deadline()).await?,
            Outcome::Accepted(_)
        ),
        "register field"
    );
    ensure!(
        matches!(
            store.write(&facts.batch, deadline()).await?,
            Outcome::Accepted(_)
        ),
        "persist batch"
    );
    Ok(())
}
async fn open(
    reader: &selection::Reader,
    owner: &ChOwner<SystemClock>,
    tenant: TenantId,
    rev: i64,
) -> Result<ChStore<SystemClock>> {
    Ok(reader.bind(owner, tenant, rev, deadline()).await?)
}
pub(super) async fn exercise(
    runtime: &serde_json::Value,
    primary: &crate::config::Database,
    a: Uuid,
    b: Uuid,
) -> Result<()> {
    let config: crate::config::Config = serde_json::from_value(runtime.clone())?;
    let physical = config
        .telemetry
        .iter()
        .find(|p| matches!(p.backend, crate::telemetry::Storage::ClickHouse { .. }))
        .context("ClickHouse installation")?;
    let a = TenantId::parse(&a.to_string())?;
    let b = TenantId::parse(&b.to_string())?;
    let (ra, va) = material(primary, &config, a, physical.resource_id).await?;
    let (rb, vb) = material(primary, &config, b, physical.resource_id).await?;
    ensure!((va, vb) == (1, 2));
    let fa = facts(a, 11)?;
    let fb = facts(b, 22)?;
    let backend = physical.open_backend().await?;
    let Backend::ClickHouse(owner) = &backend else {
        anyhow::bail!("expected ClickHouse")
    };
    ensure!(
        open(&ra, owner, b, vb).await.is_err(),
        "foreign reader qualified for B"
    );
    let sa = open(&ra, owner, a, va).await?;
    let sb = open(&rb, owner, b, vb).await?;
    publish(&sa, &fa).await?;
    publish(&sb, &fb).await?;
    let first = sb.query(&fb.query, None, deadline()).await?;
    let cursor = first.next.context("two stored samples must paginate")?;
    ensure!(
        first.rows.len() == 1
            && first.rows[0].sample.input().reading
                == Reading::Valid(Value::Number(Number::I64(22)))
    );
    ensure!(
        sa.query(&fb.query, None, deadline()).await.is_err()
            && sa
                .query(&fa.query, Some(&cursor), deadline())
                .await
                .is_err()
    );
    sb.retire(deadline()).await?;
    ensure!(
        sa.query(&fa.query, None, deadline()).await?.rows[0]
            .sample
            .input()
            .reading
            == Reading::Valid(Value::Number(Number::I64(11)))
    );
    backend.close(deadline()).await?;
    let backend = physical.open_backend().await?;
    let Backend::ClickHouse(owner) = &backend else {
        anyhow::bail!("expected original ClickHouse")
    };
    let (rb, vb) = material(primary, &config, b, physical.resource_id).await?;
    let recovered = open(&rb, owner, b, vb).await?;
    ensure!(
        matches!(
            recovered.write(&fb.batch, deadline()).await?,
            Outcome::Replay(_)
        ),
        "original receipt"
    );
    let page = recovered
        .query(&fb.query, Some(&cursor), deadline())
        .await?;
    ensure!(
        page.rows.len() == 1 && page.next.is_none() && page.rows[0].sample.input().sequence == 2,
        "original cursor and unique second sample"
    );
    backend.close(deadline()).await?;
    Ok(())
}
