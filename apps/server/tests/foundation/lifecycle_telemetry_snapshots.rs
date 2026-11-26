//! Product paging, physical publication recovery and queue capacity on the installed store.
use super::*;
use rss_timeseries::{
    Authorized, Batch, Id, Interval, Maintainer, MaintenanceAction, MaintenanceBudget,
    MaintenanceRequest, Outcome, ReceiptQuery, Sample, SampleInput, Selection, Stream, Timestamp,
    Writer,
};
use rss_timeseries_clickhouse::{Credentials, CursorKey, ProjectionProgress};

use rss_mdm_telemetry_service::backend::{Backend, SystemClock};
use rss_timeseries_clickhouse::{ChOwner, ChStore};

fn cutoff() -> Result<rss_request_context::Deadline> {
    Ok(rss_request_context::Deadline::from_timeout(
        &SystemClock,
        Duration::from_secs(10),
    )?)
}

async fn open(
    config: &crate::telemetry::Config,
    ch: &Value,
    tenant: TenantId,
    client_password: &str,
) -> Result<(ChOwner<SystemClock>, ChStore<SystemClock>)> {
    let id = Uuid::parse_str(&tenant.to_string())?;
    let Backend::ClickHouse(owner) = config.open_backend().await? else {
        anyhow::bail!("expected ClickHouse")
    };
    let reader = Credentials::new(recovery::reader(ch, id)?, client_password.to_owned())?;
    let store = owner
        .bind_tenant(
            tenant,
            reader,
            CursorKey::new([3; 32]),
            std::num::NonZeroU64::MIN,
            cutoff()?,
        )
        .await?;
    Ok((owner, store))
}

async fn verify_queue(
    store: &ChStore<SystemClock>,
    identity: &Authorized<ReceiptQuery>,
    admin: &sqlx::PgPool,
) -> Result<()> {
    // Use the physical owner directly so product authentication and audit locks cannot serialize the clients.
    let mut blocker = admin.begin().await?;
    sqlx::query("LOCK TABLE rss_ts_ch.batches IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let first = store.progress(identity, cutoff()?);
    tokio::pin!(first);
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename='metrics_click_house' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))")
                .fetch_one(&mut *blocker).await?;
            if waiting {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    tokio::select! {
        early = &mut first => anyhow::bail!("head read escaped physical lock: {early:?}"),
        result = observed => result.context("wait for slot holder")??,
    }
    let waiter = store.progress(identity, cutoff()?);
    tokio::pin!(waiter);
    ensure!(futures::poll!(&mut waiter).is_pending());
    let excess = tokio::time::timeout(Duration::from_secs(1), store.progress(identity, cutoff()?))
        .await?
        .expect_err("queue full");
    ensure!(excess == rss_timeseries::Error::Unavailable);
    ensure!(
        rss_mdm_management_http::telemetry::error(excess.into())
            .status()
            .as_u16()
            == 503
    );
    blocker.rollback().await?;
    let (head, queued) = tokio::try_join!(first, waiter)?;
    ensure!(matches!(
        (head, queued),
        (
            ProjectionProgress::NotVisible,
            ProjectionProgress::NotVisible
        )
    ));
    Ok(())
}

fn unrelated_batch(
    original: &Sample,
    authority: &ScopeAuthority,
    name: &str,
) -> Result<(Authorized<Batch>, Authorized<ReceiptQuery>)> {
    let scope = original.input().stream.scope();
    let mut input: SampleInput = original.clone().into();
    input.stream = Stream::new(scope.clone(), Id::new(name)?, Id::new("sample-generation")?);
    input.id = Id::new(name)?;
    let batch = Batch::new(
        input.stream.clone(),
        Id::new(name)?,
        vec![Sample::new(input)?],
    )?;
    let identity = ReceiptQuery {
        stream: batch.stream().clone(),
        batch_id: batch.id().clone(),
        digest: batch.digest()?,
    };
    Ok((
        Authorized::<Batch>::verify(authority, batch)?,
        Authorized::<ReceiptQuery>::verify(authority, identity)?,
    ))
}

async fn interrupt_projection(
    store: &ChStore<SystemClock>,
    ch: &Value,
    first: &Authorized<Batch>,
    first_id: &Authorized<ReceiptQuery>,
) -> Result<()> {
    recovery::admin_sql(ch, "REVOKE INSERT ON rss_ts_ch.raw FROM metric_writer").await?;
    let interrupted = Box::pin(store.write(first, cutoff()?)).await;
    recovery::admin_sql(ch, "GRANT INSERT ON rss_ts_ch.raw TO metric_writer").await?;
    ensure!(!matches!(
        interrupted,
        Ok(Outcome::Accepted(_) | Outcome::Replay(_))
    ));
    assert_eq!(
        store.progress(first_id, cutoff()?).await?,
        ProjectionProgress::Prepared
    );
    Ok(())
}

async fn publish_unrelated(
    store: &ChStore<SystemClock>,
    original: &Sample,
    ch: &Value,
    admin: &sqlx::PgPool,
) -> Result<()> {
    let scope = original.input().stream.scope().clone();
    let authority = ScopeAuthority(scope.clone());
    let (first, first_id) = unrelated_batch(original, &authority, "pending-other-stream")?;
    let (second, second_id) = unrelated_batch(original, &authority, "following-other-stream")?;
    verify_queue(store, &first_id, admin).await?;
    interrupt_projection(store, ch, &first, &first_id).await?;
    ensure!(matches!(
        Box::pin(store.write(&second, cutoff()?)).await,
        Err(rss_timeseries::Error::Unavailable)
    ));
    assert_eq!(
        store.progress(&second_id, cutoff()?).await?,
        ProjectionProgress::NotVisible
    );
    let recovered = Box::pin(store.recover(&scope, &authority, cutoff()?)).await?;
    ensure!(
        matches!(recovered, Outcome::Accepted(Some(ref r)) | Outcome::Replay(Some(ref r)) if r.identity().batch_id == first_id.request().batch_id)
    );
    ensure!(matches!(
        Box::pin(store.write(&second, cutoff()?)).await?,
        Outcome::Accepted(_)
    ));
    assert_eq!(
        store.progress(&second_id, cutoff()?).await?,
        ProjectionProgress::Published
    );
    Ok(())
}

async fn fence_budget(
    store: &ChStore<SystemClock>,
    budget_scope: rss_timeseries::Scope,
) -> Result<Authorized<MaintenanceRequest>> {
    let budget_authority = ScopeAuthority(budget_scope.clone());
    let request = |n: u32| -> Result<_> {
        let selection = Selection::Resource {
            scope: budget_scope.clone(),
            subject: Id::new(format!("target-{n}"))?,
            resource: Id::new("device")?,
            keys: Default::default(),
        };
        let op = MaintenanceRequest::new(
            Id::new(format!("cutoff-{n}"))?,
            MaintenanceAction::AdvanceCutoff {
                selection,
                before: Timestamp::new(10)?,
            },
            MaintenanceBudget {
                rows: std::num::NonZeroU32::MIN,
                buckets: std::num::NonZeroU32::MIN,
            },
        )?;
        Ok(Authorized::<MaintenanceRequest>::verify(
            &budget_authority,
            op,
        )?)
    };
    for n in 1..=100 {
        ensure!(matches!(
            store.step(&request(n)?, None, cutoff()?).await?,
            Outcome::Accepted(_)
        ));
    }
    let blocked = request(101)?;
    ensure!(matches!(
        store.step(&blocked, None, cutoff()?).await,
        Err(rss_timeseries::Error::BudgetExceeded)
    ));
    Ok(blocked)
}

async fn expand_fence_budget(
    config: &crate::telemetry::Config,
    ch: &Value,
    tenant: TenantId,
    client_password: &str,
    blocked: &Authorized<MaintenanceRequest>,
) -> Result<()> {
    let mut expanded = ch["configuration"].clone();
    expanded["backend"]["max_fences"] = json!(1000);
    let expanded: crate::telemetry::Config = serde_json::from_value(expanded)?;
    ensure!(expanded.configuration_binding()? == config.configuration_binding()?);
    let (owner, enlarged) = open(&expanded, ch, tenant, client_password).await?;
    ensure!(matches!(
        enlarged.step(blocked, None, cutoff()?).await?,
        Outcome::Accepted(_)
    ));
    owner.close(cutoff()?).await?;
    Ok(())
}

impl Upload {
    pub(in super::super) async fn exhaust_retention_fences(
        &self,
        ch: &Value,
        password: &str,
    ) -> Result<()> {
        let tenant = self.principal.tenant();
        let config = serde_json::from_value(ch["configuration"].clone())?;
        let (owner, store) = open(&config, ch, tenant, password).await?;
        fence_budget(
            &store,
            rss_timeseries::Scope::new(tenant, Id::new("mdm.telemetry")?),
        )
        .await?;
        owner.close(cutoff()?).await?;
        Ok(())
    }

    pub(in super::super) async fn retention_health(
        &self,
        browser: &mut Browser,
        primary: &sqlx::PgPool,
        state: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let tenant = self.principal.tenant();
        let device = self.principal.device();
        let field = self.history["field"].as_str().context("telemetry field")?;
        let updated = sqlx::query("UPDATE mdm_telemetry.retention_targets SET result=NULL,phase=0,next_check=0,due_at=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE tenant_id=$1::uuid AND device=$2 AND field=$3")
            .bind(tenant.to_string()).bind(device.into_uuid()).bind(field).execute(primary).await?;
        ensure!(updated.rows_affected() > 0);
        let path = format!("/api/v1/tenants/{tenant}/telemetry/health");
        let query = json!({"device":device,"field":field,"receivedFrom":0,"receivedUntil":i64::MAX,"maxBatches":16});
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let (status, body) = browser
                    .call(Method::POST, &path, Some(query.clone()), None)
                    .await?;
                ensure!(status == 200, "retention health {status}: {body}");
                let targets = body["retention"]
                    .as_array()
                    .context("health retention targets")?;
                if targets.iter().any(|row| {
                    let progress = &row["progress"];
                    progress["state"] == state && progress["reason"].as_str() == reason
                }) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .with_context(|| format!("worker health {state} {reason:?}"))?
    }

    async fn aggregate(&self, browser: &mut Browser, after: Option<&str>) -> Result<(u16, Value)> {
        let mut query = self.history.clone();
        let start = self.input.observations[0].observed_at;
        query["startMicros"] = json!(start.to_string());
        query["endMicros"] = json!((start + 2).to_string());
        if let Some(cursor) = after {
            query["after"] = json!(cursor);
        }
        let request = json!({"query":query,"definitionVersion":"1","source":"agent.script","epoch":self.input.configuration().source_epoch,
            "dimensions":{},"resolutionMicros":"1","operation":"mean","coverage":{"coverage":"observedOnly"},"maxGapMicros":null});
        browser
            .call(
                Method::POST,
                &format!(
                    "/api/v1/tenants/{}/telemetry/aggregate",
                    self.principal.tenant()
                ),
                Some(request),
                None,
            )
            .await
    }

    pub(in super::super) async fn aggregate_pages(&self, browser: &mut Browser) -> Result<String> {
        let (status, first) = self.aggregate(browser, None).await?;
        ensure!(
            status == 200 && first["buckets"].as_array().is_some_and(|b| b.len() == 1),
            "first aggregate page {status}: {first}"
        );
        let cursor = first["next"].as_str().context("aggregate continuation")?;
        let (status, second) = self.aggregate(browser, Some(cursor)).await?;
        ensure!(
            status == 200
                && second["next"].is_null()
                && second["buckets"].as_array().is_some_and(|b| b.len() == 1)
                && first["buckets"][0]["window"] != second["buckets"][0]["window"],
            "second aggregate page {status}: {second}"
        );
        let mut latest = self.history.clone();
        latest["mode"] = json!("latest");
        let (status, body) = browser
            .call(
                Method::POST,
                &format!(
                    "/api/v1/tenants/{}/telemetry/history",
                    self.principal.tenant()
                ),
                Some(latest),
                None,
            )
            .await?;
        ensure!(
            status == 200 && body["rows"].as_array().is_some_and(|r| !r.is_empty()),
            "latest {status}: {body}"
        );
        Ok(cursor.to_owned())
    }

    pub(in super::super) async fn verify_snapshot(
        &self,
        browser: &mut Browser,
        client_password: &str,
        ch: &Value,
    ) -> Result<()> {
        let cursor = self.aggregate_pages(browser).await?;
        let (_, baseline) = self.aggregate(browser, Some(&cursor)).await?;
        let tenant = self.principal.tenant();
        let id = Uuid::parse_str(&tenant.to_string())?;
        let original: Sample = serde_json::from_str(&recovery::admin_sql(ch, &format!(
            "SELECT payload FROM rss_ts_ch.raw WHERE tenant='{id}' AND generation='{}' AND observed_at={} LIMIT 1 FORMAT TabSeparatedRaw",
            self.input.configuration().source_epoch, self.input.observations[0].observed_at)).await?)?;
        let config: crate::telemetry::Config = serde_json::from_value(ch["configuration"].clone())?;

        let (owner, store) = open(&config, ch, tenant, client_password).await?;
        let admin: crate::config::Database = serde_json::from_value(ch["administrator"].clone())?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(admin.options()?)
            .await?;
        Box::pin(publish_unrelated(&store, &original, ch, &pool))
            .await
            .context("unrelated published revisions and queue capacity")?;
        pool.close().await;
        let (status, continued) = self.aggregate(browser, Some(&cursor)).await?;
        ensure!(
            status == 200 && continued["buckets"] == baseline["buckets"],
            "unrelated stream changed continuation"
        );

        self.check_invalidation(browser, &store, &original, &cursor)
            .await?;
        let scope = rss_timeseries::Scope::new(tenant, Id::new("fence-budget-proof")?);
        let blocked = fence_budget(&store, scope).await?;
        owner.close(cutoff()?).await?;
        expand_fence_budget(&config, ch, tenant, client_password, &blocked).await
    }

    async fn check_invalidation(
        &self,
        browser: &mut Browser,
        store: &ChStore<SystemClock>,
        original: &Sample,
        cursor: &str,
    ) -> Result<()> {
        let tenant = self.principal.tenant();
        let authority = ScopeAuthority(original.input().stream.scope().clone());
        let series = original.input().series.clone();
        let start = original.input().observed_at.micros();
        let delete = MaintenanceRequest::new(
            Id::new("snapshot-test-delete")?,
            MaintenanceAction::Delete {
                selection: Selection::Exact {
                    stream: original.input().stream.clone(),
                    series,
                },
                window: Interval::new(Timestamp::new(start)?, Timestamp::new(start + 2)?)?,
                restore_until: Timestamp::new(i64::MAX - 1)?,
            },
            MaintenanceBudget {
                rows: std::num::NonZeroU32::MIN,
                buckets: std::num::NonZeroU32::MIN,
            },
        )?;
        let step = store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority, delete)?,
                None,
                cutoff()?,
            )
            .await?;
        ensure!(matches!(step, Outcome::Accepted(_) | Outcome::Replay(_)));
        let (status, changed) = self.aggregate(browser, Some(cursor)).await?;
        ensure!(
            status == 409 && changed["code"] == "query_cursor_invalidated",
            "changed aggregate {status}: {changed}"
        );
        let mut history = self.history.clone();
        history["after"] = json!(self.cursor);
        let (status, lost) = browser
            .call(
                Method::POST,
                &format!("/api/v1/tenants/{tenant}/telemetry/history"),
                Some(history),
                None,
            )
            .await?;
        ensure!(
            status == 409 && lost["code"] == "query_result_unavailable",
            "expired history {status}: {lost}"
        );
        Ok(())
    }
}

struct ScopeAuthority(rss_timeseries::Scope);
impl rss_timeseries::Authority for ScopeAuthority {
    fn authorize(
        &self,
        access: rss_timeseries::Access<'_>,
    ) -> std::result::Result<(), rss_timeseries::Error> {
        use rss_timeseries::Access;
        let scope = match access {
            Access::Write(batch) => batch.stream().scope(),
            Access::Receipt(query) => query.stream.scope(),
            Access::Maintain(request) => request.scope(),
            _ => return Err(rss_timeseries::Error::Unauthorized),
        };
        if scope == &self.0 {
            Ok(())
        } else {
            Err(rss_timeseries::Error::Unauthorized)
        }
    }
}
