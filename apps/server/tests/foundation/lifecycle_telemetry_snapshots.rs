//! Product HTTP paging and bounded admission against the installed ClickHouse owner.
use super::*;
impl Upload {
    /// Hold the sole installed CH operation in provider IO; one waiter fits and the third read gets 503.
    pub(in super::super) async fn verify_queue(
        &self,
        browser: &Browser,
        other: &Self,
        peer: &Browser,
        admin: &sqlx::PgPool,
    ) -> Result<()> {
        use futures::{StreamExt, stream::FuturesUnordered};
        let mut blocker = admin.begin().await?;
        sqlx::query("LOCK TABLE rss_ts_ch.namespaces IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;
        let mut calls = FuturesUnordered::new();
        for (data, mut client) in [
            (self, browser.clone()),
            (other, peer.clone()),
            (self, browser.clone()),
        ] {
            calls.push(async move {
                client
                    .call(
                        Method::POST,
                        &format!(
                            "/api/v1/tenants/{}/telemetry/history",
                            data.principal.tenant()
                        ),
                        Some(data.history.clone()),
                        None,
                    )
                    .await
            });
        }
        let (status, body) = tokio::time::timeout(Duration::from_secs(4), calls.next())
            .await?
            .context("three concurrent reads")??;
        ensure!(status == 503, "queue overflow {status}: {body}");
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE current_database()=datname AND usename='metrics_click_house' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))").fetch_one(&mut *blocker).await?;
        ensure!(
            blocked,
            "overload observed before the held reader completed"
        );
        blocker.rollback().await?;
        while let Some(reply) = calls.next().await {
            let (status, body) = reply?;
            ensure!(
                status == 200 && body["rows"].as_array().is_some_and(|r| !r.is_empty()),
                "queued read {status}: {body}"
            );
        }
        Ok(())
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
        use rss_timeseries::{
            Authorized, Batch, Id, Interval, Maintainer, MaintenanceAction, MaintenanceBudget,
            MaintenanceRequest, Outcome, ReceiptQuery, Sample, SampleInput, Selection, Stream,
            Timestamp, Writer,
        };
        use rss_timeseries_clickhouse::{Credentials, CursorKey, ProjectionProgress};
        let cursor = self.aggregate_pages(browser).await?;
        let (_, baseline) = self.aggregate(browser, Some(&cursor)).await?;
        let tenant = self.principal.tenant();
        let id = Uuid::parse_str(&tenant.to_string())?;
        let original: Sample = serde_json::from_str(&recovery::admin_sql(ch, &format!(
            "SELECT payload FROM rss_ts_ch.raw WHERE tenant='{id}' AND generation='{}' AND observed_at={} LIMIT 1 FORMAT TabSeparatedRaw",
            self.input.configuration().source_epoch, self.input.observations[0].observed_at)).await?)?;
        let config: crate::telemetry::Config = serde_json::from_value(ch["configuration"].clone())?;
        let rss_mdm_telemetry_service::backend::Backend::ClickHouse(owner) =
            config.open_backend().await?
        else {
            anyhow::bail!("expected ClickHouse")
        };
        let cutoff = || {
            rss_request_context::Deadline::from_timeout(
                &rss_mdm_telemetry_service::backend::SystemClock,
                Duration::from_secs(10),
            )
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
        let scope = original.input().stream.scope().clone();
        let authority = ScopeAuthority(scope.clone());
        let new_batch = |name: &str| -> Result<_> {
            let mut input: SampleInput = original.clone().into();
            input.stream =
                Stream::new(scope.clone(), Id::new(name)?, Id::new("sample-generation")?);
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
                Authorized::<Batch>::verify(&authority, batch)?,
                Authorized::<ReceiptQuery>::verify(&authority, identity)?,
            ))
        };
        let (first, first_id) = new_batch("pending-other-stream")?;
        let (second, second_id) = new_batch("following-other-stream")?;
        recovery::admin_sql(ch, "REVOKE INSERT ON rss_ts_ch.raw FROM metric_writer").await?;
        let interrupted = store.write(&first, cutoff()?).await;
        recovery::admin_sql(ch, "GRANT INSERT ON rss_ts_ch.raw TO metric_writer").await?;
        ensure!(!matches!(
            interrupted,
            Ok(Outcome::Accepted(_) | Outcome::Replay(_))
        ));
        ensure!(matches!(
            store.progress(&first_id, cutoff()?).await?,
            ProjectionProgress::Prepared
        ));
        ensure!(matches!(
            store.write(&second, cutoff()?).await,
            Err(rss_timeseries::Error::Unavailable)
        ));
        ensure!(matches!(
            store.progress(&second_id, cutoff()?).await?,
            ProjectionProgress::NotVisible
        ));
        let recovered = store.recover(&scope, &authority, cutoff()?).await?;
        ensure!(
            matches!(recovered, Outcome::Accepted(Some(ref r)) | Outcome::Replay(Some(ref r)) if r.identity().batch_id == first_id.request().batch_id)
        );
        ensure!(matches!(
            store.write(&second, cutoff()?).await?,
            Outcome::Accepted(_)
        ));
        ensure!(matches!(
            store.progress(&second_id, cutoff()?).await?,
            ProjectionProgress::Published
        ));
        let (status, continued) = self.aggregate(browser, Some(&cursor)).await?;
        ensure!(
            status == 200 && continued["buckets"] == baseline["buckets"],
            "unrelated stream changed continuation"
        );
        let series = original.input().series.clone();
        let start = self.input.observations[0].observed_at;
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
        let (status, changed) = self.aggregate(browser, Some(&cursor)).await?;
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
        // A fresh isolated namespace exercises the product default without consuming other readers' fences.
        let budget_scope = rss_timeseries::Scope::new(tenant, Id::new("fence-budget-proof")?);
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
        owner.close(cutoff()?).await?;
        let mut expanded = ch["configuration"].clone();
        expanded["backend"]["max_fences"] = json!(1000);
        let expanded: crate::telemetry::Config = serde_json::from_value(expanded)?;
        ensure!(expanded.configuration_binding()? == config.configuration_binding()?);
        let rss_mdm_telemetry_service::backend::Backend::ClickHouse(owner) =
            expanded.open_backend().await?
        else {
            anyhow::bail!("expected expanded ClickHouse owner")
        };
        let reader = Credentials::new(recovery::reader(ch, id)?, client_password.to_owned())?;
        let enlarged = owner
            .bind_tenant(
                tenant,
                reader,
                CursorKey::new([3; 32]),
                std::num::NonZeroU64::MIN,
                cutoff()?,
            )
            .await?;
        ensure!(matches!(
            enlarged.step(&blocked, None, cutoff()?).await?,
            Outcome::Accepted(_)
        ));
        owner.close(cutoff()?).await?;
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
