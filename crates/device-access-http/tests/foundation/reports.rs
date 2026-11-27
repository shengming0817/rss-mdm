//! Production HTTP + TLS + PostgreSQL report admission, replay, paging and effect isolation.
use super::*;
use rss_mdm_agent_wire::da;
pub async fn verify(
    c: &Context,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    token: &str,
    registration: &da::Registration,
    signed: &da::SignedConfiguration,
) -> Result<()> {
    let management = c.management_base();
    let identity = da::ReportIdentity {
        service_id: registration.service_id,
        tenant: registration.tenant,
        device_id: registration.device,
    };
    let mut report = da::StatusReport {
        identity: identity.clone(),
        sequence: 1,
        observed_at: Some(0),
        client_version: "foundation".into(),
        modules: da::ClientModules {
            da: da::ModuleObservation {
                installed: Some(true),
                enabled: Some(true),
            },
            mdm: da::ModuleObservation {
                installed: None,
                enabled: Some(false),
            },
            application: da::ModuleApplication::Pending,
        },
        contract_version: 1,
        binding: da::Health::Ready,
        factor: da::Health::Ready,
        health: da::Health::Ready,
        configuration_digest: Some(signed.digest.clone()),
        errors: vec![],
    };
    let url = format!("{base}/status-reports");
    assert_eq!(client.post(&url).json(&report).send().await?.status(), 401);
    // Keep the first report durable on the DA side while the Observation owner is busy.
    let mut gate = c.operator.begin().await?;
    sqlx::query("LOCK TABLE rss_observation.objects IN SHARE MODE")
        .execute(&mut *gate)
        .await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_report_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'lost DA acknowledgement'; END $$; CREATE TRIGGER reject_report_ack BEFORE UPDATE OF delivery_pending ON rss_da.report_history FOR EACH ROW WHEN (OLD.delivery_pending AND NOT NEW.delivery_pending) EXECUTE FUNCTION public.reject_report_ack()").execute(&c.operator).await?;
    let first: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    let repeated: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    assert_eq!(
        first, repeated,
        "exact retry preserves the original receipt time"
    );
    assert_eq!(first["evidence"], "reported");
    report.health = da::Health::Blocked;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 409);
    report.health = da::Health::Ready;
    report.sequence = 2;
    report.identity.device_id = rss_mdm_agent_wire::DeviceId::new_v4();
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 403);
    report.identity = identity.clone();
    let application = da::ApplicationReport {
        identity,
        operation_id: Uuid::new_v4(),
        sequence: 1,
        artifact: signed.decode()?.operation_id,
        digest: signed.digest.clone(),
        sources: vec![da::ReportedSource {
            artifact: signed.decode()?.operation_id,
            digest: signed.digest.clone(),
            delivery: da::DeliveryPermission::ManagedMandatory,
            state: da::SourceState::Present,
        }],
        state: da::ApplicationState::Applied,
        error: None,
    };
    // Even a false managed-delivery claim cannot obtain verified status or signing-key ACK.
    let before:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.bindings),(SELECT count(*) FROM rss_da.signing_acknowledgements)").fetch_one(&c.operator).await?;
    let accepted: serde_json::Value = material::success(
        peer.post(format!("{base}/configuration-reports"))
            .json(&application)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(accepted["evidence"], "reported");
    let retry: serde_json::Value = material::success(
        peer.post(format!("{base}/configuration-reports"))
            .json(&application)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(accepted, retry);
    let after:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.bindings),(SELECT count(*) FROM rss_da.signing_acknowledgements)").fetch_one(&c.operator).await?;
    assert_eq!(before, after);
    let diagnostic: serde_json::Value = material::success(
        client
            .get(format!(
                "{management}/admin/devices/{}/configuration",
                registration.device
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert!(diagnostic["evidence"].is_null());
    assert_eq!(diagnostic["resolution"]["fields"][1]["source"], "da");
    assert_eq!(diagnostic["resolution"]["fields"][1]["locked"], false);
    report.client_version = "\\".repeat(128);
    report.errors = vec![da::Diagnostic::InvalidConfiguration; 16];
    report.observed_at = Some(i64::MAX);
    let second: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    let retry: serde_json::Value =
        material::success(peer.post(&url).json(&report).send().await?).await?;
    assert_eq!(retry, second);
    report.sequence = 3;
    assert_eq!(peer.post(&url).json(&report).send().await?.status(), 429);
    let mut intake = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *intake)
        .await?;
    let deleted = sqlx::query(
        "DELETE FROM rss_da.report_history WHERE tenant_id=$1::uuid AND delivery_pending",
    )
    .bind(c.tenant.to_string())
    .execute(&mut *intake)
    .await?;
    assert_eq!(
        deleted.rows_affected(),
        0,
        "intake login must preserve unacknowledged reports"
    );
    intake.rollback().await?;
    gate.rollback().await?;
    tokio::time::timeout(Duration::from_secs(20),async{
        loop{
            let count:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1 AND delivery_pending),(SELECT count(*) FROM rss_observation.batches WHERE tenant_id=$1)").bind(Uuid::parse_str(&c.tenant.to_string())?).fetch_one(&c.operator).await?;
            if count==(3,1){return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await??;
    sqlx::raw_sql("DROP TRIGGER reject_report_ack ON rss_da.report_history; DROP FUNCTION public.reject_report_ack()").execute(&c.operator).await?;
    tokio::time::timeout(Duration::from_secs(20),async{
        loop{
            let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1::uuid AND delivery_pending").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
            if remaining==0{return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await??;
    let received: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_observation.batches WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(received, 3);
    for sequence in 3..=4 {
        report.sequence = sequence;
        material::success::<serde_json::Value>(peer.post(&url).json(&report).send().await?).await?;
    }
    report.sequence = 1;
    assert_eq!(
        peer.post(&url).json(&report).send().await?.status(),
        409,
        "history pruning cannot reset sequence high-water"
    );
    let history = format!("{management}/admin/devices/{}/reports", registration.device);
    let page: serde_json::Value = material::success(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1")])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(page["items"][0]["receipt"]["sequence"], 4);
    assert_eq!(
        page["items"][0]["stale"], false,
        "device observedAt does not determine freshness"
    );
    let cursor = page["nextCursor"].as_str().unwrap();
    let next: serde_json::Value = material::success(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1"), ("cursor", cursor)])
            .send()
            .await?,
    )
    .await?;
    assert_eq!(next["items"][0]["receipt"]["sequence"], 3);
    assert!(next["nextCursor"].is_null());
    let invalidated = client
        .get(&history)
        .bearer_auth(token)
        .query(&[("kind", "application"), ("limit", "1"), ("cursor", cursor)])
        .send()
        .await?;
    assert_eq!(invalidated.status(), 409);
    assert_eq!(
        invalidated.json::<serde_json::Value>().await?["code"],
        "query_cursor_invalidated"
    );
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "101")])
            .send()
            .await?
            .status(),
        400
    );
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(token)
            .query(&[("limit", "1"), ("limit", "2")])
            .send()
            .await?
            .status(),
        400
    );
    // A retained offline snapshot is stale by the original server receipt time.
    sqlx::query("UPDATE rss_da.report_heads SET receipt = jsonb_set(receipt, '{receivedAt}', to_jsonb(CAST($1 AS bigint))) WHERE tenant_id = CAST($2 AS uuid) AND device = $3 AND kind = 'status'").bind(now()-901).bind(c.tenant.to_string()).bind(registration.device.into_uuid()).execute(&c.operator).await?;
    let stale: serde_json::Value = material::success(
        client
            .get(format!(
                "{management}/admin/devices/{}/status",
                registration.device
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(stale["stale"], true);
    assert_eq!(
        stale["report"]["modules"],
        serde_json::to_value(report.modules)?
    );
    assert_eq!(
        stale["report"]["observedAt"],
        serde_json::json!(report.observed_at)
    );
    let limited = material::device_administrator(c, &registration.device).await?;
    assert_eq!(
        client
            .get(&history)
            .bearer_auth(limited)
            .send()
            .await?
            .status(),
        403,
        "configuration write does not grant report read"
    );
    for suffix in ["status", "reports"] {
        let missing = format!("{management}/admin/devices/{}/{suffix}", Uuid::new_v4());
        assert_eq!(
            client
                .get(missing)
                .bearer_auth(token)
                .send()
                .await?
                .status(),
            404
        );
    }
    let current: serde_json::Value =
        material::success(peer.get(format!("{base}/configuration")).send().await?).await?;
    assert_eq!(current["state"], "present");
    let assets_url = format!(
        "{management}/admin/devices/{}/inventory",
        registration.device
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let view: serde_json::Value =
                material::success(client.get(&assets_url).bearer_auth(token).send().await?).await?;
            anyhow::ensure!(view["projection"]["state"] == "running");
            let facts = view["assets"].as_array().unwrap();
            if facts.len() == 2
                && facts
                    .iter()
                    .any(|asset| asset["kind"] == "status" && asset["sequence"] == 4)
            {
                anyhow::ensure!(facts.iter().all(|asset| asset["evidence"] == "reported"
                    && asset["position"].as_i64().is_some_and(|v| v > 0)));
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    // Establish the current database window explicitly; exercise both streams, and only
    // rebuild this prerequisite if the server clock actually crosses a minute boundary.
    let mut application = application;
    report.sequence = 5;
    for attempt in 0..3 {
        let minute: i64 = sqlx::query_scalar("UPDATE rss_da.report_budget SET minute=floor(extract(epoch FROM clock_timestamp()))::bigint/60,reports=9,bytes=0 WHERE tenant_id=$1::uuid RETURNING minute")
            .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
        application.sequence += 1;
        application.operation_id = Uuid::new_v4();
        let accepted: serde_json::Value = material::success(
            peer.post(format!("{base}/configuration-reports"))
                .json(&application)
                .send()
                .await?,
        )
        .await?;
        let response = peer.post(&url).json(&report).send().await?;
        if response.status() == 429 && accepted["receivedAt"].as_i64().unwrap() / 60 == minute {
            return mixed_page(c, peer, base, report, application).await;
        }
        let current: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint/60")
                .fetch_one(&c.operator)
                .await?;
        anyhow::ensure!(
            current != minute && attempt < 2,
            "quota must reject inside the same window: {}",
            response.status()
        );
        if response.status().is_success() {
            report.sequence += 1;
        } else {
            anyhow::ensure!(response.status() == 429, "unexpected budget response");
        }
    }
    unreachable!("bounded quota proof exits with a result")
}

async fn checkpoint(c: &Context, tenant: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT position FROM rss_projection.checkpoints WHERE tenant_id=$1 AND projection_id='da-inventory'")
        .bind(tenant).fetch_one(&c.operator).await
}

async fn pause_projection(
    c: &Context,
    tenant: Uuid,
) -> Result<(i64, sqlx::Transaction<'static, sqlx::Postgres>)> {
    use anyhow::Context as _;
    tokio::time::timeout(Duration::from_secs(20),async{
        loop{
            let caught:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM rss_da.report_history WHERE tenant_id=$1 AND delivery_pending) AND (SELECT position FROM rss_projection.checkpoints WHERE tenant_id=$1 AND projection_id='da-inventory')=(SELECT last_position FROM rss_observation.journals WHERE tenant_id=$1)").bind(tenant).fetch_one(&c.operator).await?;
            if caught{return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await??;
    let before = checkpoint(c, tenant).await?;
    let mut gate = c.operator.begin().await?;
    sqlx::query("LOCK TABLE rss_projection.checkpoints IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await?;
    tokio::time::timeout(Duration::from_secs(4),async{
        loop{
            let waiting:bool=sqlx::query_scalar("SELECT count(*)>=2 FROM pg_stat_activity WHERE usename='da_report_projection' AND $1=ANY(pg_blocking_pids(pid))").bind(pid).fetch_one(&c.operator).await?;
            if waiting{return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    }).await.context("both installed tenant workers at checkpoint")??;
    sqlx::query("DELETE FROM rss_da.report_budget WHERE tenant_id=$1")
        .bind(tenant)
        .execute(&c.operator)
        .await?;
    Ok((before, gate))
}

/// Queue both kinds behind the real projection checkpoint before releasing the worker.
async fn mixed_page(
    c: &Context,
    peer: &reqwest::Client,
    base: &str,
    mut status: da::StatusReport,
    mut application: da::ApplicationReport,
) -> Result<()> {
    use anyhow::{Context as _, ensure};
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    sqlx::raw_sql(include_str!(
        "../../../../hack/test-support/inventory-pages.sql"
    ))
    .execute(&c.operator)
    .await?;
    let (before, gate) = pause_projection(c, tenant).await?;
    status.sequence += 10;
    let large = status.clone();
    let mut small = status;
    small.sequence -= 1;
    small.client_version = "v".into();
    small.errors.clear();
    application.sequence += 10;
    application.operation_id = Uuid::new_v4();
    for (route, wire) in [
        ("status-reports", serde_json::to_value(&small)?),
        ("configuration-reports", serde_json::to_value(&application)?),
        ("status-reports", serde_json::to_value(&large)?),
    ] {
        let request = peer.post(format!("{base}/{route}")).json(&wire).build()?;
        let bytes = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .context("buffered report")?
            .len();
        material::success::<serde_json::Value>(peer.execute(request).await?).await?;
        eprintln!(
            "da_report_wire route={route} sequence={} bytes={bytes}",
            wire["sequence"]
        );
    }
    gate.commit().await?;
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if checkpoint(c, tenant).await? == before + 3 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let rows:Vec<(i64,i64,String,i32,i64)>=sqlx::query_as("SELECT b.log_position,p.position,b.scope::jsonb->>'dataset',octet_length(b.raw),b.sequence::bigint FROM rss_observation.batches b JOIN rss_projection.receipts r ON r.tenant_id=b.tenant_id AND r.event_id=encode(b.fingerprint,'hex') JOIN public.t2_inventory_pages p ON p.tenant=r.tenant_id AND p.projection=r.projection_id AND p.writer::text=r.xmin::text WHERE b.tenant_id=$1 AND b.log_position>$2 ORDER BY b.log_position").bind(tenant).bind(before).fetch_all(&c.operator).await?;
    ensure!(
        rows.iter()
            .map(|r| (r.0 - before, r.1 - before))
            .eq([(1, 2), (2, 2), (3, 3)]),
        "DA mixed page checkpoints {rows:?}"
    );
    let statuses: Vec<_> = rows.iter().filter(|r| r.2 == "status").collect();
    ensure!(
        statuses.len() == 2
            && statuses[0].4 == small.sequence
            && statuses[1].4 == large.sequence
            && statuses[0].3 < statuses[1].3
    );
    eprintln!("da_formal_mixed_pages coordinates={rows:?}, checkpoint_base={before}");
    sqlx::raw_sql("DROP TRIGGER t2_inventory_page ON rss_projection.checkpoints; DROP FUNCTION public.t2_inventory_page(); DROP TABLE public.t2_inventory_pages").execute(&c.operator).await?;
    Ok(())
}

/// Observe the number of page commits between delivery passes on a live backlog.
pub(super) async fn configured_page(
    c: &Context,
    runtime_file: &std::path::Path,
    peer: &reqwest::Client,
    base: &str,
    device: &da::Registration,
    rows: u32,
) -> Result<()> {
    const REPORTS: u32 = 65;
    let mut config: rss_da_app::config::Config = rss_da_app::config::load(runtime_file)?;
    config.projection_batch = rows;
    config.reports.history_count = REPORTS;
    config.reports.reports_per_minute = REPORTS;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let host = tokio::spawn(rss_da_app::host::serve(config, async move {
        stopped.await.map_err(std::io::Error::other)
    }));
    let result = async {
        let tenant = Uuid::parse_str(&c.tenant.to_string())?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(response) = peer.get(format!("{base}/configuration-trust")).send().await
                    && response.status().is_success() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await?;
        let (before, gate) = pause_projection(c, tenant).await?;
        sqlx::raw_sql(include_str!("../../../../hack/test-support/da-delivery-checkpoints.sql"))
            .execute(&c.operator).await?;
        let document: serde_json::Value = sqlx::query_scalar(
            "SELECT document FROM rss_da.report_heads WHERE tenant_id=$1 AND device=$2 AND kind='status'",
        ).bind(tenant).bind(device.device.into_uuid()).fetch_one(&c.operator).await?;
        let mut report: da::StatusReport = serde_json::from_value(document)?;
        for _ in 0..REPORTS {
            report.sequence += 1;
            material::success::<serde_json::Value>(
                peer.post(format!("{base}/status-reports")).json(&report).send().await?
            ).await?;
        }
        gate.commit().await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            while checkpoint(c, tenant).await? < before + i64::from(REPORTS) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<_, anyhow::Error>(())
        }).await??;
        let receipts: (i64,i64) = sqlx::query_as(
            "SELECT count(*),count(DISTINCT r.xmin::text) FROM rss_observation.batches b JOIN rss_projection.receipts r ON r.tenant_id=b.tenant_id AND r.projection_id='da-inventory' AND r.event_id=encode(b.fingerprint,'hex') WHERE b.tenant_id=$1 AND b.log_position>$2"
        ).bind(tenant).bind(before).fetch_one(&c.operator).await?;
        let expected_xids = i64::from(REPORTS.div_ceil(rows));
        anyhow::ensure!(receipts == (i64::from(REPORTS), expected_xids), "configured {rows}-row page produced {receipts:?}");
        let phases: Vec<(i64,i64)> = sqlx::query_as(
            "SELECT position-$1,count(*) FROM public.t2_da_delivery_progress WHERE tenant=$2 GROUP BY position ORDER BY position"
        ).bind(before).bind(tenant).fetch_all(&c.operator).await?;
        // Delivery sees the old checkpoint until the projection pass commits its pages.
        // With single-row pages, the 65th delivery sees a whole pass of 64 committed pages.
        let expected = if rows == 1 { vec![(0,64),(64,1)] } else { vec![(0,65)] };
        anyhow::ensure!(phases == expected, "delivery checkpoints for page {rows}: {phases:?}");
        eprintln!("da_configured_page rows={rows} receipts={} writer_xids={} delivery_checkpoints={phases:?}", receipts.0,receipts.1);
        sqlx::raw_sql("DROP TRIGGER t2_delivery ON rss_da.report_history; DROP FUNCTION public.t2_da_delivery(); DROP TABLE public.t2_da_delivery_progress")
            .execute(&c.operator).await?;
        Ok(())
    }.await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(50), host).await???;
    result
}

/// A second owner fences this tenant. The original serving process must stop clearing its pins.
pub(super) async fn fenced_backpressure(
    c: &Context,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    token: &str,
    device: &da::Registration,
) -> Result<()> {
    use rss_mdm_device_access_postgres::reports::inventory::{Admission, MIN_PAGE_BYTES};
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let pool = c.inputs.database("da_report_projection").pool().await?;
    let cutoff =
        rss_request_context::Deadline::from_timeout(&context::Timer, Duration::from_secs(10))?;
    let admission = Admission::check(
        pool.clone(),
        device.service_id,
        c.execution(),
        MIN_PAGE_BYTES,
        cutoff,
        Arc::new(context::Timer),
    )
    .await?;
    drop(admission.start(cutoff).await?);
    let url = format!(
        "{}/admin/devices/{}/inventory",
        c.management_base(),
        device.device
    );
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let data: serde_json::Value =
                material::success(client.get(&url).bearer_auth(token).send().await?).await?;
            if data["projection"]["state"] == "fenced" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    sqlx::query("DELETE FROM rss_da.report_budget WHERE tenant_id=$1")
        .bind(tenant)
        .execute(&c.operator)
        .await?;
    let mut report = da::StatusReport {
        identity: da::ReportIdentity {
            service_id: device.service_id,
            tenant,
            device_id: device.device,
        },
        sequence: 100,
        observed_at: None,
        client_version: "sample".into(),
        modules: Default::default(),
        contract_version: 1,
        binding: da::Health::Unknown,
        factor: da::Health::Unknown,
        health: da::Health::Unknown,
        configuration_digest: None,
        errors: vec![],
    };
    for (sequence, expected) in [(100, 200), (101, 200), (102, 429)] {
        report.sequence = sequence;
        let response = peer
            .post(format!("{base}/status-reports"))
            .json(&report)
            .send()
            .await?;
        assert_eq!(response.status().as_u16(), expected);
    }
    let pending:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1 AND device=$2 AND delivery_pending").bind(tenant).bind(device.device.into_uuid()).fetch_one(&c.operator).await?;
    assert_eq!(pending, 2);
    pool.close().await;
    Ok(())
}
