//! Fixed workload through the WNS registration, provider TLS endpoint and real PostgreSQL pools.
use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::time::Instant;

#[derive(Default)]
struct Traffic {
    active: AtomicUsize,
    peak: AtomicUsize,
}

#[tokio::test]
#[ignore = "T2: configured WNS limits bound actual provider requests on a fixed cross-page workload"]
async fn configured_wns_capacity_measures_actual_sends_and_settlements() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let peer = Context::open("shared", &[]).await?;
    let first = identity::seed(&c, "windows").await?;
    let second = identity::seed(&peer, "windows").await?;
    let windows_host = windows(&c, &first).await?;
    let _peer_host = windows(&peer, &second).await?;
    let listener = crate::provider_http_t2_support::Listener::open(&first.directory).await?;
    let h = host_with_provider(
        &c,
        &first,
        windows_host,
        Some((
            listener.address()?.port(),
            reqwest::Certificate::from_der(&first.root)?,
        )),
    )
    .await?;
    let a = &h.assembly;
    let key = &a.resources.protection;
    let owner = Arc::new(crate::assembly::windows_business::WindowsBusiness(
        a.service.clone(),
        a.configuration.clone(),
        a.collections.clone(),
        a.software.service.clone(),
        a.registration.native.clone(),
    ));
    let tenants = vec![
        Uuid::parse_str(&c.tenant.to_string())?,
        Uuid::parse_str(&peer.tenant.to_string())?,
    ];
    const JOBS: i64 = 36;
    for (ctx, sid) in [(&c, "ms-app://capacity-a"), (&peer, "ms-app://capacity-b")] {
        let config = selected_configuration(ctx, key, sid).await?;
        for _ in 0..JOBS / 2 {
            let device = crate::planning_t2_support::endpoint(ctx).await?.members[0].device;
            channel(
                ctx,
                device,
                key,
                config,
                b"https://fixture.notify.windows.com/capacity",
            )
            .await?;
            identity_cases::seed_device_group(
                ctx,
                device,
                key,
                &identity_cases::request(false, false)?,
                &[Uuid::new_v4()],
            )
            .await?;
        }
    }
    let traffic = Arc::new(Traffic::default());
    let route = {
        let traffic = traffic.clone();
        axum::routing::post(move || {
            let traffic = traffic.clone();
            async move {
                let active = traffic.active.fetch_add(1, Ordering::AcqRel) + 1;
                traffic.peak.fetch_max(active, Ordering::AcqRel);
                tokio::time::sleep(Duration::from_millis(300)).await;
                traffic.active.fetch_sub(1, Ordering::AcqRel);
                axum::http::StatusCode::OK
            }
        })
    };
    let router=axum::Router::new().route("/accesstoken.srf",axum::routing::post(||async {axum::Json(serde_json::json!({"token_type":"bearer","access_token":"capacity-token","expires_in":600}))})).route("/capacity",route);
    let server = tokio::spawn(axum::serve(listener, router).into_future());
    let mut measurements = Vec::new();
    for (total, resource) in [(1usize, 1usize), (4, 3), (8, 7), (16, 15), (8, 1)] {
        sqlx::query("UPDATE mdm_windows.push_channels SET status=NULL,outcome=NULL,settled_id=NULL,next_push=clock_timestamp() WHERE tenant_id=ANY($1)").bind(&tenants).execute(&c.operator).await?;
        traffic.peak.store(0, Ordering::Release);
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = stack.startup()?.commit();
        let db_start: f64 =
            sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::float8")
                .fetch_one(&c.operator)
                .await?;
        let start = Instant::now();
        launch.stage_deferred_task_with_token(
            push::registration(
                h.state.clone(),
                owner.clone(),
                rss_mdm_work_page::external::Limits::new(total.try_into()?, resource.try_into()?)
                    .unwrap(),
                Arc::new(tokio::sync::Notify::new()),
            )
            .critical(),
        );
        launch.finish();
        let pool = c.database.archive_pool();
        let mut waits = Vec::new();
        let measured=tokio::time::timeout(Duration::from_secs(40),async{
            loop {
                let before=Instant::now();
                let conn=pool.acquire().await?;
                waits.push(before.elapsed().as_secs_f64()*1000.);
                drop(conn);
                let (count,p95):(i64,Option<f64>)=sqlx::query_as("SELECT count(*),percentile_cont(0.95) WITHIN GROUP(ORDER BY (extract(epoch FROM next_push)::float8-120-$2)*1000) FROM mdm_windows.push_channels WHERE tenant_id=ANY($1) AND settled_id IS NOT NULL AND status=200 AND outcome='accepted'").bind(&tenants).bind(db_start).fetch_one(&c.operator).await?;
                if count==JOBS {break Ok::<_,anyhow::Error>((p95.unwrap(),start.elapsed().as_secs_f64()));}
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }).await;
        anyhow::ensure!(stack.shutdown().join().await?.is_clean());
        let (settlement_ms, seconds) = measured??;
        let peak = traffic.peak.load(Ordering::Acquire);
        let ceiling = total.min(2 * resource.saturating_sub(1).max(1));
        anyhow::ensure!(
            peak > 0 && peak <= ceiling,
            "peak {peak}, ceiling {ceiling}"
        );
        if total > 1 {
            anyhow::ensure!(peak >= 2);
        }
        waits.sort_by(f64::total_cmp);
        measurements.push(serde_json::json!({"total":total,"perCredential":resource,"jobs":JOBS,"peakHttps":peak,"completedPerSecond":JOBS as f64/seconds,"readyToSettlementP95Ms":settlement_ms,"accessPoolProbeP95Ms":waits[(waits.len()*95).div_ceil(100)-1]}));
    }
    server.abort();
    let _ = server.await;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/local-t2/wns-capacity.json");
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, serde_json::to_vec_pretty(&measurements)?)?;
    h.close().await?;
    peer.close().await;
    c.close().await;
    Ok(())
}
