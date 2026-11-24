//! Fixed workload through the WNS registration, provider TLS endpoint and real PostgreSQL pools.
use super::*;
use anyhow::Context as _;
use rss_request_context::Clock as _;
use std::sync::atomic::AtomicUsize;

#[allow(
    clippy::disallowed_methods,
    reason = "measures two readings of the same injected host clock for the capacity report"
)]
fn elapsed(start: std::time::Instant) -> Duration {
    crate::lifecycle::RuntimeTimer.now().duration_since(start)
}
#[derive(Default)]
struct Traffic {
    active: AtomicUsize,
    peak: AtomicUsize,
    goal: AtomicUsize,
    by_credential: [AtomicUsize; 2],
    credential_peaks: [AtomicUsize; 2],
}

/// Observe the cursor after the real worker has consumed a later page containing B.
struct PeerPage {
    owner: Arc<crate::assembly::windows_business::WindowsBusiness>,
    peer: (Uuid, Uuid),
    ready: AtomicBool,
    consumed: tokio_util::sync::CancellationToken,
}
impl rss_mdm_windows_channel::participants::WakeDemand for PeerPage {
    fn candidates<'a>(
        &'a self,
        connection: &'a mut sqlx::PgConnection,
        after: Option<(Uuid, Uuid)>,
    ) -> rss_mdm_windows_channel::participants::Pending<
        'a,
        Vec<rss_mdm_windows_channel::participants::WakeCandidate>,
    > {
        Box::pin(async move {
            if after.is_some_and(|key| key >= self.peer) && self.ready.load(Ordering::Acquire) {
                self.consumed.cancel();
            }
            let rows = self.owner.candidates(connection, after).await?;
            if after.is_some()
                && rows
                    .iter()
                    .any(|(t, d, _, ms)| (*t, *d) == self.peer && *ms == 0)
            {
                self.ready.store(true, Ordering::Release);
            }
            Ok(rows)
        })
    }
    fn pending<'a>(
        &'a self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &'a mut sqlx::PgConnection,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> rss_mdm_windows_channel::participants::Pending<'a, bool> {
        self.owner.pending(binding, tx, device)
    }
}

#[tokio::test]
#[ignore = "T2: configured WNS limits bound actual provider requests on a fixed cross-page workload"]
async fn configured_wns_capacity_measures_actual_sends_and_settlements() -> Result<()> {
    let c = Context::open("external_capacity", &[]).await?;
    let peer = Context::open("external_capacity", &[]).await?;
    let third = Context::open("external_capacity", &[]).await?;
    let (c, third) = if c.tenant.to_string() < third.tenant.to_string() {
        (c, third)
    } else {
        (third, c)
    };
    let shared = identity::seed(&third, "windows").await?;
    let _shared_host = windows(&third, &shared).await?;
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
        Uuid::parse_str(&third.tenant.to_string())?,
    ];
    const HOT_JOBS: i64 = 34;
    const JOBS: i64 = HOT_JOBS + 24;
    let mut peer_device = None;
    for (ctx, sid, lane, count) in [
        (&c, "ms-app://capacity-a", 0, HOT_JOBS),
        (&peer, "ms-app://capacity-b", 1, 12),
        (&third, "ms-app://capacity-a", 2, 12),
    ] {
        let config = selected_configuration(ctx, key, sid).await?;
        for _ in 0..count {
            let device = crate::planning_t2_support::endpoint(ctx).await?.members[0].device;
            if lane == 2 {
                peer_device = Some(device.into_uuid());
            }
            let provider = usize::from(lane == 1);
            let uri = format!(
                "https://fixture.notify.windows.com/capacity/{provider}/{lane}/{}",
                device.into_uuid()
            );
            channel(ctx, device, key, config, uri.as_bytes()).await?;
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
    let handoff = Arc::new(AtomicBool::new(false));
    let (arrivals, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let route = {
        let handoff = handoff.clone();
        let traffic = traffic.clone();
        axum::routing::post(
            move |axum::extract::Path((index, lane, device)): axum::extract::Path<(
                usize,
                usize,
                Uuid,
            )>,
                  headers: axum::http::HeaderMap| {
                let traffic = traffic.clone();
                let (handoff, arrivals) = (handoff.clone(), arrivals.clone());
                async move {
                    assert_eq!(
                        headers["authorization"].to_str().unwrap(),
                        format!("Bearer capacity-{index}")
                    );
                    let credential =
                        traffic.by_credential[index].fetch_add(1, Ordering::AcqRel) + 1;
                    traffic.credential_peaks[index].fetch_max(credential, Ordering::AcqRel);
                    let active = traffic.active.fetch_add(1, Ordering::AcqRel) + 1;
                    traffic.peak.fetch_max(active, Ordering::AcqRel);
                    if handoff.load(Ordering::Acquire) {
                        let (release, wait) = tokio::sync::oneshot::channel();
                        let _ = arrivals.send((lane, device, release));
                        let _ = wait.await;
                    } else {
                        while traffic.peak.load(Ordering::Acquire)
                            < traffic.goal.load(Ordering::Acquire)
                        {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        tokio::time::sleep(Duration::from_millis(120)).await;
                    }
                    traffic.by_credential[index].fetch_sub(1, Ordering::AcqRel);
                    traffic.active.fetch_sub(1, Ordering::AcqRel);
                    axum::http::StatusCode::OK
                }
            },
        )
    };
    use axum::response::IntoResponse;
    use tokio_util::sync::CancellationToken;
    let cold = Arc::new(AtomicBool::new(true));
    let entered = CancellationToken::new();
    let release = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let oauth = {
        let (cold, entered, release, attempts) = (
            cold.clone(),
            entered.clone(),
            release.clone(),
            attempts.clone(),
        );
        axum::routing::post(move |body: String| {
            let (cold, entered, release, attempts) = (
                cold.clone(),
                entered.clone(),
                release.clone(),
                attempts.clone(),
            );
            async move {
                if cold.load(Ordering::Acquire) {
                    attempts.fetch_add(1, Ordering::AcqRel);
                    entered.cancel();
                    release.cancelled().await;
                    return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                let index = usize::from(body.contains("capacity-b"));
                axum::Json(serde_json::json!({"token_type":"bearer","access_token":format!("capacity-{index}"),"expires_in":600})).into_response()
            }
        })
    };
    let router = axum::Router::new()
        .route("/accesstoken.srf", oauth)
        .route("/capacity/{index}/{lane}/{device}", route);
    let server = tokio::spawn(axum::serve(listener, router).into_future());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_task_with_token(
        push::registration(
            h.state.clone(),
            owner.clone(),
            h.receipts.audit.clone(),
            rss_mdm_work_page::external::Limits::new(8.try_into()?, 7.try_into()?).unwrap(),
            Arc::new(tokio::sync::Notify::new()),
        )
        .critical(),
    );
    launch.finish();
    tokio::time::timeout(Duration::from_secs(6), entered.cancelled()).await?;
    let claimed:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_windows.push_channels WHERE tenant_id=ANY($1) AND lease_id IS NOT NULL").bind(&tenants).fetch_one(&c.operator).await?;
    let drain = stack.shutdown();
    release.cancel();
    assert!(drain.join().await?.is_clean());
    assert_eq!(claimed, 0, "slow OAuth must precede every durable lease");
    assert!(attempts.load(Ordering::Acquire) <= tenants.len());
    cold.store(false, Ordering::Release);
    let peer_device = peer_device.unwrap();
    let consumed = CancellationToken::new();
    let witness = Arc::new(PeerPage {
        owner: owner.clone(),
        peer: (tenants[2], peer_device),
        ready: AtomicBool::new(false),
        consumed: consumed.clone(),
    });
    sqlx::query("UPDATE mdm_windows.push_channels SET next_push=clock_timestamp()+interval '1 hour' WHERE tenant_id=ANY($1)")
        .bind(&tenants[1..]).execute(&c.operator).await?;
    let hint = Arc::new(tokio::sync::Notify::new());
    handoff.store(true, Ordering::Release);
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut start = stack.startup()?.commit();
    start.stage_task_with_token(
        push::registration(
            h.state.clone(),
            witness,
            h.receipts.audit.clone(),
            rss_mdm_work_page::external::Limits::new(8.try_into()?, 8.try_into()?).unwrap(),
            hint.clone(),
        )
        .critical(),
    );
    start.finish();
    let mut held = Vec::new();
    let proof = tokio::time::timeout(Duration::from_secs(5), async {
        while held.len()<8 {
            let (lane, _, release) = requests.recv().await.context("WNS provider exited")?;
            anyhow::ensure!(lane == 0);
            held.push(release);
        }
        sqlx::query("UPDATE mdm_windows.push_channels SET next_push=clock_timestamp() WHERE tenant_id=$1 AND device=$2")
            .bind(tenants[2]).bind(peer_device).execute(&c.operator).await?;
        hint.notify_one();
        consumed.cancelled().await;
        held.pop().unwrap().send(()).unwrap();
        let (lane,device,release) = requests.recv().await.context("missing WNS handoff")?;
        anyhow::ensure!((lane,device) == (2,peer_device), "A refilled before discovered B");
        release.send(()).unwrap();
        loop {
            let accepted:bool=sqlx::query_scalar("SELECT settled_id IS NOT NULL AND status=200 AND outcome='accepted' FROM mdm_windows.push_channels WHERE tenant_id=$1 AND device=$2")
                .bind(tenants[2]).bind(peer_device).fetch_one(&c.operator).await?;
            if accepted {break;}
            tokio::task::yield_now().await;
        }
        anyhow::ensure!(held.len()==7 && traffic.peak.load(Ordering::Acquire) == 8);
        Ok::<_,anyhow::Error>(())
    }).await;
    let drain = stack.shutdown();
    handoff.store(false, Ordering::Release);
    drop(held);
    // An A refill can start as soon as B has settled.
    requests.close();
    while let Ok((_, _, release)) = requests.try_recv() {
        let _ = release.send(());
    }
    anyhow::ensure!(drain.join().await?.is_clean());
    proof??;
    let mut measurements = Vec::new();
    for (total, resource, single) in [
        (1usize, 1usize, true),
        (8, 8, true),
        (8, 3, true),
        (4, 3, false),
        (8, 7, false),
        (16, 15, false),
        (8, 1, false),
    ] {
        let selected = if single { &tenants[..1] } else { &tenants[..] };
        let jobs = if single { HOT_JOBS } else { JOBS };
        sqlx::query("UPDATE mdm_windows.push_channels SET status=NULL,outcome=NULL,settled_id=NULL,next_push=CASE WHEN tenant_id=ANY($2) THEN clock_timestamp() ELSE clock_timestamp()+interval '1 hour' END WHERE tenant_id=ANY($1)").bind(&tenants).bind(selected).execute(&c.operator).await?;
        let ceiling = total.min(if single { resource } else { 2 * resource });
        traffic.goal.store(ceiling, Ordering::Release);
        traffic.peak.store(0, Ordering::Release);
        for v in &traffic.credential_peaks {
            v.store(0, Ordering::Release);
        }
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = stack.startup()?.commit();
        let db_start: f64 =
            sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::float8")
                .fetch_one(&c.operator)
                .await?;
        let start = crate::lifecycle::RuntimeTimer.now();
        launch.stage_task_with_token(
            push::registration(
                h.state.clone(),
                owner.clone(),
                h.receipts.audit.clone(),
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
                let before=crate::lifecycle::RuntimeTimer.now();
                let conn=pool.acquire().await?;
                waits.push(elapsed(before).as_secs_f64()*1000.);
                drop(conn);
                let (count,p95):(i64,Option<f64>)=sqlx::query_as("SELECT count(*),percentile_cont(0.95) WITHIN GROUP(ORDER BY (extract(epoch FROM next_push)::float8-120-$2)*1000) FROM mdm_windows.push_channels WHERE tenant_id=ANY($1) AND settled_id IS NOT NULL AND status=200 AND outcome='accepted'").bind(selected).bind(db_start).fetch_one(&c.operator).await?;
                if count==jobs {break Ok::<_,anyhow::Error>((p95.unwrap(),elapsed(start).as_secs_f64()));}
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }).await;
        anyhow::ensure!(stack.shutdown().join().await?.is_clean());
        let (settlement_ms, seconds) = measured??;
        let peak = traffic.peak.load(Ordering::Acquire);
        anyhow::ensure!(
            peak == ceiling,
            "expected {ceiling} concurrent provider calls, measured {peak}"
        );
        let per_sid = traffic
            .credential_peaks
            .each_ref()
            .map(|v| v.load(Ordering::Acquire));
        anyhow::ensure!(
            per_sid[0] > 0 && (single || per_sid[1] > 0) && per_sid.iter().all(|&n| n <= resource),
            "SID peaks {per_sid:?}, limit {resource}"
        );
        waits.sort_by(f64::total_cmp);
        measurements.push(serde_json::json!({"total":total,"perCredential":resource,"jobs":jobs,"singleTenant":single,"peakHttps":peak,"credentialPeaks":per_sid,"completedPerSecond":jobs as f64/seconds,"readyToSettlementP95Ms":settlement_ms,"accessPoolProbeP95Ms":waits[(waits.len()*95).div_ceil(100)-1]}));
    }
    server.abort();
    let _ = server.await;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/local-t2/wns-capacity.json");
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, serde_json::to_vec_pretty(&measurements)?)?;
    h.close().await?;
    third.close().await;
    peer.close().await;
    c.close().await;
    Ok(())
}
