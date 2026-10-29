use crate::planning::test_support::*;
use crate::planning::*;
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff};
use rss_reconcile_postgres::PgClaim;

type Worker = crate::test_support::workers::Workers;

async fn connect(service: &Arc<Application>) -> Arc<Worker> {
    Arc::new(
        Worker::open(service.clone(), None, options())
            .await
            .unwrap(),
    )
}

async fn claim(worker: &Worker) -> PgClaim {
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker
        .source
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap(),
            64,
            Duration::from_secs(30),
            &control,
        )
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.target().entity() == "changes")
        .unwrap()
}

async fn step(
    worker: &Worker,
    claim: &PgClaim,
    budget: Duration,
) -> Result<(), rss_reconcile::Error> {
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, budget, &cancel);
    let result = worker
        .source
        .apply(
            claim,
            ReconcileDiff::between(DesiredState::present(false), ActualState::present(true)),
            &control,
        )
        .await;
    eprintln!("ingress page: result={result:?}");
    result
}

fn checkpoint() -> Value {
    serde_json::from_str(&sql(&format!(
        "SELECT jsonb_build_array(consumed,watermark,cursor) FROM mdm_commands.device_source_dispatch WHERE tenant_id='{}'", tenant(),
    ))).unwrap()
}

fn revisions(devices: &[String]) -> Vec<i64> {
    let names = devices
        .iter()
        .map(|d| format!("'{d}'"))
        .collect::<Vec<_>>()
        .join(",");
    serde_json::from_str(&sql(&format!(
        "SELECT jsonb_agg(input_revision ORDER BY device COLLATE \"C\") FROM mdm_planning.configuration_devices WHERE tenant_id='{}' AND device IN ({names})", tenant(),
    ))).unwrap()
}

fn seed(devices: &[String]) {
    let values = devices
        .iter()
        .map(|d| format!("('{}','{d}')", tenant()))
        .collect::<Vec<_>>()
        .join(",");
    sql(&format!(
        "INSERT INTO mdm_access.devices VALUES {values}; INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES {values};"
    ));
}

#[cfg(feature = "integration")]
async fn release(worker: &Worker, claim: &PgClaim) {
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker.source.release(claim, &control).await.unwrap();
}

async fn close(worker: Arc<Worker>, service: &Application) {
    rss_runtime::ManagedResource::shutdown(&worker.scheduler)
        .await
        .unwrap();
    service.runtime.close().await;
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=planning.recovery: real PG page settlement and restart"]
async fn device_pages_commit_unknown_restart_and_later_window() {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let first = Arc::new(planning(tenant()).await);
    let prefix = Uuid::new_v4();
    let mut devices = (0..61)
        .map(|n| format!("{prefix}-{n:03}"))
        .collect::<Vec<_>>();
    devices.extend(["A", "a", "Z", "z"].map(|s| format!("{prefix}-{s}")));
    seed(&devices);
    devices.sort();
    let peer = crate::test_support::case::peer();
    let foreign = format!("!foreign-{prefix}");
    sql(&format!(
        "SET rss.tenant_id='{peer}'; INSERT INTO mdm_access.devices VALUES('{peer}','{foreign}'); INSERT INTO mdm_planning.configuration_devices(tenant_id,device,input_revision) VALUES('{peer}','{foreign}',7); INSERT INTO mdm_commands.device_source_dispatch(tenant_id) VALUES('{peer}')"
    ));
    // Repeated changes in one fixed window must not repeat a device wake.
    sql(&format!(
        "SELECT mdm.record_asset_change('{}','device',jsonb_build_object('device','{}'),ARRAY[]::text[])",
        tenant(),
        devices[0]
    ));
    let worker = connect(&first).await;
    let old = claim(&worker).await;
    let watermark: i64 = sql(&format!(
        "SELECT revision FROM mdm.asset_clock WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    first
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let error = step(&worker, &old, Duration::from_secs(6))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), rss_reconcile::ErrorKind::CommitUnknown);
    assert_eq!(checkpoint(), json!([0, watermark, devices[31]]));
    let mut expected = vec![1; 65];
    expected[..32].fill(2);
    assert_eq!(revisions(&devices), expected);
    release(&worker, &old).await;
    close(worker, &first).await;

    let resumed = Arc::new(planning(tenant()).await);
    let worker = connect(&resumed).await;
    let current = claim(&worker).await;
    assert!(current.epoch() > old.epoch());
    let later = vec![format!("{prefix}-later")];
    seed(&later);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(checkpoint(), json!([0, watermark, devices[63]]));
    expected[..64].fill(2);
    assert_eq!(revisions(&devices), expected);
    assert_eq!(revisions(&later), vec![1]);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(checkpoint(), json!([watermark, watermark, null]));
    assert_eq!(revisions(&devices), vec![2; 65]);
    assert_eq!(checkpoint()[0], watermark);
    for _ in 0..4 {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
    }
    assert_eq!(checkpoint()[0], checkpoint()[1]);
    assert_eq!(checkpoint()[2], Value::Null);
    assert_eq!(revisions(&devices), vec![2; 65]);
    assert_eq!(revisions(&later), vec![2]);
    assert_eq!(
        sql(&format!(
            "SELECT input_revision FROM mdm_planning.configuration_devices WHERE tenant_id='{peer}' AND device='{foreign}'"
        )),
        "7"
    );
    assert_eq!(
        sql(&format!(
            "SELECT consumed||','||watermark FROM mdm_commands.device_source_dispatch WHERE tenant_id='{peer}'"
        )),
        "0,0"
    );
    close(worker, &resumed).await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real PG partial page rollback"]
async fn device_page_timeout_rolls_back_wakes_and_cursor() {
    use sqlx::Connection;
    let service = Arc::new(planning(tenant()).await);
    let prefix = Uuid::new_v4();
    let devices = (0..33)
        .map(|n| format!("{prefix}-{n:03}"))
        .collect::<Vec<_>>();
    seed(&devices);
    let worker = connect(&service).await;
    let current = claim(&worker).await;
    sql(&format!(
        "INSERT INTO mdm_commands.device_source_dispatch(tenant_id) VALUES('{}') ON CONFLICT DO NOTHING",
        tenant()
    ));
    let before = checkpoint();
    let mut holder =
        sqlx::PgConnection::connect_with(&options().username("postgres").password("local-fixture"))
            .await
            .unwrap();
    sqlx::query("BEGIN").execute(&mut holder).await.unwrap();
    sqlx::query("SELECT 1 FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE")
        .bind(tenant().to_string()).bind(&devices[20]).fetch_one(&mut holder).await.unwrap();
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut holder)
        .await
        .unwrap();
    // Observe the wait on the later device, proving the earlier writes ran.
    let blocked = tokio::time::timeout(Duration::from_millis(1900), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(holder_pid)
            .fetch_one(&mut holder)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let (failed, observed) = tokio::join!(step(&worker, &current, Duration::from_secs(2)), blocked);
    sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
    holder.close().await.unwrap();
    assert!(failed.is_err());
    observed.expect("page never reached the locked later device");
    assert_eq!(checkpoint(), before);
    assert_eq!(revisions(&devices), vec![1; 33]);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(checkpoint()[2], devices[31]);
    let mut expected = vec![2; 33];
    expected[32] = 1;
    assert_eq!(revisions(&devices), expected);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert!(checkpoint()[2].is_null());
    assert_eq!(checkpoint()[0], checkpoint()[1]);
    assert_eq!(revisions(&devices), vec![2; 33]);
    close(worker, &service).await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real Inventory registration fallback and Scope pages"]
async fn installation_fallback_and_scope_pages_do_not_repeat_wakes() {
    let service = Arc::new(planning(tenant()).await);
    let device = format!("installation-{}", Uuid::new_v4());
    let registration = seed_device(&device);
    sql(&format!(
        "INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES('{}','{device}')",
        tenant()
    ));
    let scope_owner = scopes(&service).await;
    service
        .runtime
        .local_tx_with_context(
            tenant(),
            deadline(),
            (scope_owner.as_ref(), &device),
            |(service, seeded_device), tx| {
                Box::pin(async move {
                    for _ in 0..33 {
                        service
                            .seed_scope_in(
                                tx,
                                Uuid::new_v4(),
                                ScopeDefinition {
                                    targets: [Reference::Device(seeded_device.clone())]
                                        .into_iter()
                                        .collect(),
                                    limitations: None,
                                    exclusions: Default::default(),
                                },
                            )
                            .await
                            .map_err(|e| {
                                rss_transactional_messaging_postgres::PgError::from(
                                    sqlx::Error::Protocol(e.to_string()),
                                )
                            })?;
                    }
                    Ok(())
                })
            },
        )
        .await
        .fold(
            |_| (),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );

    let devices = vec![device];
    let initial_revision = revisions(&devices)[0];
    // Start after registration ingress; only the real inventory trigger supplies
    // the wake input, whose identity carries registration rather than device.
    sql(&format!(
        "INSERT INTO mdm_commands.device_source_dispatch(tenant_id,consumed,watermark) SELECT '{t}',revision,revision FROM mdm.asset_clock WHERE tenant_id='{t}' ON CONFLICT (tenant_id) DO UPDATE SET consumed=EXCLUDED.consumed,watermark=EXCLUDED.watermark,cursor=NULL; INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,collection_sequence,source,epoch) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{t}','fallback','1','device','fixture','channel.agent.installation',jsonb_build_object('kind','string','value','present')::text,'batch',1,1,'known','{registration}',1,'mdm.windows',(SELECT epoch::text FROM mdm_access.report_sources WHERE tenant_id='{t}' AND registration='{registration}'::uuid LIMIT 1))",
        t = tenant()
    ));
    let worker = connect(&service).await;
    let current = claim(&worker).await;
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(revisions(&devices), vec![initial_revision + 1]);
    // A new authority change selects all 33 Scope references across two pages.
    let jobs_before: i64 = sql(&format!(
        "SELECT count(*) FROM mdm_scope.tasks WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    sql(&format!(
        "SELECT mdm.record_asset_change('{}','device',jsonb_build_object('device','{}'),ARRAY[]::text[])",
        tenant(),
        devices[0]
    ));
    let scope_worker = ScopeWorker::open(&service).await;
    for _ in 0..3 {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
        scope_worker.reconcile_inputs().await.unwrap();
        assert_eq!(revisions(&devices), vec![initial_revision + 2]);
    }
    let jobs_after: i64 = sql(&format!(
        "SELECT count(*) FROM mdm_scope.tasks WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    assert_eq!(jobs_after - jobs_before, 33);
    assert_eq!(checkpoint()[0], checkpoint()[1]);
    scope_worker.close().await;
    close(worker, &service).await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: source scheduler settlement has its own finite budget"]
async fn source_finish_bounds_a_blocked_scheduler_transaction() {
    use sqlx::Connection;
    let service = Arc::new(planning(tenant()).await);
    let worker = connect(&service).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let lifetime = rss_reconcile::Control::new(&timer, Duration::MAX, &cancel);
    let target = rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap(),
        "changes",
    )
    .unwrap();
    worker
        .source
        .wake(&target, &lifetime.child(Duration::from_secs(6)))
        .await
        .unwrap();
    let current = claim(&worker).await;
    let mut holder =
        sqlx::PgConnection::connect_with(&options().username("postgres").password("local-fixture"))
            .await
            .unwrap();
    sqlx::query("BEGIN").execute(&mut holder).await.unwrap();
    sqlx::query("SELECT 1 FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.assets' AND entity='changes' FOR UPDATE").bind(tenant().to_string()).fetch_one(&mut holder).await.unwrap();
    let outcome = rss_reconcile::Completion::Reobserve(Duration::from_millis(100));
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        worker.source.finish(&current, outcome, &lifetime),
    )
    .await;
    sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
    holder.close().await.unwrap();
    assert!(
        result.is_ok(),
        "source settlement inherited the unlimited runner lifetime"
    );
    assert!(
        result.unwrap().is_err(),
        "blocked settlement unexpectedly succeeded"
    );
    worker
        .source
        .finish(&current, outcome, &lifetime)
        .await
        .unwrap();
    close(worker, &service).await;
}
