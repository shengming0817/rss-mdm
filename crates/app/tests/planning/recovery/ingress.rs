use crate::planning::test_support::*;
use crate::planning::*;
use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff, Reconciler};
use rss_reconcile_postgres::PgClaim;

type Worker = crate::automation::Automation;

async fn connect(service: &Arc<Planning>) -> Arc<Worker> {
    Worker::connect(
        service.clone(),
        assets(service).await,
        compliance(service).await,
        options(),
    )
    .await
    .unwrap()
}

async fn claim(worker: &Worker) -> PgClaim {
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker
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
        "SELECT jsonb_build_array(consumed,watermark,phase,cursor) FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'", tenant(),
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

async fn release(worker: &Worker, claim: &PgClaim) {
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker.release(claim, &control).await.unwrap();
}

async fn close(worker: Arc<Worker>, service: &Planning) {
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
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
        "SET rss.tenant_id='{peer}'; INSERT INTO mdm_access.devices VALUES('{peer}','{foreign}'); INSERT INTO mdm_planning.configuration_devices(tenant_id,device,input_revision) VALUES('{peer}','{foreign}',7); INSERT INTO mdm_planning.asset_dispatch(tenant_id) VALUES('{peer}')"
    ));
    // Repeated changes in one fixed window must not repeat a device wake.
    sql(&format!(
        "SELECT mdm.record_asset_change('{}','device',jsonb_build_object('device','{}'),ARRAY[]::text[])",
        tenant(),
        devices[0]
    ));
    let worker = connect(&first).await;
    let old = claim(&worker).await;
    step(&worker, &old, Duration::from_secs(6)).await.unwrap();
    let watermark = checkpoint()[1].clone();
    assert_eq!(checkpoint()[2], "devices");
    first
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let error = step(&worker, &old, Duration::from_secs(6))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), rss_reconcile::ErrorKind::CommitUnknown);
    assert_eq!(checkpoint(), json!([0, watermark, "devices", devices[31]]));
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
    assert_eq!(checkpoint(), json!([0, watermark, "devices", devices[63]]));
    expected[..64].fill(2);
    assert_eq!(revisions(&devices), expected);
    assert_eq!(revisions(&later), vec![1]);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(checkpoint(), json!([0, watermark, "scopes", null]));
    assert_eq!(revisions(&devices), vec![2; 65]);
    for phase in ["compliance", "groups"] {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
        assert_eq!(checkpoint()[2], phase);
        assert_eq!(revisions(&devices), vec![2; 65]);
    }
    assert_eq!(checkpoint()[0], watermark);
    for _ in 0..4 {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
    }
    assert_eq!(checkpoint()[0], checkpoint()[1]);
    assert_eq!(checkpoint()[2], "groups");
    assert_eq!(checkpoint()[3], Value::Null);
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
            "SELECT consumed||','||watermark||','||phase FROM mdm_planning.asset_dispatch WHERE tenant_id='{peer}'"
        )),
        "0,0,groups"
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
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
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
    assert_eq!(checkpoint()[3], devices[31]);
    let mut expected = vec![2; 33];
    expected[32] = 1;
    assert_eq!(revisions(&devices), expected);
    step(&worker, &current, Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(checkpoint()[2], "scopes");
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
    let preparer = RunningAutomation::start(service.clone()).await;
    let mut initial_tasks = Vec::new();
    for _ in 0..33 {
        let scope = Uuid::new_v4();
        let accepted = execute(
            &service,
            &Command::Scope {
                id: scope,
                change: operation(
                    0,
                    ScopeChange::Put {
                        definition: ScopeDefinition {
                            targets: [Reference::Device(device.clone())].into_iter().collect(),
                            limitations: None,
                            exclusions: Default::default(),
                        },
                    },
                ),
            },
        )
        .await
        .unwrap();
        initial_tasks.push((
            scope,
            Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap(),
        ));
    }
    // Publish initial Scope work so new invalidation creates new jobs rather
    // than being absorbed by the legitimate pending-job deduplication.
    for (scope, task) in initial_tasks {
        wait_task(
            &service,
            task,
            crate::automation::TaskKind::Scope,
            &scope.to_string(),
        )
        .await;
    }
    preparer.stop().await;
    let devices = vec![device];
    let initial_revision = revisions(&devices)[0];
    // Start after registration ingress; only the real inventory trigger supplies
    // the wake input, whose identity carries registration rather than device.
    sql(&format!(
        "INSERT INTO mdm_planning.asset_dispatch(tenant_id,consumed,watermark) SELECT '{t}',revision,revision FROM mdm.asset_clock WHERE tenant_id='{t}' ON CONFLICT (tenant_id) DO UPDATE SET consumed=EXCLUDED.consumed,watermark=EXCLUDED.watermark,cursor=NULL,phase='groups'; INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,collection_sequence,source,epoch) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{t}','fallback','1','device','fixture','channel.agent.installation','present','batch',1,1,'known','{registration}',1,'mdm.windows',(SELECT epoch::text FROM mdm_access.report_sources WHERE tenant_id='{t}' AND registration='{registration}'::uuid LIMIT 1))",
        t = tenant()
    ));
    let worker = connect(&service).await;
    let current = claim(&worker).await;
    for phase in ["devices", "scopes", "compliance", "groups"] {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
        assert_eq!(checkpoint()[2], phase);
    }
    assert_eq!(revisions(&devices), vec![initial_revision + 1]);
    // A new authority change selects all 33 Scope references across two pages.
    let jobs_before: i64 = sql(&format!(
        "SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    sql(&format!(
        "SELECT mdm.record_asset_change('{}','device',jsonb_build_object('device','{}'),ARRAY[]::text[])",
        tenant(),
        devices[0]
    ));
    for phase in ["devices", "scopes", "scopes", "compliance", "groups"] {
        step(&worker, &current, Duration::from_secs(6))
            .await
            .unwrap();
        assert_eq!(checkpoint()[2], phase);
        if phase == "scopes" || phase == "compliance" || phase == "groups" {
            assert_eq!(revisions(&devices), vec![initial_revision + 2]);
        }
    }
    let jobs_after: i64 = sql(&format!(
        "SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    assert_eq!(jobs_after - jobs_before, 33);
    assert_eq!(checkpoint()[0], checkpoint()[1]);
    close(worker, &service).await;
}
