use super::*;

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn result_cursors_survive_instances_restart_and_group_deletion() {
    let first = Arc::new(management(tenant()).await);
    let running = RunningAutomation::start(first.clone()).await;
    let group = Uuid::new_v4();
    let devices: Vec<_> = (0..2).map(|n| format!("cursor-{group}-{n}")).collect();
    for device in &devices {
        seed_device(device);
    }
    execute(
        &first,
        &Command::Group {
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "cursor".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    let accepted = execute(
        &first,
        &Command::Group {
            id: group,
            change: operation(
                1,
                GroupChange::Members {
                    add: devices.clone(),
                    remove: vec![],
                },
            ),
        },
    )
    .await
    .unwrap();
    let result = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    wait_task(
        &first,
        result,
        automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    running.stop().await;
    let page = |cursor| Command::GroupPage {
        group,
        result,
        projection: pages::GroupPageKind::Members,
        query: pages::PageQuery { limit: 1, cursor },
    };
    let initial = execute(&first, &page(None)).await.unwrap();
    assert_eq!(initial["page"]["items"], json!([devices[0]]));
    let cursor = initial["nextCursor"].as_str().unwrap().to_owned();
    let second = management(tenant()).await;
    assert_eq!(
        execute(&second, &page(Some(cursor.clone()))).await.unwrap()["page"]["items"],
        json!([devices[1]])
    );
    second.runtime.close().await;
    first.runtime.close().await;
    let restarted = management(tenant()).await;
    assert_eq!(
        execute(&restarted, &page(Some(cursor.clone())))
            .await
            .unwrap()["page"]["items"],
        json!([devices[1]])
    );
    execute(
        &restarted,
        &Command::Group {
            id: group,
            change: operation(2, GroupChange::Delete),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        execute(&restarted, &page(Some(cursor))).await.unwrap()["page"]["items"],
        json!([devices[1]])
    );
    restarted.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn unknown_policy_result_is_not_found() {
    let service = management(tenant()).await;
    let result = execute(
        &service,
        &Command::PolicyPage {
            policy: Uuid::new_v4().to_string(),
            result: Uuid::new_v4(),
            projection: pages::PolicyPageKind::Targets,
            query: pages::PageQuery {
                limit: 1,
                cursor: None,
            },
        },
    )
    .await;
    assert!(
        matches!(result, Err(Error::ManagementNotFound(Missing::Preview))),
        "{result:?}"
    );
    let missing = execute(
        &service,
        &Command::TaskRead {
            id: Uuid::new_v4(),
            target: Uuid::new_v4().to_string(),
            family: automation::TaskKind::Policy,
        },
    )
    .await;
    assert!(
        matches!(missing, Err(Error::ManagementNotFound(Missing::Preview))),
        "{missing:?}"
    );
    service.runtime.close().await;
}

fn options() -> sqlx::postgres::PgConnectOptions {
    let config = fixture();
    sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database("backend")
        .username("mdm_management_runtime")
        .password("backend-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap())
}
async fn query_job(service: &Management, count: usize) -> Uuid {
    let prefix = Uuid::new_v4();
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','resume-{prefix}-'||lpad(n::text,4,'0') FROM generate_series(1,{count}) n",
        tenant()
    ));
    let task = Uuid::new_v4();
    execute(
        service,
        &Command::Asset {
            command: assets::Command::Search {
                request: Operation {
                    operation_id: task,
                    expected_revision: 0,
                    input: assets::Query::default(),
                },
                scope: assets::ReadScope {
                    subject: prefix.to_string(),
                    devices: Some(
                        (1..=count)
                            .map(|n| format!("resume-{prefix}-{n:04}"))
                            .collect(),
                    ),
                },
            },
        },
    )
    .await
    .unwrap();
    service.forward_jobs().await.unwrap();
    task
}
async fn claim_job(
    worker: &automation::Automation,
    task: Uuid,
    lease: Duration,
) -> rss_reconcile_postgres::PgClaim {
    use rss_reconcile::DurableStore;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.target().entity() == format!("job:{task}"))
        .expect("job must be claimable")
}
fn snapshot(task: Uuid) -> String {
    sql(&format!(
        "SELECT jsonb_build_array(j.cursor,j.completed,j.failure,r.total,(SELECT count(*) FROM mdm_management.asset_query_results WHERE run='{task}')) FROM mdm_management.automation_jobs j JOIN mdm_management.asset_query_runs r ON r.id=j.id AND r.tenant_id=j.tenant_id WHERE j.id='{task}'"
    ))
}
#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn live_checkpoint_restart_fences_old_worker() {
    use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff, Reconciler};
    let first = Arc::new(management(tenant()).await);
    let old = automation::Automation::connect(first.clone(), options())
        .await
        .unwrap();
    let task = query_job(&first, 256).await;
    let stale = claim_job(&old, task, Duration::from_secs(2)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    let diff = || ReconcileDiff::between(DesiredState::present(false), ActualState::present(true));
    old.apply(&stale, diff(), &control).await.unwrap();
    let checkpoint = snapshot(task);
    assert_eq!(serde_json::from_str::<Value>(&checkpoint).unwrap()[3], 128);
    rss_runtime::ManagedResource::shutdown(&automation::Resource(old.clone()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let second = Arc::new(management(tenant()).await);
    let resumed = automation::Automation::connect(second.clone(), options())
        .await
        .unwrap();
    let current = claim_job(&resumed, task, Duration::from_secs(6)).await;
    assert!(current.epoch() > stale.epoch());
    assert!(old.apply(&stale, diff(), &control).await.is_err());
    assert!(
        old.finish(
            &stale,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control
        )
        .await
        .is_err()
    );
    assert_eq!(
        snapshot(task),
        checkpoint,
        "stale claim changed persisted progress or cleared new work"
    );
    resumed.apply(&current, diff(), &control).await.unwrap();
    let completed: Value = serde_json::from_str(&snapshot(task)).unwrap();
    assert_eq!(completed[1], true);
    assert_eq!(completed[3], 256);
    assert_eq!(completed[4], 256);
    resumed
        .finish(&current, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&automation::Resource(resumed))
        .await
        .unwrap();
    first.runtime.close().await;
    second.runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn rss_exhaustion_records_failed_task_and_atomic_audit() {
    use rss_reconcile::DurableStore;
    let service = Arc::new(management(tenant()).await);
    let worker = automation::Automation::connect(service.clone(), options())
        .await
        .unwrap();
    let task = query_job(&service, 1).await;
    let claim = claim_job(&worker, task, Duration::from_secs(6)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    // Failure of the companion audit must leave both job and RSS claim retryable.
    sql("REVOKE INSERT ON mdm_access.audit FROM mdm_management_runtime");
    let result = worker
        .finish(
            &claim,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control,
        )
        .await;
    sql("GRANT INSERT ON mdm_access.audit TO mdm_management_runtime");
    assert!(result.is_err());
    assert_eq!(
        serde_json::from_str::<Value>(&snapshot(task)).unwrap()[1],
        false
    );
    worker.release(&claim, &control).await.unwrap();
    // Let the actual RSS worker select Suspended after an unrecoverable page write.
    sql("REVOKE INSERT ON mdm_management.asset_query_results FROM mdm_management_runtime");
    let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(3),
        attempt_timeout: Duration::from_secs(1),
        scan_interval: Duration::from_millis(20),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(20),
        max_attempts: 1,
    })
    .unwrap();
    let scope = rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap();
    let runner = rss_reconcile::run(
        worker.as_ref(),
        worker.as_ref(),
        &scope,
        policy,
        &control,
        |_| {},
    );
    let target = sql(&format!(
        "SELECT target FROM mdm_management.automation_jobs WHERE id='{task}'"
    ));
    let inspect = async {
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = execute(
                    &service,
                    &Command::TaskRead {
                        id: task,
                        target: target.clone(),
                        family: automation::TaskKind::AssetQuery,
                    },
                )
                .await;
                if let Ok(state) = state
                    && state["status"] == "failed"
                {
                    return state;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await;
        cancel.cancel();
        outcome
    };
    let (_, state) = tokio::join!(runner, inspect);
    sql("GRANT INSERT ON mdm_management.asset_query_results TO mdm_management_runtime");
    assert_eq!(state.unwrap()["failure"], "automation_suspended");
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_access.audit WHERE action='automation_failed' AND operation_id='{task}'"
        )),
        "1"
    );
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn suspended_ingress_fails_readiness_and_restart_recovers_forwarded_input() {
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(management(tenant()).await);
    let worker = automation::Automation::connect(service.clone(), options())
        .await
        .unwrap();
    let peer_service = Arc::new(management(tenant()).await);
    let peer = automation::Automation::connect(peer_service.clone(), options())
        .await
        .unwrap();
    sql(&format!(
        "INSERT INTO mdm_access.devices VALUES('{}','ingress-{}')",
        tenant(),
        Uuid::new_v4()
    ));
    service.forward_asset_changes().await.unwrap();
    assert_eq!(
        sql("SELECT count(*) FROM mdm.asset_changes WHERE NOT forwarded"),
        "0"
    );
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap();
    let claim = worker
        .claim_due(&scope, 64, Duration::from_secs(3), &control)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.target().entity() == "changes")
        .unwrap();
    // A newer wake may make RSS retain pending work instead of suspending.
    // The durable diagnosis deliberately fails closed until explicit recovery.
    sql(&format!(
        "INSERT INTO mdm_access.devices VALUES('{}','later-{}')",
        tenant(),
        Uuid::new_v4()
    ));
    service.forward_asset_changes().await.unwrap();
    worker
        .finish(
            &claim,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control,
        )
        .await
        .unwrap();
    assert_eq!(
        sql("SELECT failure FROM mdm_management.asset_dispatch"),
        "automation_suspended"
    );
    assert!(!service.ingress_ready().await);
    assert!(
        !peer_service.ingress_ready().await,
        "another instance reported healthy"
    );
    // Even an instance started after the failure must retain the diagnosis.
    let late_service = Arc::new(management(tenant()).await);
    let late = automation::Automation::connect(late_service.clone(), options())
        .await
        .unwrap();
    assert!(
        !late_service.ingress_ready().await,
        "startup cleared failure before successful recovery"
    );
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&automation::Resource(late))
        .await
        .unwrap();
    late_service.runtime.close().await;
    service.runtime.close().await;
    let restarted = Arc::new(management(tenant()).await);
    let worker = automation::Automation::connect(restarted.clone(), options())
        .await
        .unwrap();
    let claim = worker
        .claim_due(&scope, 64, Duration::from_secs(6), &control)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.target().entity() == "changes")
        .expect("startup must wake already-forwarded input");
    for _ in 0..8 {
        let diff = worker.observe(&claim, &control).await.unwrap();
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&claim, diff, &control).await.unwrap();
    }
    assert_eq!(
        worker.observe(&claim, &control).await.unwrap().drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    assert_eq!(
        sql(
            "SELECT consumed=(SELECT max(revision) FROM mdm.asset_changes) FROM mdm_management.asset_dispatch"
        ),
        "t"
    );
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    assert!(restarted.ingress_ready().await);
    assert!(
        peer_service.ingress_ready().await,
        "recovered checkpoint not visible to peer"
    );
    rss_runtime::ManagedResource::shutdown(&automation::Resource(peer))
        .await
        .unwrap();
    peer_service.runtime.close().await;
    restarted.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn policy_waits_for_scope_and_inherits_failure() {
    use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
    let service = Arc::new(management(tenant()).await);
    let scope = Uuid::new_v4();
    let resolution = Uuid::new_v4();
    let task = Uuid::new_v4();
    let policy = Uuid::new_v4().to_string();
    let source = automation::JobInput::Scope { scope };
    let dependent = automation::JobInput::Policy {
        policy: policy.clone(),
        scope,
        resolution,
        assignment_revision: None,
        expected_revision: 1,
        as_of: 1,
    };
    for (id, kind, target, input) in [
        (resolution, "scope", scope.to_string(), source),
        (task, "policy", policy, dependent),
    ] {
        let document = serde_json::to_string(&input).unwrap();
        sql(&format!(
            "INSERT INTO mdm_management.automation_jobs(tenant_id,id,kind,target,input) VALUES('{}','{id}','{}','{}','{document}')",
            tenant(),
            kind,
            target
        ));
    }
    assert_eq!(
        service.forward_jobs().await.unwrap(),
        1,
        "dependent policy was scheduled before its Scope completed"
    );
    assert_eq!(
        sql(&format!(
            "SELECT forwarded FROM mdm_management.automation_jobs WHERE id='{task}'"
        )),
        "f"
    );
    assert_eq!(service.forward_jobs().await.unwrap(), 0);
    // Model a prerequisite terminal rejection without producing a Scope result.
    sql(&format!(
        "UPDATE mdm_management.automation_jobs SET completed=true,failure='capacity_exceeded' WHERE id='{resolution}'"
    ));
    assert_eq!(service.forward_jobs().await.unwrap(), 1);
    let worker = automation::Automation::connect(service.clone(), options())
        .await
        .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(6)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    worker
        .apply(
            &claim,
            ReconcileDiff::between(DesiredState::present(false), ActualState::present(true)),
            &control,
        )
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT completed AND failure='source_unavailable' FROM mdm_management.automation_jobs WHERE id='{task}'"
        )),
        "t"
    );
    assert_eq!(sql("SELECT count(*) FROM mdm_policy.facts"), "0");
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn scope_history_survives_deletion() {
    let service = Arc::new(management(tenant()).await);
    let devices: Vec<_> = (0..2).map(|n| format!("scope-history-{n}")).collect();
    for d in &devices {
        seed_device(d);
    }
    let running = RunningAutomation::start(service.clone()).await;
    let scope = Uuid::new_v4();
    let accepted = execute(
        &service,
        &Command::Scope {
            id: scope,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: devices.iter().cloned().map(Reference::Device).collect(),
                        limitations: None,
                        exclusions: Default::default(),
                    },
                },
            ),
        },
    )
    .await
    .unwrap();
    let result = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    wait_task(
        &service,
        result,
        automation::TaskKind::Scope,
        &scope.to_string(),
    )
    .await;
    running.stop().await;
    for projection in [
        pages::ScopePageKind::Members,
        pages::ScopePageKind::Decisions,
    ] {
        let query = |cursor| Command::ScopePage {
            scope,
            result,
            projection,
            query: pages::PageQuery { limit: 1, cursor },
        };
        let before = execute(&service, &query(None)).await.unwrap();
        if projection == pages::ScopePageKind::Members {
            execute(
                &service,
                &Command::Scope {
                    id: scope,
                    change: operation(1, ScopeChange::Delete),
                },
            )
            .await
            .unwrap();
        }
        let first = execute(&service, &query(None)).await.unwrap();
        assert_eq!(first["current"], false);
        assert_eq!(first["page"], before["page"]);
        let mut next = first["nextCursor"].as_str().map(str::to_owned);
        let mut count = first["page"]["items"].as_array().unwrap().len();
        while let Some(cursor) = next {
            let page = execute(&service, &query(Some(cursor))).await.unwrap();
            assert_eq!(page["current"], false);
            count += page["page"]["items"].as_array().unwrap().len();
            next = page["nextCursor"].as_str().map(str::to_owned);
        }
        assert_eq!(count, 2);
    }
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn corrupt_background_query_is_not_client_input() {
    use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
    let service = Arc::new(management(tenant()).await);
    let task = query_job(&service, 1).await;
    let original = sql(&format!(
        "SELECT input FROM mdm_management.automation_jobs WHERE id='{task}'"
    ));
    let worker = automation::Automation::connect(service.clone(), options())
        .await
        .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(30)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    for (value, cursor) in [
        ("jsonb_set(input,'{as_of}','-1')", "NULL"),
        ("input", "''"),
        (
            "jsonb_set(input,'{query,criteria}','{\"kind\":\"and\",\"children\":[]}'::jsonb)",
            "NULL",
        ),
    ] {
        sql(&format!(
            "UPDATE mdm_management.automation_jobs SET input='{original}',cursor=NULL WHERE id='{task}'; UPDATE mdm_management.automation_jobs SET input={value},cursor={cursor} WHERE id='{task}'"
        ));
        let result = worker
            .apply(
                &claim,
                ReconcileDiff::between(DesiredState::present(false), ActualState::present(true)),
                &control,
            )
            .await;
        assert!(
            result.is_err(),
            "corrupt durable input was accepted or permanently classified as client input"
        );
        assert_eq!(
            sql(&format!(
                "SELECT NOT completed AND failure IS NULL FROM mdm_management.automation_jobs WHERE id='{task}'"
            )),
            "t"
        );
        assert_eq!(
            sql(&format!(
                "SELECT total FROM mdm_management.asset_query_runs WHERE id='{task}'"
            )),
            "0"
        );
    }
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}

async fn frozen_device(service: &Management, device: &str, watermark: i64) -> Value {
    let device = device.to_owned();
    service
        .runtime
        .local_tx_with_context(tenant(), deadline(), service, move |m, tx| {
            Box::pin(async move {
                let page = m
                    .asset_page_in(
                        tx,
                        watermark,
                        None,
                        1,
                        &assets::ReadScope {
                            subject: "history-evidence".into(),
                            devices: Some([device].into()),
                        },
                    )
                    .await
                    .map_err(|_| sqlx::Error::Protocol("history fixture read failed".into()))?;
                Ok(serde_json::to_value(&page.devices[0]).unwrap())
            })
        })
        .await
        .fold(
            |v| v,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        )
}
#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn frozen_fields_manual_and_quality_survive_updates_deletes_and_rollback() {
    let t = tenant();
    let device = "all-histories";
    let registration = seed_device(device);
    let epoch = sql(&format!(
        "SELECT epoch FROM mdm_access.report_sources WHERE registration='{registration}'"
    ));
    let scope = crate::device::scope(
        t,
        Uuid::parse_str(&registration).unwrap(),
        "mdm.windows",
        Uuid::parse_str(&epoch).unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage()).unwrap();
    let collection = Uuid::new_v4();
    let attempts = serde_json::to_string(&crate::collection::Attempts::default()).unwrap();
    sql(&format!(
        "INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch) VALUES('{t}','mdm.observation.v1','inventory-v2','{scope}','{coverage}','device.model','Old','old-batch',1,2,'known','{registration}','mdm.windows','{epoch}'); INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result) VALUES('{t}','{collection}','{registration}','mdm.windows','{epoch}','{scope}',1,'history',1,1024,decode('01','hex'),1,'{attempts}','pending')"
    ));
    let service = management(t).await;
    let manual = |revision, input| Command::Asset {
        command: assets::Command::Manual {
            device: device.into(),
            field: assets::FieldKey::IsLoaner,
            owner: assets::Owner {
                instance: "history".into(),
                principal: "operator".into(),
            },
            change: operation(revision, input),
        },
    };
    execute(
        &service,
        &manual(
            0,
            assets::ManualChange::Set {
                value: rss_mdm_inventory::Scalar::Boolean(true),
            },
        ),
    )
    .await
    .unwrap();
    let watermark = || {
        sql(&format!(
            "SELECT revision FROM mdm.asset_clock WHERE tenant_id='{t}'"
        ))
        .parse::<i64>()
        .unwrap()
    };
    let old_watermark = watermark();
    let before = frozen_device(&service, device, old_watermark).await;
    assert_eq!(
        before["fields"]["device.model"]["state"]["value"]["value"],
        "Old"
    );
    assert_eq!(
        before["fields"]["custom.is_loaner"]["state"]["value"]["value"],
        true
    );
    assert_eq!(before["quality"][0]["result"], "pending");
    let mut failed = crate::collection::Attempts::default();
    failed.fields[0].quality = crate::collection::Quality::Failed;
    failed.fields[0].status = Some(500);
    failed.fields[0].received_at = Some(4);
    let failed = serde_json::to_string(&failed).unwrap();
    let changes = format!(
        "UPDATE mdm.inventory SET value='New',batch_id='new-batch',observed_at=3,received_at=4 WHERE registration='{registration}'; UPDATE mdm.manual_assignments SET revision=revision+1,fact=jsonb_set(fact,'{{state}}','{{\"kind\":\"null\"}}') WHERE device='{device}'; UPDATE mdm_access.collection_runs SET attempts='{failed}',result='failed',reason='timeout',sealed_at=4 WHERE id='{collection}';"
    );
    sql(&format!("BEGIN; {changes} ROLLBACK;"));
    assert_eq!(
        watermark(),
        old_watermark,
        "rollback advanced committed watermarks"
    );
    assert_eq!(frozen_device(&service, device, watermark()).await, before);
    sql(&changes);
    let new_watermark = watermark();
    let changed = frozen_device(&service, device, new_watermark).await;
    assert_eq!(
        changed["fields"]["device.model"]["state"]["value"]["value"],
        "New"
    );
    assert_eq!(
        changed["fields"]["custom.is_loaner"]["state"]["kind"],
        "null"
    );
    assert_eq!(changed["quality"][0]["result"], "failed");
    assert_eq!(changed["quality"][0]["fields"][0]["quality"], "failed");
    assert_eq!(changed["quality"][0]["fields"][0]["status"], 500);
    assert_eq!(frozen_device(&service, device, old_watermark).await, before);
    execute(&service, &manual(2, assets::ManualChange::Delete {}))
        .await
        .unwrap();
    sql(&format!(
        "DELETE FROM mdm.inventory WHERE registration='{registration}'; DELETE FROM mdm_access.collection_runs WHERE id='{collection}'"
    ));
    let deleted = frozen_device(&service, device, watermark()).await;
    assert_eq!(
        deleted["fields"]["device.model"]["state"]["kind"],
        "missing"
    );
    assert_eq!(
        deleted["fields"]["custom.is_loaner"]["state"]["kind"],
        "deleted"
    );
    assert_eq!(deleted["quality"], json!([]));
    assert_eq!(
        frozen_device(&service, device, new_watermark).await,
        changed
    );
    assert_eq!(frozen_device(&service, device, old_watermark).await, before);
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn ingress_batches_reuse_published_group_coverage() {
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(management(tenant()).await);
    let worker = automation::Automation::connect(service.clone(), options())
        .await
        .unwrap();
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','batch-'||lpad(n::text,4,'0') FROM generate_series(1,1001) n",
        tenant()
    ));
    let group = Uuid::new_v4();
    let accepted = execute(
        &service,
        &Command::Group {
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "bounded-ingress".into(),
                    description: String::new(),
                    criteria: Some(assets::Criteria::Predicate {
                        field: assets::FieldKey::IsLoaner,
                        op: assets::Operator::Eq,
                        value: Some(assets::Scalar::Boolean(true)),
                        values: None,
                    }),
                },
            ),
        },
    )
    .await
    .unwrap();
    let task = accepted["task"].as_str().unwrap();
    service.forward_jobs().await.unwrap();
    while service.forward_asset_changes().await.unwrap() > 0 {}
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let scope = rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap();
    let mut claims = worker
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await
        .unwrap();
    let pos = claims
        .iter()
        .position(|c| c.target().entity() == format!("job:{task}"))
        .unwrap();
    let claim = claims.remove(pos);
    for _ in 0..12 {
        let diff = worker.observe(&claim, &control).await.unwrap();
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&claim, diff, &control).await.unwrap();
    }
    assert_eq!(
        worker.observe(&claim, &control).await.unwrap().drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    assert_eq!(
        sql("SELECT count(*) FROM mdm_management.automation_jobs"),
        "1"
    );
    let claim = claims
        .into_iter()
        .find(|c| c.target().entity() == "changes")
        .unwrap();
    for (consumed, watermark) in [(0, 1000), (1000, 1000), (1000, 1001), (1001, 1001)] {
        let diff = worker.observe(&claim, &control).await.unwrap();
        worker.apply(&claim, diff, &control).await.unwrap();
        assert_eq!(
            sql("SELECT consumed||','||watermark FROM mdm_management.asset_dispatch"),
            format!("{consumed},{watermark}")
        );
        assert_eq!(
            sql("SELECT count(*) FROM mdm_management.automation_jobs"),
            "1",
            "covered batches recreated the million-device calculation"
        );
    }
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}
