use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn management_admission_rejects_schema_and_privilege_drift() {
    let service = planning(tenant()).await;
    for (change, restore) in [
        (
            "GRANT DELETE ON mdm_commands.action_runs TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_commands.action_runs FROM mdm_flow_runtime",
        ),
        (
            "REVOKE INSERT ON mdm_policy.versions FROM mdm_policy_runtime",
            "GRANT INSERT ON mdm_policy.versions TO mdm_policy_runtime",
        ),
        (
            "GRANT UPDATE(number) ON mdm_policy.versions TO mdm_flow_runtime",
            "REVOKE UPDATE(number) ON mdm_policy.versions FROM mdm_flow_runtime",
        ),
        (
            "REVOKE SELECT ON mdm_agent.bindings FROM mdm_flow_runtime",
            "GRANT SELECT ON mdm_agent.bindings TO mdm_flow_runtime",
        ),
        (
            "CREATE ROLE flow_drift NOLOGIN; GRANT UPDATE(number) ON mdm_policy.versions TO flow_drift; GRANT flow_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE flow_drift FROM mdm_flow_runtime; DROP OWNED BY flow_drift; DROP ROLE flow_drift",
        ),
        (
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact DROP NOT NULL",
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact SET NOT NULL",
        ),
        (
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(true)",
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(revision>0)",
        ),
        (
            "GRANT SELECT ON mdm_access.credentials TO mdm_flow_runtime",
            "REVOKE SELECT ON mdm_access.credentials FROM mdm_flow_runtime; GRANT SELECT(tenant_id,registration,state) ON mdm_access.credentials TO mdm_flow_runtime",
        ),
        (
            "ALTER TABLE mdm_planning.scopes DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_planning.scopes ENABLE ROW LEVEL SECURITY",
        ),
        (
            "GRANT DELETE ON mdm_automation.automation_jobs TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_automation.automation_jobs FROM mdm_flow_runtime",
        ),
        (
            "GRANT UPDATE ON mdm_access.authorization_rules TO mdm_flow_runtime",
            "REVOKE UPDATE ON mdm_access.authorization_rules FROM mdm_flow_runtime",
        ),
    ] {
        sql(change);
        let rejected = rss_mdm_flow_service::storage::admit(&service.runtime, tenant())
            .await
            .is_err()
            || rss_mdm_policy_postgres::PolicyStore::new(
                service.runtime.clone(),
                tenant(),
                deadline(),
            )
            .await
            .is_err();
        sql(restore);
        assert!(rejected, "accepted privilege drift: {change}");
    }
    for (table, column) in [
        ("mdm_access.devices", "id"),
        ("mdm_access.registrations", "state"),
        ("mdm_access.report_sources", "enabled"),
        ("mdm.inventory", "value"),
    ] {
        assert_eq!(
            sql(&format!(
                "SELECT has_column_privilege('mdm_flow_runtime','{table}','{column}','UPDATE')"
            )),
            "f"
        );
        sql(&format!(
            "GRANT UPDATE({column}) ON {table} TO mdm_flow_runtime"
        ));
        let rejected = rss_mdm_flow_service::storage::admit(&service.runtime, tenant())
            .await
            .is_err()
            || rss_mdm_policy_postgres::PolicyStore::new(
                service.runtime.clone(),
                tenant(),
                deadline(),
            )
            .await
            .is_err();
        sql(&format!(
            "REVOKE UPDATE({column}) ON {table} FROM mdm_flow_runtime"
        ));
        assert!(rejected);
    }
    rss_mdm_flow_service::storage::admit(&service.runtime, tenant())
        .await
        .unwrap();
    let denied = service
        .runtime
        .local_tx(tenant(), deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT locator FROM mdm_access.credentials")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await?;
                Ok(())
            })
        })
        .await;
    assert!(denied.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn expired_guard_after_lock_rejects_mutation_and_replay() {
    use sqlx::{
        Connection,
        postgres::{PgConnectOptions, PgSslMode},
    };
    let m = planning(tenant()).await;
    let config = fixture();
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("postgres")
        .password("local-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut holder = sqlx::PgConnection::connect_with(&options).await.unwrap();
    for replay in [false, true] {
        let id = Uuid::new_v4();
        let command = Command::Group {
            id,
            change: operation(
                0,
                GroupChange::Create {
                    name: "guarded".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        };
        if replay {
            execute(&m, &command).await.unwrap();
        }
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2390))")
            .bind(tenant().to_string())
            .execute(&mut holder)
            .await
            .unwrap();
        let audit = RequestAudit::new(tenant().to_string(), "management_write");
        audit.set_principal("operator", crate::test_support::INSTANCE);
        let expires = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_millis(150);
        let authorize = || {
            if rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < expires {
                Ok(())
            } else {
                Err(rss_mdm_flow_service::Error::Forbidden)
            }
        };
        let release = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2390))")
                .bind(tenant().to_string())
                .execute(&mut holder)
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(m.execute(&command, &audit, &authorize), release);
        audit.finalize(None);
        assert!(matches!(
            result,
            Err(rss_mdm_flow_service::Error::Forbidden)
        ));
        let read = execute(&m, &Command::GroupRead { id }).await;
        assert_eq!(
            read.is_ok(),
            replay,
            "expired new write must leave no group"
        );
    }
    holder.close().await.unwrap();
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn result_cursors_survive_instances_restart_and_group_deletion() {
    let first = Arc::new(planning(tenant()).await);
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
        crate::automation::TaskKind::Group,
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
    let second = planning(tenant()).await;
    assert_eq!(
        execute(&second, &page(Some(cursor.clone()))).await.unwrap()["page"]["items"],
        json!([devices[1]])
    );
    second.runtime.close().await;
    first.runtime.close().await;
    let restarted = planning(tenant()).await;
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
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn live_checkpoint_restart_fences_old_worker() {
    use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff, Reconciler};
    let first = Arc::new(planning(tenant()).await);
    let old =
        crate::automation::Automation::connect(first.clone(), assets(&first).await, options())
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
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(old.clone()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let second = Arc::new(planning(tenant()).await);
    let resumed =
        crate::automation::Automation::connect(second.clone(), assets(&second).await, options())
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
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(resumed))
        .await
        .unwrap();
    first.runtime.close().await;
    second.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn rss_exhaustion_records_failed_task_and_atomic_audit() {
    use rss_reconcile::DurableStore;
    let service = Arc::new(planning(tenant()).await);
    let worker =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options())
            .await
            .unwrap();
    let task = query_job(&service, 1).await;
    let claim = claim_job(&worker, task, Duration::from_secs(6)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    // Failure of the companion audit must leave both job and RSS claim retryable.
    sql("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime");
    let result = worker
        .finish(
            &claim,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control,
        )
        .await;
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime");
    assert!(result.is_err());
    assert_eq!(
        serde_json::from_str::<Value>(&snapshot(task)).unwrap()[1],
        false
    );
    worker.release(&claim, &control).await.unwrap();
    // Let the actual RSS worker select Suspended after an unrecoverable page write.
    sql("REVOKE INSERT ON mdm_assets.asset_query_results FROM mdm_flow_runtime");
    let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(3),
        attempt_timeout: Duration::from_secs(1),
        scan_interval: Duration::from_millis(20),
        idle_scan_interval: Duration::from_millis(20),
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
    let query_scope: assets::ReadScope = serde_json::from_str(&sql(&format!(
        "SELECT (input->'scope')::text FROM mdm_automation.automation_jobs WHERE id='{task}'"
    )))
    .unwrap();
    let inspect = async {
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = execute_asset(
                    &service,
                    &assets::Command::QueryStatus {
                        task,
                        scope: query_scope.clone(),
                    },
                )
                .await;
                if let Ok(state) = state
                    && state["asset"]["status"] == "failed"
                {
                    return state["asset"].clone();
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await;
        cancel.cancel();
        outcome
    };
    let (_, state) = tokio::join!(runner, inspect);
    sql("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_flow_runtime");
    assert_eq!(state.unwrap()["failure"], "automation_suspended");
    assert_eq!(
        audit_records()
            .iter()
            .filter(|r| r.action() == "automation_failed"
                && r.operation() == Some(task.to_string().as_str()))
            .count(),
        1
    );
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn suspended_ingress_fails_readiness_and_restart_recovers_forwarded_input() {
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let worker =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options())
            .await
            .unwrap();
    let peer_service = Arc::new(planning(tenant()).await);
    let peer = crate::automation::Automation::connect(
        peer_service.clone(),
        assets(&peer_service).await,
        options(),
    )
    .await
    .unwrap();
    sql(&format!(
        "INSERT INTO mdm_access.devices VALUES('{}','ingress-{}')",
        tenant(),
        Uuid::new_v4()
    ));
    service.forward_asset_changes().await.unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm.asset_changes WHERE tenant_id='{}' AND NOT forwarded",
            tenant()
        )),
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
        sql(&format!(
            "SELECT failure FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'",
            tenant()
        )),
        "automation_suspended"
    );
    assert!(
        service
            .ingress_health(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    + Duration::from_secs(5)
            )
            .await
            .unwrap()
            .suspended
    );
    assert!(
        peer_service
            .ingress_health(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    + Duration::from_secs(5)
            )
            .await
            .unwrap()
            .suspended,
        "another instance reported healthy"
    );
    // Even an instance started after the failure must retain the diagnosis.
    let late_service = Arc::new(planning(tenant()).await);
    let late = crate::automation::Automation::connect(
        late_service.clone(),
        assets(&late_service).await,
        options(),
    )
    .await
    .unwrap();
    assert!(
        late_service
            .ingress_health(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    + Duration::from_secs(5)
            )
            .await
            .unwrap()
            .suspended,
        "startup cleared failure before successful recovery"
    );
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(late))
        .await
        .unwrap();
    late_service.runtime.close().await;
    service.runtime.close().await;
    let restarted = Arc::new(planning(tenant()).await);
    let worker = crate::automation::Automation::connect(
        restarted.clone(),
        assets(&restarted).await,
        options(),
    )
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
        sql(&format!(
            "SELECT consumed=(SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id='{tenant}') FROM mdm_planning.asset_dispatch WHERE tenant_id='{tenant}'",
            tenant = tenant()
        )),
        "t"
    );
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    assert!(
        !restarted
            .ingress_health(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    + Duration::from_secs(5)
            )
            .await
            .unwrap()
            .suspended
    );
    assert!(
        !peer_service
            .ingress_health(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    + Duration::from_secs(5)
            )
            .await
            .unwrap()
            .suspended,
        "recovered checkpoint not visible to peer"
    );
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(peer))
        .await
        .unwrap();
    peer_service.runtime.close().await;
    restarted.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn corrupt_background_query_is_not_client_input() {
    use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let task = query_job(&service, 1).await;
    let original = sql(&format!(
        "SELECT input FROM mdm_automation.automation_jobs WHERE id='{task}'"
    ));
    let worker =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options())
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
            "UPDATE mdm_automation.automation_jobs SET input='{original}',cursor=NULL WHERE id='{task}'; UPDATE mdm_automation.automation_jobs SET input={value},cursor={cursor} WHERE id='{task}'"
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
                "SELECT NOT completed AND failure IS NULL FROM mdm_automation.automation_jobs WHERE id='{task}'"
            )),
            "t"
        );
        assert_eq!(
            sql(&format!(
                "SELECT total FROM mdm_assets.asset_query_runs WHERE id='{task}'"
            )),
            "0"
        );
    }
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}
