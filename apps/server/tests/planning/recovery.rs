#[cfg(feature = "integration")]
use rss_mdm_scope::ScopeDefinition;
#[cfg(feature = "integration")]
use rss_mdm_scope_service::ScopeChange;
use rss_reconcile::Reconciler;
mod ingress;

use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn management_admission_rejects_schema_and_privilege_drift() {
    let service = planning(tenant()).await;
    async fn admitted(service: &OwnerFixture, owner: &str) -> bool {
        match owner {
            "policy" => rss_mdm_policy_postgres::PolicyStore::new(
                service.policy.runtime.clone(),
                service.tenant,
                deadline(),
            )
            .await
            .is_ok(),
            "inventory" => service
                .inventory
                .runtime
                .local_tx(service.tenant, deadline(), |tx| {
                    Box::pin(async move {
                        tx.with_connection(|c| {
                            Box::pin(async move {
                                rss_mdm_inventory_service::admit_storage_in(c, tenant()).await
                            })
                        })
                        .await
                    })
                })
                .await
                .fold(
                    |_| true,
                    |_| false,
                    |_| false,
                    |_| false,
                    |_| false,
                    |_| false,
                ),
            "software" => service
                .software
                .runtime
                .local_tx(service.tenant, deadline(), |tx| {
                    Box::pin(async move {
                        tx.with_connection(|c| {
                            Box::pin(async move {
                                sqlx::query_scalar::<_, bool>(
                                    rss_mdm_software_service::catalog::ADMISSION_SQL,
                                )
                                .fetch_one(c)
                                .await
                            })
                        })
                        .await
                    })
                })
                .await
                .fold(|v| v, |_| false, |_| false, |_| false, |_| false, |_| false),
            _ => unreachable!(),
        }
    }
    for (owner, change, restore) in [
        (
            "policy",
            "REVOKE INSERT ON mdm_policy.versions FROM mdm_policy_runtime",
            "GRANT INSERT ON mdm_policy.versions TO mdm_policy_runtime",
        ),
        (
            "policy",
            "GRANT UPDATE(number) ON mdm_policy.versions TO mdm_policy_runtime",
            "REVOKE UPDATE(number) ON mdm_policy.versions FROM mdm_policy_runtime",
        ),
        (
            "policy",
            "GRANT DELETE ON mdm_policy.work TO mdm_policy_runtime",
            "REVOKE DELETE ON mdm_policy.work FROM mdm_policy_runtime",
        ),
        (
            "policy",
            "CREATE ROLE policy_drift NOLOGIN; GRANT UPDATE(number) ON mdm_policy.versions TO policy_drift; GRANT policy_drift TO mdm_policy_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE policy_drift FROM mdm_policy_runtime; DROP OWNED BY policy_drift; DROP ROLE policy_drift",
        ),
        (
            "inventory",
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact DROP NOT NULL",
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact SET NOT NULL",
        ),
        (
            "software",
            "GRANT UPDATE(definition) ON mdm_software.sources TO mdm_software_runtime",
            "REVOKE UPDATE(definition) ON mdm_software.sources FROM mdm_software_runtime",
        ),
        (
            "software",
            "CREATE ROLE software_drift NOLOGIN; GRANT DELETE ON mdm_software.sources TO software_drift; GRANT software_drift TO mdm_software_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE software_drift FROM mdm_software_runtime; DROP OWNED BY software_drift; DROP ROLE software_drift",
        ),
    ] {
        assert!(admitted(&service, owner).await, "baseline {owner}");
        sql(change);
        let rejected = !admitted(&service, owner).await;
        sql(restore);
        assert!(rejected, "accepted privilege drift: {change}");
        assert!(admitted(&service, owner).await, "restored {owner}");
    }
    for role in [
        "mdm_inventory_runtime",
        "mdm_scope_runtime",
        "mdm_policy_runtime",
        "mdm_resource_runtime",
        "mdm_software_runtime",
        "mdm_content_runtime",
        "mdm_telemetry_runtime",
    ] {
        assert_eq!(
            sql(&format!(
                "SELECT NOT pg_has_role('{role}','mdm_command_runtime','MEMBER') AND NOT has_column_privilege('{role}','mdm_access.credentials','locator','SELECT')"
            )),
            "t"
        );
    }
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn revoked_authority_after_lock_rejects_mutation_and_replay() {
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
    let group_service = groups(&m).await;
    for replay in [false, true] {
        let id = Uuid::new_v4();
        let command = GroupCommand::Group {
            id,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"guarded","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: None,
                },
            )),
        };
        if replay {
            execute(&m, &command).await.unwrap();
        }
        // Restore the fixture actor between the new-write and replay cases.
        let proof = group_proof(&m).await;
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2363))")
            .bind(format!("{}:{}", tenant(), crate::test_support::INSTANCE))
            .execute(&mut holder)
            .await
            .unwrap();
        let audit = RequestAudit::new(
            tenant().to_string(),
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.set_principal("operator", crate::test_support::INSTANCE);
        let before = sql(&format!(
            "SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}' AND source_id='mdm.business'",
            tenant()
        ));
        let release = async {
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))").fetch_one(&mut holder).await.unwrap();
                    if waiting { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("request never reached the held lock");
            sql(&format!(
                "UPDATE mdm_access.authorization_rules SET document=NULL,revision=revision+1 WHERE tenant_id='{}' AND id=md5('group-use-cases:'||'{}'||':'||'{}')::uuid",
                tenant(),
                tenant(),
                crate::test_support::case::admin()
            ));
            sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2363))")
                .bind(format!("{}:{}", tenant(), crate::test_support::INSTANCE))
                .execute(&mut holder)
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(group_service.execute(&command, &audit, &proof), release);
        audit.finalize(None);
        assert!(matches!(
            result,
            Err(rss_mdm_inventory_service::Error::Forbidden)
        ));
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}' AND source_id='mdm.business'",
                tenant()
            )),
            before
        );
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{}' AND id='{id}'",
                tenant()
            )),
            if replay { "1" } else { "0" }
        );
        // Delete only this fixture grant so the next case seeds a fresh authorized actor.
        sql(&format!(
            "DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{}' AND id=md5('group-use-cases:'||'{}'||':'||'{}')::uuid",
            tenant(),
            tenant(),
            crate::test_support::case::admin()
        ));
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
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"cursor","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: None,
                },
            )),
        },
    )
    .await
    .unwrap();
    let accepted = execute(
        &first,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                1,
                GroupChange::Members {
                    add: devices
                        .iter()
                        .cloned()
                        .map(rss_mdm_inventory_service::objects::ObjectRef::Endpoint)
                        .collect(),
                    remove: vec![],
                },
            )),
        },
    )
    .await
    .unwrap();
    let result = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    wait_task(&first, result, TaskFamily::Group, &group.to_string()).await;
    running.stop().await;
    let page = |cursor| GroupCommand::GroupPage {
        group,
        result,
        projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
        query: crate::planning::test_support::group_page_query(1, cursor),
    };
    let initial = execute(&first, &page(None)).await.unwrap();
    assert_eq!(
        initial["page"]["items"],
        json!([{"kind":"endpoint","id":devices[0]}])
    );
    let cursor = initial["nextCursor"].as_str().unwrap().to_owned();
    let second = planning(tenant()).await;
    assert_eq!(
        execute(&second, &page(Some(cursor.clone()))).await.unwrap()["page"]["items"],
        json!([{"kind":"endpoint","id":devices[1]}])
    );
    second.close().await;
    first.close().await;
    let restarted = planning(tenant()).await;
    assert_eq!(
        execute(&restarted, &page(Some(cursor.clone())))
            .await
            .unwrap()["page"]["items"],
        json!([{"kind":"endpoint","id":devices[1]}])
    );
    execute(
        &restarted,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(2, GroupChange::Delete)),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        execute(&restarted, &page(Some(cursor))).await.unwrap()["page"]["items"],
        json!([{"kind":"endpoint","id":devices[1]}])
    );
    restarted.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn live_checkpoint_restart_fences_old_worker() {
    use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff};
    let first = Arc::new(planning(tenant()).await);
    let old = QueryWorker::open(&first).await;
    let task = query_job(&first, 129).await;
    // This verifies persisted fencing, not a two-second throughput guarantee for 128 rows.
    let lease = Duration::from_secs(300);
    let stale = claim_query(&old, task, lease).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(120), &cancel);
    let diff = || ReconcileDiff::between(DesiredState::present(false), ActualState::present(true));
    crate::test_support::runtime::reconcile_ready(
        old.apply(&stale, diff(), &control).await.unwrap(),
    );
    let checkpoint = snapshot(task);
    assert_eq!(serde_json::from_str::<Value>(&checkpoint).unwrap()[3], 128);
    old.close().await;

    let second = Arc::new(planning(tenant()).await);
    let resumed = QueryWorker::open(&second).await;
    let claims = resumed
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.asset-queries").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap()
        .claims;
    assert!(
        !claims
            .iter()
            .any(|c| c.target().entity() == format!("task:{task}")),
        "unexpired claim was stolen"
    );
    let token = sql(&format!(
        "SELECT token FROM rss_reconcile.targets WHERE tenant_id='{}' AND reconciler='mdm.asset-queries' AND entity='task:{task}' AND epoch={}",
        tenant(),
        stale.epoch()
    ));
    assert_eq!(
        sql(&format!(
            "WITH expired AS (UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id='{}' AND reconciler='mdm.asset-queries' AND entity='task:{task}' AND epoch={} AND token='{token}' RETURNING 1) SELECT count(*) FROM expired",
            tenant(),
            stale.epoch()
        )),
        "1"
    );
    let current = claim_query(&resumed, task, lease).await;
    assert!(current.epoch() > stale.epoch());
    assert_eq!(
        resumed
            .apply(&stale, diff(), &control)
            .await
            .unwrap_err()
            .kind(),
        rss_reconcile::ErrorKind::Fenced
    );
    assert_eq!(
        resumed
            .finish(
                &stale,
                rss_reconcile::Completion::Suspended { failures: 1 },
                &control
            )
            .await
            .unwrap_err()
            .kind(),
        rss_reconcile::ErrorKind::Fenced
    );
    assert_eq!(
        snapshot(task),
        checkpoint,
        "stale claim changed persisted progress or cleared new work"
    );
    crate::test_support::runtime::reconcile_ready(
        resumed.apply(&current, diff(), &control).await.unwrap(),
    );
    let completed: Value = serde_json::from_str(&snapshot(task)).unwrap();
    assert_eq!(completed[1], true);
    assert_eq!(completed[3], 129);
    assert_eq!(completed[4], 129);
    resumed
        .finish(&current, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    resumed.close().await;
    first.close().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn rss_exhaustion_records_failed_task_and_atomic_audit() {
    use rss_reconcile::DurableStore;
    let service = Arc::new(planning(tenant()).await);
    let worker = QueryWorker::open(&service).await;
    let task = query_job(&service, 1).await;
    let claim = claim_query(&worker, task, Duration::from_secs(6)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    // Failure of the companion audit must leave both job and RSS claim retryable.
    sql(
        "REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_inventory_runtime",
    );
    let result = worker
        .finish(
            &claim,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control,
        )
        .await;
    sql(
        "GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_inventory_runtime",
    );
    assert!(result.is_err());
    assert_eq!(
        serde_json::from_str::<Value>(&snapshot(task)).unwrap()[1],
        false
    );
    worker.release(&claim, &control).await.unwrap();
    // Let the actual RSS worker select Suspended after an unrecoverable page write.
    sql("REVOKE INSERT ON mdm_assets.asset_query_results FROM mdm_inventory_runtime");
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
    let scope = rss_reconcile::Scope::new(tenant(), "mdm.asset-queries").unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let runner = rss_reconcile::run(
        worker.as_ref(),
        worker.as_ref(),
        &scope,
        policy,
        &control,
        &stop,
        |_| {},
    );
    let query_scope: assets::ReadScope = serde_json::from_str(&sql(&format!(
        "SELECT (input->'scope')::text FROM mdm_assets.asset_query_runs WHERE id='{task}'"
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
        stop.cancel();
        outcome
    };
    let (_, state) = tokio::join!(runner, inspect);
    sql("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_inventory_runtime");
    assert_eq!(state.unwrap()["failure"], "automation_suspended");
    assert_eq!(
        audit_records()
            .await
            .iter()
            .filter(|r| r.action() == "automation_failed"
                && r.operation() == Some(task.to_string().as_str()))
            .count(),
        1
    );
    worker.close().await;
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn suspended_inputs_remain_failed_until_owner_recovery_commits() {
    use crate::test_support::execution_inputs::InputOwner;
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let worker = InputOwner::open(&service, 4).await.unwrap();
    let peer = InputOwner::open(&service, 4).await.unwrap();
    sql(&format!(
        "INSERT INTO mdm_access.devices VALUES('{}','ingress-{}')",
        tenant(),
        Uuid::new_v4()
    ));
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    let scope = rss_mdm_execution_service::recovery_scope(tenant());
    let claim = worker
        .execution
        .recovery_store()
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await
        .unwrap()
        .claims
        .into_iter()
        .find(|c| c.target().entity() == "inputs")
        .unwrap();
    worker
        .execution
        .recovery_store()
        .finish(
            &claim,
            rss_reconcile::Completion::Suspended { failures: 1 },
            &control,
        )
        .await
        .unwrap();
    let cutoff = || {
        rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) + Duration::from_secs(5)
    };
    assert!(
        worker
            .execution
            .ingress_health(cutoff())
            .await
            .unwrap()
            .suspended
    );
    assert!(
        peer.execution
            .ingress_health(cutoff())
            .await
            .unwrap()
            .suspended
    );
    let late = InputOwner::open(&service, 4).await.unwrap();
    assert!(
        late.execution
            .ingress_health(cutoff())
            .await
            .unwrap()
            .suspended,
        "startup cannot clear an unsettled failure"
    );
    late.close().await;
    worker.close().await;
    let resumed = InputOwner::open(&service, 4).await.unwrap();
    let claim = resumed
        .execution
        .recovery_store()
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await
        .unwrap()
        .claims
        .into_iter()
        .find(|c| c.target().entity() == "inputs")
        .unwrap();
    for _ in 0..8 {
        let diff = crate::test_support::runtime::reconcile_ready(
            resumed.execution.observe(&claim, &control).await.unwrap(),
        );
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        crate::test_support::runtime::reconcile_ready(
            resumed
                .execution
                .apply(&claim, diff, &control)
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        crate::test_support::runtime::reconcile_ready(
            resumed.execution.observe(&claim, &control).await.unwrap()
        )
        .drift(),
        rss_reconcile::DriftKind::Converged
    );
    resumed
        .execution
        .recovery_store()
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT to_cut IS NULL AND NOT EXISTS(SELECT 1 FROM mdm.asset_changes e WHERE e.tenant_id=d.tenant_id AND NOT mdm.asset_visible(d.from_cut,e.revision)) FROM mdm_commands.device_source_dispatch d WHERE tenant_id='{t}'",
            t = tenant()
        )),
        "t"
    );
    assert!(
        !peer
            .execution
            .ingress_health(cutoff())
            .await
            .unwrap()
            .suspended
    );
    resumed.close().await;
    peer.close().await;
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real capability storage and transactions"]
async fn corrupt_background_query_is_not_client_input() {
    use rss_reconcile::{ActualState, DesiredState, ReconcileDiff};
    let service = Arc::new(planning(tenant()).await);
    let task = query_job(&service, 1).await;
    let original = sql(&format!(
        "SELECT input FROM mdm_assets.asset_query_runs WHERE id='{task}'"
    ));
    let worker = QueryWorker::open(&service).await;
    let claim = claim_query(&worker, task, Duration::from_secs(30)).await;
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
            "UPDATE mdm_assets.asset_query_runs SET input='{original}',cursor=NULL WHERE id='{task}'; UPDATE mdm_assets.asset_query_runs SET input={value},cursor={cursor} WHERE id='{task}'"
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
                "SELECT NOT completed AND failure IS NULL FROM mdm_assets.asset_query_runs WHERE id='{task}'"
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
    sql(&format!(
        "UPDATE mdm_assets.asset_query_runs SET input='{original}',cursor=NULL WHERE id='{task}'"
    ));
    crate::test_support::runtime::reconcile_ready(
        worker
            .apply(
                &claim,
                ReconcileDiff::between(DesiredState::present(false), ActualState::present(true)),
                &control,
            )
            .await
            .unwrap(),
    );
    let completed: Value = serde_json::from_str(&snapshot(task)).unwrap();
    assert_eq!(completed[1], true);
    assert_eq!(completed[4], 1);
    worker.close().await;
    service.close().await;
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=planning.recovery: real PG owner settlement and receipt replay"]
async fn planning_owner_settlement_preserves_unknown_rollback_and_exact_replay() {
    use rss_transactional_messaging_postgres::PgTransactionFault as F;
    let service = planning(tenant()).await;
    let owner = scopes(&service).await;
    for (fault, unknown) in [
        (F::CommitUnknownAfterAck, true),
        (F::RollbackFailedAfterAck, false),
    ] {
        let id = Uuid::new_v4();
        let command = Command::Scope {
            id,
            change: scope_operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: Default::default(),
                        limitations: None,
                        exclusions: Default::default(),
                    },
                },
            ),
        };
        let audit = RequestAudit::new(
            tenant().to_string(),
            "management_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.set_principal("operator", crate::test_support::INSTANCE);
        service.scope.runtime.inject_next_transaction_fault(fault);
        let first = if unknown {
            owner.execute(&command, &audit, &|| Ok(())).await
        } else {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            owner
                .execute(&command, &audit, &|| {
                    if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(rss_mdm_scope_service::Error::Forbidden)
                    }
                })
                .await
        };
        assert!(
            matches!(
                (&first, unknown),
                (Err(rss_mdm_scope_service::Error::CommitUnknown), true)
                    | (Err(rss_mdm_scope_service::Error::RollbackFailed), false)
            ),
            "{first:?}"
        );
        audit.finalize(None);
        let settled = execute(&service, &command).await.unwrap();
        assert_eq!(execute(&service, &command).await.unwrap(), settled);
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_scope.scope_versions WHERE tenant_id='{}' AND id='{id}'",
                tenant()
            ))
            .trim(),
            "1"
        );
        let op = match &command {
            Command::Scope { change, .. } => change.operation_id,
            _ => unreachable!(),
        };
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_planning.operations WHERE tenant_id='{}' AND id='{op}'",
                tenant()
            ))
            .trim(),
            "1"
        );
    }
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.recovery: real owner pools must finish shutdown before clean is reported"]
async fn fixture_success_and_partial_initialization_close_real_owner_pools() {
    use crate::test_support::runtime::Resources;
    let fixture = Arc::new(planning(tenant()).await);
    let runtimes = [
        fixture.policy.runtime.clone(),
        fixture.inventory.runtime.clone(),
        fixture.scope.runtime.clone(),
        fixture.resource.runtime.clone(),
        fixture.software.runtime.clone(),
    ];
    let mut resources = Resources::default();
    resources.resource(OwnerResource(fixture));
    resources.finish(async { Ok(()) }).await.unwrap();
    for runtime in runtimes {
        let result = runtime
            .local_tx(tenant(), deadline(), |_| Box::pin(async { Ok(()) }))
            .await;
        assert!(
            result.fold(
                |_| false,
                |_| true,
                |_| false,
                |_| false,
                |_| false,
                |_| false
            ),
            "successful fixture shutdown returned before its owner pool closed"
        );
    }
    let audit = audit_store().await;
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observe = captured.clone();
    let result = Resources::build::<()>(move |resources| {
        Box::pin(async move {
            for role in ["mdm_inventory_runtime", "mdm_scope_runtime"] {
                let owner = owner(audit.clone(), tenant(), role, resources).await;
                observe.lock().unwrap().push(owner.runtime);
            }
            anyhow::bail!("injected later owner initialization failure")
        })
    })
    .await;
    assert!(result.is_err());
    let runtimes = std::mem::take(&mut *captured.lock().unwrap());
    for runtime in runtimes {
        let result = runtime
            .local_tx(tenant(), deadline(), |_| Box::pin(async { Ok(()) }))
            .await;
        assert!(
            result.fold(
                |_| false,
                |_| true,
                |_| false,
                |_| false,
                |_| false,
                |_| false
            ),
            "initialization failure left an earlier owner pool open"
        );
    }
}
