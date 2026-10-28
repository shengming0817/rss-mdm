use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=groups.service: real capability storage and transactions"]
async fn ingress_batches_reuse_published_group_coverage() {
    let service = Arc::new(planning(tenant()).await);
    let worker = GroupWorker::open(&service).await;
    while worker.reconcile_inputs().await.unwrap() {}
    let initial_central = sql(&format!(
        "SELECT coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'),0)",
        tenant()
    ));
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','batch-'||lpad(n::text,4,'0') FROM generate_series(1,1001) n",
        tenant()
    ));
    let group = Uuid::new_v4();
    let accepted = seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"bounded-ingress","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::IS_LOANER,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::Boolean(true)),
                                values: None,
                            },
                    }),
                },
            )),
        },
    )
    .await
    .unwrap();

    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let claim = claim_group(&worker, task, Duration::from_secs(120)).await;
    finish_group_claim(&worker, &claim).await;
    let before = sql(&format!(
        "SELECT count(*) FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND target='{group}'",
        tenant()
    ));
    while worker.reconcile_inputs().await.unwrap() {}
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND target='{group}'",
            tenant()
        )),
        before
    );
    assert_eq!(
        sql(&format!(
            "SELECT consumed=(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{}') FROM mdm_assets.group_dispatch WHERE tenant_id='{}'",
            tenant(),
            tenant()
        )),
        "t"
    );
    assert_eq!(
        sql(&format!(
            "SELECT coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'),0)",
            tenant()
        )),
        initial_central
    );
    worker.close().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.service: real capability storage and transactions"]
async fn superseded_group_links_reused_successor() {
    let service = planning(tenant()).await;
    let group = Uuid::new_v4();
    seed_device(&format!("successor-{group}"));
    let created = seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"successor","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::IS_LOANER,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::Boolean(true)),
                                values: None,
                            },
                    }),
                },
            )),
        },
    )
    .await
    .unwrap();
    let first = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    seed_device(&format!("successor-new-input-{group}"));
    let next = seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                1,
                GroupChange::Rule {
                    criteria: assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::IS_LOANER,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::Boolean(true)),
                                values: None,
                            },
                    },
                },
            )),
        },
    )
    .await
    .unwrap();
    let second = Uuid::parse_str(next["task"].as_str().unwrap()).unwrap();
    assert_ne!(first, second);
    let worker = GroupWorker::open(&service).await;
    let claim = claim_group(&worker, first, Duration::from_secs(60)).await;
    finish_group_claim(&worker, &claim).await;
    worker.close().await;
    assert_eq!(
        sql(&format!(
            "SELECT replacement_task FROM mdm_assets.group_tasks WHERE id='{first}'"
        )),
        second.to_string()
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_assets.group_tasks WHERE target='{group}' AND NOT completed"
        )),
        "1"
    );
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.service: real dependency transactions"]
async fn concurrent_opposite_group_references_never_commit_a_cycle() {
    use rss_mdm_inventory_service::groups::criteria::{Criteria, MembershipOp};
    let first = Arc::new(planning(tenant()).await);
    let second = planning(tenant()).await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    for id in [a, b] {
        seed_group(
            &first,
            &GroupCommand::Group {
                id,

                change: Box::new(group_operation(
                    0,
                    GroupChange::Create {
                        asset_context: rss_mdm_group::AssetContext::Endpoint,
                        presentation: json!({"name":"cycle-race","description":""})
                            .as_object()
                            .unwrap()
                            .clone(),
                        criteria: Some(assets::InventoryCondition {
                            selector: assets::ScopeSelector::Device,
                            quantifier: assets::ScopeQuantifier::One,
                            criteria: Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::MODEL,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::String("any".into())),
                                values: None,
                            },
                        }),
                    },
                )),
            },
        )
        .await
        .unwrap();
    }
    let change = |id, target| GroupCommand::Group {
        id,

        change: Box::new(group_operation(
            1,
            GroupChange::Rule {
                criteria: assets::InventoryCondition {
                    selector: assets::ScopeSelector::Device,
                    quantifier: assets::ScopeQuantifier::One,
                    criteria: Criteria::Group {
                        group_id: target,
                        op: MembershipOp::MemberOf,
                    },
                },
            },
        )),
    };
    let left = change(a, b);
    let right = change(b, a);
    use sqlx::Connection;
    let mut holder =
        sqlx::PgConnection::connect_with(&options().username("postgres").password("local-fixture"))
            .await
            .unwrap();
    sqlx::query("BEGIN").execute(&mut holder).await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
        .bind(tenant().to_string())
        .execute(&mut holder)
        .await
        .unwrap();
    let release = async {
        tokio::time::timeout(Duration::from_secs(8),async {
            loop {
                let waiting:i64=sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked").fetch_one(&mut holder).await.unwrap();
                if waiting>=2 {break;}tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("opposite graph writes never overlapped");
        sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
    };
    let (left, right, ()) = tokio::join!(execute(&first, &left), execute(&second, &right), release);
    let left = left.unwrap();
    let right = right.unwrap();
    let worker = GroupWorker::open(&first).await;

    let left_id = Uuid::parse_str(left["task"].as_str().unwrap()).unwrap();
    let right_id = Uuid::parse_str(right["task"].as_str().unwrap()).unwrap();
    let left_claim = claim_group(&worker, left_id, Duration::from_secs(120)).await;
    let right_claim = claim_group(&worker, right_id, Duration::from_secs(120)).await;
    tokio::join!(
        finish_group_claim(&worker, &left_claim),
        finish_group_claim(&worker, &right_claim)
    );
    let outcomes = sql(&format!(
        "SELECT count(*) FILTER(WHERE completed AND failure IS NULL),count(*) FILTER(WHERE completed AND failure='invalid_input') FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id IN('{left_id}','{right_id}')",
        tenant()
    ));
    assert_eq!(outcomes, "1|1");
    worker.close().await;
    let count = sql(&format!(
        "SELECT count(*) FROM mdm_group.groups g JOIN mdm_group.rules s ON(s.tenant_id,s.group_id,s.version)=(g.tenant_id,g.id,g.rule_version) WHERE g.tenant_id='{}' AND g.id IN('{a}','{b}') AND cardinality(s.group_ids)>0",
        tenant()
    ));
    assert_eq!(count, "1");
    holder.close().await.unwrap();
    first.runtime.close().await;
    second.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.service: real large source evidence pages"]
async fn nested_large_source_evidence_retries_with_smaller_pages() {
    use rss_mdm_group_postgres::core as g;
    use rss_reconcile::{DurableStore, Reconciler};
    use std::collections::{BTreeMap, BTreeSet};
    let service = Arc::new(planning(tenant()).await);
    let prefix = format!("large-source-{}", Uuid::new_v4());
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','{prefix}-'||lpad(n::text,4,'0') FROM generate_series(1,600) n",
        tenant()
    ));
    let source = Uuid::new_v4();
    let created = seed_group(
        &service,
        &GroupCommand::Group {
            id: source,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"large-evidence-source","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::AllAuthorized,
                        quantifier: assets::ScopeQuantifier::Any,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::MODEL,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::String("model".into())),
                                values: None,
                            },
                    }),
                },
            )),
        },
    )
    .await
    .unwrap();
    let task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    let run = rss_mdm_group::OperationId::parse(&task.to_string()).unwrap();
    let build = service
        .runtime
        .local_tx_with_context(tenant(), deadline(), &service, |s, tx| {
            Box::pin(async move { s.groups.build_in(tx, run).await })
        })
        .await
        .fold(
            |v| v.unwrap(),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    // The upstream owner supplies valid frozen core input. The tested action is reading its
    // persisted evidence through the real nested worker, not reconstructing inventory ingress.
    let objects: Vec<_> = (1..=600)
        .map(|n| g::ObjectSnapshot {
            key: g::ObjectKey::new(tenant(), format!("{prefix}-{n:04}")).unwrap(),
            memberships: BTreeMap::new(),
            quantifier: g::Quantifier::Any,
            complete: true,
            contexts: (0..4)
                .map(|c| {
                    (
                        format!("context-{c}"),
                        BTreeMap::from([(
                            "device.model".into(),
                            g::Fact {
                                state: g::FactState::Known(g::Value::Scalar(g::Scalar::String(
                                    "model".into(),
                                ))),
                                source: "s".repeat(4000),
                                snapshot_id: "p".repeat(4000),
                                observed_at: build.request.as_of,
                            },
                        )]),
                    )
                })
                .collect(),
        })
        .collect();
    let coverage = BTreeSet::from(["device.model".into()]);
    for start in (0..600).step_by(100) {
        let page = g::PageInput {
            tenant: tenant(),
            id: "assets",
            version: &build.request.input_version,
            dictionary_version: rss_mdm_inventory::DICTIONARY,
            coverage: &coverage,
            objects: &objects[start..start + 100],
            after: if start == 0 {
                None
            } else {
                Some(&objects[start - 1].key)
            },
        };
        service
            .runtime
            .local_tx_with_context(tenant(), deadline(), (&service, &page), |ctx, tx| {
                Box::pin(async move { ctx.0.groups.append_build_page_in(tx, run, ctx.1).await })
            })
            .await
            .fold(
                |v| {
                    v.unwrap();
                },
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            );
    }
    service
        .runtime
        .local_tx_with_context(tenant(), deadline(), &service, |s, tx| {
            Box::pin(async move { s.groups.seal_build_in(tx, run, 600).await })
        })
        .await
        .fold(
            |v| {
                v.unwrap();
            },
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    let worker = GroupWorker::open(&service).await;
    let claim = claim_group(&worker, task, Duration::from_secs(300)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(120), &cancel);
    for _ in 0..16 {
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
    assert!(
        sql(&format!(
            "SELECT sum(octet_length(evidence))>16777216 FROM mdm_group.member_rows WHERE tenant_id='{}' AND run_id='{task}'",
            tenant()
        )) == "t"
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    let target = Uuid::new_v4();
    let accepted = seed_group(
        &service,
        &GroupCommand::Group {
            id: target,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"small-leaf-large-source","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria: rss_mdm_inventory_service::groups::criteria::Criteria::Group {
                            group_id: source,
                            op: rss_mdm_inventory_service::groups::criteria::MembershipOp::MemberOf,
                        },
                    }),
                },
            )),
        },
    )
    .await
    .unwrap();
    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();

    let claim = claim_group(&worker, task, Duration::from_secs(300)).await;
    let diff = worker.observe(&claim, &control).await.unwrap();
    worker.apply(&claim, diff, &control).await.unwrap();
    let processed: i64 = sql(&format!(
        "SELECT processed_count FROM mdm_group.member_runs WHERE tenant_id='{}' AND id='{task}'",
        tenant()
    ))
    .parse()
    .unwrap();
    assert!(
        processed > 0 && processed < 600,
        "oversized source page was not retried: {processed}"
    );
    for _ in 0..24 {
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
    assert_eq!(
        sql(&format!(
            "SELECT member_count FROM mdm_group.groups WHERE tenant_id='{}' AND id='{target}'",
            tenant()
        )),
        "600"
    );
    assert_eq!(
        sql(&format!(
            "SELECT coalesce(failure,'ok') FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "ok"
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    worker.close().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.service: durable definition validation and publication CAS"]
async fn definition_validation_resumes_without_partial_publication() {
    use rss_mdm_inventory_service::groups::criteria::{Criteria, MembershipOp};
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let condition = |source: Option<Uuid>| assets::InventoryCondition {
        selector: assets::ScopeSelector::Device,
        quantifier: assets::ScopeQuantifier::One,
        criteria: source.map_or(
            Criteria::Predicate {
                field: rss_mdm_inventory::builtin::MODEL,
                op: assets::Operator::Eq,
                value: Some(assets::Scalar::String("fixture".into())),
                values: None,
            },
            |group_id| Criteria::Group {
                group_id,
                op: MembershipOp::MemberOf,
            },
        ),
    };
    let create = |id, source| GroupCommand::Group {
        id,

        change: Box::new(group_operation(
            0,
            GroupChange::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                presentation: json!({"name":"graph baseline","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                criteria: Some(condition(source)),
            },
        )),
    };
    let mut source = None;
    for _ in 0..20 {
        let id = Uuid::new_v4();
        seed_group(&service, &create(id, source)).await.unwrap();
        source = Some(id);
    }
    let root = Uuid::new_v4();
    seed_group(&service, &create(root, None)).await.unwrap();
    let change = GroupCommand::Group {
        id: root,
        change: Box::new(group_operation(
            1,
            GroupChange::Rule {
                criteria: condition(source),
            },
        )),
    };
    let accepted = execute(&service, &change).await.unwrap();
    assert_eq!(accepted["kind"], "group_definition");
    assert!(accepted.get("group").is_none());
    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let worker = GroupWorker::open(&service).await;

    let claim = claim_group(&worker, task, Duration::from_secs(120)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    let diff = worker.observe(&claim, &control).await.unwrap();
    worker.apply(&claim, diff, &control).await.unwrap();
    assert_eq!(
        execute(&service, &GroupCommand::GroupRead { id: root })
            .await
            .unwrap()["group"]["revision"],
        1
    );
    assert_eq!(
        sql(&format!(
            "SELECT (cursor::jsonb->>'ready')::boolean FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "f"
    );
    assert!(sql(&format!("SELECT count(*) FROM mdm_group.definition_walk WHERE tenant_id='{}' AND task_id='{task}'", tenant())).parse::<usize>().unwrap() > 0);
    worker.release(&claim, &control).await.unwrap();
    worker.close().await;
    let resumed = GroupWorker::open(&service).await;
    let claim = claim_group(&resumed, task, Duration::from_secs(120)).await;
    finish_group_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.definition_walk WHERE tenant_id='{}' AND task_id='{task}'",
            tenant()
        )),
        "0"
    );
    assert_eq!(
        execute(&service, &GroupCommand::GroupRead { id: root })
            .await
            .unwrap()["group"]["revision"],
        2
    );
    assert_eq!(execute(&service, &change).await.unwrap(), accepted);
    let queued = execute(
        &service,
        &GroupCommand::Group {
            id: root,
            change: Box::new(group_operation(
                2,
                GroupChange::Rule {
                    criteria: condition(None),
                },
            )),
        },
    )
    .await
    .unwrap();
    execute(
        &service,
        &GroupCommand::Group {
            id: root,
            change: Box::new(group_operation(
                2,
                GroupChange::Edit {
                    presentation: json!({"name":"later edit","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                },
            )),
        },
    )
    .await
    .unwrap();

    let task = Uuid::parse_str(queued["task"].as_str().unwrap()).unwrap();
    let claim = claim_group(&resumed, task, Duration::from_secs(120)).await;
    finish_group_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.definition_walk WHERE tenant_id='{}' AND task_id='{task}'",
            tenant()
        )),
        "0"
    );
    assert_eq!(
        sql(&format!(
            "SELECT failure FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "owner_conflict"
    );
    assert_eq!(
        execute(&service, &GroupCommand::GroupRead { id: root })
            .await
            .unwrap()["group"]["revision"],
        3
    );
    assert!(
        execute(
            &service,
            &GroupCommand::Group {
                id: source.unwrap(),
                change: Box::new(group_operation(1, GroupChange::Delete))
            }
        )
        .await
        .is_err()
    );
    let removed = Uuid::new_v4();
    seed_group(&service, &create(removed, None)).await.unwrap();
    let dependent = Uuid::new_v4();
    let accepted = execute(&service, &create(dependent, Some(removed)))
        .await
        .unwrap();
    execute(
        &service,
        &GroupCommand::Group {
            id: removed,
            change: Box::new(group_operation(1, GroupChange::Delete)),
        },
    )
    .await
    .unwrap();

    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let claim = claim_group(&resumed, task, Duration::from_secs(120)).await;
    finish_group_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.definition_walk WHERE tenant_id='{}' AND task_id='{task}'",
            tenant()
        )),
        "0"
    );
    assert_eq!(
        sql(&format!(
            "SELECT failure FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "source_unavailable"
    );
    assert!(
        execute(&service, &GroupCommand::GroupRead { id: dependent })
            .await
            .is_err()
    );
    let denied_group = Uuid::new_v4();
    let denied = execute(&service, &create(denied_group, source))
        .await
        .unwrap();
    let task = Uuid::parse_str(denied["task"].as_str().unwrap()).unwrap();
    sql(&format!(
        "INSERT INTO mdm_group.definition_walk(tenant_id,task_id,node_id,graph_revision) VALUES('{}','{task}','{root}',0)",
        tenant()
    ));
    sql(&format!(
        "UPDATE mdm_access.authorization_rules SET document=NULL,revision=revision+1 WHERE tenant_id='{}' AND id=md5('group-use-cases:'||'{}'||':'||'{}')::uuid",
        tenant(),
        tenant(),
        crate::test_support::case::admin()
    ));
    let claim = claim_group(&resumed, task, Duration::from_secs(120)).await;
    finish_group_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{}' AND id='{denied_group}'",
            tenant()
        )),
        "0"
    );
    assert_eq!(
        sql(&format!(
            "SELECT completed AND failure='permission_denied' AND NOT EXISTS(SELECT 1 FROM mdm_group.definition_walk WHERE tenant_id='{}' AND task_id='{task}') FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND id='{task}'",
            tenant(),
            tenant()
        )),
        "t"
    );
    assert!(
        execute(&service, &GroupCommand::GroupRead { id: denied_group })
            .await
            .is_err()
    );
    resumed.close().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.service: Group checkpoint restart and real lease fencing"]
async fn group_checkpoint_restart_fences_old_apply_and_finish() {
    use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff, Reconciler};
    let service = planning(tenant()).await;
    let group = Uuid::new_v4();
    seed_device(&format!("group-fence-{group}"));
    let accepted = seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"fenced group","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::builtin::IS_LOANER,
                                op: assets::Operator::Eq,
                                value: Some(assets::Scalar::Boolean(true)),
                                values: None,
                            },
                    }),
                },
            )),
        },
    )
    .await
    .unwrap();
    let id = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let old = GroupWorker::open(&service).await;
    let lease = Duration::from_secs(300);
    let stale = claim_group(&old, id, lease).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(120), &cancel);
    let diff = || ReconcileDiff::between(DesiredState::present(false), ActualState::present(true));
    old.apply(&stale, diff(), &control).await.unwrap();
    let snapshot = || {
        sql(&format!(
            "SELECT jsonb_build_array(j.completed,j.failure,j.cursor,j.replacement_task,r.phase,r.processed_count,encode(r.receipt,'hex'),g.member_set,(SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}'),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND domain='mdm-group')) FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(j.tenant_id,j.id) JOIN mdm_group.groups g ON(g.tenant_id,g.id)=(r.tenant_id,r.group_id) WHERE j.tenant_id='{}' AND j.id='{id}'",
            tenant(),
            tenant(),
            tenant()
        ))
    };
    let checkpoint = snapshot();
    assert_eq!(
        serde_json::from_str::<Value>(&checkpoint).unwrap()[0],
        false
    );
    old.close().await;
    let second = planning(tenant()).await;
    let resumed = GroupWorker::open(&second).await;
    let claims = resumed
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.groups").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap();
    for claim in claims {
        assert_ne!(
            claim.target().entity(),
            format!("task:{id}"),
            "live Group lease was stolen"
        );
        resumed.release(&claim, &control).await.unwrap();
    }
    let token = sql(&format!(
        "SELECT token FROM rss_reconcile.targets WHERE tenant_id='{}' AND reconciler='mdm.groups' AND entity='task:{id}' AND epoch={}",
        tenant(),
        stale.epoch()
    ));
    assert_eq!(
        sql(&format!(
            "WITH expired AS (UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id='{}' AND reconciler='mdm.groups' AND entity='task:{id}' AND epoch={} AND token='{token}' RETURNING 1) SELECT count(*) FROM expired",
            tenant(),
            stale.epoch()
        )),
        "1"
    );
    let current = claim_group(&resumed, id, lease).await;
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
        snapshot(),
        checkpoint,
        "stale owner changed Group progress, result, work or audit"
    );
    finish_group_claim(&resumed, &current).await;
    assert_eq!(serde_json::from_str::<Value>(&snapshot()).unwrap()[0], true);
    resumed.close().await;
    service.runtime.close().await;
    second.runtime.close().await;
}
