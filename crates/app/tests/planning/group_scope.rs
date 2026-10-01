use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn durable_asset_group_scope_pipeline() {
    let service = Arc::new(planning(tenant()).await);
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_flow_runtime")
        .password("runtime-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let notifications = crate::worker_wake::Listener::new(
        options
            .clone()
            .username("mdm_access")
            .password("access-fixture"),
        service.tenant,
    );
    let automation =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options)
            .await
            .unwrap();
    let device = format!("automation-{}", Uuid::new_v4());
    seed_device(&device);
    let owner = assets::Owner {
        instance: Uuid::new_v4().to_string(),
        principal: Uuid::new_v4().to_string(),
    };
    execute_asset(
        &service,
        &assets::Command::Manual {
            device: device.clone(),
            field: rss_mdm_inventory::builtin::IS_LOANER,
            owner: owner.clone(),
            change: inventory_operation(
                0,
                assets::ManualChange::Set {
                    value: assets::Scalar::Boolean(true),
                },
            ),
        },
    )
    .await
    .unwrap();
    let group = Uuid::new_v4();
    let created = execute(
        &service,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "automation".into(),
                    description: String::new(),
                    criteria: Some(assets::Criteria::Predicate {
                        field: rss_mdm_inventory::builtin::IS_LOANER,
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
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10)).unwrap(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    let mut startup = stack.startup().unwrap();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.clone().registration().critical());
    launch.stage_deferred_task_with_token(
        automation
            .clone()
            .registration(notifications.signals.flow())
            .critical(),
    );
    launch.finish();
    let task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    assert_eq!(
        wait_task(
            &service,
            task,
            crate::automation::TaskKind::Group,
            &group.to_string()
        )
        .await["members"],
        1
    );
    let page_command = Command::GroupPage {
        group,
        result: task,
        projection: pages::GroupPageKind::Members,
        query: pages::PageQuery {
            limit: 1,
            cursor: None,
        },
    };
    let page = execute(&service, &page_command).await.unwrap();
    assert_eq!(page["page"]["items"], serde_json::json!([device]));
    assert_eq!(page["current"], true);
    assert!(wire::Response::decode(page.clone()).is_ok());
    let continuation = execute(
        &service,
        &Command::GroupPage {
            group,
            result: task,
            projection: pages::GroupPageKind::Members,
            query: pages::PageQuery {
                limit: 1,
                cursor: Some(page["nextCursor"].as_str().unwrap().into()),
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(continuation["page"]["items"], serde_json::json!([]));
    let denied_audit = RequestAudit::new(tenant().to_string(), "management_read");
    assert!(matches!(
        service
            .execute(&page_command, &denied_audit, &|| Err(
                rss_mdm_flow_service::Error::Forbidden
            ))
            .await,
        Err(rss_mdm_flow_service::Error::Forbidden)
    ));
    denied_audit.finalize(None);
    let query_scope = assets::ReadScope {
        sensitive: true,
        subject: "query-owner".into(),
        devices: Some([device.clone()].into()),
    };
    let query = execute_asset(
        &service,
        &assets::Command::Search {
            request: inventory_operation(
                0,
                assets::Query {
                    criteria: Some(assets::Criteria::Predicate {
                        field: rss_mdm_inventory::builtin::IS_LOANER,
                        op: assets::Operator::Eq,
                        value: Some(assets::Scalar::Boolean(true)),
                        values: None,
                    }),
                    select: vec![rss_mdm_inventory::builtin::IS_LOANER],
                    sort: Some(assets::Sort {
                        field: rss_mdm_inventory::builtin::IS_LOANER,
                        descending: true,
                    }),
                },
            ),
            scope: query_scope.clone(),
        },
    )
    .await
    .unwrap();
    let query_task = Uuid::parse_str(query["asset"]["task"].as_str().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = execute_asset(
                &service,
                &assets::Command::QueryStatus {
                    task: query_task,
                    scope: query_scope.clone(),
                },
            )
            .await
            .unwrap();
            assert!(status["asset"]["failure"].is_null(), "{status}");
            if status["asset"]["status"] == "completed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let query_items = execute_asset(
        &service,
        &assets::Command::QueryItems {
            task: query_task,
            scope: query_scope.clone(),
            limit: 1,
            cursor: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(query_items["asset"]["summary"]["matched"], 1);
    assert_eq!(query_items["asset"]["items"][0]["device"], device);
    assert_eq!(
        query_items["asset"]["items"][0]["fields"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        execute_asset(
            &service,
            &assets::Command::QueryItems {
                task: query_task,
                scope: assets::ReadScope::all(),
                limit: 1,
                cursor: None
            }
        )
        .await,
        Err(Error::Service(rss_mdm_flow_service::Error::Forbidden))
    ));
    let facets = execute_asset(
        &service,
        &assets::Command::QueryFacets {
            task: query_task,
            scope: query_scope.clone(),
            facet: assets::Facet::AssetStates,
            limit: 1,
            cursor: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(facets["asset"]["items"][0]["label"], "known");
    assert_eq!(facets["asset"]["items"][0]["total"], 1);
    let scope_id = Uuid::new_v4();
    let scoped = execute(
        &service,
        &Command::Scope {
            id: scope_id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(group),
                },
            ),
        },
    )
    .await
    .unwrap();
    let scope_task = Uuid::parse_str(scoped["task"].as_str().unwrap()).unwrap();
    assert_eq!(
        wait_task(
            &service,
            scope_task,
            crate::automation::TaskKind::Scope,
            &scope_id.to_string()
        )
        .await["members"],
        1
    );
    for projection in [
        pages::ScopePageKind::Members,
        pages::ScopePageKind::Decisions,
    ] {
        let page = execute(
            &service,
            &Command::ScopePage {
                scope: scope_id,
                result: scope_task,
                projection,
                query: pages::PageQuery {
                    limit: 1000,
                    cursor: None,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(page["totalMembers"], 1);
        assert!(wire::Response::decode(page).is_ok());
    }
    assert!(stack.shutdown().join().await.unwrap().is_clean());
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(automation))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn group_scope_replay_and_audit_atomicity() {
    let m = Arc::new(planning(tenant()).await);
    let device = format!("设备-{}", Uuid::new_v4());
    seed_device(&device);
    let group = Uuid::new_v4();
    let create = Command::Group {
        sensitive: true,
        id: group,
        change: operation(
            0,
            GroupChange::Create {
                name: "fleet".into(),
                description: String::new(),
                criteria: None,
            },
        ),
    };
    let first = execute(&m, &create).await.unwrap();
    assert_eq!(first, execute(&m, &create).await.unwrap());
    let running = RunningAutomation::start(m.clone()).await;
    let members = execute(
        &m,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(
                1,
                GroupChange::Members {
                    add: vec![device.clone()],
                    remove: vec![],
                },
            ),
        },
    )
    .await
    .unwrap();
    wait_task(
        &m,
        Uuid::parse_str(members["task"].as_str().unwrap()).unwrap(),
        crate::automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    let scope_id = Uuid::new_v4();
    execute(
        &m,
        &Command::Scope {
            id: scope_id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(group),
                },
            ),
        },
    )
    .await
    .unwrap();
    running.stop().await;
    let denied = Uuid::new_v4();
    sql("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime");
    let result = execute(
        &m,
        &Command::Group {
            sensitive: true,
            id: denied,
            change: operation(
                0,
                GroupChange::Create {
                    name: "denied".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        },
    )
    .await;
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime");
    assert!(matches!(
        result,
        Err(Error::Service(rss_mdm_flow_service::Error::Unavailable(
            rss_mdm_flow_service::Failure::AuditAdmission
        )))
    ));
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.groups WHERE id='{denied}'"
        )),
        "0"
    );
    let foreign = planning(TenantId::parse(crate::test_support::case::peer()).unwrap()).await;
    assert!(
        execute(&foreign, &Command::ScopeRead { id: scope_id })
            .await
            .is_err()
    );
    foreign.runtime.close().await;
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn initial_empty_group_scope_and_revision_competition() {
    let m = planning(tenant()).await;
    let g = Uuid::new_v4();
    execute(
        &m,
        &Command::Group {
            sensitive: true,
            id: g,
            change: operation(
                0,
                GroupChange::Create {
                    name: "empty".into(),
                    description: "".into(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    let s = Uuid::new_v4();
    execute(
        &m,
        &Command::Scope {
            id: s,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(g),
                },
            ),
        },
    )
    .await
    .unwrap();
    let a = Command::Scope {
        id: s,
        change: operation(
            1,
            ScopeChange::Put {
                definition: ScopeDefinition {
                    targets: Default::default(),
                    limitations: Some(Default::default()),
                    exclusions: Default::default(),
                },
            },
        ),
    };
    let b = Command::Scope {
        id: s,
        change: operation(1, ScopeChange::Delete),
    };
    let (a, b) = tokio::join!(execute(&m, &a), execute(&m, &b));
    assert_ne!(a.is_ok(), b.is_ok());
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn registration_replacement_invalidates_direct_and_group_admission() {
    let m = Arc::new(planning(tenant()).await);
    let running = RunningAutomation::start(m.clone()).await;
    let device = format!("device-{}", Uuid::new_v4());
    let old = seed_device(&device);
    let group = Uuid::new_v4();
    execute(
        &m,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "registration".into(),
                    description: "".into(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    let membership = execute(
        &m,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(
                1,
                GroupChange::Members {
                    add: vec![device.clone()],
                    remove: vec![],
                },
            ),
        },
    )
    .await
    .unwrap();
    wait_task(
        &m,
        Uuid::parse_str(membership["task"].as_str().unwrap()).unwrap(),
        crate::automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    let mut pending = Vec::new();
    for reference in [Reference::Device(device.clone()), Reference::Group(group)] {
        let id = Uuid::new_v4();
        let receipt = execute(
            &m,
            &Command::Scope {
                id,
                change: operation(
                    0,
                    ScopeChange::Put {
                        definition: ScopeDefinition {
                            targets: [reference].into(),
                            limitations: None,
                            exclusions: Default::default(),
                        },
                    },
                ),
            },
        )
        .await
        .unwrap();
        wait_task(
            &m,
            Uuid::parse_str(receipt["task"].as_str().unwrap()).unwrap(),
            crate::automation::TaskKind::Scope,
            &id.to_string(),
        )
        .await;
        pending.push(id);
    }
    running.stop().await;
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    let t = tenant();
    sql(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{old}';INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{t}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.registrations VALUES('{t}','{replacement}','{device}','mdm',2,'{request}','active');"
    ));
    for id in pending {
        assert_eq!(
            sql(&format!(
                "SELECT mdm_planning.scope_admission('{id}','{device}')->>'state'"
            )),
            "pending"
        );
    }
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn group_delete_scope_reference_compete_without_dangling_references() {
    let first = planning(tenant()).await;
    let second = planning(tenant()).await;
    for reverse in [false, true] {
        let group = Uuid::new_v4();
        let scope_id = Uuid::new_v4();
        execute(
            &first,
            &Command::Group {
                sensitive: true,
                id: group,
                change: operation(
                    0,
                    GroupChange::Create {
                        name: "reference-race".into(),
                        description: "".into(),
                        criteria: None,
                    },
                ),
            },
        )
        .await
        .unwrap();
        let delete = Command::Group {
            sensitive: true,
            id: group,
            change: operation(1, GroupChange::Delete),
        };
        let reference = Command::Scope {
            id: scope_id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(group),
                },
            ),
        };
        let (a, b) = if reverse {
            tokio::join!(execute(&first, &reference), execute(&second, &delete))
        } else {
            tokio::join!(execute(&first, &delete), execute(&second, &reference))
        };
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_planning.scopes s JOIN mdm_planning.scope_versions v USING(tenant_id,id,revision) JOIN mdm_group.groups g ON g.tenant_id=s.tenant_id AND g.id='{group}' WHERE s.id='{scope_id}' AND g.deleted AND NOT s.deleted"
            )),
            "0"
        );
    }
    first.runtime.close().await;
    second.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn ingress_batches_reuse_published_group_coverage() {
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let worker =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options())
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
            sensitive: true,
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "bounded-ingress".into(),
                    description: String::new(),
                    criteria: Some(assets::Criteria::Predicate {
                        field: rss_mdm_inventory::builtin::IS_LOANER,
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
    crate::automation::jobs::forward_jobs(&service.runtime, service.tenant, &service.audit_store)
        .await
        .unwrap();
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
        sql(&format!(
            "SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{}'",
            tenant()
        )),
        "1"
    );
    let claim = claims
        .into_iter()
        .find(|c| c.target().entity() == "changes")
        .unwrap();
    for (consumed, watermark, phase) in [
        (0, 1000, "devices"),
        (0, 1000, "compliance"),
        (1000, 1000, "groups"),
        (1000, 1001, "devices"),
        (1000, 1001, "compliance"),
        (1001, 1001, "groups"),
    ] {
        let diff = worker.observe(&claim, &control).await.unwrap();
        worker.apply(&claim, diff, &control).await.unwrap();
        assert_eq!(
            sql(&format!(
                "SELECT consumed||','||watermark||','||phase FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'",
                tenant()
            )),
            format!("{consumed},{watermark},{phase}")
        );
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{}'",
                tenant()
            )),
            "1",
            "covered batches recreated the million-device calculation"
        );
    }
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn superseded_group_links_reused_successor() {
    let service = planning(tenant()).await;
    let group = Uuid::new_v4();
    seed_device(&format!("successor-{group}"));
    let created = execute(
        &service,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "successor".into(),
                    description: String::new(),
                    criteria: Some(assets::Criteria::Predicate {
                        field: rss_mdm_inventory::builtin::IS_LOANER,
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
    let first = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    seed_device(&format!("successor-new-input-{group}"));
    let next = execute(
        &service,
        &Command::Group {
            sensitive: true,
            id: group,
            change: operation(1, GroupChange::Recompute {}),
        },
    )
    .await
    .unwrap();
    let second = Uuid::parse_str(next["task"].as_str().unwrap()).unwrap();
    assert_ne!(first, second);
    service
        .runtime
        .local_tx_with_context(tenant(), deadline(), &service, |s, tx| {
            Box::pin(async move {
                async {
                    crate::automation::jobs::finish_job_in(
                        tx,
                        &s.audit_store,
                        first,
                        Some("superseded"),
                    )
                    .await?;
                    s.retry_superseded_group_in(tx, first).await
                }
                .await
                .map_err(|_| sqlx::Error::Protocol("successor recovery".into()).into())
            })
        })
        .await
        .fold(
            |_| (),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    assert_eq!(
        sql(&format!(
            "SELECT replacement_task FROM mdm_automation.automation_jobs WHERE id='{first}'"
        )),
        second.to_string()
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_automation.automation_jobs WHERE target='{group}' AND NOT completed"
        )),
        "1"
    );
    service.runtime.close().await;
}
