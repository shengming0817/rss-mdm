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
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options)
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
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
    let created = seed_group(
        &service,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"automation","description":""})
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
    let page_command = GroupCommand::GroupPage {
        group,
        result: task,
        projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
        query: rss_mdm_inventory_service::groups::pages::PageQuery {
            limit: 1,
            cursor: None,
        },
    };
    let page = execute(&service, &page_command).await.unwrap();
    assert_eq!(
        page["page"]["items"],
        serde_json::json!([{"kind":"endpoint","id":device}])
    );
    assert_eq!(page["current"], true);
    assert!(rss_mdm_inventory_service::groups::response::Response::decode(page.clone()).is_ok());
    let continuation = execute(
        &service,
        &GroupCommand::GroupPage {
            group,
            result: task,
            projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
            query: rss_mdm_inventory_service::groups::pages::PageQuery {
                limit: 1,
                cursor: Some(page["nextCursor"].as_str().unwrap().into()),
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(continuation["page"]["items"], serde_json::json!([]));
    let denied_audit = RequestAudit::new(
        tenant().to_string(),
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    assert!(matches!(
        groups(&service)
            .await
            .execute(
                &page_command,
                &denied_audit,
                &|| Err(rss_mdm_inventory_service::Error::Forbidden),
                service.as_ref()
            )
            .await,
        Err(rss_mdm_inventory_service::Error::Forbidden)
    ));
    denied_audit.finalize(None);
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
                    channel: rss_mdm_inventory::Channel::Mdm,
                    limit: 1000,
                    cursor: None,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(page["page"]["items"].as_array().unwrap().len(), 1);
        assert!(wire::Response::decode(page).is_ok());
    }
    assert!(stack.shutdown().join().await.unwrap().is_clean());
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(automation.work.clone()))
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
    let create = GroupCommand::Group {
        sensitive: true,
        id: group,
        change: Box::new(group_operation(
            0,
            GroupChange::Create {
                asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                presentation: serde_json::json!({"name":"fleet","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                criteria: None,
            },
        )),
    };
    let first = execute(&m, &create).await.unwrap();
    assert_eq!(first, execute(&m, &create).await.unwrap());
    let running = RunningAutomation::start(m.clone()).await;
    let members = execute(
        &m,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                1,
                GroupChange::Members {
                    add: vec![rss_mdm_inventory_service::objects::ObjectRef::Endpoint(
                        device.clone(),
                    )],
                    remove: vec![],
                },
            )),
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
        &GroupCommand::Group {
            sensitive: true,
            id: denied,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"denied","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: None,
                },
            )),
        },
    )
    .await;
    sql(
        "GRANT INSERT(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) ON mdm_audit.receipts TO mdm_flow_runtime",
    );
    assert!(matches!(
        result,
        Err(Error::Inventory(rss_mdm_inventory_service::Error::Audit(e)))
            if matches!(e.class(), rss_mdm_audit_integration::ErrorClass::Audit)
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
async fn group_scope_revision_competition() {
    let m = planning(tenant()).await;
    let g = Uuid::new_v4();
    execute(
        &m,
        &GroupCommand::Group {
            sensitive: true,
            id: g,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"empty","description":""})
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
    let (winner, loser) = match a {
        Ok(winner) => (winner, b),
        Err(error) => (b.unwrap(), Err(error)),
    };
    assert!(matches!(
        loser,
        Err(Error::Flow(rss_mdm_flow_service::Error::Conflict))
    ));
    assert_eq!(winner["revision"], 2);
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm_planning.scopes WHERE tenant_id='{}' AND id='{s}'",
            tenant()
        )),
        "2"
    );
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
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"registration","description":""})
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
    let membership = execute(
        &m,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                1,
                GroupChange::Members {
                    add: vec![rss_mdm_inventory_service::objects::ObjectRef::Endpoint(
                        device.clone(),
                    )],
                    remove: vec![],
                },
            )),
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
        assert!(matches!(
            scope_admission(&m, id, rss_mdm_inventory::Channel::Mdm, &device).await,
            rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { .. }
        ));
        pending.push(id);
    }
    running.stop().await;
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    let t = tenant();
    sql(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{old}';INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) VALUES('{t}','{request}','{grant}','mdm.windows','Device');INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES('{t}','{replacement}','{device}','mdm',2,'{request}','active','primary',gen_random_uuid());"
    ));
    for id in pending {
        assert_eq!(
            scope_admission(&m, id, rss_mdm_inventory::Channel::Mdm, &device).await,
            rss_mdm_execution_service::source_authority::ScopeAdmission::Pending
        );
    }
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn group_delete_scope_reference_compete_without_dangling_references() {
    let first = planning(tenant()).await;
    let second = planning(tenant()).await;
    let (identity, identity_resources) =
        crate::test_support::identity::identity(&tenant().to_string())
            .await
            .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            crate::test_support::identity::config(&tenant().to_string())
                .unwrap()
                .access_options()
                .unwrap(),
        )
        .await
        .unwrap();
    let access = rss_mdm_authorization_service::Store::from_pool(
        pool.clone(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    );
    let mut grants =
        crate::test_support::identity::device_grants(None, &["inventory_read"]).unwrap();
    for operation in [
        crate::authorization::Permission::ComplianceWrite,
        crate::authorization::Permission::GroupRead,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::seed_grants(
        &tenant().to_string(),
        crate::test_support::case::admin(),
        grants,
    )
    .await
    .unwrap();
    let proof = crate::authorization::context::AuthorizedPrincipal::new(
        identity
            .authority
            .inspect_session(
                tenant(),
                crate::test_support::identity::credential_for(&tenant().to_string(), "admin")
                    .unwrap(),
                crate::identity::deadline(),
            )
            .await
            .unwrap(),
    )
    .unwrap()
    .load_authorization(&access)
    .await
    .unwrap();

    for kind in ["scope", "compliance"] {
        let group = Uuid::new_v4();
        let scope_id = Uuid::new_v4();
        execute(
            &first,
            &GroupCommand::Group {
                sensitive: true,
                id: group,
                change: Box::new(group_operation(
                    0,
                    GroupChange::Create {
                        asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
                        presentation: serde_json::json!({"name":"reference-race","description":""})
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
        let delete = GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(1, GroupChange::Delete)),
        };
        let reference = async {
            match kind {
                "scope" => {
                    execute(
                        &second,
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
                }
                _ => {
                    let s = compliance(&second).await;
                    let audit = RequestAudit::new(
                        second.tenant.to_string(),
                        "compliance_write",
                        rss_mdm_audit_integration::AuditIntent::Management,
                    );
                    proof.bind_audit(&audit).unwrap();
                    let input=serde_json::from_value(json!({"presentation":{"name":"disabled-race"},"severity":"high","enabled":false,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"any"}}}})).unwrap();
                    let command = rss_mdm_inventory_service::compliance::Command::Put {
                        id: scope_id,
                        request: Box::new(rss_mdm_inventory_service::operation::Operation {
                            operation_id: Uuid::new_v4(),
                            expected_revision: 0,
                            input,
                        }),
                    };
                    let result = s
                        .execute(&command, &audit, &proof)
                        .await
                        .map_err(Into::into);
                    audit.finalize(None);
                    result
                }
            }
        };
        use sqlx::Connection;
        let mut holder = sqlx::PgConnection::connect_with(
            &options().username("postgres").password("local-fixture"),
        )
        .await
        .unwrap();
        sqlx::query("BEGIN").execute(&mut holder).await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
            .bind(tenant().to_string())
            .fetch_one(&mut holder)
            .await
            .unwrap();
        let release = async {
            let overlapped=tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut holder).await.unwrap();
                    let waiting: i64 = sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked").fetch_one(&mut holder).await.unwrap();
                    if waiting >= 2 { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.is_ok();
            sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
            overlapped
        };
        let (a, b, overlapped) = tokio::join!(execute(&first, &delete), reference, release);
        holder.close().await.unwrap();
        assert!(
            overlapped,
            "{kind}: delete and reference did not overlap: delete={a:?}, reference={b:?}"
        );
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_group.groups g JOIN mdm_assets.group_selections s ON(s.tenant_id,s.group_id,s.rule_version)=(g.tenant_id,g.id,g.rule_version) JOIN mdm_group.groups target ON target.tenant_id=g.tenant_id AND s.group_ids @> ARRAY[target.id] WHERE g.tenant_id='{}' AND NOT g.deleted AND target.deleted",
                tenant()
            )),
            "0"
        );
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_compliance.groups edge JOIN mdm_group.groups target ON(target.tenant_id,target.id)=(edge.tenant_id,edge.group_id) WHERE edge.tenant_id='{}' AND target.deleted",
                tenant()
            )),
            "0"
        );
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_planning.scopes s JOIN mdm_planning.scope_versions v USING(tenant_id,id,revision) JOIN mdm_group.groups g ON g.tenant_id=s.tenant_id AND g.id='{group}' WHERE s.id='{scope_id}' AND g.deleted AND NOT s.deleted"
            )),
            "0"
        );
    }
    first.runtime.close().await;
    second.runtime.close().await;
    identity_resources.finish(async { Ok(()) }).await.unwrap();
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn ingress_batches_reuse_published_group_coverage() {
    use rss_reconcile::{DurableStore, Reconciler};
    let service = Arc::new(planning(tenant()).await);
    let worker = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options())
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
    .await
    .unwrap();
    // Finish catalog initialization through the real dispatcher before measuring device batches.
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let scope = rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap();
    while service.forward_asset_changes().await.unwrap() > 0 {}
    for claim in worker
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await
        .unwrap()
    {
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
        worker
            .finish(&claim, rss_reconcile::Completion::Converged, &control)
            .await
            .unwrap();
    }
    let initialized: i64 = sql(&format!(
        "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id='{}'",
        tenant()
    ))
    .parse()
    .unwrap();
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','batch-'||lpad(n::text,4,'0') FROM generate_series(1,1001) n",
        tenant()
    ));
    let group = Uuid::new_v4();
    let accepted = seed_group(
        &service,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
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
    let task = accepted["task"].as_str().unwrap();
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    while service.forward_asset_changes().await.unwrap() > 0 {}
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
    let mut steps = vec![(0, 1000, "devices")];
    // A thousand devices now commit in 32-device pages before Scope dispatch.
    steps.extend(std::iter::repeat_n((0, 1000, "devices"), 31));
    steps.extend([
        (0, 1000, "scopes"),
        (0, 1000, "compliance"),
        (1000, 1000, "groups"),
        (1000, 1001, "devices"),
        (1000, 1001, "scopes"),
        (1000, 1001, "compliance"),
        (1001, 1001, "groups"),
    ]);
    for (consumed, watermark, phase) in steps {
        let diff = worker.observe(&claim, &control).await.unwrap();
        worker.apply(&claim, diff, &control).await.unwrap();
        assert_eq!(
            sql(&format!(
                "SELECT consumed||','||watermark||','||phase FROM mdm_planning.asset_dispatch WHERE tenant_id='{}'",
                tenant()
            )),
            format!(
                "{},{},{phase}",
                initialized + consumed,
                initialized + watermark
            )
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
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker.work.clone()))
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
    let created = seed_group(
        &service,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
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
    let next = execute(
        &service,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(1, GroupChange::Recompute {})),
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
                    s.audit_store.bind_in(tx).await?;
                    let tenant = tx.tenant_id();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await
                        })
                    })
                    .await?;
                    rss_mdm_flow_service::transaction::lock(tx).await?;
                    let (job, _, _, _, _) = crate::automation::jobs::read_in(tx, first).await?;
                    let crate::automation::JobInput::Group { group, .. } = &job else {
                        panic!("successor fixture requires a group job");
                    };
                    // JobInput::audit_partition is crate-private; derive this fixture's
                    // group identity from the persisted job using the public source API.
                    let audit_partition = rss_mdm_audit_integration::source_partition(
                        tx.tenant_id(),
                        "group",
                        &job.target(),
                    )?;
                    let group_partition = s.groups.partition(&group.to_string())?;
                    tx.prepare_outbox_partitions(&[audit_partition, group_partition])
                        .await?;
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

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real dependency transactions"]
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
                sensitive: true,
                change: Box::new(group_operation(
                    0,
                    GroupChange::Create {
                        asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
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
        sensitive: true,
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
    let worker = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(first.clone(), options())
            .await
            .unwrap(),
        assets(&first).await,
        compliance(&first).await,
    )
    .await
    .unwrap();
    crate::automation::jobs::forward_jobs(
        &first.reconcile_messaging,
        &first.runtime,
        first.tenant,
        &first.audit_store,
    )
    .await
    .unwrap();
    let left_id = Uuid::parse_str(left["task"].as_str().unwrap()).unwrap();
    let right_id = Uuid::parse_str(right["task"].as_str().unwrap()).unwrap();
    let left_claim = claim_job(&worker, left_id, Duration::from_secs(120)).await;
    let right_claim = claim_job(&worker, right_id, Duration::from_secs(120)).await;
    tokio::join!(
        finish_claim(&worker, &left_claim),
        finish_claim(&worker, &right_claim)
    );
    let outcomes = sql(&format!(
        "SELECT count(*) FILTER(WHERE completed AND failure IS NULL),count(*) FILTER(WHERE completed AND failure='invalid_input') FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id IN('{left_id}','{right_id}')",
        tenant()
    ));
    assert_eq!(outcomes, "1|1");
    worker.work.close().await.unwrap();
    let count = sql(&format!(
        "SELECT count(*) FROM mdm_group.groups g JOIN mdm_assets.group_selections s ON(s.tenant_id,s.group_id,s.rule_version)=(g.tenant_id,g.id,g.rule_version) WHERE g.tenant_id='{}' AND g.id IN('{a}','{b}') AND cardinality(s.group_ids)>0",
        tenant()
    ));
    assert_eq!(count, "1");
    holder.close().await.unwrap();
    first.runtime.close().await;
    second.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real large source evidence pages"]
async fn nested_large_source_evidence_retries_with_smaller_pages() {
    use rss_mdm_group_postgres::{self as pg, core as g};
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
            sensitive: true,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: pg::AssetContext::Endpoint,
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
    let run = pg::OperationId::parse(&task.to_string()).unwrap();
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
    let worker = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options())
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
    .await
    .unwrap();
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(300)).await;
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
            sensitive: true,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: pg::AssetContext::Endpoint,
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
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(300)).await;
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
            "SELECT coalesce(failure,'ok') FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "ok"
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker.work.clone()))
        .await
        .unwrap();
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: authenticated lifecycle snapshots without Inventory"]
async fn system_lifecycle_snapshot_pages_before_collection_and_preserves_old_authority() {
    use sqlx::Connection;
    let prefix = format!("zzz-system-{}-", Uuid::new_v4());
    let t = tenant();
    let rows = format!(
        "SELECT '{prefix}'||lpad(i::text,4,'0') AS device,md5('{prefix}grant'||i)::uuid AS grant_id,md5('{prefix}request'||i)::uuid AS request,md5('{prefix}registration'||i)::uuid AS registration  ,i AS ordinal FROM generate_series(0,1001)i"
    );
    sql(&format!("SET rss.tenant_id='{t}';
        WITH x AS ({rows}) INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{t}',grant_id,'operator','mdm',device,'enrollment','consumed',clock_timestamp()+interval '60s' FROM x;
        WITH x AS ({rows}) INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) SELECT '{t}',request,grant_id,CASE WHEN ordinal=1001 THEN 'mdm.apple' ELSE 'mdm.windows' END,CASE WHEN ordinal=1001 THEN NULL ELSE 'Device' END FROM x;
        WITH x AS ({rows}) INSERT INTO mdm_access.devices(tenant_id,id) SELECT '{t}',device FROM x;
        WITH x AS ({rows}) INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) SELECT '{t}',registration,device,'mdm',1,request,'active','primary',gen_random_uuid() FROM x;
        WITH x AS ({rows}) INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) SELECT '{t}',gen_random_uuid(),registration,'mdm',encode(sha256(convert_to(device,'UTF8')),'hex'),'active' FROM x;
        WITH x AS ({rows}) INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) SELECT '{t}',registration,CASE WHEN ordinal=1001 THEN 'mdm.apple' ELSE 'mdm.windows' END,gen_random_uuid(),true FROM x;"));
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_flow_runtime")
        .password("runtime-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(t.to_string())
        .execute(&mut c)
        .await
        .unwrap();
    let watermark = rss_mdm_inventory_postgres::watermark_in(&mut c, t)
        .await
        .unwrap();
    let first = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        watermark,
        Some(prefix.clone()),
        None,
        1000,
    )
    .await
    .unwrap();
    assert_eq!(first.len(), 1000);
    assert!(first.iter().all(|d| d.device.starts_with(&prefix)
        && d.managed
        && !d.platform_conflict
        && d.platform == Some(rss_mdm_agent_wire::runtime::TaskPlatform::Windows)));
    let last = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        watermark,
        Some(first.last().unwrap().device.clone()),
        None,
        1000,
    )
    .await
    .unwrap();
    assert_eq!(
        last.iter()
            .filter(|d| d.device.starts_with(&prefix))
            .count(),
        2
    );
    let service = Arc::new(planning(t).await);
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options.clone())
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
    .await
    .unwrap();
    let notifications = crate::worker_wake::Listener::new(
        options
            .clone()
            .username("mdm_access")
            .password("access-fixture"),
        t,
    );
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
    let access_config = crate::test_support::identity::config(&t.to_string()).unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(access_config.access_options().unwrap())
        .await
        .unwrap();
    let access = rss_mdm_authorization_service::Store::from_pool(
        pool.clone(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    );
    let mut windows_group = None;
    for (selector, count) in [
        (rss_mdm_group_postgres::SystemSelector::Windows, 1001),
        (rss_mdm_group_postgres::SystemSelector::Macos, 1),
    ] {
        let group = Uuid::new_v4();
        let mut conn = pool.clone().acquire().await.unwrap();
        let mut tx = (*conn).begin().await.unwrap();
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(t.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let (_, capability) = crate::authorization::baseline::grant_administrator_on(
            &mut tx,
            crate::test_support::identity::user(&t.to_string(), crate::test_support::case::admin()),
            Uuid::new_v4(),
            [group.to_string()].into(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(conn);
        let proof = capability.principal(&access).await.unwrap();
        let audit = RequestAudit::new(
            t.to_string(),
            "baseline_initialize",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        proof.bind_audit(&audit).unwrap();
        let command = GroupCommand::Group {
            id: group,
            sensitive: false,
            change: Box::new(group_operation(
                0,
                GroupChange::CreateSystem {
                    selector,
                    presentation: json!({"name":"system","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                },
            )),
        };
        let receipt = groups(&service)
            .await
            .execute_initialization(&command, &audit, &proof, service.as_ref())
            .await
            .unwrap();
        audit.finalize(None);
        let task = Uuid::parse_str(receipt["task"].as_str().unwrap()).unwrap();
        assert_eq!(
            wait_task(
                &service,
                task,
                crate::automation::TaskKind::Group,
                &group.to_string()
            )
            .await["members"],
            count
        );
        let scope_id = Uuid::new_v4();
        let scope_receipt = execute(
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
        let scope_task = Uuid::parse_str(scope_receipt["task"].as_str().unwrap()).unwrap();
        assert_eq!(
            // 1001 endpoints require at least 63 bounded projection pages.
            // This verifies publication correctness, not a 30-second throughput SLA.
            wait_task_with_budget(
                &service,
                scope_task,
                crate::automation::TaskKind::Scope,
                &scope_id.to_string(),
                Duration::from_secs(120)
            )
            .await["members"],
            count
        );
        if selector == rss_mdm_group_postgres::SystemSelector::Windows {
            windows_group = Some(group);
        }
    }
    let device = first[0].device.clone();
    let revoke = format!(
        "SET rss.tenant_id='{t}';UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id='{t}' AND registration IN(SELECT id FROM mdm_access.registrations WHERE tenant_id='{t}' AND device='{device}')"
    );
    // The credential trigger takes the watermark also held by the live automation
    // task. Keep the runtime available while the synchronous fixture waits for it.
    tokio::task::spawn_blocking(move || sql(&revoke))
        .await
        .expect("credential revocation fixture failed");
    let old = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        watermark,
        None,
        Some(vec![device.clone()]),
        1,
    )
    .await
    .unwrap();
    assert!(old[0].managed);
    let current = rss_mdm_inventory_postgres::watermark_in(&mut c, t)
        .await
        .unwrap();
    let revoked = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        current,
        None,
        Some(vec![device]),
        1,
    )
    .await
    .unwrap();
    assert!(!revoked[0].managed);
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let group = service
                .groups
                .get(
                    rss_mdm_group_postgres::GroupId::parse(&windows_group.unwrap().to_string())
                        .unwrap(),
                    deadline(),
                )
                .await
                .unwrap()
                .unwrap();
            if group.member_count == 1000 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("credential lifecycle delta removes system membership");
    c.close().await.unwrap();
    assert!(stack.shutdown().join().await.unwrap().is_clean());
    pool.close().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: durable definition validation and publication CAS"]
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
        sensitive: true,
        change: Box::new(group_operation(
            0,
            GroupChange::Create {
                asset_context: rss_mdm_group_postgres::AssetContext::Endpoint,
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
        sensitive: true,
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
    let worker = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options())
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
    .await
    .unwrap();
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(120)).await;
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
            "SELECT (cursor::jsonb->>'ready')::boolean FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "f"
    );
    worker.release(&claim, &control).await.unwrap();
    worker.work.close().await.unwrap();
    let resumed = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(service.clone(), options())
            .await
            .unwrap(),
        assets(&service).await,
        compliance(&service).await,
    )
    .await
    .unwrap();
    let claim = claim_job(&resumed, task, Duration::from_secs(120)).await;
    finish_claim(&resumed, &claim).await;
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
            sensitive: true,
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
            sensitive: true,
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
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    let task = Uuid::parse_str(queued["task"].as_str().unwrap()).unwrap();
    let claim = claim_job(&resumed, task, Duration::from_secs(120)).await;
    finish_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT failure FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{task}'",
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
                sensitive: true,
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
            sensitive: true,
            change: Box::new(group_operation(1, GroupChange::Delete)),
        },
    )
    .await
    .unwrap();
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let claim = claim_job(&resumed, task, Duration::from_secs(120)).await;
    finish_claim(&resumed, &claim).await;
    assert_eq!(
        sql(&format!(
            "SELECT failure FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{task}'",
            tenant()
        )),
        "source_unavailable"
    );
    assert!(
        execute(&service, &GroupCommand::GroupRead { id: dependent })
            .await
            .is_err()
    );
    resumed.work.close().await.unwrap();
    service.runtime.close().await;
}
