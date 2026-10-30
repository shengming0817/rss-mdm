use crate::planning::test_support::*;
use crate::planning::*;
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_mdm_scope_service::ScopeChange;

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn durable_asset_group_scope_pipeline() {
    let service = Arc::new(planning(tenant()).await);
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_scheduler_runtime")
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
        crate::test_support::workers::Workers::open(service.policy.clone(), None, options)
            .await
            .unwrap();
    let (group_work, scope_work, scope_delivery) =
        scope_group_components(&service, automation.scheduler.store.clone()).await;
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
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
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
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::scope_group_changes::Resource(scope_delivery.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.clone().registration().critical());
    automation.register(&notifications.signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.stage_deferred_task_with_token(
        scope_work
            .registration(
                notifications
                    .signals
                    .handle(crate::worker_wake::Work::Scopes),
            )
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        group_work
            .registration(
                notifications
                    .signals
                    .handle(crate::worker_wake::Work::Groups),
            )
            .critical(),
    );
    launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
    launch.finish();
    let task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    assert_eq!(
        wait_task(&service, task, TaskFamily::Group, &group.to_string()).await["members"],
        1
    );
    let page_command = GroupCommand::GroupPage {
        group,
        result: task,
        projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
        query: crate::planning::test_support::group_page_query(1, None),
    };
    let page = execute(&service, &page_command).await.unwrap();
    assert_eq!(
        page["page"]["items"],
        serde_json::json!([{"kind":"endpoint","id":device}])
    );
    assert_eq!(page["current"], true);
    assert!(rss_mdm_inventory_service::groups::response::Response::decode(page.clone()).is_ok());
    assert!(
        page["nextCursor"].is_null(),
        "exact final page must terminate"
    );
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
                &crate::device::test_support::admin(&tenant().to_string(), "other-a")
                    .await
                    .unwrap()
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
            change: scope_operation(
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
            TaskFamily::Scope,
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
            &pages::PageRequest {
                scope: scope_id,
                result: scope_task,
                projection,
                query: crate::planning::test_support::scope_page_query(1000, None),
            },
        )
        .await
        .unwrap();
        assert_eq!(page["page"]["items"].as_array().unwrap().len(), 1);
        assert!(rss_mdm_scope_service::wire::Response::decode(page).is_ok());
    }
    assert!(stack.shutdown().join().await.unwrap().is_clean());
    rss_runtime::ManagedResource::shutdown(&automation.scheduler.clone())
        .await
        .unwrap();
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn group_scope_replay_and_audit_atomicity() {
    let m = Arc::new(planning(tenant()).await);
    let device = format!("设备-{}", Uuid::new_v4());
    seed_device(&device);
    let group = Uuid::new_v4();
    let create = GroupCommand::Group {
        id: group,
        change: Box::new(group_operation(
            0,
            GroupChange::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
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
        TaskFamily::Group,
        &group.to_string(),
    )
    .await;
    let scope_id = Uuid::new_v4();
    execute(
        &m,
        &Command::Scope {
            id: scope_id,
            change: scope_operation(
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
    sql(
        "REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_inventory_runtime",
    );
    let result = execute(
        &m,
        &GroupCommand::Group {
            id: denied,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
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
        "GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_inventory_runtime",
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
    foreign.close().await;
    m.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: real capability storage and transactions"]
async fn group_scope_revision_competition() {
    let m = planning(tenant()).await;
    let g = Uuid::new_v4();
    execute(
        &m,
        &GroupCommand::Group {
            id: g,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
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
            change: scope_operation(
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
        change: scope_operation(
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
        change: scope_operation(1, ScopeChange::Delete),
    };
    let (a, b) = tokio::join!(execute(&m, &a), execute(&m, &b));
    assert_ne!(a.is_ok(), b.is_ok());
    let (winner, loser) = match a {
        Ok(winner) => (winner, b),
        Err(error) => (b.unwrap(), Err(error)),
    };
    assert!(matches!(
        loser,
        Err(Error::Scope(rss_mdm_scope_service::Error::Conflict))
    ));
    assert_eq!(winner["revision"], 2);
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm_scope.scopes WHERE tenant_id='{}' AND id='{s}'",
            tenant()
        )),
        "2"
    );
    m.close().await;
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
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
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
        TaskFamily::Group,
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
                change: scope_operation(
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
            TaskFamily::Scope,
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
    m.close().await;
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
                id: group,
                change: Box::new(group_operation(
                    0,
                    GroupChange::Create {
                        asset_context: rss_mdm_group::AssetContext::Endpoint,
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
            id: group,
            change: Box::new(group_operation(1, GroupChange::Delete)),
        };
        let reference = || async {
            match kind {
                "scope" => {
                    execute(
                        &second,
                        &Command::Scope {
                            id: scope_id,
                            change: scope_operation(
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
                        .map(|value| {
                            serde_json::to_value(value).expect("compliance response serializes")
                        })
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
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2387))")
            .bind(format!("group:{}:{group}", tenant()))
            .fetch_one(&mut holder)
            .await
            .unwrap();
        let (held_delete, held_reference) = tokio::join!(execute(&first, &delete), reference());
        sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
        holder.close().await.unwrap();
        assert!(
            held_delete.is_err() && held_reference.is_err(),
            "{kind}: held Group fence admitted a contender: delete={held_delete:?}, reference={held_reference:?}"
        );
        assert_eq!(
            sql(&format!(
                "SELECT deleted FROM mdm_group.groups WHERE tenant_id='{}' AND id='{group}'",
                tenant()
            )),
            "f"
        );
        let (a, b) = tokio::join!(execute(&first, &delete), reference());
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_group.groups g JOIN mdm_group.rules s ON(s.tenant_id,s.group_id,s.version)=(g.tenant_id,g.id,g.rule_version) JOIN mdm_group.groups target ON target.tenant_id=g.tenant_id AND s.group_ids @> ARRAY[target.id] WHERE g.tenant_id='{}' AND NOT g.deleted AND target.deleted",
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
                "SELECT count(*) FROM mdm_scope.scopes s JOIN mdm_scope.scope_versions v USING(tenant_id,id,revision) JOIN mdm_group.groups g ON g.tenant_id=s.tenant_id AND g.id='{group}' WHERE s.id='{scope_id}' AND g.deleted AND NOT s.deleted"
            )),
            "0"
        );
    }
    first.close().await;
    second.close().await;
    identity_resources.finish(async { Ok(()) }).await.unwrap();
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
        .username("mdm_policy_runtime")
        .password("runtime-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(t.to_string())
        .execute(&mut c)
        .await
        .unwrap();
    let cut = asset_cut();
    let first = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        &cut,
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
        &cut,
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
    let automation = crate::test_support::workers::Workers::open(
        service.policy.clone(),
        None,
        options.clone().username("mdm_scheduler_runtime"),
    )
    .await
    .unwrap();
    let (group_work, scope_work, scope_delivery) =
        scope_group_components(&service, automation.scheduler.store.clone()).await;
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
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::scope_group_changes::Resource(scope_delivery.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.clone().registration().critical());
    automation.register(&notifications.signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.stage_deferred_task_with_token(
        scope_work
            .registration(
                notifications
                    .signals
                    .handle(crate::worker_wake::Work::Scopes),
            )
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        group_work
            .registration(
                notifications
                    .signals
                    .handle(crate::worker_wake::Work::Groups),
            )
            .critical(),
    );
    launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
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
            .execute_initialization(&command, &audit, &proof)
            .await
            .unwrap();
        audit.finalize(None);
        let task = Uuid::parse_str(receipt["task"].as_str().unwrap()).unwrap();
        assert_eq!(
            wait_task(&service, task, TaskFamily::Group, &group.to_string()).await["members"],
            count
        );
        let scope_id = Uuid::new_v4();
        let scope_receipt = execute(
            &service,
            &Command::Scope {
                id: scope_id,
                change: scope_operation(
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
                TaskFamily::Scope,
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
    // Keep the runtime available while the fixture commits credential revocation.
    tokio::task::spawn_blocking(move || sql(&revoke))
        .await
        .expect("credential revocation fixture failed");
    let old = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        &cut,
        None,
        Some(vec![device.clone()]),
        1,
    )
    .await
    .unwrap();
    assert!(old[0].managed);
    let current = asset_cut();
    let revoked = rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
        &mut c,
        &t.to_string(),
        &current,
        None,
        Some(vec![device]),
        1,
    )
    .await
    .unwrap();
    assert!(!revoked[0].managed);
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let group = crate::planning::test_support::group_store(&service)
                .await
                .get(
                    rss_mdm_group::GroupId::parse(&windows_group.unwrap().to_string()).unwrap(),
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
    service.close().await;
}
