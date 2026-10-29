//! Same original endpoints, one associated object, one selected execution target.
use crate::planning::test_support::*;
use crate::planning::*;
use rss_mdm_execution_service::source_authority::{Availability, ScopeAdmission, SourceAuthority};
use rss_mdm_group::AssetContext;
use rss_mdm_inventory::Channel;
use rss_mdm_inventory_service::objects::ObjectRef;
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_mdm_scope_service::ScopeChange;
use sqlx::Connection;
#[tokio::test]
#[ignore = "MODULE=planning.group_scope: associated sources, fixed snapshots and channel admission"]
async fn associated_context_maps_before_exclusions_and_missing_channels_recover() {
    let (access, associations, admin, _, _audit_store) =
        crate::device::t2::associations::setup().await.unwrap();
    let mdm = crate::test_support::case::name("associated-mdm");
    let agent = crate::test_support::case::name("associated-agent");
    let alone = crate::test_support::case::name("associated-alone");
    crate::device::t2::associations::seed(mdm, "mdm", "2714-SERIAL").unwrap();
    crate::device::t2::associations::seed(agent, "agent", "2714-serial").unwrap();
    crate::device::t2::associations::seed(alone, "agent", "2714-other").unwrap();
    associations.drain().await.unwrap();
    let service = Arc::new(planning(tenant()).await);
    let running = RunningAutomation::start(service.clone()).await;
    let group = Uuid::new_v4();
    let accepted = seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: AssetContext::AssociatedDevice,
                    presentation:
                        serde_json::json!({"name":"one physical object","description":""})
                            .as_object()
                            .unwrap()
                            .clone(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria:
                            rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
                                field: rss_mdm_inventory::FieldKey::parse("device.model").unwrap(),
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
    let result = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    wait_task(&service, result, TaskFamily::Group, &group.to_string()).await;
    let page = execute(
        &service,
        &GroupCommand::GroupPage {
            group,
            result,
            projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
            query: crate::planning::test_support::group_page_query(1000, None),
        },
    )
    .await
    .unwrap();
    let mut connection = sqlx::PgConnection::connect_with(
        &crate::device::test_support::options("mdm_flow_runtime")
            .unwrap()
            .password("runtime-fixture"),
    )
    .await
    .unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant().to_string())
        .execute(&mut connection)
        .await
        .unwrap();
    let snapshot = service
        .objects
        .capture(&mut connection, tenant(), None)
        .await
        .unwrap();
    for statement in [
        "UPDATE mdm_devices.object_cuts SET watermark=watermark+1 WHERE tenant_id=$1::uuid AND id=$2",
        "INSERT INTO mdm_devices.object_versions(tenant_id,object,revision,input,devices) SELECT v.tenant_id,v.object||'-tamper',v.revision,v.input,v.devices FROM mdm_devices.object_versions v JOIN mdm_devices.object_cuts c ON c.tenant_id=v.tenant_id AND c.id=$2 WHERE v.tenant_id=$1::uuid LIMIT 1",
    ] {
        let mut transaction = connection.begin().await.unwrap();
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant().to_string())
            .execute(&mut *transaction)
            .await
            .unwrap();
        let failure = sqlx::query(statement)
            .bind(tenant().to_string())
            .bind(snapshot.id)
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        assert_eq!(
            failure.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
        transaction.rollback().await.unwrap();
    }
    connection.close().await.unwrap();
    let members: Vec<ObjectRef> = serde_json::from_value(page["page"]["items"].clone()).unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&ObjectRef::Endpoint(alone.into())));
    let association = members
        .iter()
        .find_map(|o| {
            if let ObjectRef::Association(id) = o {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap();
    let scope = Uuid::new_v4();
    let accepted = execute(
        &service,
        &Command::Scope {
            id: scope,
            change: scope_operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: std::collections::BTreeSet::from([Reference::Group(group)]),
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
        &service,
        Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap(),
        TaskFamily::Scope,
        &scope.to_string(),
    )
    .await;
    let objects = |channel| {
        let source = rss_mdm_policy_service::management::source::execution(service.objects.clone());
        let runtime = service.runtime.clone();
        async move {
            runtime
                .local_tx(tenant(), deadline(), move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(source
                                    .assignment_objects_on(c, tenant(), scope, channel, None, 1000)
                                    .await)
                            })
                        })
                        .await
                    })
                })
                .await
                .fold(
                    |v| v.unwrap(),
                    |e| panic!("{e:?}"),
                    |e| panic!("{e:?}"),
                    |_| panic!("unknown"),
                    |_| panic!("unknown"),
                    |e| panic!("{e:?}"),
                )
        }
    };
    // Both endpoint sources denote one complete device. Its final key must also
    // be the seek cursor, or the association reappears on a subsequent page.
    let lifecycle_scope = Uuid::new_v4();
    let accepted = execute(
        &service,
        &Command::Scope {
            id: lifecycle_scope,
            change: scope_operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: [mdm, agent, alone]
                            .into_iter()
                            .map(|id| Reference::Device(id.into()))
                            .collect(),
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
        &service,
        Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap(),
        TaskFamily::Scope,
        &lifecycle_scope.to_string(),
    )
    .await;
    let mut lifecycle_connection = sqlx::PgConnection::connect_with(
        &crate::device::test_support::options("mdm_flow_runtime")
            .unwrap()
            .password("runtime-fixture"),
    )
    .await
    .unwrap();
    let mut tx = lifecycle_connection.begin().await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant().to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let page = rss_mdm_execution_service::scope::targets::lifecycle_objects_on(
        service.objects.as_ref(),
        &mut tx,
        tenant(),
        lifecycle_scope,
        None,
        1000,
    )
    .await
    .unwrap();
    assert_eq!(
        page.len(),
        2,
        "both endpoint sources must yield only one association"
    );
    let pair_key = ObjectRef::Association(association).key();
    assert_eq!(page[0].cursor, pair_key);
    assert_eq!(page[0].object.object, ObjectRef::Association(association));
    let after_pair = rss_mdm_execution_service::scope::targets::lifecycle_objects_on(
        service.objects.as_ref(),
        &mut tx,
        tenant(),
        lifecycle_scope,
        Some(&pair_key),
        1000,
    )
    .await
    .unwrap();
    assert_eq!(
        after_pair.len(),
        1,
        "normalized seek must not repeat the pair"
    );
    assert_eq!(
        after_pair[0].object.object,
        ObjectRef::Endpoint(alone.into())
    );
    tx.rollback().await.unwrap();
    lifecycle_connection.close().await.unwrap();
    let mdm_objects = objects(Channel::Mdm).await;
    let pair = mdm_objects
        .iter()
        .find(|o| o.object == ObjectRef::Association(association))
        .unwrap();
    assert_eq!(pair.availability, Availability::Ready);
    assert_eq!(pair.target.as_ref().unwrap().device, mdm);
    let missing = mdm_objects
        .iter()
        .find(|o| o.object == ObjectRef::Endpoint(alone.into()))
        .unwrap();
    assert_eq!(missing.availability, Availability::Unavailable);
    assert!(missing.target.is_none());
    assert_eq!(
        objects(Channel::Agent)
            .await
            .iter()
            .find(|o| o.object == ObjectRef::Association(association))
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .device,
        agent
    );
    let accepted = execute(
        &service,
        &Command::Scope {
            id: scope,
            change: scope_operation(
                1,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: std::collections::BTreeSet::from([
                            Reference::Group(group),
                            Reference::Device(mdm.into()),
                        ]),
                        limitations: None,
                        exclusions: std::collections::BTreeSet::from([Reference::Device(
                            mdm.into(),
                        )]),
                    },
                },
            ),
        },
    )
    .await
    .unwrap();
    wait_task(
        &service,
        Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap(),
        TaskFamily::Scope,
        &scope.to_string(),
    )
    .await;
    assert_eq!(
        objects(Channel::Mdm)
            .await
            .iter()
            .find(|o| o.object == ObjectRef::Association(association))
            .unwrap()
            .admission,
        ScopeAdmission::Excluded
    );
    assert_eq!(
        objects(Channel::Agent)
            .await
            .iter()
            .find(|o| o.object == ObjectRef::Association(association))
            .unwrap()
            .availability,
        Availability::Ready
    );
    crate::test_support::inventory::seed_source(alone, "mdm", "mdm.windows", "model").unwrap();
    {
        let input = GroupWorker::open(&service).await;
        while input_step(input.as_ref(), "mdm.groups").await.unwrap() {}
        input.close().await;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if objects(Channel::Mdm).await.iter().any(|o| {
                o.object == ObjectRef::Endpoint(alone.into())
                    && o.availability == Availability::Ready
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let before = sql(&format!(
        "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}'",
        tenant()
    ));
    let revoke_audit = RequestAudit::new(
        tenant().to_string(),
        "device_association_revoke",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    associations
        .revoke(
            &admin,
            association,
            &rss_mdm_device_service::Revoke {
                operation_id: Uuid::new_v4(),
                expected_version: associations.get(&admin, association).await.unwrap().version,
                reason: "separate ownership".into(),
            },
            &revoke_audit,
        )
        .await
        .unwrap();
    revoke_audit.finalize(None);
    {
        let input = GroupWorker::open(&service).await;
        while input_step(input.as_ref(), "mdm.groups").await.unwrap() {}
        input.close().await;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let current = execute(&service, &GroupCommand::GroupRead { id: group })
                .await
                .unwrap();
            if current["group"]["member_count"] == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        before,
        sql(&format!(
            "SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{}'",
            tenant()
        ))
    );
    let current = Uuid::parse_str(&sql(&format!(
        "SELECT member_set FROM mdm_group.groups WHERE tenant_id='{}' AND id='{group}'",
        tenant()
    )))
    .unwrap();
    for (result, removed) in [(result, false), (current, true)] {
        let decisions = execute(
            &service,
            &GroupCommand::GroupPage {
                group,
                result,
                projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Decisions,
                query: crate::planning::test_support::group_page_query(1000, None),
            },
        )
        .await
        .unwrap();
        let decision = decisions["page"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["object"]["id"] == association.to_string())
            .unwrap();
        assert_eq!(
            decision["decision"],
            if removed { "no_match" } else { "match" }
        );
        assert_eq!(
            decision["sourceObjects"].as_array().unwrap().is_empty(),
            removed
        );
    }
    running.stop().await;
    service.runtime.close().await;
    access.finish(async { Ok(()) }).await.unwrap();
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: Agent health selects the associated original MDM configuration target"]
async fn agent_health_drives_mdm_configuration_assignment() -> anyhow::Result<()> {
    use crate::test_support::planning_http::*;
    use crate::test_support::{http::*, process::*, runtime::*, *};
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
    let mdm = case::name("health-mdm");
    let agent = case::name("health-agent");
    crate::device::t2::associations::seed(mdm, "mdm", "2714-HEALTH")?;
    let registration = crate::device::t2::associations::seed(agent, "agent", "2714-health")?;
    let field = rss_mdm_inventory::builtin::CORPORATE_AGENT_HEALTHY;
    let epoch = Uuid::new_v4();
    let definition = inventory::definition(field.as_str(), "agent.script", &[field]);
    inventory::register_definition(&definition)?;
    let encoded = crate::device::scope_dataset(
        tenant(),
        registration,
        "agent.script",
        epoch,
        field.as_str(),
    )?
    .encode()?
    .replace('\'', "''");
    let coverage = serde_json::to_string(&definition.coverage()?)?;
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::Boolean(false))?;
    pg(&format!(
        "INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{t}','{registration}','agent.script','{epoch}',true);INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{t}','mdm.observation.v1','inventory-projection-v1','{encoded}','{coverage}','custom.corporate_agent.healthy','{value}','health-fixture',1,2,'known','{value}','health-fixture',1,2,'{registration}','agent.script','{epoch}',0)",
        t = case_tenant()
    ))?;
    crate::test_support::device_worker::drain(fixture.audit.clone(),tenant()).await?;
        let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = crate::cursor_keys::load(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(rss_mdm_policy_service::application::Application::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects)).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { scopes:crate::planning::test_support::scopes(&planning).await, groups }));
    let router = fixture.router({
 rss_mdm_http_contract::route_module! { struct AgentHealthDrivesMdmConfigurationAssignmentModule1 for [Browser] { api_v1 at "/api/v1", fixture } }
 AgentHealthDrivesMdmConfigurationAssignmentModule1 { api_v1: routes,
fixture: fixture.authorization() }.assemble()
})?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let member = prepared_subject(&browser)?;
    let mut grants = identity::device_grants(None, &["inventory_read"])?;
    for p in [
        "group_read",
        "group_write",
        "group_recompute",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(p))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::seed_grants(case_tenant(), &member, grants).await?;
    let automation = start_automation(&fixture.base).await?;
    let group = Uuid::new_v4();
    call(&mut browser,&router,&format!("/api/v1/groups/{group}"),0,json!({"action":"create","assetContext":"associated_device","presentation":{"name":"unhealthy Agent","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":false}}}})).await?;
    let group_read=browser.call(&router,Method::GET,&format!("/api/v1/groups/{group}"),None).await?.1;
    let (_, decisions) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v1/groups/{group}/results/{}/decisions",
                group_read["memberSet"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        decisions["page"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["object"]["kind"] == "association"
                && d["sourceObjects"][0]["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m["registrationId"] == registration.to_string()))
    );
    let reverse=browser.call(&router,Method::GET,&format!("/api/v1/devices/{mdm}/groups"),None).await?;
    ensure!(reverse.0==StatusCode::OK,"associated group reverse: {reverse:?}");
    let item=reverse.1["items"].as_array().and_then(|items|items.iter().find(|v|v["id"]==group.to_string())).ok_or_else(||anyhow::anyhow!("associated group absent: {reverse:?}"))?;
    ensure!(item["assetContext"]=="associated_device" && item["objects"][0]["kind"]=="association","association flattened: {item}");
    ensure!(item["memberSet"].is_string() && item["evaluatedRuleVersion"].is_string() && item["inputCurrent"].is_boolean(),"missing membership basis: {item}");
    stop_worker(automation).await?;
    Ok(())
    }).await

    }).await
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: source membership changes at an already observed Device cut"]
async fn associated_parent_recomputes_when_only_frozen_source_membership_changes() {
    let (access, devices, _, _, _) = crate::device::t2::associations::setup().await.unwrap();
    let endpoint = crate::test_support::case::name("associated-source-order");
    let registration =
        crate::device::t2::associations::seed(endpoint, "agent", "source-order").unwrap();
    devices.drain().await.unwrap();
    let service = Arc::new(planning(tenant()).await);
    let worker = GroupWorker::open(&service).await;
    let source = Uuid::new_v4();
    let parent = Uuid::new_v4();
    for (id, criteria) in [
        (
            source,
            serde_json::json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"model"}}),
        ),
        (
            parent,
            serde_json::json!({"kind":"group","groupId":source,"op":"member_of"}),
        ),
    ] {
        let created = seed_group(&service, &GroupCommand::Group {
            id, change: Box::new(group_operation(0, GroupChange::Create {
                asset_context: AssetContext::AssociatedDevice,
                presentation: serde_json::json!({"name":"source order","description":""}).as_object().unwrap().clone(),
                criteria: Some(serde_json::from_value(serde_json::json!({"selector":{"kind":"device"},"quantifier":"one","criteria":criteria})).unwrap()),
            })),
        }).await.unwrap();
        let id = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
        let claim = claim_group(&worker, id, Duration::from_secs(60)).await;
        finish_group_claim(&worker, &claim).await;
    }
    let member_count = |group| {
        sql(&format!(
            "SELECT member_count FROM mdm_group.groups WHERE tenant_id='{}' AND id='{group}'",
            tenant()
        ))
    };
    assert_eq!(member_count(parent), "1");
    sql(&format!(
        "UPDATE mdm.inventory SET value='{{\"kind\":\"string\",\"value\":\"changed\"}}',batch_id='changed-model' WHERE tenant_id='{}' AND registration='{registration}' AND field='device.model'",
        tenant()
    ));
    devices.drain().await.unwrap();
    // The parent observes the new Device cut before its source is redispatched.
    // Its source is still a valid frozen old result. Source publication must later
    // invalidate those reused decisions even though the Device cut stays unchanged.
    for group in [parent, source] {
        let changed = execute(
            &service,
            &GroupCommand::Group {
                id: group,
                change: Box::new(group_operation(1, GroupChange::Recompute {})),
            },
        )
        .await
        .unwrap();
        let task = Uuid::parse_str(changed["task"].as_str().unwrap()).unwrap();
        let claim = claim_group(&worker, task, Duration::from_secs(60)).await;
        finish_group_claim(&worker, &claim).await;
    }
    assert_eq!(member_count(parent), "1");
    assert_eq!(member_count(source), "0");
    let cut = sql(&format!(
        "SELECT input_version FROM mdm_group.member_runs WHERE tenant_id='{}' AND id=(SELECT member_set FROM mdm_group.groups WHERE tenant_id='{}' AND id='{parent}')",
        tenant(),
        tenant()
    ));
    worker.close().await;
    let running = RunningAutomation::start(service.clone()).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while member_count(parent) != "0" {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        cut,
        sql(&format!(
            "SELECT input_version FROM mdm_group.member_runs WHERE tenant_id='{}' AND id=(SELECT member_set FROM mdm_group.groups WHERE tenant_id='{}' AND id='{parent}')",
            tenant(),
            tenant()
        ))
    );
    running.stop().await;
    service.runtime.close().await;
    access.finish(async { Ok(()) }).await.unwrap();
}
