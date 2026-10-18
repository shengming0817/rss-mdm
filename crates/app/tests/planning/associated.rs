//! Same original endpoints, one associated object, one selected execution target.
use crate::planning::test_support::*;
use crate::planning::*;
use rss_mdm_execution_service::source_authority::{Availability, ScopeAdmission, SourceAuthority};
use rss_mdm_group_postgres::AssetContext;
use rss_mdm_inventory::Channel;
use rss_mdm_inventory_service::objects::ObjectRef;
#[tokio::test]
#[ignore = "MODULE=planning.group_scope: associated sources, fixed snapshots and channel admission"]
async fn associated_context_maps_before_exclusions_and_missing_channels_recover() {
    let (access, associations, admin, _) = crate::device::t2::associations::setup().await.unwrap();
    let mdm = crate::test_support::case::name("associated-mdm");
    let agent = crate::test_support::case::name("associated-agent");
    let alone = crate::test_support::case::name("associated-alone");
    crate::device::t2::associations::seed(mdm, "mdm", "2714-SERIAL").unwrap();
    crate::device::t2::associations::seed(agent, "agent", "2714-serial").unwrap();
    crate::device::t2::associations::seed(alone, "agent", "2714-other").unwrap();
    associations.reconcile().await.unwrap();
    let service = Arc::new(planning(tenant()).await);
    // A committed builder coordinate survives a rolled back page; incomplete data is hidden.
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect_with(
        &crate::device::test_support::options("mdm_flow_runtime")
            .unwrap()
            .password("runtime-fixture"),
    )
    .await
    .unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant().to_string())
        .execute(&mut *transaction)
        .await
        .unwrap();
    let snapshot = service
        .objects
        .freeze(&mut transaction, tenant())
        .await
        .unwrap();
    assert!(
        !service
            .objects
            .current(&mut transaction, tenant(), &snapshot)
            .await
            .unwrap()
    );
    assert!(
        service
            .objects
            .page(&mut transaction, tenant(), snapshot.id, None, 64)
            .await
            .unwrap()
            .is_empty()
    );
    transaction.commit().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant().to_string())
        .execute(&mut *transaction)
        .await
        .unwrap();
    assert!(matches!(
        service
            .objects
            .advance(&mut transaction, tenant(), &snapshot)
            .await
            .unwrap(),
        rss_mdm_inventory_service::objects::SnapshotProgress::Building
    ));
    transaction.rollback().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant().to_string())
        .execute(&mut *transaction)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT object_count FROM mdm_devices.input_snapshots WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant().to_string())
    .bind(snapshot.id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    // Tenant RLS is applied inside each transaction.
    assert_eq!(count, 0);
    connection.close().await.unwrap();
    let running = RunningAutomation::start(service.clone()).await;
    let group = Uuid::new_v4();
    let accepted = execute(
        &service,
        &GroupCommand::Group {
            sensitive: true,
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: AssetContext::AssociatedDevice,
                    name: "one physical object".into(),
                    description: String::new(),
                    criteria: Some(assets::InventoryCondition {
                        selector: assets::ScopeSelector::Device,
                        quantifier: assets::ScopeQuantifier::One,
                        criteria: assets::Criteria::Predicate {
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
    wait_task(
        &service,
        result,
        crate::automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    let page = execute(
        &service,
        &GroupCommand::GroupPage {
            group,
            result,
            projection: rss_mdm_inventory_service::groups::pages::GroupPageKind::Members,
            query: rss_mdm_inventory_service::groups::pages::PageQuery {
                limit: 1000,
                cursor: None,
            },
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
    for statement in [
        "UPDATE mdm_devices.input_snapshots SET phase='endpoints' WHERE tenant_id=$1::uuid AND id=$2",
        "INSERT INTO mdm_devices.input_objects(tenant_id,snapshot,object,input,hardware,devices) SELECT tenant_id,snapshot,object||'-tamper',input,hardware,devices FROM mdm_devices.input_objects WHERE tenant_id=$1::uuid AND snapshot=$2 LIMIT 1",
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
            Some("P0001")
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
            change: operation(
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
        crate::automation::TaskKind::Scope,
        &scope.to_string(),
    )
    .await;
    let objects = |channel| {
        let source =
            crate::planning::execution_source::ExecutionSource::new(service.objects.clone());
        let runtime = service.runtime.clone();
        async move {
            runtime
                .local_tx(tenant(), deadline(), move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(source
                                    .assignment_objects_on(c, tenant(), scope, channel, None)
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
            change: operation(
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
        crate::automation::TaskKind::Scope,
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
    let page = rss_mdm_flow_service::planning::targets::lifecycle_objects_on(
        service.objects.as_ref(),
        &mut tx,
        tenant(),
        lifecycle_scope,
        None,
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
    let after_pair = rss_mdm_flow_service::planning::targets::lifecycle_objects_on(
        service.objects.as_ref(),
        &mut tx,
        tenant(),
        lifecycle_scope,
        Some(&pair_key),
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
            change: operation(
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
        crate::automation::TaskKind::Scope,
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
    service.forward_asset_changes().await.unwrap();
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
    associations
        .revoke(
            &admin,
            association,
            &rss_mdm_device_service::Revoke {
                operation_id: Uuid::new_v4(),
                expected_version: associations.get(&admin, association).await.unwrap().version,
                reason: "separate ownership".into(),
            },
            &RequestAudit::new(tenant().to_string(), "device_association_revoke"),
        )
        .await
        .unwrap();
    service.forward_asset_changes().await.unwrap();
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
    running.stop().await;
    service.runtime.close().await;
    access.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.group_scope: Agent health selects the associated original MDM configuration target"]
async fn agent_health_drives_mdm_configuration_assignment() -> anyhow::Result<()> {
    use crate::test_support::planning_http::*;
    use crate::test_support::*;
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
        "INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{t}','{registration}','agent.script','{epoch}',true);INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{t}','mdm.observation.v1','inventory-v7','{encoded}','{coverage}','custom.corporate_agent.healthy','{value}','health-fixture',1,2,'known','{value}','health-fixture',1,2,'{registration}','agent.script','{epoch}',0)",
        t = case_tenant()
    ))?;
    let associations =
        rss_mdm_device_service::Associations::new(fixture.audit.clone(), tenant(), &[7; 32])?;
    associations.reconcile().await?;
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let member = browser_subject(&browser, &router).await?;
    let mut grants = identity::device_grants(None, &["inventory_read", "configuration_write"])?;
    for p in [
        "group_read",
        "group_write",
        "group_recompute",
        "scope_read",
        "scope_write",
        "policy_read",
        "policy_write",
        "resource_read",
        "resource_write",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(p))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::set_grants(case_tenant(), &member, grants).await?;
    let automation = start_automation(&fixture.base).await?;
    let group = Uuid::new_v4();
    let scope = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let resource = Uuid::new_v4();
    let receipt=call(&mut browser,&router,&format!("/api/v1/groups/{group}"),0,json!({"action":"create","assetContext":"associated_device","name":"unhealthy Agent","description":"","criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":false}}}})).await?;
    let (_, decisions) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v1/groups/{group}/results/{}/decisions",
                receipt["task"].as_str().unwrap()
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
    call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    native_configuration_resource(
        &mut browser,
        &router,
        resource,
        "windows",
        "x86_64",
        windows_configuration(),
    )
    .await?;
    call(&mut browser,&router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"configuration","resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"exit":"retain"}}})).await?;
    await_ingress().await?;
    let (status, page) = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/assignments"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK, "{page}");
    let assignments = page["items"].as_array().unwrap();
    ensure!(assignments.len() == 1, "{page}");
    ensure!(
        assignments[0]["availability"] == "ready"
            && assignments[0]["object"]["kind"] == "association"
            && assignments[0]["channel"] == "mdm"
            && assignments[0]["target"]["device"] == mdm,
        "{page}"
    );
    ensure!(
        assignments[0]["sources"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["device"] == agent && m["registrationId"] == registration.to_string()),
        "{page}"
    );
    let old_route = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/devices"),
            None,
        )
        .await?;
    ensure!(old_route.0 == StatusCode::NOT_FOUND);
    stop_worker(automation).await?;
    Ok(())
    }).await

    }).await
}
