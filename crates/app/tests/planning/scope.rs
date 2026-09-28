use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=planning.scope: real capability storage and transactions"]
async fn corrupt_scope_is_a_storage_failure_not_a_client_error() {
    let m = planning(tenant()).await;
    let id = Uuid::new_v4();
    let command = Command::Scope {
        id,
        change: operation(
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
    let receipt = execute(&m, &command).await.unwrap();
    sql(&format!(
        "UPDATE mdm_planning.scope_versions SET definition='[]' WHERE id='{id}'"
    ));
    assert!(matches!(
        execute(&m, &Command::ScopeRead { id }).await,
        Err(Error::Unavailable(Failure::PlanningStorage))
    ));
    sql(&format!(
        "UPDATE mdm_planning.scope_versions SET definition='{{\"targets\":[],\"limitations\":null,\"exclusions\":[]}}' WHERE id='{id}'"
    ));
    let operation = match &command {
        Command::Scope { change, .. } => change.operation_id,
        _ => unreachable!(),
    };
    sql(&format!(
        "UPDATE mdm_planning.operations SET response='[]' WHERE id='{operation}'"
    ));
    let before = sql("SELECT count(*) FROM rss_audit.records");
    assert!(
        matches!(
            execute(&m, &command).await,
            Err(Error::Unavailable(Failure::PlanningStorage))
        ),
        "corrupt replay receipt must fail before success audit"
    );
    assert_eq!(before, sql("SELECT count(*) FROM rss_audit.records"));
    let document = serde_json::to_string(&receipt).unwrap().replace('\'', "''");
    sql(&format!(
        "UPDATE mdm_planning.operations SET response='{document}' WHERE id='{operation}'"
    ));
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.scope: real capability storage and transactions"]
async fn scope_history_survives_deletion() {
    let service = Arc::new(planning(tenant()).await);
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
        crate::automation::TaskKind::Scope,
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
#[ignore = "MODULE=planning.scope: real capability storage and transactions"]
async fn published_scope_job_does_not_swallow_new_definition() {
    let service = Arc::new(planning(tenant()).await);
    let id = Uuid::new_v4();
    let old = format!("scope-old-{id}");
    let new = format!("scope-new-{id}");
    seed_device(&old);
    seed_device(&new);
    let definition = |device: &str| {
        serde_json::from_value(
            json!({"targets":[{"kind":"device","id":device}],"limitations":null,"exclusions":[]}),
        )
        .unwrap()
    };
    let created = execute(
        &service,
        &Command::Scope {
            id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: definition(&old),
                },
            ),
        },
    )
    .await
    .unwrap();
    let first = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    // Stop at the real publication boundary before the final propagation page.
    for _ in 0..10 {
        service
            .runtime
            .local_tx_with_context(tenant(), deadline(), service.as_ref(), |s, tx| {
                Box::pin(async move {
                    s.advance_scope_job_in(tx, first, id, None)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("scope step failed".into()).into())
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
        if sql(&format!(
            "SELECT phase FROM mdm_planning.scope_runs WHERE id='{first}'"
        )) == "published"
        {
            break;
        }
    }
    assert_eq!(
        sql(&format!(
            "SELECT phase FROM mdm_planning.scope_runs WHERE id='{first}'"
        )),
        "published"
    );
    assert_eq!(
        sql(&format!(
            "SELECT completed FROM mdm_automation.automation_jobs WHERE id='{first}'"
        )),
        "f"
    );
    let updated = execute(
        &service,
        &Command::Scope {
            id,
            change: operation(
                1,
                ScopeChange::Put {
                    definition: definition(&new),
                },
            ),
        },
    )
    .await
    .unwrap();
    let second = Uuid::parse_str(updated["task"].as_str().unwrap()).unwrap();
    assert_ne!(
        first, second,
        "published work can no longer absorb an updated source"
    );
    let worker = RunningAutomation::start(service.clone()).await;
    wait_task(
        &service,
        second,
        crate::automation::TaskKind::Scope,
        &id.to_string(),
    )
    .await;
    assert_eq!(
        sql(&format!(
            "SELECT r.device FROM mdm_planning.scope_results r JOIN mdm_planning.scopes s ON(s.tenant_id,s.resolution)=(r.tenant_id,r.run) WHERE s.id='{id}' AND r.matched"
        )),
        new
    );
    worker.stop().await;
    service.runtime.close().await;
}
