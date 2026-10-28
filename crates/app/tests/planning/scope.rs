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
        Err(Error::Flow(rss_mdm_flow_service::Error::Unavailable(
            rss_mdm_flow_service::Failure::PlanningStorage
        )))
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
    let before = sql("SELECT count(*) FROM rss_audit.records WHERE source_id='mdm.business'");
    assert!(
        matches!(
            execute(&m, &command).await,
            Err(Error::Flow(rss_mdm_flow_service::Error::Unavailable(
                rss_mdm_flow_service::Failure::PlanningStorage
            )))
        ),
        "corrupt replay receipt must fail before success audit"
    );
    assert_eq!(
        before,
        sql("SELECT count(*) FROM rss_audit.records WHERE source_id='mdm.business'")
    );
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
    wait_task(&service, result, TaskFamily::Scope, &scope.to_string()).await;
    running.stop().await;
    let projections = [
        pages::ScopePageKind::Members,
        pages::ScopePageKind::Decisions,
    ];
    let mut histories = Vec::new();
    for projection in projections {
        let before = execute(
            &service,
            &Command::ScopePage {
                scope,
                result,
                projection,
                query: crate::planning::test_support::scope_page_query(100, None),
            },
        )
        .await
        .unwrap();
        assert_eq!(before["page"]["items"].as_array().unwrap().len(), 2);
        histories.push(before["page"]["items"].as_array().unwrap().clone());
    }
    execute(
        &service,
        &Command::Scope {
            id: scope,
            change: operation(1, ScopeChange::Delete),
        },
    )
    .await
    .unwrap();
    for (projection, expected) in projections.into_iter().zip(histories) {
        let mut cursor = None;
        let mut items = Vec::new();
        loop {
            let page = execute(
                &service,
                &Command::ScopePage {
                    scope,
                    result,
                    projection,
                    query: crate::planning::test_support::scope_page_query(1, cursor),
                },
            )
            .await
            .unwrap();
            assert_eq!(page["current"], false);
            items.extend(page["page"]["items"].as_array().unwrap().iter().cloned());
            cursor = page["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
            assert!(
                items.len() <= expected.len(),
                "history cursor repeated results"
            );
        }
        assert_eq!(items, expected);
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
    wait_task(&service, second, TaskFamily::Scope, &id.to_string()).await;
    assert_eq!(
        sql(&format!(
            "SELECT r.device FROM mdm_planning.scope_results r JOIN mdm_planning.scopes s ON(s.tenant_id,s.resolution)=(r.tenant_id,r.run) WHERE s.id='{id}' AND r.matched"
        )),
        format!("endpoint:{new}")
    );
    worker.stop().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.scope: persistent pending sources and restart"]
async fn pending_group_source_keeps_scope_identity_and_recovers_after_restart() {
    use rss_reconcile::DurableStore;
    let first = Arc::new(planning(tenant()).await);
    let device = format!("pending-source-{}", Uuid::new_v4());
    seed_device(&device);
    execute_asset(
        &first,
        &assets::Command::Manual {
            device: device.clone(),
            field: rss_mdm_inventory::builtin::IS_LOANER,
            owner: assets::Owner {
                instance: Uuid::new_v4().to_string(),
                principal: Uuid::new_v4().to_string(),
            },
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
    let source = seed_group(
        &first,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"pending-source","description":""})
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
    let source_task = Uuid::parse_str(source["task"].as_str().unwrap()).unwrap();
    let scope = Uuid::new_v4();
    let saved = execute(
        &first,
        &Command::Scope {
            id: scope,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: [Reference::Group(group)].into(),
                        limitations: None,
                        exclusions: Default::default(),
                    },
                },
            ),
        },
    )
    .await
    .unwrap();
    let task = Uuid::parse_str(saved["task"].as_str().unwrap()).unwrap();
    let worker = crate::automation::PlanningWork::connect_planning(first.clone(), options())
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
    // Hold the upstream computation pending. This exercises the downstream wait
    // contract independently of the upstream capacity/retry policy.
    let claim = claim_job(&worker, task, Duration::from_secs(300)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(120), &cancel);
    let diff = worker.observe(&claim, &control).await.unwrap();
    worker.apply(&claim, diff, &control).await.unwrap();
    let state = || {
        sql(&format!(
            "SELECT jsonb_build_array(phase,input,source_index,source_cursor,(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{t}' AND target='{scope}'),(SELECT count(*) FROM mdm_planning.scope_runs WHERE tenant_id='{t}' AND scope='{scope}'),(SELECT count(*) FROM rss_audit.records WHERE source_id='mdm.business' AND tenant_id='{t}')) FROM mdm_planning.scope_runs WHERE tenant_id='{t}' AND id='{task}'",
            t = tenant()
        ))
    };
    let before = state();
    for _ in 0..2 {
        let diff = worker.observe(&claim, &control).await.unwrap();
        assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
        worker.apply(&claim, diff, &control).await.unwrap();
    }
    assert_eq!(
        state(),
        before,
        "pending source created work or audit facts"
    );
    worker.release(&claim, &control).await.unwrap();
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();

    let second = Arc::new(planning(tenant()).await);
    let worker = crate::automation::PlanningWork::connect_planning(second.clone(), options())
        .await
        .unwrap();
    let claim = claim_job(&worker, task, Duration::from_secs(300)).await;
    for _ in 0..2 {
        let diff = worker.observe(&claim, &control).await.unwrap();
        assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
        worker.apply(&claim, diff, &control).await.unwrap();
    }
    assert_eq!(state(), before, "restart expanded the replacement chain");

    // Removing the unavailable reference must also escape the wait. Scope jobs
    // deduplicate by scope identity, so definition validation precedes waiting.
    let changed_scope = Uuid::new_v4();
    let put = |revision, reference| Command::Scope {
        id: changed_scope,
        change: operation(
            revision,
            ScopeChange::Put {
                definition: ScopeDefinition {
                    targets: [reference].into(),
                    limitations: None,
                    exclusions: Default::default(),
                },
            },
        ),
    };
    let old = execute(&second, &put(0, Reference::Group(group)))
        .await
        .unwrap();
    let old = Uuid::parse_str(old["task"].as_str().unwrap()).unwrap();
    crate::automation::jobs::forward_jobs(
        &second.reconcile_messaging,
        &second.runtime,
        second.tenant,
        &second.audit_store,
    )
    .await
    .unwrap();
    let old_claim = claim_job(&worker, old, Duration::from_secs(300)).await;
    let diff = worker.observe(&old_claim, &control).await.unwrap();
    worker.apply(&old_claim, diff, &control).await.unwrap();
    let changed = execute(&second, &put(1, Reference::Device(device.clone())))
        .await
        .unwrap();
    assert_eq!(changed["task"], old.to_string());
    let diff = worker.observe(&old_claim, &control).await.unwrap();
    worker.apply(&old_claim, diff, &control).await.unwrap();
    worker
        .finish(&old_claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    let replacement = sql(&format!(
        "SELECT replacement_task FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{old}' AND failure='superseded'",
        tenant()
    ));
    let replacement = Uuid::parse_str(&replacement).unwrap();
    crate::automation::jobs::forward_jobs(
        &second.reconcile_messaging,
        &second.runtime,
        second.tenant,
        &second.audit_store,
    )
    .await
    .unwrap();
    let changed_claim = claim_job(&worker, replacement, Duration::from_secs(300)).await;
    for _ in 0..20 {
        let diff = worker.observe(&changed_claim, &control).await.unwrap();
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&changed_claim, diff, &control).await.unwrap();
    }
    assert_eq!(
        worker
            .observe(&changed_claim, &control)
            .await
            .unwrap()
            .drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(
            &changed_claim,
            rss_reconcile::Completion::Converged,
            &control,
        )
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_planning.scope_results WHERE tenant_id='{}' AND run='{replacement}' AND matched",
            tenant()
        )),
        "1"
    );
    assert_eq!(
        sql(&format!(
            "SELECT member_set IS NULL FROM mdm_group.groups WHERE tenant_id='{}' AND id='{group}'",
            tenant()
        )),
        "t"
    );

    let source_claim = claim_job(&worker, source_task, Duration::from_secs(300)).await;
    for _ in 0..20 {
        let diff = worker.observe(&source_claim, &control).await.unwrap();
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&source_claim, diff, &control).await.unwrap();
    }
    assert_eq!(
        worker
            .observe(&source_claim, &control)
            .await
            .unwrap()
            .drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(
            &source_claim,
            rss_reconcile::Completion::Converged,
            &control,
        )
        .await
        .unwrap();
    let diff = worker.observe(&claim, &control).await.unwrap();
    worker.apply(&claim, diff, &control).await.unwrap();
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    let replacement = sql(&format!(
        "SELECT replacement_task FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND id='{task}' AND failure='superseded'",
        tenant()
    ));
    let replacement = Uuid::parse_str(&replacement).unwrap();
    crate::automation::jobs::forward_jobs(
        &second.reconcile_messaging,
        &second.runtime,
        second.tenant,
        &second.audit_store,
    )
    .await
    .unwrap();
    let ready = claim_job(&worker, replacement, Duration::from_secs(300)).await;
    for _ in 0..20 {
        let diff = worker.observe(&ready, &control).await.unwrap();
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&ready, diff, &control).await.unwrap();
    }
    assert_eq!(
        worker.observe(&ready, &control).await.unwrap().drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(&ready, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT count(*)=2 AND count(*) FILTER(WHERE replacement_task IS NOT NULL)=1 FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND target='{scope}'",
            tenant()
        )),
        "t"
    );
    assert_eq!(
        sql(&format!(
            "SELECT s.resolution='{replacement}'::uuid AND r.phase='published' AND r.member_count=1 FROM mdm_planning.scopes s JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id='{}' AND s.id='{scope}'",
            tenant()
        )),
        "t"
    );
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(worker))
        .await
        .unwrap();
    first.runtime.close().await;
    second.runtime.close().await;
}

use rss_mdm_scope::{Reference, ScopeDefinition};

use rss_mdm_scope_service::ScopeChange;

#[tokio::test]
#[ignore = "MODULE=planning.scope: real runtime and tenant provenance"]
async fn scope_participation_rejects_foreign_runtime_before_reading() {
    let service = planning(tenant()).await;
    let id = Uuid::new_v4();
    execute(
        &service,
        &Command::Scope {
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
        },
    )
    .await
    .unwrap();
    let foreign = rss_mdm_scope_postgres::ScopeBinding::new(
        service.runtime.clone(),
        TenantId::parse(&Uuid::new_v4().to_string()).unwrap(),
    );
    service
        .runtime
        .local_tx_with_context(tenant(), deadline(), &foreign, |binding, tx| {
            Box::pin(async move {
                assert!(matches!(
                    binding.validate_in(tx),
                    Err(rss_mdm_scope_postgres::BindingError::TenantMismatch)
                ));
                Ok(())
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
    let other = runtime(tenant()).await;
    for (runtime, accepted) in [(&service.runtime, true), (&other, false)] {
        runtime
            .local_tx_with_context(tenant(), deadline(), &service, |service, tx| {
                Box::pin(async move {
                    match service.scope_definition(tx, id).await {
                        Ok(snapshot) => {
                            assert!(accepted);
                            assert_eq!(snapshot.revision, 1);
                        }
                        Err(rss_mdm_flow_service::transaction::Fault::Storage(error)) => {
                            assert!(!accepted);
                            assert_eq!(
                                error.kind(),
                                rss_transactional_messaging::error::MessagingErrorKind::Invariant
                            );
                            return Err(error);
                        }
                        Err(other) => panic!("unexpected scope participation failure: {other:?}"),
                    }
                    Ok(())
                })
            })
            .await
            .fold(
                |_| assert!(accepted),
                |e| panic!("transaction did not start: {e:?}"),
                |_| assert!(!accepted),
                |e| panic!("rollback failed: {e:?}"),
                |e| panic!("commit unknown: {e:?}"),
                |e| panic!("transaction fenced: {e:?}"),
            );
    }
    other.close().await;
    service.runtime.close().await;
}
