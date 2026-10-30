use crate::planning::test_support::*;
use crate::planning::*;

#[tokio::test]
#[ignore = "MODULE=scope.service: real capability storage and transactions"]
async fn corrupt_scope_is_a_storage_failure_not_a_client_error() {
    let m = planning(tenant()).await;
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
    let receipt = execute(&m, &command).await.unwrap();
    sql(&format!(
        "UPDATE mdm_scope.scope_versions SET definition='[]' WHERE id='{id}'"
    ));
    assert!(matches!(
        execute(&m, &Command::ScopeRead { id }).await,
        Err(Error::Scope(rss_mdm_scope_service::Error::Unavailable(
            rss_mdm_scope_service::Failure::Storage
        )))
    ));
    sql(&format!(
        "UPDATE mdm_scope.scope_versions SET definition='{{\"targets\":[],\"limitations\":null,\"exclusions\":[]}}' WHERE id='{id}'"
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
            Err(Error::Scope(rss_mdm_scope_service::Error::Unavailable(
                rss_mdm_scope_service::Failure::Storage
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
    m.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: real capability storage and transactions"]
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
            change: scope_operation(
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
            change: scope_operation(1, ScopeChange::Delete),
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
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: real capability storage and transactions"]
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
            change: scope_operation(
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
    // Scope completes at publication; Policy propagation remains separately pending.
    let scope_owner = scopes(&service).await;
    for _ in 0..10 {
        service
            .scope
            .runtime
            .local_tx_with_context(tenant(), deadline(), scope_owner.as_ref(), |s, tx| {
                Box::pin(async move {
                    s.audit_store
                        .bind_in(tx)
                        .await
                        .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                    s.advance_in(tx, first)
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
            "SELECT phase FROM mdm_scope.scope_runs WHERE id='{first}'"
        )) == "published"
        {
            break;
        }
    }
    assert_eq!(
        sql(&format!(
            "SELECT phase FROM mdm_scope.scope_runs WHERE id='{first}'"
        )),
        "published"
    );
    assert_eq!(
        sql(&format!(
            "SELECT completed FROM mdm_policy.work WHERE id='{first}'"
        )),
        "f"
    );
    assert_eq!(
        sql(&format!(
            "SELECT completed FROM mdm_scope.tasks WHERE id='{first}'"
        )),
        "t"
    );
    let updated = execute(
        &service,
        &Command::Scope {
            id,
            change: scope_operation(
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
            "SELECT r.device FROM mdm_scope.scope_results r JOIN mdm_scope.scopes s ON(s.tenant_id,s.resolution)=(r.tenant_id,r.run) WHERE s.id='{id}' AND r.matched"
        )),
        format!("endpoint:{new}")
    );
    worker.stop().await;
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: persistent pending sources and restart"]
async fn pending_group_source_keeps_scope_identity_and_recovers_after_restart() {
    use rss_reconcile::{DurableStore, Reconciler};
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
            change: scope_operation(
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
    let worker = ScopeWorker::open(&first).await;
    // Hold the upstream computation pending. This exercises the downstream wait
    // contract independently of the upstream capacity/retry policy.
    let claim = claim_scope(&worker, task, Duration::from_secs(300)).await;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(120), &cancel);
    let diff = crate::test_support::runtime::reconcile_ready(
        worker.observe(&claim, &control).await.unwrap(),
    );
    crate::test_support::runtime::reconcile_ready(
        worker.apply(&claim, diff, &control).await.unwrap(),
    );
    let state = || {
        sql(&format!(
            "SELECT jsonb_build_array(phase,input,source_index,source_cursor,(SELECT count(*) FROM mdm_scope.tasks WHERE tenant_id='{t}' AND scope='{scope}'),(SELECT count(*) FROM mdm_scope.scope_runs WHERE tenant_id='{t}' AND scope='{scope}'),(SELECT count(*) FROM rss_audit.records WHERE source_id='mdm.business' AND tenant_id='{t}')) FROM mdm_scope.scope_runs WHERE tenant_id='{t}' AND id='{task}'",
            t = tenant()
        ))
    };
    let before = state();
    for _ in 0..2 {
        let diff = crate::test_support::runtime::reconcile_ready(
            worker.observe(&claim, &control).await.unwrap(),
        );
        assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
        crate::test_support::runtime::reconcile_ready(
            worker.apply(&claim, diff, &control).await.unwrap(),
        );
    }
    assert_eq!(
        state(),
        before,
        "pending source created work or audit facts"
    );
    worker.release(&claim, &control).await.unwrap();
    worker.close().await;

    let second = Arc::new(planning(tenant()).await);
    let worker = ScopeWorker::open(&second).await;
    let claim = claim_scope(&worker, task, Duration::from_secs(300)).await;
    for _ in 0..2 {
        let diff = crate::test_support::runtime::reconcile_ready(
            worker.observe(&claim, &control).await.unwrap(),
        );
        assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
        crate::test_support::runtime::reconcile_ready(
            worker.apply(&claim, diff, &control).await.unwrap(),
        );
    }
    assert_eq!(state(), before, "restart expanded the replacement chain");

    // Removing the unavailable reference must also escape the wait. Scope jobs
    // deduplicate by scope identity, so definition validation precedes waiting.
    let changed_scope = Uuid::new_v4();
    let put = |revision, reference| Command::Scope {
        id: changed_scope,
        change: scope_operation(
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
    let old_claim = claim_scope(&worker, old, Duration::from_secs(300)).await;
    let diff = crate::test_support::runtime::reconcile_ready(
        worker.observe(&old_claim, &control).await.unwrap(),
    );
    crate::test_support::runtime::reconcile_ready(
        worker.apply(&old_claim, diff, &control).await.unwrap(),
    );
    let changed = execute(&second, &put(1, Reference::Device(device.clone())))
        .await
        .unwrap();
    assert_eq!(changed["task"], old.to_string());
    let diff = crate::test_support::runtime::reconcile_ready(
        worker.observe(&old_claim, &control).await.unwrap(),
    );
    crate::test_support::runtime::reconcile_ready(
        worker.apply(&old_claim, diff, &control).await.unwrap(),
    );
    worker
        .finish(&old_claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    let replacement = sql(&format!(
        "SELECT replacement_task FROM mdm_scope.tasks WHERE tenant_id='{}' AND id='{old}' AND failure='superseded'",
        tenant()
    ));
    let replacement = Uuid::parse_str(&replacement).unwrap();
    let changed_claim = claim_scope(&worker, replacement, Duration::from_secs(300)).await;
    for _ in 0..20 {
        let diff = crate::test_support::runtime::reconcile_ready(
            worker.observe(&changed_claim, &control).await.unwrap(),
        );
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        crate::test_support::runtime::reconcile_ready(
            worker.apply(&changed_claim, diff, &control).await.unwrap(),
        );
    }
    assert_eq!(
        crate::test_support::runtime::reconcile_ready(
            worker.observe(&changed_claim, &control).await.unwrap()
        )
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
            "SELECT count(*) FROM mdm_scope.scope_results WHERE tenant_id='{}' AND run='{replacement}' AND matched",
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

    let group_worker = GroupWorker::open(&second).await;
    let source_claim = claim_group(&group_worker, source_task, Duration::from_secs(300)).await;
    finish_group_claim(&group_worker, &source_claim).await;
    group_worker.close().await;
    let diff = crate::test_support::runtime::reconcile_ready(
        worker.observe(&claim, &control).await.unwrap(),
    );
    crate::test_support::runtime::reconcile_ready(
        worker.apply(&claim, diff, &control).await.unwrap(),
    );
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    let replacement = sql(&format!(
        "SELECT replacement_task FROM mdm_scope.tasks WHERE tenant_id='{}' AND id='{task}' AND failure='superseded'",
        tenant()
    ));
    let replacement = Uuid::parse_str(&replacement).unwrap();
    let ready = claim_scope(&worker, replacement, Duration::from_secs(300)).await;
    for _ in 0..20 {
        let diff = crate::test_support::runtime::reconcile_ready(
            worker.observe(&ready, &control).await.unwrap(),
        );
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        crate::test_support::runtime::reconcile_ready(
            worker.apply(&ready, diff, &control).await.unwrap(),
        );
    }
    assert_eq!(
        crate::test_support::runtime::reconcile_ready(
            worker.observe(&ready, &control).await.unwrap()
        )
        .drift(),
        rss_reconcile::DriftKind::Converged
    );
    worker
        .finish(&ready, rss_reconcile::Completion::Converged, &control)
        .await
        .unwrap();
    assert_eq!(
        sql(&format!(
            "SELECT count(*)=2 AND count(*) FILTER(WHERE replacement_task IS NOT NULL)=1 FROM mdm_scope.tasks WHERE tenant_id='{}' AND scope='{scope}'",
            tenant()
        )),
        "t"
    );
    assert_eq!(
        sql(&format!(
            "SELECT s.resolution='{replacement}'::uuid AND r.phase='published' AND r.member_count=1 FROM mdm_scope.scopes s JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id='{}' AND s.id='{scope}'",
            tenant()
        )),
        "t"
    );
    worker.close().await;
    first.close().await;
    second.close().await;
}

use rss_mdm_scope::{Reference, ScopeDefinition};

use rss_mdm_scope_service::ScopeChange;

#[tokio::test]
#[ignore = "MODULE=scope.service: real runtime and tenant provenance"]
async fn scope_participation_rejects_foreign_runtime_before_reading() {
    let service = planning(tenant()).await;
    let id = Uuid::new_v4();
    execute(
        &service,
        &Command::Scope {
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
        },
    )
    .await
    .unwrap();
    let foreign = rss_mdm_scope_postgres::ScopeBinding::new(
        service.scope.runtime.clone(),
        TenantId::parse(&Uuid::new_v4().to_string()).unwrap(),
    );
    service
        .scope
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
    let scope_owner = scopes(&service).await;
    let other = policy_runtime(tenant()).await;
    for (runtime, accepted) in [(&service.scope.runtime, true), (&other, false)] {
        runtime
            .local_tx_with_context(tenant(), deadline(), scope_owner.as_ref(), |service, tx| {
                Box::pin(async move {
                    match service.scope_definition(tx, id).await {
                        Ok(snapshot) => {
                            assert!(accepted);
                            assert_eq!(snapshot.revision, 1);
                        }
                        Err(rss_mdm_scope_service::transaction::Fault::Storage(error)) => {
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
    service.close().await;
}

#[cfg(feature = "integration")]
struct FailingProjection {
    inner: rss_mdm_execution_service::scope::ScopeProjection,
    fail: std::sync::atomic::AtomicBool,
}
#[cfg(feature = "integration")]
impl rss_mdm_scope_service::sources::ChannelProjectionPublisher for FailingProjection {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        p: &'a rss_mdm_scope_postgres::Publication,
    ) -> rss_mdm_scope_service::sources::Pending<'a, bool, rss_mdm_scope_service::transaction::Fault>
    {
        self.inner.advance_in(tx, p)
    }
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        p: &'a rss_mdm_scope_postgres::Publication,
    ) -> rss_mdm_scope_service::sources::Pending<'a, bool, rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move {
            let changed = self.inner.publish_in(tx, p).await?;
            if self.fail.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(rss_mdm_scope_service::Error::Unavailable(
                    rss_mdm_scope_service::Failure::Storage,
                )
                .into());
            }
            Ok(changed)
        })
    }
    fn result_devices_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        page: rss_mdm_scope_service::sources::ResultPage<'a>,
    ) -> rss_mdm_scope_service::sources::Pending<
        'a,
        rss_mdm_scope_service::sources::ResultDevices,
        rss_mdm_scope_service::transaction::Fault,
    > {
        self.inner.result_devices_on(c, page)
    }
    fn result_detail_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        t: TenantId,
        s: Uuid,
        r: Uuid,
        ch: rss_mdm_inventory::Channel,
        d: &'a str,
    ) -> rss_mdm_scope_service::sources::Pending<
        'a,
        rss_mdm_scope_service::sources::ResultDetail,
        rss_mdm_scope_service::transaction::Fault,
    > {
        self.inner.result_detail_on(c, t, s, r, ch, d)
    }
}
#[cfg(feature = "integration")]
struct FailingDependents {
    inner: crate::policy_assembly::ScopeDependents,
    fail: std::sync::atomic::AtomicBool,
}
#[cfg(feature = "integration")]
impl rss_mdm_scope_service::sources::ScopeDependents for FailingDependents {
    fn used_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        s: Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, bool, rss_mdm_scope_service::transaction::Fault>
    {
        rss_mdm_scope_service::sources::ScopeDependents::used_in(&self.inner, tx, s)
    }
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        s: Uuid,
        r: Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, (), rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move {
            rss_mdm_scope_service::sources::ScopeDependents::publication_recorded_in(
                &self.inner,
                tx,
                s,
                r,
            )
            .await?;
            if self.fail.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Err(rss_mdm_scope_service::Error::Unavailable(
                    rss_mdm_scope_service::Failure::Storage,
                )
                .into());
            }
            Ok(())
        })
    }
}
async fn step_scope(
    s: &rss_mdm_scope_service::Scopes,
    task: Uuid,
) -> std::result::Result<(), rss_mdm_scope_service::Error> {
    let audit = RequestAudit::new(
        s.tenant.to_string(),
        "scope_test_step",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let result = rss_mdm_scope_service::transaction::run(
        &s.audit_store,
        &s.runtime,
        s.tenant,
        &audit,
        s,
        |s, tx| Box::pin(async move { s.advance_in(tx, task).await }),
    )
    .await;
    audit.finalize(None);
    result
}
async fn scope_until_ready(s: &rss_mdm_scope_service::Scopes, task: Uuid) {
    for _ in 0..64 {
        if sql(&format!(
            "SELECT phase FROM mdm_scope.scope_runs WHERE id='{task}'"
        )) == "ready"
        {
            return;
        }
        step_scope(s, task).await.unwrap();
    }
    panic!("Scope did not reach its bounded publication boundary");
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=scope.service: real projection/Scope/Policy atomic publication and unknown commit"]
async fn publication_rolls_back_every_owner_and_finishes_without_policy_worker() {
    let fixture = planning(tenant()).await;
    let device = format!("scope-atomic-{}", Uuid::new_v4());
    seed_device(&device);
    for fail_projection in [true, false] {
        let owner = rss_mdm_scope_service::Scopes::new(
            fixture.scope.runtime.clone(),
            fixture.tenant,
            Arc::new(ScopeClock(fixture.clock.clone())),
            rss_mdm_scope_service::Dependencies {
                audit_store: fixture.scope.audit.clone(),
                reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(
                    fixture.scope.runtime.clone(),
                    fixture.tenant,
                    deadline(),
                )
                .await
                .unwrap(),
                objects: fixture.objects.clone(),
                groups: Arc::new(
                    rss_mdm_group_postgres::GroupSources::bind(
                        fixture.scope.runtime.clone(),
                        fixture.tenant,
                        deadline(),
                    )
                    .await
                    .unwrap(),
                ),
                cursor_key: fixture.cursor_key.clone(),
                projection: Arc::new(FailingProjection {
                    inner: rss_mdm_execution_service::scope::ScopeProjection::new(
                        fixture.scope.runtime.clone(),
                        fixture.tenant,
                    ),
                    fail: std::sync::atomic::AtomicBool::new(fail_projection),
                }),
                dependents: Arc::new(FailingDependents {
                    inner: crate::policy_assembly::ScopeDependents(
                        rss_mdm_policy_service::management::scope_changes::ScopeChanges::new(
                            fixture.scope.runtime.clone(),
                            fixture.tenant,
                        ),
                    ),
                    fail: std::sync::atomic::AtomicBool::new(!fail_projection),
                }),
            },
        )
        .await
        .unwrap();
        let scope = Uuid::new_v4();
        let command = Command::Scope {
            id: scope,
            change: scope_operation(
                0,
                ScopeChange::Put {
                    definition: ScopeDefinition {
                        targets: [Reference::Device(device.clone())].into(),
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
        let saved = owner.execute(&command, &audit, &|| Ok(())).await.unwrap();
        audit.finalize(None);
        let run = Uuid::parse_str(saved["task"].as_str().unwrap()).unwrap();
        scope_until_ready(&owner, run).await;
        let state = || {
            sql(&format!(
                "SELECT jsonb_build_array((SELECT resolution FROM mdm_scope.scopes WHERE id='{scope}'),(SELECT phase FROM mdm_scope.scope_runs WHERE id='{run}'),(SELECT phase FROM mdm_commands.scope_projection_runs WHERE id='{run}'),(SELECT completed FROM mdm_scope.tasks WHERE id='{run}'),(SELECT count(*) FROM mdm_policy.work WHERE id='{run}'),(SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}'))",
                tenant()
            ))
        };
        let before = state();
        assert!(matches!(
            step_scope(&owner, run).await,
            Err(rss_mdm_scope_service::Error::Unavailable(_))
        ));
        assert_eq!(
            state(),
            before,
            "failed participant leaked an active result, audit or downstream task"
        );
        owner.runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        assert!(matches!(
            step_scope(&owner, run).await,
            Err(rss_mdm_scope_service::Error::CommitUnknown)
        ));
        let published = state();
        step_scope(&owner, run).await.unwrap();
        assert_eq!(
            state(),
            published,
            "unknown-commit replay duplicated publication effects"
        );
        assert_eq!(
            sql(&format!(
                "SELECT s.resolution='{run}'::uuid AND r.phase='published' AND p.phase='published' AND t.completed AND NOT j.completed AND j.kind='policy_scope' FROM mdm_scope.scopes s JOIN mdm_scope.scope_runs r ON r.id=s.resolution JOIN mdm_commands.scope_projection_runs p ON p.id=r.id JOIN mdm_scope.tasks t ON t.id=r.id JOIN mdm_policy.work j ON j.id=r.id WHERE s.id='{scope}'"
            )),
            "t"
        );
        assert_ne!(
            sql(&format!(
                "SELECT count(*) FROM mdm_commands.scope_channel_results WHERE run='{run}' AND matched AND NOT pending"
            )),
            "0",
            "failure-only publication proof is vacuous"
        );
        let versions = sql(&format!(
            "SELECT jsonb_build_array(s.resolution_revision,p.agent_revision,p.mdm_revision) FROM mdm_scope.scopes s JOIN mdm_commands.scope_projection_runs p ON p.id=s.resolution WHERE s.id='{scope}'"
        ));
        seed_device(&format!("scope-unrelated-{}", Uuid::new_v4()));
        assert_eq!(
            sql(&format!(
                "SELECT mdm_scope.scope_admission('{scope}',NULL)->>'state'"
            )),
            "fresh"
        );
        assert_eq!(
            sql(&format!(
                "SELECT jsonb_build_array(s.resolution_revision,p.agent_revision,p.mdm_revision) FROM mdm_scope.scopes s JOIN mdm_commands.scope_projection_runs p ON p.id=s.resolution WHERE s.id='{scope}'"
            )),
            versions
        );
    }
    fixture.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: Group definition fencing before notification delivery"]
async fn group_definition_changes_block_frozen_results_before_delivery() {
    let fixture = planning(tenant()).await;
    let owner = scopes(&fixture).await;
    let group_worker = GroupWorker::open(&fixture).await;
    let first = format!("scope-source-first-{}", Uuid::new_v4());
    let second = format!("scope-source-second-{}", Uuid::new_v4());
    seed_device(&first);
    seed_device(&second);
    for (device, value) in [(&first, true), (&second, false)] {
        execute_asset(
            &fixture,
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
                        value: assets::Scalar::Boolean(value),
                    },
                ),
            },
        )
        .await
        .unwrap();
    }
    let criteria = |value| assets::InventoryCondition {
        selector: assets::ScopeSelector::Device,
        quantifier: assets::ScopeQuantifier::One,
        criteria: rss_mdm_inventory_service::groups::criteria::Criteria::Predicate {
            field: rss_mdm_inventory::builtin::IS_LOANER,
            op: assets::Operator::Eq,
            value: Some(assets::Scalar::Boolean(value)),
            values: None,
        },
    };
    let group = Uuid::new_v4();
    let created = execute(
        &fixture,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    presentation: json!({"name":"scope-fence","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(criteria(true)),
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                },
            )),
        },
    )
    .await
    .unwrap();
    let group_task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    let claim = claim_group(&group_worker, group_task, Duration::from_secs(60)).await;
    finish_group_claim(&group_worker, &claim).await;
    // Definition publication queues a separate membership calculation; finish both real jobs.
    let calculation = Uuid::parse_str(&sql(&format!(
        "SELECT id::text FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND target='{group}' AND NOT completed", tenant()
    ))).unwrap();
    let claim = claim_group(&group_worker, calculation, Duration::from_secs(60)).await;
    finish_group_claim(&group_worker, &claim).await;

    let scope = Uuid::new_v4();
    let saved = execute(
        &fixture,
        &Command::Scope {
            id: scope,
            change: scope_operation(
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
    let run = Uuid::parse_str(saved["task"].as_str().unwrap()).unwrap();
    scope_until_ready(&owner, run).await;
    // A real Group owner commits the new definition/result. No Group-to-Scope receiver is running.
    let changed = execute(
        &fixture,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                1,
                GroupChange::Rule {
                    criteria: criteria(false),
                },
            )),
        },
    )
    .await
    .unwrap();
    let group_task = Uuid::parse_str(changed["task"].as_str().unwrap()).unwrap();
    let claim = claim_group(&group_worker, group_task, Duration::from_secs(60)).await;
    finish_group_claim(&group_worker, &claim).await;
    // Definition publication queues a separate membership calculation; finish both real jobs.
    let calculation = Uuid::parse_str(&sql(&format!(
        "SELECT id::text FROM mdm_assets.group_tasks WHERE tenant_id='{}' AND target='{group}' AND NOT completed", tenant()
    ))).unwrap();
    let claim = claim_group(&group_worker, calculation, Duration::from_secs(60)).await;
    finish_group_claim(&group_worker, &claim).await;

    assert!(matches!(
        step_scope(&owner, run).await,
        Err(rss_mdm_scope_service::Error::Conflict)
    ));
    assert_eq!(
        sql(&format!(
            "SELECT resolution IS NULL FROM mdm_scope.scopes WHERE id='{scope}'"
        )),
        "t"
    );
    assert_eq!(
        sql(&format!(
            "SELECT mdm_scope.scope_admission('{scope}',NULL)->>'state'"
        )),
        "pending"
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_policy.work WHERE id='{run}'"
        )),
        "0"
    );
    group_worker.close().await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: role closure admission with non-inherited write capabilities"]
async fn scope_admission_rejects_set_role_write_escalation() {
    let fixture = planning(tenant()).await;
    let binding =
        rss_mdm_scope_postgres::ScopeBinding::new(fixture.scope.runtime.clone(), fixture.tenant);
    for alteration in [
        None,
        Some((
            "CREATE ROLE scope_extra_writer NOLOGIN; GRANT UPDATE(input) ON mdm_scope.scope_runs TO scope_extra_writer; GRANT scope_extra_writer TO mdm_scope_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE scope_extra_writer FROM mdm_scope_runtime; DROP OWNED BY scope_extra_writer; DROP ROLE scope_extra_writer",
        )),
        Some((
            "ALTER TABLE mdm_scope.scopes DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_scope.scopes ENABLE ROW LEVEL SECURITY",
        )),
        None,
    ] {
        if let Some((change, _)) = alteration {
            sql(change);
        }
        let admitted = fixture
            .scope
            .runtime
            .local_tx_with_context(tenant(), deadline(), &binding, |binding, tx| {
                Box::pin(async move { Ok(binding.admit_in(tx).await.is_ok()) })
            })
            .await
            .fold(
                |v| v,
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            );
        if let Some((_, restore)) = alteration {
            sql(restore);
        }
        assert_eq!(admitted, alteration.is_none());
    }
    fixture.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: real Group byte-budget pagination"]
async fn group_short_pages_preserve_every_scope_member() {
    let fixture = planning(tenant()).await;
    let prefix = format!("scope-short-page-{}", Uuid::new_v4());
    let devices: Vec<_> = (0..20).map(|n| format!("{prefix}-{n:02}")).collect();
    for device in &devices {
        seed_device(device);
        execute_asset(
            &fixture,
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
    }
    let group = Uuid::new_v4();
    let created = seed_group(
        &fixture,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"short-page-source","description":""})
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
    let task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    let group_worker = GroupWorker::open(&fixture).await;
    let claim = claim_group(&group_worker, task, Duration::from_secs(300)).await;
    finish_group_claim(&group_worker, &claim).await;
    // Preserve the real upstream decisions; legal JSON whitespace makes the provider's
    // byte budget end a page before its requested row limit, without changing membership.
    sql(&format!(
        "UPDATE mdm_group.member_rows SET evidence=convert_to(rpad(convert_from(evidence,'UTF8'),1000000,' '),'UTF8') WHERE run_id='{task}'"
    ));
    sql(&format!(
        "UPDATE mdm_group.member_rows SET evidence_digest=sha256(evidence) WHERE run_id='{task}'"
    ));
    let run = rss_mdm_group::OperationId::parse(&task.to_string()).unwrap();
    let storage = rss_mdm_group_postgres::GroupSources::bind(
        fixture.scope.runtime.clone(),
        tenant(),
        deadline(),
    )
    .await
    .unwrap();
    let count = fixture
        .scope
        .runtime
        .local_tx_with_context(tenant(), deadline(), (&storage, run), |(s, run), tx| {
            Box::pin(async move { s.build_decisions_in(tx, *run, None, 1000).await })
        })
        .await
        .fold(
            |v| v.unwrap().len(),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    assert!(
        count > 0 && count < devices.len(),
        "fixture must hit the Group byte budget"
    );
    let scope = Uuid::new_v4();
    let accepted = execute(
        &fixture,
        &Command::Scope {
            id: scope,
            change: scope_operation(
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
    let task = Uuid::parse_str(accepted["task"].as_str().unwrap()).unwrap();
    let owner = scopes(&fixture).await;
    scope_until_ready(&owner, task).await;
    step_scope(&owner, task).await.unwrap();
    let members = execute(
        &fixture,
        &Command::ScopePage {
            scope,
            result: task,
            projection: pages::ScopePageKind::Members,
            query: scope_page_query(100, None),
        },
    )
    .await
    .unwrap();
    let serialized = serde_json::to_string(&members["page"]["items"]).unwrap();
    for device in devices {
        assert!(
            serialized.contains(&device),
            "missing last-page member {device}"
        );
    }
    group_worker.close().await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "make t2 MODULE=scope.service"]
async fn absent_scope_aggregate_has_a_nonwaiting_identity_fence() {
    let first = runtime_role(tenant(), "mdm_scope_runtime").await;
    let second = runtime_role(tenant(), "mdm_scope_runtime").await;
    let one = rss_mdm_scope_postgres::ScopeBinding::new(first.clone(), tenant());
    let two = rss_mdm_scope_postgres::ScopeBinding::new(second.clone(), tenant());
    let id = Uuid::new_v4();
    let (ready, wait_ready) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let holder = first.local_tx_with_context(tenant(), deadline(), &one, |binding, tx| {
        Box::pin(async move {
            binding.lock_scope_in(tx, id).await.map_err(|e| match e {
                rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                _ => panic!("unexpected binding rejection"),
            })?;
            ready.send(()).unwrap();
            wait_release.await.unwrap();
            Ok(())
        })
    });
    let contender = async {
        wait_ready.await.unwrap();
        second
            .local_tx_with_context(tenant(), deadline(), &two, |binding, tx| {
                Box::pin(async move {
                    binding.lock_scope_in(tx, id).await.map_err(|e| match e {
                        rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                        _ => panic!("unexpected binding rejection"),
                    })
                })
            })
            .await
            .fold(
                |_| panic!("absent identity must still be fenced"),
                |e| panic!("{e:?}"),
                |e| {
                    assert_eq!(
                        e.kind(),
                        rss_transactional_messaging::error::MessagingErrorKind::Transient
                    )
                },
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            );
        second
            .local_tx_with_context(tenant(), deadline(), &two, |binding, tx| {
                Box::pin(async move {
                    binding
                        .lock_scope_in(tx, Uuid::new_v4())
                        .await
                        .map_err(|e| match e {
                            rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                            _ => panic!("unexpected binding rejection"),
                        })
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
        release.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(holder, contender);
    result.fold(
        |_| (),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    );
    second.close().await;
    first.close().await;
}

#[tokio::test]
#[ignore = "MODULE=scope.service: Policy reference locking without Scope write authority"]
async fn policy_reference_lock_admits_only_the_owner_kernel() {
    let fixture = planning(tenant()).await;
    let id = Uuid::new_v4();
    execute(
        &fixture,
        &Command::Scope {
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
        },
    )
    .await
    .unwrap();
    let reader =
        rss_mdm_scope_postgres::ScopeBinding::new(fixture.policy.runtime.clone(), tenant());
    async fn accepted(
        fixture: &OwnerFixture,
        reader: &rss_mdm_scope_postgres::ScopeBinding,
        id: Uuid,
    ) -> bool {
        fixture.policy.runtime.local_tx_with_context(tenant(), deadline(), reader, |reader, tx| Box::pin(async move {
            tx.with_connection(|c| Box::pin(async move {
                rss_mdm_scope_postgres::verify_authority(c).await?;
                let writes: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'mdm_scope.scopes','INSERT,UPDATE,DELETE') OR has_any_column_privilege(current_user,'mdm_scope.scopes','INSERT,UPDATE')").fetch_one(c).await?;
                assert!(!writes, "Policy gained Scope writer rights");
                Ok(())
            })).await?;
            reader.lock_references_in(tx, &[id]).await.map_err(|_| rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol("Scope reference rejected".into())))?;
            Ok(())
        })).await.fold(|_|true, |_|false, |_|false, |_|false, |_|false, |_|false)
    }
    assert!(accepted(&fixture, &reader, id).await);
    for (change, restore) in [
        (
            "GRANT EXECUTE ON FUNCTION mdm_scope.lock_reference_target(uuid) TO mdm_resource_runtime",
            "REVOKE EXECUTE ON FUNCTION mdm_scope.lock_reference_target(uuid) FROM mdm_resource_runtime",
        ),
        (
            "ALTER FUNCTION mdm_scope.lock_reference_target(uuid) SET search_path=public",
            "ALTER FUNCTION mdm_scope.lock_reference_target(uuid) SET search_path=pg_catalog",
        ),
        (
            "ALTER TABLE mdm_scope.scopes NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_scope.scopes FORCE ROW LEVEL SECURITY",
        ),
    ] {
        sql(change);
        let rejected = !accepted(&fixture, &reader, id).await;
        sql(restore);
        assert!(rejected, "accepted Scope reference drift: {change}");
        assert!(accepted(&fixture, &reader, id).await);
    }
    let original = rss_mdm_scope_postgres::INSTALL_SQL
        .split_once("CREATE FUNCTION mdm_scope.lock_reference_target(")
        .unwrap()
        .1;
    sql(
        "CREATE OR REPLACE FUNCTION mdm_scope.lock_reference_target(p_scope uuid) RETURNS SETOF mdm_scope.scopes LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN RETURN; END $$",
    );
    let rejected = !accepted(&fixture, &reader, id).await;
    sql(&format!(
        "CREATE OR REPLACE FUNCTION mdm_scope.lock_reference_target({original}"
    ));
    assert!(rejected, "accepted changed reference function body");
    assert!(accepted(&fixture, &reader, id).await);
    fixture
        .scope
        .runtime
        .local_tx_with_context(tenant(), deadline(), &reader, |reader, tx| {
            Box::pin(async move {
                assert!(reader.lock_references_in(tx, &[id]).await.is_err());
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
    fixture.close().await;
}
