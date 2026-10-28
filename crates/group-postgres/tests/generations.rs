use rss_mdm_group::{AssetContext, GroupId, GroupSource, SourceCoordinates};
use rss_mdm_group_postgres::{core::*, *};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;
fn committed<T>(attempt: LocalTxAttempt<std::result::Result<T, Rejection>, PgError>) -> T {
    attempt.fold(
        |v| v.unwrap(),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    )
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=group.generations"]
async fn staged_pages_publish_atomically_and_replay_without_duplicate_members() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (rule, snapshot) = inputs();
    let group = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group,
                presentation: serde_json::json!({"name":"paged","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = BuildRequest {
        sources: vec![],
        id: op(),
        group,
        expected: created.group.revision,
        base_calculation: created.group.calculation_revision,
        changed_devices: None,
        rule_version: Some("rule-1".into()),
        patch: None,
        input_version: "watermark-1".into(),
        as_of: at(),
    };
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
            })
            .await,
    );
    for (start, count) in [(0, 2), (2, 1)] {
        for _ in 0..2 {
            let page = committed(
                runtime
                    .local_tx_with_context(
                        tenant(),
                        deadline(),
                        (&s, &request, &snapshot),
                        move |ctx, tx| {
                            Box::pin(async move {
                                let objects: Vec<_> = (start..start + count)
                                    .map(|i| {
                                        let mut o = ctx.2.objects[0].clone();
                                        o.key = ObjectKey::new(tenant(), format!("device-{i:07}"))
                                            .unwrap();
                                        o
                                    })
                                    .collect();
                                let after = if start == 0 {
                                    None
                                } else {
                                    Some(
                                        ObjectKey::new(
                                            tenant(),
                                            format!("device-{:07}", start - 1),
                                        )
                                        .unwrap(),
                                    )
                                };
                                let page = PageInput {
                                    tenant: tenant(),
                                    id: "assets",
                                    version: &ctx.1.input_version,
                                    dictionary_version: "dictionary-1",
                                    coverage: &ctx.2.coverage,
                                    objects: &objects,
                                    after: after.as_ref(),
                                };
                                ctx.0.append_build_page_in(tx, ctx.1.id, &page).await
                            })
                        },
                    )
                    .await,
            );
            assert_eq!(page.objects, start + count);
        }
        assert_eq!(
            s.get(group, deadline())
                .await
                .unwrap()
                .unwrap()
                .member_count,
            0
        );
    }
    let sealed = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.seal_build_in(tx, request.id, 3).await })
            })
            .await,
    );
    assert!(sealed.input_sealed);
    let mut ready = false;
    for _ in 0..2 {
        ready = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_difference_in(tx, request.id).await })
                })
                .await,
        )
        .build
        .ready;
    }
    assert!(ready);
    let receipt = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[s.partition(&group.to_string())?])
                        .await?;
                    s.publish_build_in(tx, request.id, 0).await
                })
            })
            .await,
    );
    assert_eq!(receipt.added, 3);
    assert_eq!(receipt.group.member_count, 3);
    let replay = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.publish_build_in(tx, request.id, 0).await })
            })
            .await,
    );
    assert_eq!(receipt, replay);
    let page = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move {
                    s.build_members_in(tx, request.id, Some("device-0000001".into()), 2)
                        .await
                })
            })
            .await,
    );
    assert_eq!(page, vec!["device-0000002"]);
    let evidence = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move {
                    s.build_decisions_in(tx, request.id, Some("device-0000001".into()), 2)
                        .await
                })
            })
            .await,
    );
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].device, "device-0000002");
    assert_eq!(evidence[0].origin, DecisionOrigin::Rule);
    assert_eq!(evidence[0].decision, DecisionValue::Match);
    let changes = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.build_changes_in(tx, request.id, None, 2).await })
            })
            .await,
    );
    assert_eq!(changes.added.len(), 2);
    assert!(changes.removed.is_empty());
    assert_eq!(changes.next.as_deref(), Some("device-0000001"));

    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=group.generations"]
async fn static_patches_use_the_same_sealed_publication_and_preserve_old_sets() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    committed(runtime.local_tx_with_context(tenant(), deadline(), &s, |_, tx| Box::pin(async move {
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.groups(tenant_id,id,kind,presentation,revision,member_version,member_count,deleted,calculation_revision,asset_context) VALUES($1::uuid,$2::uuid,'static',$3,1,0,0,false,0,'endpoint')")
                .bind(tenant().to_string()).bind(group.to_string())
                .bind(serde_json::json!({"name":"static-paged","description":""}))
                .execute(c).await?;
            Ok(())
        })).await?;
        Ok(Ok(()))
    })).await);
    let mut current = s.get(group, deadline()).await.unwrap().unwrap();
    let mut previous = None;
    for (add, remove) in [
        (vec!["a".into(), "b".into()], vec![]),
        (vec!["c".into()], vec!["a".into()]),
    ] {
        let request = BuildRequest {
            sources: vec![],
            id: op(),
            group,
            expected: current.revision,
            base_calculation: current.calculation_revision,
            changed_devices: None,
            rule_version: None,
            patch: Some(MemberPatch { add, remove }),
            input_version: format!("members-{}", current.revision.get()),
            as_of: at(),
        };
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                    Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
                })
                .await,
        );
        if previous.is_none() {
            s.execute(
                op(),
                at(),
                &Command::Edit {
                    group,
                    expected: current.revision,
                    presentation:
                        serde_json::json!({"name":"renamed after acceptance","description":""})
                            .as_object()
                            .unwrap()
                            .clone(),
                },
                deadline(),
            )
            .await
            .unwrap();
        }
        let staged = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_static_in(tx, request.id).await })
                })
                .await,
        );
        assert!(staged.input_sealed);
        let ready = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_difference_in(tx, request.id).await })
                })
                .await,
        );
        assert!(ready.build.ready);
        let before = affected(&runtime, &s, vec!["a".into()], None, 33).await;
        assert_eq!(
            before.contains(&group),
            previous.is_some(),
            "unpublished changes leaked"
        );
        let published = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(&group.to_string())?])
                            .await?;
                        s.publish_build_in(tx, request.id, 0).await
                    })
                })
                .await,
        );
        assert_eq!(
            published,
            builds::publish(&runtime, &s, &request).await.unwrap()
        );
        if let Some(old) = previous {
            assert_eq!((published.added, published.removed), (1, 1));
            let old_members = committed(
                runtime
                    .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                        Box::pin(async move { s.build_members_in(tx, old, None, 1000).await })
                    })
                    .await,
            );
            assert_eq!(old_members, vec!["a", "b"]);
            let members = committed(
                runtime
                    .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                        Box::pin(
                            async move { s.build_members_in(tx, request.id, None, 1000).await },
                        )
                    })
                    .await,
            );
            assert_eq!(members, vec!["b", "c"]);
        }
        let after = affected(&runtime, &s, vec!["a".into()], None, 33).await;
        assert_eq!(
            after.contains(&group),
            previous.is_none(),
            "latest published removal ignored"
        );
        assert!(
            affected(&runtime, &s, vec!["b".into()], Some(group), 33)
                .await
                .is_empty()
        );
        let stored_rows = runtime.local_tx_with_context(tenant(), deadline(), &s, |_, tx|Box::pin(async move {
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid")
                    .bind(tenant().to_string()).bind(request.id.to_string()).fetch_one(c).await
            })).await
        })).await.fold(|v|v,|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"));
        assert_eq!(
            stored_rows, 0,
            "static membership must reuse immutable changes instead of copying unchanged devices"
        );
        current = published.group;
        previous = Some(request.id);
    }
    // The same published set also proves a borrowed delete rolls back its receipt and event.
    let deletion = op();
    let delete = Command::Delete {
        group,
        expected: current.revision,
    };
    let attempt = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &delete), |ctx, tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[ctx.0.partition(&ctx.1.group().to_string())?])
                    .await?;
                ctx.0.execute_in(tx, deletion, at(), ctx.1).await?.unwrap();
                Err::<(), _>(PgError::from(sqlx::Error::RowNotFound))
            })
        })
        .await;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(!s.get(group, deadline()).await.unwrap().unwrap().deleted);
    let effects = runtime.local_tx_with_context(tenant(), deadline(), &s, |_, tx| Box::pin(async move {
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as::<_, (i64, i64)>("SELECT (SELECT count(*) FROM mdm_group.operations WHERE tenant_id=$1::uuid AND id=$2::uuid), (SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$3)")
                .bind(tenant().to_string()).bind(deletion.to_string()).bind(format!("group.changed.v1:{deletion}")).fetch_one(c).await
        })).await
    })).await.fold(|v|v,|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"));
    assert_eq!(effects, (0, 0));
    let foreign_store = store(runtime.clone(), foreign()).await;
    assert!(
        affected(&runtime, &foreign_store, vec!["b".into()], None, 33)
            .await
            .is_empty()
    );
    for (devices, limit) in [(vec![], 0), (vec![], 1001)] {
        let result = runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(
                    async move { s.affected_groups_in(tx, &devices, false, None, limit).await },
                )
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
        assert_eq!(result, Err(Rejection::InvalidInput));
    }
    runtime.close().await;
}

async fn affected(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    store: &GroupStore,
    devices: Vec<String>,
    after: Option<GroupId>,
    limit: usize,
) -> Vec<GroupId> {
    committed(
        runtime
            .local_tx_with_context(store.tenant(), deadline(), store, |s, tx| {
                Box::pin(async move {
                    s.affected_groups_in(tx, &devices, false, after, limit)
                        .await
                })
            })
            .await,
    )
}

#[path = "support/builds.rs"]
mod builds;
#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.generations"]
async fn durable_recalculation_no_change_fences_stale_run() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let (rule, page) = inputs();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group: id,
                presentation: serde_json::json!({"name":"dynamic","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let first = builds::request(&created, None);
    let stale = builds::request(&created, None);
    builds::prepare(&runtime, &s, &first, &page).await.unwrap();
    builds::prepare(&runtime, &s, &stale, &page).await.unwrap();
    let published = builds::publish(&runtime, &s, &first).await.unwrap();
    assert_eq!(published.group.member_count, 1);
    assert!(matches!(
        builds::publish(&runtime, &s, &stale).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::VersionConflict
        ))
    ));
    let next = builds::request(&published, None);
    let stale_nochange = builds::request(&published, None);
    builds::prepare(&runtime, &s, &next, &page).await.unwrap();
    builds::prepare(&runtime, &s, &stale_nochange, &page)
        .await
        .unwrap();
    let unchanged = builds::publish(&runtime, &s, &next).await.unwrap();
    assert_eq!(
        unchanged.group.member_version,
        published.group.member_version
    );
    assert_eq!((unchanged.added, unchanged.removed), (0, 0));
    assert_eq!(unchanged.group.revision, published.group.revision);
    assert!(unchanged.group.calculation_revision > published.group.calculation_revision);
    assert!(matches!(
        builds::publish(&runtime, &s, &stale_nochange).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::VersionConflict
        ))
    ));
    assert_eq!(
        builds::members(&runtime, &s, first.id).await.unwrap(),
        vec!["device-1"]
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.generations"]
async fn delta_evaluates_only_changed_devices_and_preserves_old_results() {
    let runtime = connect_runtime().await;
    let store = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let (rule, mut page) = inputs();
    let mut second = page.objects[0].clone();
    second.key = ObjectKey::new(tenant(), "device-2").unwrap();
    page.objects.push(second);
    let created = store
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group: id,
                presentation: serde_json::json!({"name":"delta","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let full = builds::request(&created, None);
    builds::prepare(&runtime, &store, &full, &page)
        .await
        .unwrap();
    let published = builds::publish(&runtime, &store, &full).await.unwrap();
    let mut delta = builds::request(&published, None);
    delta.changed_devices = Some(vec!["device-2".into()]);
    page.objects.remove(0);
    let built = builds::prepare(&runtime, &store, &delta, &page)
        .await
        .unwrap();
    assert_eq!(built.processed, 1);
    assert_eq!(built.objects, 2);
    let same = builds::publish(&runtime, &store, &delta).await.unwrap();
    assert_eq!(same.group.member_count, 2);
    assert_eq!(same.group.revision, published.group.revision);
    assert_eq!(same.group.member_version, published.group.member_version);
    assert_eq!(
        builds::members(&runtime, &store, delta.id).await.unwrap(),
        vec!["device-1", "device-2"]
    );
    assert_eq!(
        builds::members(&runtime, &store, full.id).await.unwrap(),
        vec!["device-1", "device-2"]
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=group.generations"]
async fn frozen_group_decisions_survive_page_restart_without_negating_unknown() {
    use std::collections::BTreeMap;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (rule, mut source_page) = inputs();
    let source = group_id();
    let mut missing = source_page.objects[0].clone();
    missing.key = ObjectKey::new(tenant(), "device-2").unwrap();
    missing
        .contexts
        .get_mut("default")
        .unwrap()
        .get_mut("model")
        .unwrap()
        .state = FactState::Conflict;
    let mut negative = source_page.objects[0].clone();
    negative.key = ObjectKey::new(tenant(), "device-3").unwrap();
    negative
        .contexts
        .get_mut("default")
        .unwrap()
        .get_mut("model")
        .unwrap()
        .state = FactState::Known(Value::Scalar(Scalar::String("desktop".into())));
    source_page.objects.extend([missing, negative]);
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: source,
                presentation: serde_json::json!({"name":"source","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                asset_context: AssetContext::Endpoint,
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let source_request = builds::request(&created, None);
    builds::prepare(&runtime, &s, &source_request, &source_page)
        .await
        .unwrap();
    let published = builds::publish(&runtime, &s, &source_request)
        .await
        .unwrap();
    let keys: Vec<_> = source_page
        .objects
        .iter()
        .map(|o| o.key.id().to_string())
        .collect();
    let decisions = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &keys), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .source_decisions_in(tx, source_request.id, ctx.1)
                        .await
                })
            })
            .await,
    );
    assert_eq!(decisions["device-1"], Outcome::Match);
    assert_eq!(
        decisions["device-2"],
        Outcome::Unknown(UnknownReason::Conflict)
    );
    assert_eq!(decisions["device-3"], Outcome::NoMatch);
    let id = group_id();
    let rule = Rule::new(
        tenant(),
        "nested-rule",
        "dictionary-1",
        vec![],
        Criteria::membership(source.to_string(), true).unwrap(),
    )
    .unwrap();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                presentation: serde_json::json!({"name":"nested","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                asset_context: AssetContext::Endpoint,
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let mut request = builds::request(&created, None);
    request.sources = vec![GroupSource {
        group: source,
        coordinates: SourceCoordinates {
            member_set: Some(source_request.id),
            member_version: published.group.member_version as u64,
            definition_version: 1,
            authority_version: 0,
            asset_context: AssetContext::Endpoint,
        },
    }];
    builds::begin(&runtime, &s, &request).await.unwrap();
    let objects: Vec<_> = keys
        .iter()
        .map(|key| {
            let mut o =
                ObjectSnapshot::single(ObjectKey::new(tenant(), key).unwrap(), BTreeMap::new());
            o.memberships.insert(source.to_string(), decisions[key]);
            o
        })
        .collect();
    let coverage = std::collections::BTreeSet::new();
    for (start, end) in [(0, 1), (1, 3)] {
        let reloaded = store(runtime.clone(), tenant()).await;
        let recovered = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &reloaded, |s, tx| {
                    Box::pin(async move { s.build_in(tx, request.id).await })
                })
                .await,
        );
        assert_eq!(recovered.request.sources, request.sources);
        let page = PageInput {
            tenant: tenant(),
            id: "fixture",
            version: &request.input_version,
            dictionary_version: "dictionary-1",
            coverage: &coverage,
            objects: &objects[start..end],
            after: if start == 0 {
                None
            } else {
                Some(&objects[start - 1].key)
            },
        };
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&reloaded, &page), |ctx, tx| {
                    Box::pin(async move { ctx.0.append_build_page_in(tx, request.id, ctx.1).await })
                })
                .await,
        );
        assert_eq!(
            committed(
                runtime
                    .local_tx_with_context(tenant(), deadline(), &reloaded, |s, tx| Box::pin(
                        async move { s.current_member_set_in(tx, id).await }
                    ))
                    .await
            ),
            None
        );
    }
    let sealed = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.seal_build_in(tx, request.id, 3).await })
            })
            .await,
    );
    builds::resume(&runtime, &s, sealed, &FixturePage { coverage, objects })
        .await
        .unwrap();
    let result = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(result.group.member_count, 1);
    assert_eq!(
        builds::members(&runtime, &s, request.id).await.unwrap(),
        vec!["device-3".to_string()]
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=group.generations: system selectors reuse durable paged member generations"]
async fn system_members_publish_two_pages_and_keep_selector_immutable() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: AssetContext::Endpoint,
                group,
                presentation: serde_json::json!({"name":"system","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::System(SystemSelector::AllActive),
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = builds::request(&created, None);
    builds::begin(&runtime, &s, &request).await.unwrap();
    for (start, count) in [(0, 1000), (1000, 1)] {
        let decisions: Vec<_> = (start..start + count)
            .map(|i| DecisionRecord {
                device: format!("system-{i:07}"),
                origin: DecisionOrigin::System,
                decision: DecisionValue::Match,
                explanations: vec![],
                provenance: vec![],
            })
            .collect();
        let after = (start > 0).then(|| format!("system-{:07}", start - 1));
        for _ in 0..2 {
            committed(
                runtime
                    .local_tx_with_context(
                        tenant(),
                        deadline(),
                        (&s, &decisions, &after),
                        |ctx, tx| {
                            Box::pin(async move {
                                ctx.0
                                    .append_system_page_in(tx, request.id, ctx.2.as_deref(), ctx.1)
                                    .await
                            })
                        },
                    )
                    .await,
            );
        }
    }
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.seal_build_in(tx, request.id, 1001).await })
            })
            .await,
    );
    for _ in 0..2 {
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_difference_in(tx, request.id).await })
                })
                .await,
        );
    }
    let published = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(published.added, 1001);
    assert_eq!(
        published.group.system_selector,
        Some(SystemSelector::AllActive)
    );
    assert_eq!(
        builds::publish(&runtime, &s, &request).await.unwrap(),
        published
    );
    let (rule, _) = inputs();
    let altered = s
        .execute(
            op(),
            at(),
            &Command::SetRule {
                group,
                expected: published.group.revision,
                rule,
            },
            deadline(),
        )
        .await;
    assert!(altered.is_err());
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=group.generations"]
async fn authority_only_publication_has_one_event_and_replay_keeps_original_coordinate() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                asset_context: AssetContext::Endpoint,
                presentation: serde_json::json!({"name":"authority","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.register_source_in(tx, group, 1).await })
            })
            .await,
    );
    let request = builds::request(
        &created,
        Some(MemberPatch {
            add: vec![],
            remove: vec![],
        }),
    );
    builds::prepare(
        &runtime,
        &s,
        &request,
        &FixturePage {
            coverage: Default::default(),
            objects: vec![],
        },
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let receipt = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &request), |(s, r), tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(&group.to_string())?])
                            .await?;
                        s.publish_build_in(tx, r.id, 7).await
                    })
                })
                .await,
        );
        assert_eq!(receipt.group.revision.get(), 1);
        assert_eq!(receipt.group.member_version, 0);
    }
    let rejected = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &request), |(s, r), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(&group.to_string())?])
                    .await?;
                s.publish_build_in(tx, r.id, 8).await
            })
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
    assert_eq!(rejected.unwrap_err(), Rejection::IdentityConflict);
    let source = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.capture_source_in(tx, group).await })
            })
            .await,
    );
    assert_eq!(source.coordinates.authority_version, 7);
    assert_eq!(source.coordinates.member_version, 0);
    let id = format!("group.changed.v1:{}", request.id);
    let envelopes:Vec<serde_json::Value>=committed(runtime.local_tx(tenant(),deadline(),move |tx|Box::pin(async move{
        let tenant=tenant().to_string();
        Ok(Ok(tx.with_connection(move |c|Box::pin(async move{
            sqlx::query_scalar("SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2")
                .bind(tenant).bind(id).fetch_all(c).await
        })).await?))
    })).await);
    assert_eq!(envelopes.len(), 1);
    let payload: Vec<u8> = serde_json::from_value(envelopes[0]["payload"].clone()).unwrap();
    let event: GroupChanged = serde_json::from_slice(&payload).unwrap();
    assert!(matches!(event.kind, GroupChangeKind::AuthorityChanged));
    assert_eq!(event.authority_version, 7);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=group.generations"]
async fn authored_rule_blocks_old_result_but_ordinary_input_keeps_frozen_result() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let (rule, page) = inputs();
    let view = rule.view();
    let replacement = Rule::new(
        tenant(),
        "rule-2",
        view.dictionary_version,
        view.fields.values().cloned().collect(),
        view.criteria.clone(),
    )
    .unwrap();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                asset_context: AssetContext::Endpoint,
                presentation: serde_json::json!({"name":"source-rule","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.register_source_in(tx, group, 1).await })
            })
            .await,
    );
    let first = builds::request(&created, None);
    builds::prepare(&runtime, &s, &first, &page).await.unwrap();
    let published = builds::publish(&runtime, &s, &first).await.unwrap();
    let frozen = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.capture_source_in(tx, group).await })
            })
            .await,
    );
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &frozen), |(s, frozen), tx| {
                Box::pin(async move {
                    s.require_input_in(tx, group, 99).await?.unwrap();
                    assert!(s.source_current_in(tx, frozen).await?.unwrap());
                    Ok(Ok(()))
                })
            })
            .await,
    );
    let changed = s
        .execute(
            op(),
            at(),
            &Command::SetRule {
                group,
                expected: published.group.revision,
                rule: replacement,
            },
            deadline(),
        )
        .await
        .unwrap();
    let pending = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &frozen), |(s, frozen), tx| {
                Box::pin(async move {
                    s.register_source_in(tx, group, changed.group.revision.get() as u64)
                        .await?
                        .unwrap();
                    assert!(!s.source_current_in(tx, frozen).await?.unwrap());
                    let pending = s.capture_source_in(tx, group).await?.unwrap();
                    assert!(!s.source_current_in(tx, &pending).await?.unwrap());
                    assert!(!s.source_ready_in(tx, &pending).await?.unwrap());
                    Ok(Ok(pending))
                })
            })
            .await,
    );
    let next = builds::request(&changed, None);
    builds::prepare(&runtime, &s, &next, &page).await.unwrap();
    builds::publish(&runtime, &s, &next).await.unwrap();
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &pending), |(s, pending), tx| {
                Box::pin(async move {
                    assert_eq!(
                        s.source_ready_in(tx, pending).await?,
                        Err(Rejection::VersionConflict)
                    );
                    let current = s.capture_source_in(tx, group).await?.unwrap();
                    assert!(s.source_current_in(tx, &current).await?.unwrap());
                    Ok(Ok(()))
                })
            })
            .await,
    );
    runtime.close().await;
}
