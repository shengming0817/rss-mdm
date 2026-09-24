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
#[ignore = "real PostgreSQL: group-t2"]
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
                group,
                name: "paged".into(),
                description: String::new(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = BuildRequest {
        id: op(),
        group,
        expected: created.group.revision,
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
    for (start, count) in [(0, 1000), (1000, 1)] {
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
                Box::pin(async move { s.seal_build_in(tx, request.id, 1001).await })
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
                    s.publish_build_in(tx, request.id).await
                })
            })
            .await,
    );
    assert_eq!(receipt.added, 1001);
    assert_eq!(receipt.group.member_count, 1001);
    let replay = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.publish_build_in(tx, request.id).await })
            })
            .await,
    );
    assert_eq!(receipt, replay);
    let page = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move {
                    s.build_members_in(tx, request.id, Some("device-0000999".into()), 1000)
                        .await
                })
            })
            .await,
    );
    assert_eq!(page, vec!["device-0001000"]);
    let evidence = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move {
                    s.build_decisions_in(tx, request.id, Some("device-0000999".into()), 1000)
                        .await
                })
            })
            .await,
    );
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].device, "device-0001000");
    assert_eq!(evidence[0].origin, DecisionOrigin::Rule);
    assert_eq!(evidence[0].decision, DecisionValue::Match);
    let changes = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.build_changes_in(tx, request.id, None, 1000).await })
            })
            .await,
    );
    assert_eq!(changes.added.len(), 1000);
    assert!(changes.removed.is_empty());
    assert_eq!(changes.next.as_deref(), Some("device-0000999"));

    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: group-t2"]
async fn static_patches_use_the_same_sealed_publication_and_preserve_old_sets() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let mut current = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                name: "static-paged".into(),
                description: String::new(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let mut previous = None;
    for (add, remove) in [
        (vec!["a".into(), "b".into()], vec![]),
        (vec!["c".into()], vec!["a".into()]),
    ] {
        let request = BuildRequest {
            id: op(),
            group,
            expected: current.group.revision,
            rule_version: None,
            patch: Some(MemberPatch { add, remove }),
            input_version: format!("members-{}", current.group.revision.get()),
            as_of: at(),
        };
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                    Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
                })
                .await,
        );
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
        current = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(&group.to_string())?])
                            .await?;
                        s.publish_build_in(tx, request.id).await
                    })
                })
                .await,
        );
        if let Some(old) = previous {
            assert_eq!((current.added, current.removed), (1, 1));
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
                .iter()
                .all(|id| *id > group)
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
        previous = Some(request.id);
    }
    execute_companion(
        &runtime,
        &s,
        op(),
        &Command::Delete {
            group,
            expected: current.group.revision,
        },
    )
    .await
    .unwrap();
    assert!(
        !affected(&runtime, &s, vec!["b".into()], None, 33)
            .await
            .contains(&group)
    );
    let foreign_store = store(runtime.clone(), foreign()).await;
    assert!(
        affected(&runtime, &foreign_store, vec!["b".into()], None, 33)
            .await
            .is_empty()
    );
    for (devices, limit) in [(vec!["b".into(); 1001], 1), (vec![], 0), (vec![], 1001)] {
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
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn static_commands_replay_and_borrowed_rollback() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let create = Command::Create {
        group: id,
        name: "研发".into(),
        description: String::new(),
        definition: Definition::Static,
    };
    let operation = op();
    let first = s
        .execute(operation, at(), &create, deadline())
        .await
        .unwrap();
    assert_eq!(
        first,
        s.execute(operation, at(), &create, deadline())
            .await
            .unwrap()
    );
    let r = builds::request(
        &first,
        Some(MemberPatch {
            add: vec!["a".into(), "a".into(), "b".into()],
            remove: vec![],
        }),
    );
    let (_, page) = inputs();
    builds::prepare(&runtime, &s, &r, &page).await.unwrap();
    let applied = builds::publish(&runtime, &s, &r).await.unwrap();
    assert_eq!((applied.added, applied.group.member_count), (2, 2));
    assert_eq!(applied, builds::publish(&runtime, &s, &r).await.unwrap());
    assert_eq!(
        builds::members(&runtime, &s, r.id).await.unwrap(),
        vec!["a", "b"]
    );
    assert!(
        store(runtime.clone(), foreign())
            .await
            .get(id, deadline())
            .await
            .unwrap()
            .is_none()
    );
    let affected = runtime
        .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
            Box::pin(async move {
                s.affected_groups_in(tx, &["a".into()], false, None, 33)
                    .await
            })
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
    assert!(affected.contains(&id));
    let delete = Command::Delete {
        group: id,
        expected: applied.group.revision,
    };
    let attempt = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &delete), |ctx, tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[ctx.0.partition(&ctx.1.group().to_string())?])
                    .await?;
                ctx.0.execute_in(tx, op(), at(), ctx.1).await?.unwrap();
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
    assert!(!s.get(id, deadline()).await.unwrap().unwrap().deleted);
    let unchanged = s
        .execute(
            op(),
            at(),
            &Command::Edit {
                group: id,
                expected: applied.group.revision,
                name: "研发".into(),
                description: String::new(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.group.revision, applied.group.revision);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
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
                group: id,
                name: "dynamic".into(),
                description: String::new(),
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
    builds::prepare(&runtime, &s, &next, &page).await.unwrap();
    let unchanged = builds::publish(&runtime, &s, &next).await.unwrap();
    assert_eq!(
        unchanged.group.member_version,
        published.group.member_version
    );
    assert_eq!((unchanged.added, unchanged.removed), (0, 0));
    assert!(unchanged.group.revision.get() > published.group.revision.get());
    assert_eq!(
        builds::members(&runtime, &s, first.id).await.unwrap(),
        vec!["device-1"]
    );
    runtime.close().await;
}
