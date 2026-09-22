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
    runtime.close().await;
}
