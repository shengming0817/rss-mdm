//! Actual capacity acceptance; separate from ordinary T2 edit loops.
#![allow(
    clippy::disallowed_methods,
    reason = "capacity fixture records real elapsed durations"
)]
use rss_mdm_group_postgres::*;
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;
fn committed<T>(attempt: LocalTxAttempt<Result<T, Rejection>, PgError>) -> T {
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
#[ignore = "actual 1,000,000-device PostgreSQL capacity acceptance"]
async fn million_static_members_use_linear_storage_and_reject_one_more() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let started = std::time::Instant::now();
    let mut max_tx = std::time::Duration::ZERO;
    let mut current = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                name: "million-static".into(),
                description: String::new(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let mut last = None;
    for batch in 0..1000 {
        let request = BuildRequest {
            id: op(),
            group,
            expected: current.group.revision,
            rule_version: None,
            patch: Some(MemberPatch {
                add: (batch * 1000..(batch + 1) * 1000)
                    .map(|n| format!("device-{n:07}"))
                    .collect(),
                remove: vec![],
            }),
            input_version: "capacity-fixed-input".into(),
            as_of: at(),
        };
        let begin = std::time::Instant::now();
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                    Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
                })
                .await,
        );
        max_tx = max_tx.max(begin.elapsed());
        let begin = std::time::Instant::now();
        let staged = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_static_in(tx, request.id).await })
                })
                .await,
        );
        max_tx = max_tx.max(begin.elapsed());
        assert_eq!(staged.members, (batch + 1) * 1000);
        let begin = std::time::Instant::now();
        let diff = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_difference_in(tx, request.id).await })
                })
                .await,
        );
        max_tx = max_tx.max(begin.elapsed());
        assert!(diff.build.ready);
        assert_eq!(diff.devices.len(), 1000);
        let begin = std::time::Instant::now();
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
        max_tx = max_tx.max(begin.elapsed());
        last = Some(request.id);
        if (batch + 1) % 100 == 0 {
            eprintln!(
                "capacity static members={} elapsed_seconds={:.3}",
                (batch + 1) * 1000,
                started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(current.group.member_count, 1_000_000);
    let last = last.unwrap();
    let mut after = None;
    let mut total = 0;
    loop {
        let page = committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &after), |ctx, tx| {
                    Box::pin(
                        async move { ctx.0.build_members_in(tx, last, ctx.1.clone(), 1000).await },
                    )
                })
                .await,
        );
        assert!(page.len() <= 1000);
        if page.is_empty() {
            break;
        }
        for id in &page {
            assert_eq!(id, &format!("device-{total:07}"));
            total += 1;
        }
        after = page.last().cloned();
    }
    assert_eq!(total, 1_000_000);
    let request = BuildRequest {
        id: op(),
        group,
        expected: current.group.revision,
        rule_version: None,
        patch: Some(MemberPatch {
            add: vec!["device-1000000".into()],
            remove: vec![],
        }),
        input_version: "capacity-fixed-input".into(),
        as_of: at(),
    };
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
            })
            .await,
    );
    let overflow = runtime
        .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
            Box::pin(async move { s.advance_static_in(tx, request.id).await })
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
    assert_eq!(overflow.unwrap_err(), Rejection::CapacityExceeded);
    assert_eq!(
        s.get(group, deadline())
            .await
            .unwrap()
            .unwrap()
            .member_count,
        1_000_000
    );
    let counts=runtime.local_tx_with_context(tenant(),deadline(),&s,|_,tx|Box::pin(async move {
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(i64,i64)>("SELECT (SELECT count(*) FROM mdm_group.member_changes WHERE tenant_id=$1::uuid AND group_id=$2::uuid),(SELECT count(*) FROM mdm_group.member_rows m JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE r.tenant_id=$1::uuid AND r.group_id=$2::uuid)").bind(tenant().to_string()).bind(group.to_string()).fetch_one(c).await
        })).await
    })).await.fold(|v|v,|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"));
    assert_eq!(counts, (1_000_000, 0));
    println!(
        "{}",
        serde_json::json!({"scenario":"million_static","members":total,"immutable_changes":counts.0,"copied_rows":counts.1,"overflow_rejected":true,"elapsed_seconds":started.elapsed().as_secs_f64(),"max_client_transaction_seconds":max_tx.as_secs_f64()})
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "actual 1,000,000-device PostgreSQL capacity acceptance"]
async fn million_dynamic_members_cover_zero_single_percent_and_full_changes() {
    use rss_mdm_group_postgres::core::*;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let group = group_id();
    let (rule, sample) = inputs();
    let started = std::time::Instant::now();
    let mut current = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                name: "million-dynamic".into(),
                description: String::new(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let mut prior_removed = 0;
    for (iteration, removed) in [0, 0, 1, 10_000, 1_000_000].into_iter().enumerate() {
        let request = BuildRequest {
            id: op(),
            group,
            expected: current.group.revision,
            rule_version: Some("rule-1".into()),
            patch: None,
            input_version: format!("capacity-{iteration}"),
            as_of: at(),
        };
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                    Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
                })
                .await,
        );
        for batch in 0..1000 {
            committed(
                runtime
                    .local_tx_with_context(
                        tenant(),
                        deadline(),
                        (&s, &request, &sample),
                        |ctx, tx| {
                            Box::pin(async move {
                                let objects = (batch * 1000..(batch + 1) * 1000)
                                    .map(|n| {
                                        let mut object = ctx.2.objects[0].clone();
                                        object.key =
                                            ObjectKey::new(tenant(), format!("device-{n:07}"))
                                                .unwrap();
                                        if n < removed {
                                            object.facts.get_mut("model").unwrap().state =
                                                FactState::Known(Value::Scalar(Scalar::String(
                                                    "desktop".into(),
                                                )));
                                        }
                                        object
                                    })
                                    .collect::<Vec<_>>();
                                let after = if batch == 0 {
                                    None
                                } else {
                                    Some(
                                        ObjectKey::new(
                                            tenant(),
                                            format!("device-{:07}", batch * 1000 - 1),
                                        )
                                        .unwrap(),
                                    )
                                };
                                ctx.0
                                    .append_build_page_in(
                                        tx,
                                        ctx.1.id,
                                        &PageInput {
                                            tenant: tenant(),
                                            id: "capacity",
                                            version: &ctx.1.input_version,
                                            dictionary_version: "dictionary-1",
                                            coverage: &ctx.2.coverage,
                                            objects: &objects,
                                            after: after.as_ref(),
                                        },
                                    )
                                    .await
                            })
                        },
                    )
                    .await,
            );
        }
        // The extra object is rejected before sealing and leaves the accepted
        // million-object build intact. It is never treated as a truncated set.
        let rejected = runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request, &sample), |ctx, tx| {
                Box::pin(async move {
                    let mut object = ctx.2.objects[0].clone();
                    object.key = ObjectKey::new(tenant(), "device-1000000").unwrap();
                    let after = ObjectKey::new(tenant(), "device-0999999").unwrap();
                    ctx.0
                        .append_build_page_in(
                            tx,
                            ctx.1.id,
                            &PageInput {
                                tenant: tenant(),
                                id: "capacity",
                                version: &ctx.1.input_version,
                                dictionary_version: "dictionary-1",
                                coverage: &ctx.2.coverage,
                                objects: &[object],
                                after: Some(&after),
                            },
                        )
                        .await
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
        assert_eq!(rejected.unwrap_err(), Rejection::CapacityExceeded);
        committed(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.seal_build_in(tx, request.id, 1_000_000).await })
                })
                .await,
        );
        loop {
            let step = committed(
                runtime
                    .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                        Box::pin(async move { s.advance_difference_in(tx, request.id).await })
                    })
                    .await,
            );
            assert!(step.devices.len() <= 1000);
            if step.build.ready {
                break;
            }
        }
        let old_version = current.group.member_version;
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
        assert_eq!(current.group.member_count, 1_000_000 - removed);
        assert_eq!(current.added, if iteration == 0 { 1_000_000 } else { 0 });
        assert_eq!(current.removed, removed - prior_removed);
        if iteration == 1 {
            assert_eq!(current.group.member_version, old_version);
        }
        prior_removed = removed;
        println!(
            "{}",
            serde_json::json!({"scenario":"million_dynamic","iteration":iteration,"members":current.group.member_count,"added":current.added,"removed":current.removed,"overflow_rejected":true,"elapsed_seconds":started.elapsed().as_secs_f64()})
        );
    }
    runtime.close().await;
}
