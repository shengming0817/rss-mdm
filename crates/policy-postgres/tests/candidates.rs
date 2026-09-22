use rss_mdm_policy_postgres::{core::*, *};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;
fn committed<T>(attempt: LocalTxAttempt<std::result::Result<T, Rejection>, PgError>) -> T {
    attempt.fold(
        |r| r.unwrap(),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    )
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn paged_candidate_save_preserves_execution_facts_and_source_invalidation() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let policy = PolicyId::new(tenant(), unique()).unwrap();
    s.execute(
        &Request {
            id: RequestId::new(tenant(), unique()).unwrap(),
            expected_storage_revision: 0,
            as_of: at(1),
            command: Command::Create {
                policy: policy.clone(),
            },
        },
        deadline(),
    )
    .await
    .unwrap();
    let version = Version::new(
        policy.clone(),
        1,
        PayloadRef::new(PayloadId::new(tenant(), unique()).unwrap(), 1, [1; 32]).unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    s.execute(
        &Request {
            id: RequestId::new(tenant(), unique()).unwrap(),
            expected_storage_revision: 1,
            as_of: at(2),
            command: Command::Transition {
                policy: policy.clone(),
                transition: Transition::Activate(version),
            },
        },
        deadline(),
    )
    .await
    .unwrap();
    let reference = format!("scope-{}", unique());
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &reference), |ctx, tx| {
                Box::pin(async move { ctx.0.advance_reference_in(tx, ctx.1, 1).await })
            })
            .await,
    );
    let request = CandidateRequest {
        id: RequestId::new(tenant(), unique()).unwrap(),
        policy: policy.clone(),
        expected_revision: 2,
        targets: TargetSnapshotId::new(tenant(), unique()).unwrap(),
        target_revision: 1,
        references: vec![AssignmentReference {
            id: reference.clone(),
            revision: 1,
        }],
        as_of: at(3),
    };
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_candidate_in(tx, ctx.1).await })
            })
            .await,
    );
    for (start, count) in [(0, 1000), (1000, 1)] {
        for _ in 0..2 {
            let progress = committed(
                runtime
                    .local_tx_with_context(
                        tenant(),
                        deadline(),
                        (&s, &request.id),
                        move |ctx, tx| {
                            Box::pin(async move {
                                let devices: Vec<_> = (start..start + count)
                                    .map(|i| {
                                        DeviceId::new(tenant(), format!("device-{i:07}")).unwrap()
                                    })
                                    .collect();
                                let after = if start == 0 {
                                    None
                                } else {
                                    Some(
                                        DeviceId::new(tenant(), format!("device-{:07}", start - 1))
                                            .unwrap(),
                                    )
                                };
                                ctx.0
                                    .append_candidate_targets_in(
                                        tx,
                                        ctx.1,
                                        after.as_ref(),
                                        &devices,
                                    )
                                    .await
                            })
                        },
                    )
                    .await,
            );
            assert_eq!(progress.target_count, (start + count) as u64);
        }
    }
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request.id), |ctx, tx| {
                Box::pin(async move { ctx.0.seal_candidate_targets_in(tx, ctx.1, 1001).await })
            })
            .await,
    );
    let ready = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request.id), |ctx, tx| {
                Box::pin(async move { ctx.0.advance_candidate_facts_in(tx, ctx.1).await })
            })
            .await,
    );
    assert_eq!(ready.phase, CandidatePhase::Ready);
    let targets = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request.id), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .candidate_targets_in(tx, ctx.1, Some("device-0000999".into()), 1000)
                        .await
                })
            })
            .await,
    );
    assert_eq!(targets, vec!["device-0001000"]);
    let intents = committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &request.id), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .candidate_intents_in(
                            tx,
                            ctx.1,
                            IntentKind::Add,
                            Some(IntentPosition {
                                device: "device-0000999".into(),
                                execution: String::new(),
                            }),
                            1000,
                        )
                        .await
                })
            })
            .await,
    );
    assert_eq!(intents.len(), 1);
    assert!(
        matches!(&intents[0].intent,CandidateIntent::Desired {device,version:1,supersedes:false} if device.value()=="device-0001000")
    );

    assert!(
        s.get(&policy, deadline())
            .await
            .unwrap()
            .unwrap()
            .current_plan_id()
            .is_none()
    );
    let operation = RequestId::new(tenant(), unique()).unwrap();
    for _ in 0..2 {
        let saved = committed(
            runtime
                .local_tx_with_context(
                    tenant(),
                    deadline(),
                    (&s, &request.id, &operation, &policy),
                    |ctx, tx| {
                        Box::pin(async move {
                            tx.prepare_outbox_partitions(&[ctx.0.partition(ctx.3.value())?])
                                .await?;
                            ctx.0.save_candidate_in(tx, ctx.2, ctx.1, 2, at(4)).await
                        })
                    },
                )
                .await,
        );
        assert_eq!(saved.storage_revision, 3);
    }
    assert!(
        s.get(&policy, deadline())
            .await
            .unwrap()
            .unwrap()
            .plan_is_fresh()
    );
    assert!(
        s.execution_facts(&policy, None, 1000, deadline())
            .await
            .unwrap()
            .records
            .is_empty()
    );
    committed(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &reference), |ctx, tx| {
                Box::pin(async move { ctx.0.advance_reference_in(tx, ctx.1, 2).await })
            })
            .await,
    );
    assert!(
        !s.get(&policy, deadline())
            .await
            .unwrap()
            .unwrap()
            .plan_is_fresh()
    );
    runtime.close().await;
}
