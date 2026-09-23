//! Real PostgreSQL capacity, including more execution records than current devices.
#![allow(
    clippy::disallowed_methods,
    reason = "capacity measurements use elapsed wall time"
)]
use rss_mdm_policy_postgres::{core::*, *};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;

fn settled<T>(value: LocalTxAttempt<Result<T, Rejection>, PgError>) -> Result<T, Rejection> {
    value.fold(
        |v| v,
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    )
}

#[tokio::test]
#[ignore = "actual million-device PostgreSQL capacity acceptance"]
async fn million_targets_and_multiversion_history_remain_bounded() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let policy = PolicyId::new(tenant(), unique()).unwrap();
    let started = std::time::Instant::now();
    let mut max_tx = std::time::Duration::ZERO;
    let mut transactions = 0u64;
    macro_rules! tx {
        ($context:expr, |$ctx:ident,$tx:ident| $body:expr) => {{
            let start = std::time::Instant::now();
            let result = settled(
                runtime
                    .local_tx_with_context(tenant(), deadline(), $context, |$ctx, $tx| {
                        Box::pin(async move { $body })
                    })
                    .await,
            );
            max_tx = max_tx.max(start.elapsed());
            transactions += 1;
            result
        }};
    }
    let mut revision = s
        .execute(
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
        .unwrap()
        .storage_revision;
    let mut facts_total = 0;
    // Exercise the actual independent execution writer, never the save path.
    for number in 1..=3 {
        let version = Version::new(
            policy.clone(),
            number,
            PayloadRef::new(
                PayloadId::new(tenant(), format!("payload-{number}")).unwrap(),
                1,
                [number as u8; 32],
            )
            .unwrap(),
            RemovalRule::CancelOutstandingRetainEffects,
        )
        .unwrap();
        revision = s
            .execute(
                &Request {
                    id: RequestId::new(tenant(), unique()).unwrap(),
                    expected_storage_revision: revision,
                    as_of: at(2),
                    command: Command::Transition {
                        policy: policy.clone(),
                        transition: Transition::Activate(version.clone()),
                    },
                },
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
        let count = match number {
            1 => 1_000_000,
            2 => 1000,
            _ => 0,
        };
        for start in (0..count).step_by(1000) {
            let facts = (start..start + 1000)
                .map(|n| {
                    ExecutionRecord::new(
                        version.clone(),
                        DeviceId::new(tenant(), format!("device-{n:07}")).unwrap(),
                        Progress::Running,
                        Effect::Unverified,
                    )
                    .unwrap()
                })
                .collect();
            let request = Request {
                id: RequestId::new(tenant(), unique()).unwrap(),
                expected_storage_revision: revision,
                as_of: at(2),
                command: Command::RecordExecutions {
                    policy: policy.clone(),
                    facts,
                },
            };
            revision = tx!((&s, &request), |ctx, tx| {
                tx.prepare_outbox_partitions(&[ctx.0.partition(ctx.1.policy().value())?])
                    .await?;
                ctx.0.execute_in(tx, ctx.1).await
            })
            .unwrap()
            .storage_revision;
            facts_total += 1000;
            if facts_total % 100_000 == 0 {
                eprintln!("policy capacity execution_records={facts_total}");
            }
        }
    }
    assert_eq!(facts_total, 1_001_000);
    let target_identity = TargetSnapshotId::new(tenant(), unique()).unwrap();
    let mut previous_plan = None;
    for (iteration, removed) in [0, 0, 1, 10_000, 1_000_000].into_iter().enumerate() {
        let round = std::time::Instant::now();
        let request = CandidateRequest {
            id: RequestId::new(tenant(), unique()).unwrap(),
            policy: policy.clone(),
            expected_revision: revision,
            targets: target_identity.clone(),
            target_revision: if iteration < 2 { 1 } else { iteration as u64 },
            references: vec![],
            as_of: at(3),
        };
        tx!((&s, &request), |ctx, tx| ctx
            .0
            .begin_candidate_in(tx, ctx.1)
            .await)
        .unwrap();
        let page_size = if iteration == 1 { 731 } else { 1000 };
        let mut cursor = None;
        let count = 1_000_000 - removed;
        for start in (removed..1_000_000).step_by(page_size) {
            let devices = (start..(start + page_size).min(1_000_000))
                .map(|n| DeviceId::new(tenant(), format!("device-{n:07}")).unwrap())
                .collect::<Vec<_>>();
            tx!((&s, &request.id, &devices, &cursor), |ctx, tx| ctx
                .0
                .append_candidate_targets_in(tx, ctx.1, ctx.3.as_ref(), ctx.2)
                .await)
            .unwrap();
            cursor = devices.last().cloned();
        }
        if count == 1_000_000 {
            let extra = [DeviceId::new(tenant(), "device-1000000").unwrap()];
            assert_eq!(
                tx!((&s, &request.id, &extra, &cursor), |ctx, tx| ctx
                    .0
                    .append_candidate_targets_in(tx, ctx.1, ctx.3.as_ref(), ctx.2)
                    .await)
                .unwrap_err(),
                Rejection::BudgetExceeded
            );
        }
        tx!((&s, &request.id), |ctx, tx| ctx
            .0
            .seal_candidate_targets_in(tx, ctx.1, count as u64)
            .await)
        .unwrap();
        let candidate = loop {
            let result = tx!((&s, &request.id), |ctx, tx| ctx
                .0
                .advance_candidate_facts_in(tx, ctx.1)
                .await)
            .unwrap();
            if result.phase == CandidatePhase::Ready {
                break result;
            }
        };
        assert_eq!(candidate.fact_count, 1_001_000);
        assert_eq!(candidate.target_count, count as u64);
        if iteration == 1 {
            assert_eq!(
                candidate.plan, previous_plan,
                "page size must not alter plan identity"
            );
        }
        previous_plan = candidate.plan;
        let operation = RequestId::new(tenant(), unique()).unwrap();
        revision = tx!((&s, &request.id, &operation, &policy), |ctx, tx| {
            tx.prepare_outbox_partitions(&[ctx.0.partition(ctx.3.value())?])
                .await?;
            ctx.0
                .save_candidate_in(tx, ctx.2, ctx.1, revision, at(3))
                .await
        })
        .unwrap()
        .storage_revision;
        let mut after = None;
        let mut read = 0;
        loop {
            let page = s
                .execution_facts(&policy, after, 1000, deadline())
                .await
                .unwrap();
            assert!(page.records.len() <= 1000);
            read += page.records.len();
            after = page.next;
            if after.is_none() {
                break;
            }
        }
        assert_eq!(
            read, 1_001_000,
            "saving must not create or delete execution facts"
        );
        let mut after = None;
        let mut read = 0;
        loop {
            let page = tx!((&s, &request.id, &after), |ctx, tx| ctx
                .0
                .candidate_targets_in(tx, ctx.1, ctx.2.clone(), 1000)
                .await)
            .unwrap();
            assert!(page.len() <= 1000);
            read += page.len();
            if page.is_empty() {
                break;
            }
            after = page.last().cloned();
        }
        assert_eq!(read, count);
        if iteration == 0 {
            let mut after = None;
            let mut predecessor_count = 0;
            loop {
                let predecessors = tx!((&s, &request.id, &after), |ctx, tx| ctx
                    .0
                    .candidate_intents_in(tx, ctx.1, IntentKind::Predecessors, ctx.2.clone(), 1000)
                    .await)
                .unwrap();
                assert!(predecessors.len() <= 1000);
                if predecessors.is_empty() {
                    break;
                }
                for row in &predecessors {
                    assert!(
                        matches!(&row.intent,CandidateIntent::Predecessor {execution,successor_version:3} if execution.version().number()<3)
                    );
                }
                predecessor_count += predecessors.len();
                after = predecessors.last().map(|row| row.position.clone());
            }
            assert_eq!(predecessor_count, 1_001_000);
        }
        println!(
            "{}",
            serde_json::json!({"scenario":"million_policy","iteration":iteration,"targets":count,"execution_records":facts_total,"elapsed_seconds":round.elapsed().as_secs_f64(),"max_client_transaction_seconds":max_tx.as_secs_f64(),"measured_transactions":transactions})
        );
    }
    println!(
        "{}",
        serde_json::json!({"scenario":"million_policy_total","elapsed_seconds":started.elapsed().as_secs_f64(),"max_client_transaction_seconds":max_tx.as_secs_f64(),"measured_transactions":transactions})
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_policy.facts WHERE tenant_id='{}' AND owner='{}'",
            tenant(),
            policy.value()
        )),
        "1001000"
    );
    runtime.close().await;
}
