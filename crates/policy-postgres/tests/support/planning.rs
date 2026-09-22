//! Consumer-owned transaction orchestration over the public candidate API.
use super::support::{at, deadline, tenant, unique};
use rss_mdm_policy_postgres::{core::*, *};
use rss_transactional_messaging::{policy::OperationDeadline, transaction::LocalTxAttempt};
use rss_transactional_messaging_postgres::{PgError, PgRuntime};
pub fn settle<T>(attempt: LocalTxAttempt<Result<T, Rejection>, PgError>) -> Result<T, Error> {
    attempt.fold(
        |v| v.map_err(Error::Rejected),
        |e| Err(Error::NotStarted(e)),
        |e| Err(Error::RolledBack(e)),
        |e| Err(Error::RollbackFailed(e)),
        |e| Err(Error::CommitUnknown(e)),
        |e| Err(Error::Fenced(e)),
    )
}
pub async fn prepare(
    runtime: &PgRuntime,
    store: &PolicyStore,
    policy: &PolicyId,
    expected: u64,
    members: &[&str],
) -> RequestId {
    let request = CandidateRequest {
        id: RequestId::new(tenant(), unique()).unwrap(),
        policy: policy.clone(),
        expected_revision: expected,
        targets: TargetSnapshotId::new(tenant(), unique()).unwrap(),
        target_revision: 1,
        references: vec![],
        as_of: at(10),
    };
    settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (store, &request), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_candidate_in(tx, ctx.1).await })
            })
            .await,
    )
    .unwrap();
    let mut keys: Vec<_> = members
        .iter()
        .map(|v| DeviceId::new(tenant(), *v).unwrap())
        .collect();
    keys.sort();
    keys.dedup();
    let mut after = None;
    for page in keys.chunks(1000) {
        settle(
            runtime
                .local_tx_with_context(
                    tenant(),
                    deadline(),
                    (store, &request.id, page, &after),
                    |ctx, tx| {
                        Box::pin(async move {
                            ctx.0
                                .append_candidate_targets_in(tx, ctx.1, ctx.3.as_ref(), ctx.2)
                                .await
                        })
                    },
                )
                .await,
        )
        .unwrap();
        after = page.last().cloned();
    }
    settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (store, &request.id), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .seal_candidate_targets_in(tx, ctx.1, keys.len() as u64)
                        .await
                })
            })
            .await,
    )
    .unwrap();
    loop {
        let progress = settle(
            runtime
                .local_tx_with_context(tenant(), deadline(), (store, &request.id), |ctx, tx| {
                    Box::pin(async move { ctx.0.advance_candidate_facts_in(tx, ctx.1).await })
                })
                .await,
        )
        .unwrap();
        if progress.phase == CandidatePhase::Ready {
            break;
        }
    }
    request.id
}
pub async fn save(
    runtime: &PgRuntime,
    store: &PolicyStore,
    policy: &PolicyId,
    operation: &RequestId,
    candidate: &RequestId,
    expected: u64,
    deadline: OperationDeadline,
) -> Result<Receipt, Error> {
    settle(
        runtime
            .local_tx_with_context(
                tenant(),
                deadline,
                (store, policy, operation, candidate),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[ctx.0.partition(ctx.1.value())?])
                            .await?;
                        ctx.0
                            .save_candidate_in(tx, ctx.2, ctx.3, expected, at(10))
                            .await
                    })
                },
            )
            .await,
    )
}
