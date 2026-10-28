//! Real Group event, fixed Scope receiver and RSS settlement in one database.
use super::*;
use crate::planning::test_support::{
    GroupChange, GroupCommand, group_operation, planning, seed_group, sql, tenant,
};
use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;

#[tokio::test]
#[ignore = "MODULE=groups.delivery: real local projection and unknown commit recovery"]
async fn unknown_commit_preserves_one_scope_request_and_original_receipt() {
    let service = planning(tenant()).await;
    let config = crate::test_support::identity::config(&tenant().to_string()).unwrap();
    let delivery = Delivery::open(&config, config.native_protector().unwrap(), Arc::default())
        .await
        .unwrap();
    let group = uuid::Uuid::new_v4();
    let change = group_operation(
        0,
        GroupChange::Create {
            asset_context: rss_mdm_group::AssetContext::Endpoint,
            presentation: serde_json::json!({"name":"local-scope-delivery","description":""})
                .as_object()
                .unwrap()
                .clone(),
            criteria: None,
        },
    );
    let event = format!("group.changed.v1:{}", change.operation_id);
    seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(change),
        },
    )
    .await
    .unwrap();
    delivery
        .projection
        .inject_next_projection_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            std::future::ready(()),
        )
        .unwrap();
    let batch = delivery
        .projection
        .project_batch(
            &delivery.validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(6),
        )
        .await
        .unwrap();
    tokio::pin!(batch);
    let item = batch
        .next()
        .await
        .expect("created Group event")
        .into_outcome()
        .unwrap();
    let PgProjectionOutcome::Attempt(attempt) = item else {
        panic!("expected consumer transaction");
    };
    let (outcome, recovery) = attempt.into_parts();
    assert_eq!(outcome.status(), Status::CommitUnknown);
    let state = || {
        sql(&format!(
            "SELECT (SELECT count(*) FROM mdm_scope.group_changes WHERE tenant_id='{t}' AND event_id='{event}' AND group_id='{group}' AND NOT completed),(SELECT disposition FROM rss_transactional_messaging.inbox WHERE tenant_id='{t}' AND message_id='{event}' AND consumer_group='{CONSUMER}'),(SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id='{t}' AND message_id='{event}')",
            t = tenant()
        ))
    };
    assert_eq!(state(), "1|succeeded|published");
    for _ in 0..2 {
        let receipt = delivery
            .projection
            .resolve(&recovery, deadline())
            .await
            .unwrap()
            .expect("original committed receipt");
        assert_eq!(
            receipt.disposition(),
            rss_transactional_messaging::transaction::TerminalDisposition::Succeeded
        );
        assert_eq!(state(), "1|succeeded|published");
    }
    assert!(batch.next().await.is_none());
    let next = delivery
        .projection
        .project_batch(
            &delivery.validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(6),
        )
        .await
        .unwrap();
    tokio::pin!(next);
    assert!(
        next.next().await.is_none(),
        "settled source must not schedule a second effect"
    );
    let denied = delivery
        .runtime
        .local_tx(tenant(), deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("UPDATE mdm_group.groups SET deleted=true")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await;
    assert!(
        denied.fold(
            |_| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false,
            |_| false
        ),
        "consumer role must not mutate Group"
    );
    delivery.runtime.close().await;
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "MODULE=groups.delivery: producer and consumer share bigint event counts"]
async fn large_group_delete_event_is_accepted_without_a_business_count_cap() {
    let service = planning(tenant()).await;
    let config = crate::test_support::identity::config(&tenant().to_string()).unwrap();
    let delivery = Delivery::open(&config, config.native_protector().unwrap(), Arc::default())
        .await
        .unwrap();
    let group = uuid::Uuid::new_v4();
    seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: serde_json::json!({"name":"count-boundary","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: None,
                },
            )),
        },
    )
    .await
    .unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    assert!(delivery.poll(&cancel).await.is_ok());
    // This is a count-contract boundary, not a scale or membership proof.
    // The real producer reads the legal stored bigint and emits the deletion fact.
    sql(&format!(
        "UPDATE mdm_group.groups SET member_count=1000001 WHERE tenant_id='{}' AND id='{group}'",
        tenant()
    ));
    let change = group_operation(1, GroupChange::Delete);
    let event = format!("group.changed.v1:{}", change.operation_id);
    seed_group(
        &service,
        &GroupCommand::Group {
            id: group,
            change: Box::new(change),
        },
    )
    .await
    .unwrap();
    assert!(
        delivery.poll(&cancel).await.is_ok(),
        "legal producer event must not become a dead letter"
    );
    assert_eq!(
        sql(&format!(
            "SELECT (SELECT count(*) FROM mdm_scope.group_changes WHERE tenant_id='{t}' AND event_id='{event}'),(SELECT disposition FROM rss_transactional_messaging.inbox WHERE tenant_id='{t}' AND message_id='{event}' AND consumer_group='{CONSUMER}'),(SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id='{t}' AND message_id='{event}')",
            t = tenant()
        )),
        "1|succeeded|published"
    );
    delivery.runtime.close().await;
    service.runtime.close().await;
}
