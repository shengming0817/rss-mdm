//! Independent consumer: immutable pages and explicit host transactions only.
use rss_mdm_group_postgres::*;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;
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
        Err(Error::Rejected(Rejection::VersionConflict))
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
