//! Shared default-feature public consumer, run against the Group PG fixture.
use rss_mdm_group_postgres::*;
use rss_transactional_messaging_postgres::PgError;
mod support;
use support::*;
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn static_commands_replay_and_borrowed_rollback() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let create = Command::Create {
        group: id,
        name: "研发".into(),
        description: "".into(),
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
    let change = Command::Members {
        group: id,
        expected: first.group.revision,
        add: vec!["a".into(), "a".into(), "b".into()],
        remove: vec![],
    };
    let operation = op();
    let applied = s
        .execute(operation, at(), &change, deadline())
        .await
        .unwrap();
    assert_eq!((applied.added, applied.group.member_count), (2, 2));
    assert_eq!(
        applied,
        s.execute(operation, at(), &change, deadline())
            .await
            .unwrap()
    );
    assert_eq!(s.members(id, deadline()).await.unwrap().len(), 2);
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
                description: "".into(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.group, applied.group);
    let edited = s
        .execute(
            op(),
            at(),
            &Command::Edit {
                group: id,
                expected: applied.group.revision,
                name: "研发设备".into(),
                description: "静态成员".into(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        edited.group.revision.get(),
        applied.group.revision.get() + 1
    );
    assert_eq!(edited.group.member_version, applied.group.member_version);
    assert_eq!(edited.group.member_count, 2);
    let operation = op();
    let delete = Command::Delete {
        group: id,
        expected: edited.group.revision,
    };
    let deleted = s
        .execute(operation, at(), &delete, deadline())
        .await
        .unwrap();
    assert!(deleted.group.deleted);
    assert_eq!((deleted.removed, deleted.group.member_count), (2, 0));
    assert_eq!(
        deleted,
        s.execute(operation, at(), &delete, deadline())
            .await
            .unwrap()
    );
    assert_eq!(
        s.delta(operation, None, 10, deadline())
            .await
            .unwrap()
            .removed,
        ["a", "b"]
    );
    assert!(matches!(
        s.execute(op(), at(), &create, deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    runtime.close().await;
}
