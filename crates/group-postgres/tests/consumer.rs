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
    let deleted = execute_companion(&runtime, &s, operation, &delete)
        .await
        .unwrap();
    assert!(deleted.group.deleted);
    assert_eq!((deleted.removed, deleted.group.member_count), (2, 0));
    assert_eq!(
        deleted,
        execute_companion(&runtime, &s, operation, &delete)
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

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn durable_recalculation_no_change_fences_stale_run() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let (rule, snapshot) = inputs();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                name: "dynamic".into(),
                description: "".into(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = RecalculationRequest {
        id: op(),
        group: id,
        expected: created.group.revision,
        rule_version: "rule-1".into(),
        trigger: Trigger::Manual,
        snapshot: snapshot.clone(),
        as_of: at(),
    };
    let preview = s
        .preview(id, created.group.revision, &snapshot, at(), deadline())
        .await
        .unwrap();
    assert!(matches!(
        s.start_recalculation(&request, deadline())
            .await
            .unwrap()
            .state,
        RunState::Pending
    ));
    let result = s.resume(request.id, deadline()).await.unwrap();
    let RunState::Completed(receipt) = result.state else {
        panic!("not completed")
    };
    assert_eq!(receipt.group.member_count, 1);
    assert_eq!(
        s.result(request.id, deadline())
            .await
            .unwrap()
            .unwrap()
            .evaluation,
        preview
    );
    let current = receipt.group.revision;
    let mut newer = request.clone();
    newer.id = op();
    newer.expected = current;
    let mut stale = newer.clone();
    stale.id = op();
    s.start_recalculation(&newer, deadline()).await.unwrap();
    s.start_recalculation(&stale, deadline()).await.unwrap();
    let applied = s.resume(newer.id, deadline()).await.unwrap();
    let RunState::Completed(r) = applied.state else {
        panic!("not completed")
    };
    assert_eq!(r.group.member_version, receipt.group.member_version);
    assert!(r.group.revision.get() > current.get());
    assert!(matches!(
        s.resume(stale.id, deadline()).await.unwrap().state,
        RunState::Rejected(Rejection::VersionConflict)
    ));
    runtime.close().await;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    assert_eq!(
        s.get_run(request.id, deadline())
            .await
            .unwrap()
            .unwrap()
            .state,
        RunState::Completed(receipt)
    );
    let original = s.rule(id, "rule-1", deadline()).await.unwrap().unwrap();
    assert_eq!(original.evaluate(&snapshot, at()).unwrap(), preview);
    let current = s.get(id, deadline()).await.unwrap().unwrap();
    let v = original.view();
    let replacement = core::Rule::new(
        tenant(),
        "rule-2",
        v.dictionary_version,
        v.fields.values().cloned().collect(),
        v.criteria.clone(),
    )
    .unwrap();
    let changed = s
        .execute(
            op(),
            at(),
            &Command::SetRule {
                group: id,
                expected: current.revision,
                rule: replacement,
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(changed.group.rule_version.as_deref(), Some("rule-2"));
    assert_eq!(
        s.rule(id, "rule-2", deadline())
            .await
            .unwrap()
            .unwrap()
            .view()
            .version,
        "rule-2"
    );
    assert_eq!(
        s.rule(id, "rule-1", deadline())
            .await
            .unwrap()
            .unwrap()
            .evaluate(&snapshot, at())
            .unwrap(),
        preview
    );
    assert!(s.rule(id, "missing", deadline()).await.unwrap().is_none());
    assert!(
        store(runtime.clone(), foreign())
            .await
            .rule(id, "rule-1", deadline())
            .await
            .unwrap()
            .is_none()
    );
    execute_companion(
        &runtime,
        &s,
        op(),
        &Command::Delete {
            group: id,
            expected: changed.group.revision,
        },
    )
    .await
    .unwrap();
    assert!(s.rule(id, "rule-1", deadline()).await.unwrap().is_some());
    runtime.close().await;
}
