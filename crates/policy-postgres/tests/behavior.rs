use rss_mdm_policy_postgres::{core::Change, *};
mod support;
use support::*;
#[path = "support/operations.rs"]
mod operations;
use operations::*;
use uuid::Uuid;
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn configuration_cas_replay_and_runtime_isolation() {
    let runtime = runtime().await;
    let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let first = publication(
        id,
        None,
        Change::Put {
            definition: Box::new(definition()),
            enabled: true,
        },
    );
    let op = Uuid::new_v4();
    let receipt = execute(&runtime, &store, op, &first, deadline())
        .await
        .unwrap();
    assert_eq!(
        receipt,
        execute(&runtime, &store, op, &first, deadline())
            .await
            .unwrap()
    );
    let a = publication(id, Some(&first.policy), Change::Disable);
    let b = publication(id, Some(&first.policy), Change::Enable);
    let (a, b) = tokio::join!(
        execute(&runtime, &store, Uuid::new_v4(), &a, deadline()),
        execute(&runtime, &store, Uuid::new_v4(), &b, deadline())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        store.get(id, deadline()).await.unwrap().unwrap().revision,
        2
    );
    let mut altered = first;
    altered.author = serde_json::json!({"subject":"other"});
    assert!(matches!(
        execute(&runtime, &store, op, &altered, deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    let other = support::runtime().await;
    let result = other
        .local_tx_with_context(tenant(), deadline(), &store, |s, tx| {
            Box::pin(async move { s.publish_in(tx, &altered).await })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    other.close().await;
    let foreign_store = PolicyStore::new(runtime.clone(), foreign(), deadline())
        .await
        .unwrap();
    assert!(foreign_store.get(id, deadline()).await.unwrap().is_none());
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn scope_changes_preserve_execution_version() {
    let runtime = runtime().await;
    let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let mut definition = definition();
    definition.scope = Uuid::new_v4();
    let first = publication(
        id,
        None,
        Change::Put {
            definition: Box::new(definition.clone()),
            enabled: true,
        },
    );
    execute(&runtime, &store, Uuid::new_v4(), &first, deadline())
        .await
        .unwrap();
    definition.scope = Uuid::new_v4();
    let second = publication(
        id,
        Some(&first.policy),
        Change::Put {
            definition: Box::new(definition),
            enabled: true,
        },
    );
    execute(&runtime, &store, Uuid::new_v4(), &second, deadline())
        .await
        .unwrap();
    assert_eq!(first.policy.version, second.policy.version);
    assert_eq!(second.policy.number, 1);
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_policy.versions WHERE policy='{id}'"
        )),
        "1"
    );
    let disabled = publication(id, Some(&second.policy), Change::Disable);
    execute(&runtime, &store, Uuid::new_v4(), &disabled, deadline())
        .await
        .unwrap();
    assert_eq!(
        sql(
            "SELECT to_regclass('mdm_policy.facts') IS NULL AND to_regclass('mdm_policy.aggregates') IS NULL"
        ),
        "t"
    );
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn companion_failure_rolls_back_publication() {
    let runtime = runtime().await;
    let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let first = publication(
        id,
        None,
        Change::Put {
            definition: Box::new(definition()),
            enabled: true,
        },
    );
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&store, &first), |ctx, tx| {
            Box::pin(async move {
                ctx.0.publish_in(tx, ctx.1).await?.unwrap();
                Err::<(), _>(rss_transactional_messaging_postgres::PgError::from(
                    sqlx::Error::RowNotFound,
                ))
            })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(store.get(id, deadline()).await.unwrap().is_none());
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_policy.versions WHERE policy='{id}'"
        )),
        "0"
    );
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn admission_rejects_schema_and_reachable_privilege_drift() {
    let runtime = runtime().await;
    for (damage, restore) in [
        (
            "ALTER TABLE mdm_policy.policies NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_policy.policies FORCE ROW LEVEL SECURITY",
        ),
        (
            "GRANT UPDATE ON mdm_policy.versions TO mdm_policy_runtime",
            "REVOKE UPDATE ON mdm_policy.versions FROM mdm_policy_runtime",
        ),
        (
            "CREATE ROLE policy_drift NOLOGIN; GRANT DELETE ON mdm_policy.policies TO policy_drift; GRANT policy_drift TO mdm_policy_runtime WITH INHERIT FALSE,SET TRUE",
            "REVOKE policy_drift FROM mdm_policy_runtime; DROP OWNED BY policy_drift; DROP ROLE policy_drift",
        ),
    ] {
        sql(damage);
        let result = PolicyStore::new(runtime.clone(), tenant(), deadline()).await;
        sql(restore);
        assert!(result.is_err());
    }
    PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn explicit_trigger_does_not_edit_configuration() {
    let mut definition = definition();
    definition.behavior = serde_json::from_value(
        serde_json::json!({"kind":"execution","parameters":{},"runLifetimeSeconds":300}),
    )
    .unwrap();
    let runtime = runtime().await;
    let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let first = publication(
        id,
        None,
        Change::Put {
            definition: Box::new(definition),
            enabled: true,
        },
    );
    execute(&runtime, &store, Uuid::new_v4(), &first, deadline())
        .await
        .unwrap();
    let op = Uuid::new_v4();
    let version = first.policy.version;
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), &store, |s, tx| {
            Box::pin(async move { s.trigger_in(tx, op, version, 10, 100).await })
        })
        .await;
    assert!(result.fold(
        |v| v.is_ok(),
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    assert_eq!(
        store.get(id, deadline()).await.unwrap().unwrap().revision,
        1
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn borrowed_reads_reject_foreign_runtime_and_tenant() {
    let runtime = runtime().await;
    let store = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let first = publication(
        id,
        None,
        Change::Put {
            definition: Box::new(definition()),
            enabled: true,
        },
    );
    execute(&runtime, &store, Uuid::new_v4(), &first, deadline())
        .await
        .unwrap();
    let other = support::runtime().await;
    for version in [false, true] {
        let selected = if version { first.policy.version } else { id };
        let read = other
            .local_tx_with_context(tenant(), deadline(), store.reader(), |reader, tx| {
                Box::pin(async move {
                    if version {
                        reader
                            .version_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    } else {
                        reader
                            .read_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    }
                })
            })
            .await;
        assert!(
            read.fold(
                |_| false,
                |_| false,
                |_| true,
                |_| false,
                |_| false,
                |_| false
            ),
            "borrowed read accepted a different runtime instance"
        );
        let read = runtime
            .local_tx_with_context(foreign(), deadline(), store.reader(), |reader, tx| {
                Box::pin(async move {
                    if version {
                        reader
                            .version_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    } else {
                        reader
                            .read_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    }
                })
            })
            .await;
        assert!(read.fold(
            |v| matches!(v, Err(Rejection::TenantMismatch)),
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false
        ));
        let read = runtime
            .local_tx_with_context(tenant(), deadline(), store.reader(), |reader, tx| {
                Box::pin(async move {
                    if version {
                        reader
                            .version_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    } else {
                        reader
                            .read_in(tx, selected)
                            .await
                            .map(|v| v.map(|p| p.is_some()))
                    }
                })
            })
            .await;
        assert!(read.fold(
            |v| v == Ok(true),
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false
        ));
    }
    other.close().await;
    runtime.close().await;
}
