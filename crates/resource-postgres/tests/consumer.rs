use rss_mdm_resource_postgres::{core as r, *};
mod support;
use support::*;
fn id(s: &str) -> r::Id {
    r::Id::new(s).unwrap()
}
fn version(resource: &r::Id, label: &str, byte: u8) -> r::Version {
    r::Version::new(
        tenant(),
        resource.clone(),
        id(label),
        r::Kind::Software,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            id("msi"),
            r::Declaration::Software {
                package: r::Package::new(id("private"), id("Acme.App"), id(label)),
                artifact: r::Artifact::new(id("installer"), 3, r::Digest::from_bytes([byte; 32]))
                    .unwrap(),
                install: id("msi"),
                detect: id("product-code"),
                uninstall: None,
            },
        )],
    )
    .unwrap()
}
fn req(resource: &r::Id, revision: u64, command: Command) -> Request {
    Request {
        id: id(&format!("requests/{}", unique())),
        resource: resource.clone(),
        expected_storage_revision: revision,
        as_of: at(10),
        command,
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn resource_immutable_versions_restart_and_reference_rollback() {
    let runtime = runtime().await;
    let s = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let key = id(&unique());
    s.execute(
        &req(&key, 0, Command::Create(r::Kind::Software)),
        deadline(),
    )
    .await
    .unwrap();
    let insert = req(&key, 1, Command::Insert(version(&key, "one", 1)));
    let receipt = s.execute(&insert, deadline()).await.unwrap();
    assert_eq!(receipt, s.execute(&insert, deadline()).await.unwrap());
    assert!(
        s.execute(
            &req(&key, 2, Command::Insert(version(&key, "one", 2))),
            deadline()
        )
        .await
        .is_err()
    );
    s.execute(&req(&key, 2, Command::Activate(id("one"))), deadline())
        .await
        .unwrap();
    let archive = req(
        &key,
        3,
        Command::Archive {
            version: id("one"),
            references: 0,
        },
    );
    assert!(matches!(
        s.execute(&archive, deadline()).await,
        Err(Error::Rejected(Rejection::CompanionRequired))
    ));
    let blocked = req(
        &key,
        3,
        Command::Archive {
            version: id("one"),
            references: 1,
        },
    );
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &blocked), |(s, r), tx| {
            Box::pin(async move {
                s.lock_version_in(tx, &r.resource, &id("one"))
                    .await?
                    .unwrap();
                s.execute_in(tx, r).await
            })
        })
        .await;
    assert!(result.fold(
        |v| v == Err(Rejection::Referenced),
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &archive), |(s, r), tx| {
            Box::pin(async move {
                s.execute_in(tx, r).await?.unwrap();
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
    let restarted = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let resource = restarted.get(&key, deadline()).await.unwrap().unwrap();
    assert_eq!(
        resource.resource.state(&id("one")).unwrap(),
        r::State::Active
    );
    assert_eq!(
        restarted
            .version(&key, &id("one"), deadline())
            .await
            .unwrap()
            .unwrap(),
        version(&key, "one", 1)
    );
    assert_eq!(
        restarted.operation(&insert.id, deadline()).await.unwrap(),
        Some(receipt)
    );
    assert!(
        ResourceStore::new(runtime, foreign(), deadline())
            .await
            .unwrap()
            .get(&key, deadline())
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn resource_cas_events_and_owner_admission() {
    let runtime = runtime().await;
    let s = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let key = id(&unique());
    s.execute(
        &req(&key, 0, Command::Create(r::Kind::Software)),
        deadline(),
    )
    .await
    .unwrap();
    let a = req(&key, 1, Command::Insert(version(&key, "one", 1)));
    let b = req(&key, 1, Command::Insert(version(&key, "two", 2)));
    let (a, b) = tokio::join!(s.execute(&a, deadline()), s.execute(&b, deadline()));
    assert_ne!(a.is_ok(), b.is_ok());
    sql("REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_resource_runtime");
    let r = req(&key, 2, Command::Insert(version(&key, "three", 3)));
    let result = s.execute(&r, deadline()).await;
    sql("GRANT INSERT ON rss_transactional_messaging.outbox TO mdm_resource_runtime");
    assert!(result.is_err());
    assert!(
        s.version(&key, &id("three"), deadline())
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.operation(&r.id, deadline()).await.unwrap().is_none());
    let wrong = support::runtime().await;
    let result = wrong
        .local_tx_with_context(tenant(), deadline(), (&s, &r), |(s, r), tx| {
            Box::pin(async move { s.execute_in(tx, r).await })
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
    sql("GRANT UPDATE(document) ON mdm_resource.immutable TO mdm_resource_runtime");
    let bad = ResourceStore::new(runtime, tenant(), deadline()).await;
    sql("REVOKE UPDATE(document) ON mdm_resource.immutable FROM mdm_resource_runtime");
    assert!(bad.is_err());
}
