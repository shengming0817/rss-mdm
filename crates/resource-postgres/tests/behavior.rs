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
                definition: software(
                    &r::Artifact::new(id("installer"), 3, r::Digest::from_bytes([byte; 32]))
                        .unwrap(),
                ),
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
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
async fn resource_immutable_versions_reopen_and_reference_rollback() {
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
    assert_event(key.as_str(), insert.id.as_str(), 2, 10);
    assert!(matches!(
        s.execute(
            &req(&key, 2, Command::Insert(version(&key, "one", 2))),
            deadline()
        )
        .await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
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
                tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                    .await?;
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
                tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                    .await?;
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
    let presentation = serde_json::json!({"name":"renamed","vendor":{"help":"support"}})
        .as_object()
        .unwrap()
        .clone();
    let edit = req(&key, 3, Command::Present(presentation.clone()));
    let edited = s.execute(&edit, deadline()).await.unwrap();
    assert_eq!(edited, s.execute(&edit, deadline()).await.unwrap());
    let restarted = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let resource = restarted.get(&key, deadline()).await.unwrap().unwrap();
    assert_eq!(resource.resource.snapshot().presentation, presentation);
    assert_eq!(resource.storage_revision, 4);
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
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
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
    let winner = match (a, b) {
        (Ok(receipt), Err(Error::Rejected(Rejection::Conflict)))
        | (Err(Error::Rejected(Rejection::Conflict)), Ok(receipt)) => receipt,
        other => panic!("CAS must have one winner and one conflict: {other:?}"),
    };
    assert_eq!(winner.storage_revision, 2);
    assert_eq!(
        s.get(&key, deadline())
            .await
            .unwrap()
            .unwrap()
            .storage_revision,
        2
    );
    let r = req(&key, 2, Command::Insert(version(&key, "three", 3)));
    let wrong = support::runtime().await;
    let result = wrong
        .local_tx_with_context(tenant(), deadline(), (&s, &r), |(s, r), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                    .await?;
                s.execute_in(tx, r).await
            })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |error| error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant,
        |_| false,
        |_| false,
        |_| false
    ));
    let applied = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &r), |(s, r), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                    .await?;
                s.execute_in(tx, r).await
            })
        })
        .await;
    assert!(applied.fold(
        |r| r.is_ok(),
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
}

fn assert_event(id: &str, request: &str, revision: u64, occurred_at: i64) {
    use sha2::{Digest, Sha256};
    let message_id = format!("resource.v1:{:x}", Sha256::digest(request.as_bytes()));
    let envelope: serde_json::Value = serde_json::from_str(&sql(&format!(
        "SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='{}'",
        tenant(), message_id
    ))).unwrap();
    assert_eq!(envelope["tenant"], tenant().to_string());
    assert_eq!(envelope["occurred_at"], occurred_at);
    assert_eq!(envelope["domain"], "mdm-resource");
    assert_eq!(envelope["route"], "resource.changed");
    assert_eq!(envelope["contract"], "mdm.resource.changed");
    assert_eq!(envelope["version"], "v1");
    assert_eq!(envelope["partition"], id);
    assert_eq!(
        envelope["schema"],
        format!("sha256:{:x}", Sha256::digest(EVENT_SCHEMA))
    );
    let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"v":1,"id":id,"request":request,"revision":revision})
    );
    let schema: serde_json::Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
    let required: std::collections::BTreeSet<_> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        required,
        payload
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
async fn resource_admission_rejects_schema_and_privilege_drift() {
    let runtime = runtime().await;
    let s = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let key = id(&unique());
    sql(
        "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) FROM mdm_resource_runtime",
    );
    let r = req(&key, 0, Command::Create(r::Kind::Software));
    let result = s.execute(&r, deadline()).await;
    sql(
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_resource_runtime",
    );
    assert!(matches!(
        result,
        Err(Error::RolledBack(ref error)) if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Permanent
    ));
    assert!(s.get(&key, deadline()).await.unwrap().is_none());
    assert!(s.operation(&r.id, deadline()).await.unwrap().is_none());
    let cases = [
        (
            "CREATE TABLE mdm_resource.unexpected(id integer)",
            "DROP TABLE mdm_resource.unexpected",
        ),
        (
            "GRANT UPDATE(document) ON mdm_resource.immutable TO mdm_resource_runtime",
            "REVOKE UPDATE(document) ON mdm_resource.immutable FROM mdm_resource_runtime",
        ),
        (
            "ALTER TABLE mdm_resource.aggregates DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_resource.aggregates ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE mdm_resource.aggregates NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_resource.aggregates FORCE ROW LEVEL SECURITY",
        ),
        (
            "GRANT mdm_owner TO mdm_resource_runtime",
            "REVOKE mdm_owner FROM mdm_resource_runtime",
        ),
        (
            "ALTER ROLE mdm_resource_runtime SUPERUSER",
            "ALTER ROLE mdm_resource_runtime NOSUPERUSER",
        ),
        (
            "GRANT UPDATE ON mdm_resource.aggregates TO mdm_resource_runtime",
            "REVOKE UPDATE ON mdm_resource.aggregates FROM mdm_resource_runtime; GRANT UPDATE(revision,document,digest) ON mdm_resource.aggregates TO mdm_resource_runtime",
        ),
    ];
    for (change, restore) in cases {
        sql(change);
        let result = ResourceStore::new(runtime.clone(), tenant(), deadline()).await;
        sql(restore);
        assert!(
            matches!(result, Err(Error::RolledBack(ref e)) if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant),
            "admitted drift: {change}"
        );
        ResourceStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap_or_else(|e| panic!("failed to restore {change}: {e:?}"));
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
async fn admission_rejects_noninherited_switchable_privileges() {
    let runtime = runtime().await;
    let role = format!("acl_{}", unique().replace('-', "_"));
    let bridge = format!("{role}_bridge");
    sql(&format!(
        "CREATE ROLE {role} NOLOGIN; CREATE ROLE {bridge} NOLOGIN; GRANT {role} TO {bridge} WITH INHERIT FALSE, SET TRUE; GRANT {bridge} TO mdm_resource_runtime WITH INHERIT FALSE, SET TRUE; GRANT USAGE ON SCHEMA mdm_resource TO {role};"
    ));
    let roles = (role.clone(), bridge.clone());
    let outcome = tokio::spawn(async move {
    let (role, bridge) = roles;
    for membership in ["INHERIT FALSE, SET TRUE", "INHERIT TRUE, SET FALSE"] {
        sql(&format!("GRANT {role} TO {bridge} WITH {membership}"));
        for privilege in [
            "TRUNCATE ON mdm_resource.requests",
            "DELETE ON mdm_resource.immutable",
            "UPDATE(document) ON mdm_resource.immutable",
            "UPDATE ON mdm_resource.aggregates",
            "REFERENCES ON mdm_resource.aggregates",
            "TRIGGER ON mdm_resource.aggregates",
        ] {
            sql(&format!("GRANT {privilege} TO {role}"));
            let result = ResourceStore::new(runtime.clone(), tenant(), deadline()).await;
            sql(&format!("REVOKE {privilege} FROM {role}"));
            assert!(
                matches!(result, Err(Error::RolledBack(ref e)) if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant),
                "admitted switchable privilege: {privilege}"
            );
            ResourceStore::new(runtime.clone(), tenant(), deadline()).await.unwrap();
        }
    }
    // Permitted column privileges in a switchable role remain admissible.
    sql(&format!(
        "GRANT UPDATE(document) ON mdm_resource.aggregates TO {role}"
    ));
    ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    sql(&format!(
        "REVOKE UPDATE(document) ON mdm_resource.aggregates FROM {role}"
    ));
    // A role with neither inheritance nor SET permission is not executable.
    sql(&format!(
        "GRANT {bridge} TO mdm_resource_runtime WITH INHERIT FALSE, SET FALSE; GRANT TRUNCATE ON mdm_resource.requests TO {role}"
    ));
    let dormant = ResourceStore::new(runtime, tenant(), deadline()).await;
    dormant.unwrap();
    }).await;
    sql(&format!(
        "REVOKE {bridge} FROM mdm_resource_runtime; REVOKE {role} FROM {bridge}; DROP OWNED BY {role}; DROP ROLE {bridge}; DROP ROLE {role};"
    ));
    outcome.unwrap();
}

fn software(artifact: &r::Artifact) -> r::SoftwareDefinition {
    serde_json::from_value(serde_json::json!({"material":{"format":"msi","installer":"package"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":"1.2","artifacts":{"package":{"reference":artifact.reference().as_str(),"length":artifact.length(),"sha256":artifact.digest().bytes()}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":{"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2"},"upgradeInvocation":{"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap()
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
#[cfg(feature = "integration")]
async fn artifact_reference_index_covers_reuse_without_another_upload_and_archive_rollback() {
    let runtime = runtime().await;
    let store = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let first = id(&unique());
    let second = id(&unique());
    let digest = r::Digest::from_bytes([201; 32]);
    for key in [&first, &second] {
        let seeded = version(key, "v1", 201);
        runtime
            .local_tx(tenant(), deadline(), move |tx| {
                Box::pin(async move {
                    rss_mdm_resource_postgres::fixture::draft_version_in(tx, seeded, at(1)).await
                })
            })
            .await
            .fold(
                |_| (),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            );
    }
    async fn referenced(
        runtime: &rss_transactional_messaging_postgres::PgRuntime,
        tenant: rss_request_context::TenantId,
        digest: r::Digest,
    ) -> bool {
        runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move { artifact_referenced_in(tx, digest).await })
            })
            .await
            .fold(
                |v| v,
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            )
    }
    assert!(referenced(&runtime, tenant(), digest).await);
    assert!(!referenced(&runtime, foreign(), digest).await);
    let rollback = req(
        &first,
        2,
        Command::Archive {
            version: id("v1"),
            references: 0,
        },
    );
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&store, &rollback), |(s, r), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                    .await?;
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
    for (index, key) in [&second, &first].into_iter().enumerate() {
        let archive = req(
            key,
            2,
            Command::Archive {
                version: id("v1"),
                references: 0,
            },
        );
        let result = runtime
            .local_tx_with_context(tenant(), deadline(), (&store, &archive), |(s, r), tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[s.partition(r.resource.as_str())?])
                        .await?;
                    s.execute_in(tx, r).await
                })
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
            referenced(&runtime, tenant(), digest).await,
            index == 0,
            "another Resource reference must retain the shared bytes"
        );
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
#[cfg(feature = "integration")]
async fn storage_rejects_invalid_format_without_rewriting_immutable_bytes() {
    let runtime = runtime().await;
    let store = ResourceStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let key = id(&unique());
    let seeded = version(&key, "one", 1);
    runtime
        .local_tx(tenant(), deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_resource_postgres::fixture::draft_version_in(tx, seeded, at(1)).await
            })
        })
        .await
        .fold(
            |_| (),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    let read = format!(
        "SELECT convert_from(document,'UTF8') FROM mdm_resource.immutable WHERE tenant_id='{}' AND owner='{}' AND kind='version'",
        tenant(),
        key.as_str()
    );
    let original = sql(&read);
    let mut document: serde_json::Value = serde_json::from_str(&original).unwrap();
    assert_eq!(document[0], 1);
    document[0] = serde_json::json!(0);
    let old = serde_json::to_string(&document).unwrap();
    // Deliberately install an intact outer digest so rejection exercises the format boundary.
    // The damaged material belongs to this case's disposable database.
    let replace = |bytes: &str| {
        sql(&format!(
            "UPDATE mdm_resource.immutable SET document=convert_to('{bytes}','UTF8'),digest=sha256(convert_to('{bytes}','UTF8')) WHERE tenant_id='{}' AND owner='{}' AND kind='version'",
            tenant(),
            key.as_str()
        ))
    };
    replace(&old);
    assert!(store.get(&key, deadline()).await.is_err());
    assert_eq!(sql(&read), old, "failed read must not rewrite history");
    replace(&original);
    assert_eq!(
        store
            .version(&key, &id("one"), deadline())
            .await
            .unwrap()
            .unwrap(),
        version(&key, "one", 1)
    );
}

#[tokio::test]
#[ignore = "real PostgreSQL: make t2 MODULE=resource.persistence"]
async fn reference_readers_commit_independently_while_archive_waits() {
    use std::{sync::Arc, time::Duration};
    let runtime = runtime().await;
    let store = Arc::new(
        ResourceStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap(),
    );
    let resource = id(&unique());
    for request in [
        req(&resource, 0, Command::Create(r::Kind::Software)),
        req(&resource, 1, Command::Insert(version(&resource, "one", 1))),
        req(&resource, 2, Command::Activate(id("one"))),
    ] {
        store.execute(&request, deadline()).await.unwrap();
    }
    async fn reader(
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        store: Arc<ResourceStore>,
        resource: r::Id,
        write: Request,
        pause: Option<(tokio::sync::oneshot::Sender<()>, Arc<tokio::sync::Notify>)>,
    ) -> bool {
        runtime
            .local_tx_with_context(
                tenant(),
                deadline(),
                (store, resource, write, pause),
                |(store, resource, write, pause), tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[store.partition(write.resource.as_str())?])
                            .await?;
                        assert_eq!(
                            lock_reference_in(tx, resource, &id("one"))
                                .await?
                                .unwrap()
                                .1,
                            r::State::Active
                        );
                        store.execute_in(tx, write).await?.unwrap();
                        if let Some((ready, resume)) = pause.take() {
                            let _ = ready.send(());
                            tokio::time::timeout(Duration::from_secs(15), resume.notified())
                                .await
                                .map_err(|_| sqlx::Error::Protocol("reference test gate".into()))?;
                        }
                        Ok::<_, rss_transactional_messaging_postgres::PgError>(())
                    })
                },
            )
            .await
            .fold(
                |_| true,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
            )
    }
    let first = id(&unique());
    let second = id(&unique());
    let (ready, arrived) = tokio::sync::oneshot::channel();
    let resume = Arc::new(tokio::sync::Notify::new());
    let a = tokio::spawn(reader(
        runtime.clone(),
        store.clone(),
        resource.clone(),
        req(&first, 0, Command::Create(r::Kind::Software)),
        Some((ready, resume.clone())),
    ));
    tokio::time::timeout(Duration::from_secs(5), arrived)
        .await
        .unwrap()
        .unwrap();
    let b = tokio::time::timeout(
        Duration::from_secs(3),
        reader(
            runtime.clone(),
            store.clone(),
            resource.clone(),
            req(&second, 0, Command::Create(r::Kind::Software)),
            None,
        ),
    )
    .await;
    if !matches!(b, Ok(true)) {
        resume.notify_one();
        let _ = a.await;
        panic!("reference reader B could not commit while A retained real writes");
    }
    assert!(store.get(&first, deadline()).await.unwrap().is_none());
    assert!(store.get(&second, deadline()).await.unwrap().is_some());
    let (started, pid) = tokio::sync::oneshot::channel();
    let archive = req(
        &resource,
        3,
        Command::Archive {
            version: id("one"),
            references: 0,
        },
    );
    let writer_runtime = runtime.clone();
    let writer_store = store.clone();
    let writer = tokio::spawn(async move {
        writer_runtime
            .local_tx_with_context(
                tenant(),
                deadline(),
                (writer_store, archive, Some(started)),
                |(store, request, started), tx| {
                    Box::pin(async move {
                        let pid: i32 = tx
                            .with_connection(|c| {
                                Box::pin(async move {
                                    sqlx::query_scalar("SELECT pg_backend_pid()")
                                        .fetch_one(c)
                                        .await
                                })
                            })
                            .await?;
                        let _ = started.take().unwrap().send(pid);
                        tx.prepare_outbox_partitions(
                            &[store.partition(request.resource.as_str())?],
                        )
                        .await?;
                        store
                            .lock_version_in(tx, &request.resource, &id("one"))
                            .await?
                            .unwrap();
                        store.execute_in(tx, request).await?.unwrap();
                        Ok::<_, rss_transactional_messaging_postgres::PgError>(())
                    })
                },
            )
            .await
            .fold(
                |_| true,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
            )
    });
    let pid = pid.await.unwrap();
    let waiting=tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            if sql(&format!("SELECT EXISTS(SELECT FROM pg_locks WHERE pid={pid} AND locktype='advisory' AND NOT granted)")).trim()=="t" {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    resume.notify_one();
    assert!(a.await.unwrap());
    assert!(writer.await.unwrap());
    assert!(
        waiting.is_ok(),
        "archive failed to wait on the live reference transaction"
    );
    let current = runtime
        .local_tx_with_context(tenant(), deadline(), resource, |resource, tx| {
            Box::pin(async move { lock_reference_in(tx, resource, &id("one")).await })
        })
        .await;
    assert!(current.fold(
        |r| r.unwrap().1 == r::State::Archived,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
}
