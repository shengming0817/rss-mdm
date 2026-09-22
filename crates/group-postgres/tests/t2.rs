//! Real PG and only public Group/RSS interfaces. Selected explicitly by the T2 harness.
use rss_mdm_group::*;
use rss_mdm_group_postgres::*;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

mod support;
use support::*;

fn admin(sql: &str) -> String {
    use std::io::Write;
    let config = fixture_config();
    let mut process = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            config["container"].as_str().unwrap(),
            "psql",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "group_test",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(sql.as_bytes())
        .unwrap();
    let result = process.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "fixture SQL failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_string()
}
fn event_count(id: OperationId) -> i64 {
    admin(&format!("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='group.changed.v1:{id}'")).parse().unwrap()
}
fn assert_event(r: &Receipt, kind: &str) {
    use serde_json::json;
    use sha2::Digest;
    let e: serde_json::Value = serde_json::from_str(&admin(&format!(
        "SELECT envelope FROM rss_transactional_messaging.outbox WHERE message_id='group.changed.v1:{}'", r.operation))).unwrap();
    assert_eq!(e["tenant"], tenant().to_string());
    assert_eq!(e["occurred_at"], at().unix_seconds());
    assert_eq!(e["domain"], "mdm-group");
    assert_eq!(e["route"], "group.changed");
    assert_eq!(e["contract"], "mdm.group.changed");
    assert_eq!(e["version"], "v1");
    assert_eq!(e["partition"], r.group.id.to_string());
    let ordinal: i64 = admin(&format!("SELECT partition_seq FROM rss_transactional_messaging.outbox WHERE message_id='group.changed.v1:{}'", r.operation)).parse().unwrap();
    assert_eq!(ordinal, r.group.revision.get());
    assert_eq!(
        e["schema"],
        format!("sha256:{:x}", sha2::Sha256::digest(EVENT_SCHEMA.as_bytes()))
    );
    let bytes: Vec<u8> = serde_json::from_value(e["payload"].clone()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        payload,
        json!({"v":1,"kind":kind,"groupId":r.group.id.to_string(),
        "operationId":r.operation.to_string(),"groupRevision":r.group.revision.get(),
        "memberVersion":r.group.member_version,"memberCount":r.group.member_count,
        "added":r.added,"removed":r.removed,"ruleVersion":r.group.rule_version})
    );
    assert!(
        payload
            .as_object()
            .unwrap()
            .keys()
            .all(|key| !key.contains('_')),
        "event fields must be camelCase"
    );

    let schema: serde_json::Value = serde_json::from_str(EVENT_SCHEMA).unwrap();
    assert_eq!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        payload
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
    assert!(
        schema["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!(kind))
    );
}

#[path = "support/builds.rs"]
mod builds;
async fn dynamic_group(s: &GroupStore) -> (GroupId, Receipt, FixturePage) {
    let (rule, page) = inputs();
    let group = group_id();
    let receipt = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group,
                name: "dynamic".into(),
                description: String::new(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    (group, receipt, page)
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn reference_target_lock_serializes_deletion() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, _) = dynamic_group(&s).await;
    let (locked, wait_locked) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let holding = runtime.local_tx_with_context(tenant(), deadline(), &s, move |s, tx| {
        Box::pin(async move {
            assert_eq!(s.lock_reference_target_in(tx, id).await?.unwrap().id, id);
            locked.send(()).unwrap();
            wait_release.await.unwrap();
            Ok(())
        })
    });
    let deleting = async {
        wait_locked.await.unwrap();
        let command = Command::Delete {
            group: id,
            expected: created.group.revision,
        };
        let mut deletion = Box::pin(execute_companion(&runtime, &s, op(), &command));
        tokio::select! {
            result = &mut deletion => panic!("delete bypassed reference lock: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(150)) => {}
        }
        release.send(()).unwrap();
        deletion.await.unwrap()
    };
    let (held, deleted) = tokio::join!(holding, deleting);
    assert!(held.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    assert!(deleted.group.deleted);
    assert_event(&deleted, "deleted");
    runtime.close().await;
}
struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct AckProxy {
    port: u16,
    discard: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for AckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AckProxy {
    async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = fixture_config()["port"].as_u64().unwrap() as u16;
        let discard = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = discard.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        let flag = flag.clone();
                        connections.spawn(async move {
                            let server = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await.unwrap();
                            let (mut cr, mut cw) = client.into_split();
                            let (mut sr, mut sw) = server.into_split();
                            let forward = tokio::io::copy(&mut cr, &mut sw);
                            let backward = async {
                                let mut buffer = [0; 16384];
                                loop {
                                    let n = sr.read(&mut buffer).await?;
                                    if n == 0 { return Ok::<(), std::io::Error>(()); }
                                    if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                                        cw.write_all(&buffer[..n]).await?;
                                    }
                                }
                            };
                            tokio::select! { _ = forward => {}, _ = backward => {} }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            port,
            discard,
            task,
        }
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn lost_commit_ack_replays_durable_result_once() {
    let proxy = AckProxy::start().await;
    let runtime = connect_runtime_at(Some(proxy.port)).await;
    let s = store(runtime.clone(), tenant()).await;
    let (_id, created, snapshot) = dynamic_group(&s).await;
    let request = builds::request(&created, None);
    builds::prepare(&runtime, &s, &request, &snapshot)
        .await
        .unwrap();
    admin(&format!(
        "CREATE FUNCTION public.hold_group_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(238701); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER t2_hold_commit AFTER UPDATE ON mdm_group.member_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id='{}'::uuid AND NEW.phase='published') EXECUTE FUNCTION public.hold_group_commit();",
        request.id
    ));
    let config = fixture_config();
    let _holder = ChildGuard(std::process::Command::new("docker")
        .args(["exec", config["container"].as_str().unwrap(), "psql", "-At", "-U", "postgres", "-d", "group_test", "-c", "SET application_name='group_ack_holder'; SELECT pg_advisory_lock(238701); SELECT pg_sleep(30)"])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        while admin(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=238701 AND granted",
        ) != "1"
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut resume = Box::pin(builds::publish(&runtime, &s, &request));
    let at_commit = async {
        loop {
            if admin(
                "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=238701 AND NOT granted",
            ) == "1"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        gate = tokio::time::timeout(Duration::from_secs(5), at_commit) => { gate.unwrap(); }
        result = &mut resume => panic!("resume finished before COMMIT gate: {result:?}"),
    }
    proxy
        .discard
        .store(true, std::sync::atomic::Ordering::SeqCst);
    admin(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='group_ack_holder'",
    );
    let result = resume.await;
    admin(
        "DROP TRIGGER t2_hold_commit ON mdm_group.member_runs; DROP FUNCTION public.hold_group_commit()",
    );
    assert!(
        matches!(
            result,
            Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
        ),
        "{result:?}"
    );
    assert_eq!(
        admin(&format!(
            "SELECT phase FROM mdm_group.member_runs WHERE id='{}'",
            request.id
        )),
        "published"
    );
    runtime.close().await;
    drop(proxy);
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let first = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(first.group.member_count, 1);
    assert_eq!(
        first,
        builds::publish(&runtime, &s, &request).await.unwrap()
    );
    assert_eq!(
        builds::members(&runtime, &s, request.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(event_count(request.id), 1);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn admission_rejects_catalog_and_security_drift() {
    let runtime = connect_runtime().await;
    for mutation in [
        "GRANT CREATE ON SCHEMA mdm_group TO mdm_group_runtime",
        "GRANT TRUNCATE ON mdm_group.groups TO mdm_group_runtime",
        "GRANT UPDATE(id) ON mdm_group.groups TO mdm_group_runtime",
        "GRANT SELECT ON mdm_group.groups TO PUBLIC",
        "GRANT SELECT ON mdm_group.groups TO mdm_group_runtime WITH GRANT OPTION",
        "ALTER POLICY tenant ON mdm_group.groups USING (true)",
        "ALTER POLICY tenant ON mdm_group.groups WITH CHECK (true)",
        "CREATE POLICY extra ON mdm_group.groups USING (true)",
        "ALTER ROLE mdm_group_runtime BYPASSRLS",
        "ALTER TABLE mdm_group.operations DROP COLUMN receipt_digest CASCADE",
        "ALTER TABLE mdm_group.groups ALTER COLUMN name TYPE varchar",
        "ALTER TABLE mdm_group.operations ALTER COLUMN request DROP NOT NULL",
        "ALTER TABLE mdm_group.groups ALTER COLUMN deleted SET DEFAULT true",
        "ALTER TABLE mdm_group.operations DROP CONSTRAINT operations_as_of_check",
        "ALTER TABLE mdm_group.member_rows DROP CONSTRAINT member_rows_tenant_id_run_id_fkey",
        "ALTER TABLE mdm_group.member_changes DROP CONSTRAINT member_changes_pkey",
        "DROP INDEX mdm_group.member_changes_history",
        "DROP INDEX mdm_group.member_changes_history; CREATE INDEX member_changes_history ON mdm_group.member_changes(tenant_id,object_id)",
        "ALTER TABLE mdm_group.operations ADD COLUMN unexpected text",
        "UPDATE pg_index SET indisvalid=false WHERE indexrelid='mdm_group.member_changes_history'::regclass",
        "UPDATE pg_index SET indisready=false WHERE indexrelid='mdm_group.member_changes_history'::regclass",
        "UPDATE pg_index SET indislive=false WHERE indexrelid='mdm_group.member_changes_history'::regclass",
    ] {
        GroupStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        admin(mutation);
        let result = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
        // Restore before asserting so a failing case cannot contaminate later tests.
        admin(&format!(
            "ALTER ROLE mdm_group_runtime NOBYPASSRLS; UPDATE pg_index SET indisvalid=true,indisready=true,indislive=true WHERE indexrelid=to_regclass('mdm_group.member_changes_history'); DROP SCHEMA mdm_group CASCADE; SET ROLE mdm_group_owner; {MIGRATION_SQL} {OUTBOX_MIGRATION_SQL} {GENERATIONS_MIGRATION_SQL}"
        ));
        assert!(result.is_err(), "accepted drift: {mutation}");
    }
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn standalone_delete_requires_companion_transaction() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                name: "delete-boundary".into(),
                description: String::new(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let operation = op();
    let command = Command::Delete {
        group: id,
        expected: created.group.revision,
    };
    assert!(matches!(
        s.execute(operation, at(), &command, deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::CompanionTransactionRequired
        ))
    ));
    assert_eq!(s.get(id, deadline()).await.unwrap(), Some(created.group));
    assert_eq!(event_count(operation), 0);
    // A host that owns the companion checks/audit can still delete in its transaction.
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &command), move |(s, c), tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(&[s.partition(&c.group().to_string())?])
                    .await?;
                s.execute_in(tx, operation, at(), c).await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)
        .unwrap()
        .unwrap();
    assert!(result.group.deleted);
    assert!(matches!(
        s.execute(operation, at(), &command, deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::CompanionTransactionRequired
        ))
    ));
    assert_eq!(event_count(operation), 1);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn distinct_runs_compete_on_one_revision_and_preserve_event_contract() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    assert_event(&created, "created");
    let a = builds::request(&created, None);
    let b = builds::request(&created, None);
    builds::prepare(&runtime, &s, &a, &page).await.unwrap();
    builds::prepare(&runtime, &s, &b, &page).await.unwrap();
    let (first, second) = tokio::join!(
        builds::publish(&runtime, &s, &a),
        builds::publish(&runtime, &s, &b)
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let saved = first.or(second).unwrap();
    assert_event(&saved, "members_changed");
    assert_eq!(event_count(a.id) + event_count(b.id), 1);
    let changed = s
        .execute(
            op(),
            at(),
            &Command::Edit {
                group: id,
                expected: saved.group.revision,
                name: "edited".into(),
                description: String::new(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_event(&changed, "edited");
    let deleted = execute_companion(
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
    assert_event(&deleted, "deleted");
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn concurrent_inputs_rule_changes_and_kind_boundaries() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    let request = builds::request(&created, None);
    let (a, b) = tokio::join!(
        builds::begin(&runtime, &s, &request),
        builds::begin(&runtime, &s, &request)
    );
    assert!(a.is_ok() || b.is_ok());
    assert_eq!(
        builds::begin(&runtime, &s, &request).await.unwrap().objects,
        0
    );
    let mut different = request.clone();
    different.input_version = "different".into();
    assert!(matches!(
        builds::begin(&runtime, &s, &different).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::IdentityConflict
        ))
    ));
    for invalid in [
        BuildRequest {
            id: op(),
            input_version: String::new(),
            ..request.clone()
        },
        BuildRequest {
            id: op(),
            patch: Some(MemberPatch {
                add: vec![],
                remove: vec![],
            }),
            ..request.clone()
        },
    ] {
        assert!(builds::begin(&runtime, &s, &invalid).await.is_err());
    }
    builds::prepare(&runtime, &s, &request, &page)
        .await
        .unwrap();
    let original = inputs().0;
    let view = original.view();
    let replacement = Rule::new(
        tenant(),
        "rule-2",
        view.dictionary_version,
        view.fields.values().cloned().collect(),
        view.criteria.clone(),
    )
    .unwrap();
    s.execute(
        op(),
        at(),
        &Command::SetRule {
            group: id,
            expected: created.group.revision,
            rule: replacement,
        },
        deadline(),
    )
    .await
    .unwrap();
    assert!(matches!(
        builds::publish(&runtime, &s, &request).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::VersionConflict
        ))
    ));
    assert_eq!(event_count(request.id), 0);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn atomic_event_failure_rls_and_large_member_ids() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                name: "static".into(),
                description: String::new(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = builds::request(
        &created,
        Some(MemberPatch {
            add: vec!["x".repeat(256)],
            remove: vec![],
        }),
    );
    let (_, page) = inputs();
    builds::prepare(&runtime, &s, &request, &page)
        .await
        .unwrap();
    admin(
        "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) FROM mdm_group_runtime",
    );
    let failed = builds::publish(&runtime, &s, &request).await;
    admin(
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_group_runtime",
    );
    assert!(failed.is_err());
    assert_eq!(
        s.get(id, deadline()).await.unwrap().unwrap().member_count,
        0
    );
    assert_eq!(event_count(request.id), 0);
    let result = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(result.group.member_count, 1);
    assert_eq!(
        builds::members(&runtime, &s, request.id).await.unwrap(),
        vec!["x".repeat(256)]
    );
    let invalid = builds::request(
        &result,
        Some(MemberPatch {
            add: vec!["x".repeat(257)],
            remove: vec![],
        }),
    );
    assert!(matches!(
        builds::begin(&runtime, &s, &invalid).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::InvalidInput
        ))
    ));
    let foreign_store = store(runtime.clone(), foreign()).await;
    assert!(foreign_store.get(id, deadline()).await.unwrap().is_none());
    let hidden = runtime
        .local_tx_with_context(foreign(), deadline(), &foreign_store, |store, tx| {
            Box::pin(async move { store.build_in(tx, request.id).await })
        })
        .await;
    assert!(matches!(
        hidden.fold(
            |v| v,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}")
        ),
        Err(Rejection::NotFound)
    ));
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn admitted_input_and_command_commit_unknown_recover_by_original_identity() {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let operation = op();
    let command = Command::Create {
        group: id,
        name: "unknown".into(),
        description: String::new(),
        definition: Definition::Static,
    };
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        s.execute(operation, at(), &command, deadline()).await,
        Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
    ));
    let receipt = s
        .execute(operation, at(), &command, deadline())
        .await
        .unwrap();
    assert_eq!(event_count(operation), 1);
    let request = builds::request(
        &receipt,
        Some(MemberPatch {
            add: vec!["a".into()],
            remove: vec![],
        }),
    );
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        builds::begin(&runtime, &s, &request).await,
        Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
    ));
    runtime.close().await;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (_, page) = inputs();
    builds::prepare(&runtime, &s, &request, &page)
        .await
        .unwrap();
    let first = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(
        first,
        builds::publish(&runtime, &s, &request).await.unwrap()
    );
    assert_eq!(event_count(request.id), 1);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn process_death_after_admission_recovers_without_caller_snapshot() {
    if let Ok(raw) = std::env::var("GROUP_BUILD_CHILD") {
        let request: BuildRequest = serde_json::from_str(&raw).unwrap();
        let runtime = connect_runtime().await;
        let s = store(runtime.clone(), tenant()).await;
        builds::begin(&runtime, &s, &request).await.unwrap();
        builds::settle(
            runtime
                .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                    Box::pin(async move { s.advance_static_in(tx, request.id).await })
                })
                .await,
            request.id,
        )
        .unwrap();
        std::process::exit(0);
    }
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                name: "restart".into(),
                description: String::new(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let request = builds::request(
        &created,
        Some(MemberPatch {
            add: vec!["a".into(), "b".into()],
            remove: vec![],
        }),
    );
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_death_after_admission_recovers_without_caller_snapshot",
        ])
        .env(
            "GROUP_BUILD_CHILD",
            serde_json::to_string(&request).unwrap(),
        )
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let (_, page) = inputs();
    builds::prepare(&runtime, &s, &request, &page)
        .await
        .unwrap();
    let saved = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(saved.group.member_count, 2);
    assert_eq!(event_count(request.id), 1);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn borrowed_entries_reject_same_tenant_foreign_runtime_without_events() {
    let runtime = connect_runtime().await;
    let other = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    let request = builds::request(&created, None);
    for entry in 0..11 {
        let result = other
            .local_tx_with_context(tenant(), deadline(), (&s, &request, &page), |ctx, tx| {
                Box::pin(async move {
                    match entry {
                        0 => ctx.0.begin_build_in(tx, ctx.1).await.map(|v| v.map(|_| ())),
                        1 => ctx.0.build_in(tx, ctx.1.id).await.map(|v| v.map(|_| ())),
                        2 => ctx
                            .0
                            .append_build_page_in(
                                tx,
                                ctx.1.id,
                                &PageInput {
                                    tenant: tenant(),
                                    id: "fixture",
                                    version: &ctx.1.input_version,
                                    dictionary_version: "dictionary-1",
                                    coverage: &ctx.2.coverage,
                                    objects: &ctx.2.objects,
                                    after: None,
                                },
                            )
                            .await
                            .map(|v| v.map(|_| ())),
                        3 => ctx
                            .0
                            .seal_build_in(tx, ctx.1.id, 1)
                            .await
                            .map(|v| v.map(|_| ())),
                        4 => ctx
                            .0
                            .advance_static_in(tx, ctx.1.id)
                            .await
                            .map(|v| v.map(|_| ())),
                        5 => ctx
                            .0
                            .advance_difference_in(tx, ctx.1.id)
                            .await
                            .map(|v| v.map(|_| ())),
                        6 => ctx
                            .0
                            .publish_build_in(tx, ctx.1.id)
                            .await
                            .map(|v| v.map(|_| ())),
                        7 => ctx
                            .0
                            .build_decisions_in(tx, ctx.1.id, None, 1000)
                            .await
                            .map(|v| v.map(|_| ())),
                        8 => ctx
                            .0
                            .build_changes_in(tx, ctx.1.id, None, 1000)
                            .await
                            .map(|v| v.map(|_| ())),
                        9 => ctx
                            .0
                            .current_member_set_in(tx, id)
                            .await
                            .map(|v| v.map(|_| ())),
                        _ => ctx
                            .0
                            .lock_reference_target_in(tx, id)
                            .await
                            .map(|v| v.map(|_| ())),
                    }
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
    }
    assert_eq!(event_count(request.id), 0);
    other.close().await;
    runtime.close().await;
}
