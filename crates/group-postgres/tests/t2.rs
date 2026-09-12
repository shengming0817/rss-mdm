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

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn distinct_runs_compete_on_one_revision_and_preserve_event_contract() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, snapshot) = dynamic_group(&s).await;
    assert_event(&created, "created");
    let mut a = request(id, &created, snapshot.clone());
    a.trigger = Trigger::Periodic {
        slot: "slot-1".into(),
    };
    let mut b = request(id, &created, snapshot);
    b.snapshot.objects[0].key = ObjectKey::new(tenant(), "device-2").unwrap();
    b.trigger = Trigger::Change {
        source: "inventory".into(),
        event: "event-1".into(),
    };
    let (first, second) = tokio::join!(
        s.start_recalculation(&a, deadline()),
        s.start_recalculation(&b, deadline())
    );
    first.unwrap();
    second.unwrap();
    let (first, second) = tokio::join!(s.resume(a.id, deadline()), s.resume(b.id, deadline()));
    let states = [first.unwrap().state, second.unwrap().state];
    assert_eq!(
        states
            .iter()
            .filter(|s| matches!(s, RunState::Rejected(Rejection::VersionConflict)))
            .count(),
        1
    );
    let receipt = states
        .iter()
        .find_map(|s| {
            if let RunState::Completed(r) = s {
                Some(r)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(
        receipt.group.revision.get(),
        created.group.revision.get() + 1
    );
    assert_eq!(s.members(id, deadline()).await.unwrap().len(), 1);
    assert_eq!(event_count(a.id) + event_count(b.id), 1);
    assert_event(receipt, "members_changed");
    let edited = s
        .execute(
            op(),
            at(),
            &Command::Edit {
                group: id,
                expected: receipt.group.revision,
                name: "renamed".into(),
                description: "description".into(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_event(&edited, "edited");
    let deleted = s
        .execute(
            op(),
            at(),
            &Command::Delete {
                group: id,
                expected: edited.group.revision,
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_event(&deleted, "deleted");
    runtime.close().await;
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
        let mut deletion = Box::pin(s.execute(op(), at(), &command, deadline()));
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
async fn dynamic_group(s: &GroupStore) -> (GroupId, Receipt, Snapshot) {
    let (rule, snapshot) = inputs();
    let id = group_id();
    let r = s
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
    (id, r, snapshot)
}
fn request(id: GroupId, r: &Receipt, snapshot: Snapshot) -> RecalculationRequest {
    RecalculationRequest {
        id: op(),
        group: id,
        expected: r.group.revision,
        rule_version: r.group.rule_version.clone().unwrap(),
        trigger: Trigger::Manual,
        snapshot,
        as_of: at(),
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn concurrent_inputs_rule_changes_and_kind_boundaries() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let command = Command::Create {
        group: id,
        name: "same".into(),
        description: "".into(),
        definition: Definition::Static,
    };
    let operation = op();
    let (a, b) = tokio::join!(
        s.execute(operation, at(), &command, deadline()),
        s.execute(operation, at(), &command, deadline())
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(event_count(operation), 1);
    let (id, created, snapshot) = dynamic_group(&s).await;
    let pending = request(id, &created, snapshot.clone());
    for trigger in [
        Trigger::Periodic { slot: " ".into() },
        Trigger::Change {
            source: "invalid\nsource".into(),
            event: "e".into(),
        },
        Trigger::Periodic {
            slot: "x".repeat(4097),
        },
    ] {
        let invalid = RecalculationRequest {
            id: op(),
            trigger,
            ..pending.clone()
        };
        assert!(matches!(
            s.start_recalculation(&invalid, deadline()).await,
            Err(rss_mdm_group_postgres::Error::Rejected(
                Rejection::InvalidInput
            ))
        ));
        assert!(s.get_run(invalid.id, deadline()).await.unwrap().is_none());
    }
    let (a, b) = tokio::join!(
        s.start_recalculation(&pending, deadline()),
        s.start_recalculation(&pending, deadline())
    );
    assert_eq!(a.unwrap(), b.unwrap());
    let (a, b) = tokio::join!(
        s.resume(pending.id, deadline()),
        s.resume(pending.id, deadline())
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(event_count(pending.id), 1);
    let current = s.get(id, deadline()).await.unwrap().unwrap();
    let mut changed = pending.clone();
    changed.snapshot.version = "changed".into();
    assert!(matches!(
        s.start_recalculation(&changed, deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::IdentityConflict
        ))
    ));
    let manual = Command::Members {
        group: id,
        expected: current.revision,
        add: vec!["x".into()],
        remove: vec![],
    };
    assert!(matches!(
        s.execute(op(), at(), &manual, deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::KindMismatch
        ))
    ));
    let mut partial = pending.clone();
    partial.id = op();
    partial.expected = current.revision;
    partial.snapshot.complete = false;
    assert!(matches!(
        s.start_recalculation(&partial, deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::IncompleteSnapshot
        ))
    ));
    assert!(
        s.preview(id, current.revision, &partial.snapshot, at(), deadline())
            .await
            .is_ok()
    );
    let mut next = pending.clone();
    next.id = op();
    next.expected = current.revision;
    s.start_recalculation(&next, deadline()).await.unwrap();
    let (old, _) = inputs();
    let v = old.view();
    let new_rule = Rule::new(
        tenant(),
        "rule-2",
        v.dictionary_version,
        v.fields.values().cloned().collect(),
        v.criteria.clone(),
    )
    .unwrap();
    s.execute(
        op(),
        at(),
        &Command::SetRule {
            group: id,
            expected: current.revision,
            rule: new_rule,
        },
        deadline(),
    )
    .await
    .unwrap();
    assert!(matches!(
        s.resume(next.id, deadline()).await.unwrap().state,
        RunState::Rejected(Rejection::VersionConflict)
    ));
    assert_eq!(event_count(next.id), 0);
    let current = s.get(id, deadline()).await.unwrap().unwrap();
    let mut deleted = pending.clone();
    deleted.id = op();
    deleted.expected = current.revision;
    deleted.rule_version = "rule-2".into();
    s.start_recalculation(&deleted, deadline()).await.unwrap();
    s.execute(
        op(),
        at(),
        &Command::Delete {
            group: id,
            expected: current.revision,
        },
        deadline(),
    )
    .await
    .unwrap();
    assert!(matches!(
        s.resume(deleted.id, deadline()).await.unwrap().state,
        RunState::Rejected(Rejection::Deleted)
    ));
    assert_eq!(
        s.result(pending.id, deadline())
            .await
            .unwrap()
            .unwrap()
            .evaluation
            .objects[0]
            .decision,
        Decision::Match
    );
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn atomic_event_failure_rls_and_large_member_ids() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let r = s
        .execute(
            op(),
            at(),
            &Command::Create {
                group: id,
                name: "static".into(),
                description: "".into(),
                definition: Definition::Static,
            },
            deadline(),
        )
        .await
        .unwrap();
    let operation = op();
    let change = Command::Members {
        group: id,
        expected: r.group.revision,
        add: vec!["设".repeat(1365), "b".into()],
        remove: vec![],
    };
    admin("REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_group_runtime");
    let failed = s.execute(operation, at(), &change, deadline()).await;
    admin("GRANT INSERT ON rss_transactional_messaging.outbox TO mdm_group_runtime");
    assert!(failed.is_err());
    assert_eq!(s.get(id, deadline()).await.unwrap().unwrap(), r.group);
    assert_eq!(event_count(operation), 0);
    let success = s
        .execute(operation, at(), &change, deadline())
        .await
        .unwrap();
    assert_eq!(success.added, 2);
    let page = s.delta(operation, None, 1, deadline()).await.unwrap();
    assert_eq!(page.added.len(), 1);
    let next = s.delta(operation, page.next, 1, deadline()).await.unwrap();
    assert_eq!(next.added[0].len(), 4095);
    assert_eq!(
        admin("SET ROLE mdm_group_runtime; SELECT count(*) FROM mdm_group.groups")
            .lines()
            .last()
            .unwrap(),
        "0"
    );
    assert_eq!(admin(&format!("SET ROLE mdm_group_runtime; SET rss.tenant_id='{}'; SELECT count(*) FROM mdm_group.groups WHERE id='{id}'",foreign())).lines().last().unwrap(),"0");
    admin("ALTER TABLE mdm_group.members NO FORCE ROW LEVEL SECURITY");
    let rejected = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
    admin("ALTER TABLE mdm_group.members FORCE ROW LEVEL SECURITY");
    assert!(rejected.is_err());
    admin(
        "CREATE FUNCTION mdm_group.role_drift() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
    );
    let rejected = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
    admin("DROP FUNCTION mdm_group.role_drift()");
    assert!(rejected.is_err(), "executable schema drift was admitted");
    admin("CREATE VIEW mdm_group.extra_view AS SELECT 1 AS value");
    let rejected = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
    admin("DROP VIEW mdm_group.extra_view");
    assert!(rejected.is_err(), "extra relation was admitted");
    // Force an error AFTER the event and group update; neither may survive.
    admin(&format!(
        "CREATE FUNCTION public.reject_group_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.group_id='{id}'::uuid AND NEW.object_id='fail' THEN RAISE EXCEPTION 'fixture member rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER t2_fail BEFORE INSERT ON mdm_group.members FOR EACH ROW EXECUTE FUNCTION public.reject_group_member();"
    ));
    let bad = op();
    let failed = s
        .execute(
            bad,
            at(),
            &Command::Members {
                group: id,
                expected: success.group.revision,
                add: vec!["fail".into()],
                remove: vec!["b".into()],
            },
            deadline(),
        )
        .await;
    admin("DROP TRIGGER t2_fail ON mdm_group.members; DROP FUNCTION public.reject_group_member()");
    assert!(failed.is_err());
    assert_eq!(s.get(id, deadline()).await.unwrap().unwrap(), success.group);
    assert_eq!(event_count(bad), 0);
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
        description: "".into(),
        definition: Definition::Static,
    };
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        s.execute(operation, at(), &command, deadline()).await,
        Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
    ));
    let first = s
        .execute(operation, at(), &command, deadline())
        .await
        .unwrap();
    assert_eq!(event_count(operation), 1);
    assert_eq!(first.group.id, id);
    let (id, created, snapshot) = dynamic_group(&s).await;
    let request = request(id, &created, snapshot);
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        s.start_recalculation(&request, deadline()).await,
        Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
    ));
    runtime.close().await;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    assert!(
        s.recoverable(None, 1000, deadline())
            .await
            .unwrap()
            .contains(&request.id)
    );
    assert!(matches!(
        s.resume(request.id, deadline()).await.unwrap().state,
        RunState::Completed(_)
    ));
    assert_eq!(event_count(request.id), 1);
    assert!(matches!(
        s.resume(op(), deadline()).await,
        Err(rss_mdm_group_postgres::Error::Rejected(Rejection::NotFound))
    ));
    runtime.close().await;
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by hack/group-t2.py"]
async fn process_death_after_admission_recovers_without_caller_snapshot() {
    if let Ok(path) = std::env::var("GROUP_RECOVERY_CHILD") {
        let runtime = connect_runtime().await;
        let s = store(runtime, tenant()).await;
        let (id, created, snapshot) = dynamic_group(&s).await;
        let request = request(id, &created, snapshot);
        s.start_recalculation(&request, deadline()).await.unwrap();
        std::fs::write(path, request.id.to_string()).unwrap();
        // Parent kills this process after the admission acknowledgement. Bound the
        // fixture lifetime even if its parent exits before killing it.
        tokio::time::sleep(Duration::from_secs(30)).await;
        panic!("parent did not kill admitted process");
    }
    let path = std::path::PathBuf::from(std::env::var("GROUP_PG_CONFIG").unwrap())
        .with_file_name(format!("recovery-{}", op()));
    let mut child = ChildGuard(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_death_after_admission_recovers_without_caller_snapshot",
            ])
            .env("GROUP_RECOVERY_CHILD", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        while !path.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "admission child exited early"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let id = OperationId::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    assert!(
        s.recoverable(None, 1000, deadline())
            .await
            .unwrap()
            .contains(&id)
    );
    assert!(matches!(
        s.resume(id, deadline()).await.unwrap().state,
        RunState::Completed(_)
    ));
    assert_eq!(
        s.result(id, deadline())
            .await
            .unwrap()
            .unwrap()
            .evaluation
            .objects[0]
            .decision,
        Decision::Match
    );
    assert_eq!(event_count(id), 1);
    runtime.close().await;
}

// TLS remains end-to-end. The fixture only discards server traffic after COMMIT
// has entered a deferred database trigger; no SQL/protocol internals are mocked.
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
    let (id, created, snapshot) = dynamic_group(&s).await;
    let request = request(id, &created, snapshot);
    s.start_recalculation(&request, deadline()).await.unwrap();
    admin(&format!(
        "CREATE FUNCTION public.hold_group_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(238701); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER t2_hold_commit AFTER UPDATE ON mdm_group.operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id='{}'::uuid AND NEW.state='completed') EXECUTE FUNCTION public.hold_group_commit();",
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
    let mut resume = Box::pin(s.resume(request.id, deadline()));
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
        "DROP TRIGGER t2_hold_commit ON mdm_group.operations; DROP FUNCTION public.hold_group_commit()",
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
            "SELECT state FROM mdm_group.operations WHERE id='{}'",
            request.id
        )),
        "completed"
    );
    runtime.close().await;
    drop(proxy);
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let first = s.resume(request.id, deadline()).await.unwrap();
    assert!(matches!(first.state, RunState::Completed(_)));
    assert_eq!(first, s.resume(request.id, deadline()).await.unwrap());
    assert_eq!(s.members(id, deadline()).await.unwrap().len(), 1);
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
        "ALTER TABLE mdm_group.operations DROP COLUMN result_digest CASCADE",
        "ALTER TABLE mdm_group.groups ALTER COLUMN name TYPE varchar",
        "ALTER TABLE mdm_group.operations ALTER COLUMN request DROP NOT NULL",
        "ALTER TABLE mdm_group.groups ALTER COLUMN deleted SET DEFAULT true",
        "ALTER TABLE mdm_group.operations DROP CONSTRAINT operations_state_check",
        "ALTER TABLE mdm_group.members DROP CONSTRAINT members_tenant_id_group_id_fkey",
        "ALTER TABLE mdm_group.deltas DROP CONSTRAINT deltas_pkey",
        "DROP INDEX mdm_group.recoverable",
        "DROP INDEX mdm_group.recoverable; CREATE INDEX recoverable ON mdm_group.operations(tenant_id,id) WHERE state='completed'",
        "ALTER TABLE mdm_group.operations ADD COLUMN unexpected text",
        "UPDATE pg_index SET indisvalid=false WHERE indexrelid='mdm_group.recoverable'::regclass",
        "UPDATE pg_index SET indisready=false WHERE indexrelid='mdm_group.recoverable'::regclass",
        "UPDATE pg_index SET indislive=false WHERE indexrelid='mdm_group.recoverable'::regclass",
    ] {
        GroupStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        admin(mutation);
        let result = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
        // Restore before asserting so a failing case cannot contaminate later tests.
        admin(&format!(
            "ALTER ROLE mdm_group_runtime NOBYPASSRLS; UPDATE pg_index SET indisvalid=true,indisready=true,indislive=true WHERE indexrelid=to_regclass('mdm_group.recoverable'); DROP SCHEMA mdm_group CASCADE; SET ROLE mdm_group_owner; {MIGRATION_SQL}"
        ));
        assert!(result.is_err(), "accepted drift: {mutation}");
    }
    runtime.close().await;
}
