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
            config["database"].as_str().unwrap(),
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
    admin(&format!("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='group.changed.v1:{id}'", tenant())).parse().unwrap()
}
fn assert_event(r: &Receipt, kind: &str) {
    use serde_json::json;
    use sha2::Digest;
    let e: serde_json::Value = serde_json::from_str(&admin(&format!(
        "SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='group.changed.v1:{}'", tenant(), r.operation))).unwrap();
    assert_eq!(e["tenant"], tenant().to_string());
    assert_eq!(e["occurred_at"], at().unix_seconds());
    assert_eq!(e["domain"], "mdm-group");
    assert_eq!(e["route"], "group.changed");
    assert_eq!(e["contract"], "mdm.group.changed");
    assert_eq!(e["version"], "v1");
    assert_eq!(e["partition"], r.group.id.to_string());
    let ordinal: i64 = admin(&format!("SELECT partition_seq FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='group.changed.v1:{}'", tenant(), r.operation)).parse().unwrap();
    // Message ordering and authored configuration CAS are distinct coordinates:
    // member publication emits an event without editing the group definition.
    assert!(ordinal > 0);
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
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group,
                presentation: serde_json::json!({"name":"dynamic","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
                definition: Definition::Dynamic(Box::new(rule)),
            },
            deadline(),
        )
        .await
        .unwrap();
    (group, receipt, page)
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn reference_target_lock_serializes_deletion() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, _) = dynamic_group(&s).await;
    let (locked, wait_locked) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let holding = runtime.local_tx_with_context(tenant(), deadline(), &s, move |s, tx| {
        Box::pin(async move {
            assert_eq!(s.lock_reference_target_in(tx, id).await?.unwrap().id, id);
            let pid = tx
                .with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            locked.send(pid).unwrap();
            wait_release.await.unwrap();
            Ok(())
        })
    });
    let deleting = async {
        let holder = wait_locked.await.unwrap();
        let command = Command::Delete {
            group: id,
            expected: created.group.revision,
        };
        let mut deletion = Box::pin(execute_companion(&runtime, &s, op(), &command));
        tokio::select! {
            result = &mut deletion => panic!("delete bypassed reference lock: {result:?}"),
            observed = tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    if admin(&format!("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND {holder}=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked")) != "0" { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }) => { observed.expect("delete never waited on reference holder"); }
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
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
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
    let holder_name = case::name("group-ack-holder");
    let holder_sql = format!(
        "SET application_name='{holder_name}'; SELECT pg_advisory_lock(238701); SELECT pg_sleep(30)"
    );
    let _holder = ChildGuard(
        std::process::Command::new("docker")
            .args([
                "exec",
                config["container"].as_str().unwrap(),
                "psql",
                "-At",
                "-U",
                "postgres",
                "-d",
                config["database"].as_str().unwrap(),
                "-c",
                &holder_sql,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while admin(
            "SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=238701 AND granted",
        ) != "1"
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let holder_pid: u32 = admin(&format!("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='{holder_name}'")).parse().unwrap();
    let mut resume = Box::pin(builds::publish(&runtime, &s, &request));
    let at_commit = async {
        loop {
            if admin(
                "SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=238701 AND NOT granted",
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
    admin(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND pid={holder_pid} AND application_name='{holder_name}'"
    ));
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
        builds::members(&runtime, &s, request.id).await.unwrap(),
        vec!["device-1"]
    );
    assert_eq!(event_count(request.id), 1);
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn admission_rejects_missing_keys_and_unsafe_authority() {
    let runtime = connect_runtime().await;
    for (mutation, restore) in [
        (
            "GRANT CREATE ON SCHEMA mdm_group TO mdm_group_runtime",
            "REVOKE CREATE ON SCHEMA mdm_group FROM mdm_group_runtime",
        ),
        (
            "GRANT TRUNCATE ON mdm_group.groups TO mdm_group_runtime",
            "REVOKE TRUNCATE ON mdm_group.groups FROM mdm_group_runtime",
        ),
        (
            "GRANT UPDATE(id) ON mdm_group.groups TO mdm_group_runtime",
            "REVOKE UPDATE(id) ON mdm_group.groups FROM mdm_group_runtime",
        ),
        (
            "GRANT SELECT ON mdm_group.groups TO PUBLIC",
            "REVOKE SELECT ON mdm_group.groups FROM PUBLIC",
        ),
        (
            "GRANT SELECT ON mdm_group.groups TO mdm_group_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON mdm_group.groups FROM mdm_group_runtime",
        ),
        (
            "ALTER POLICY tenant ON mdm_group.groups USING (true)",
            "DROP POLICY tenant ON mdm_group.groups; CREATE POLICY tenant ON mdm_group.groups USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "ALTER POLICY tenant ON mdm_group.groups WITH CHECK (true)",
            "DROP POLICY tenant ON mdm_group.groups; CREATE POLICY tenant ON mdm_group.groups USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE POLICY extra ON mdm_group.groups USING (true)",
            "DROP POLICY extra ON mdm_group.groups",
        ),
        (
            "ALTER ROLE mdm_group_runtime BYPASSRLS",
            "ALTER ROLE mdm_group_runtime NOBYPASSRLS",
        ),
        (
            "ALTER TABLE mdm_group.operations ALTER COLUMN request DROP NOT NULL",
            "ALTER TABLE mdm_group.operations ALTER COLUMN request SET NOT NULL",
        ),
        (
            "ALTER TABLE mdm_group.member_rows DROP CONSTRAINT member_rows_tenant_id_run_id_fkey",
            "ALTER TABLE mdm_group.member_rows ADD CONSTRAINT member_rows_tenant_id_run_id_fkey FOREIGN KEY(tenant_id,run_id) REFERENCES mdm_group.member_runs(tenant_id,id)",
        ),
        (
            "ALTER TABLE mdm_group.member_changes DROP CONSTRAINT member_changes_pkey",
            "ALTER TABLE mdm_group.member_changes ADD CONSTRAINT member_changes_pkey PRIMARY KEY(tenant_id,run_id,object_id)",
        ),
    ] {
        GroupStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap();
        admin(mutation);
        let result = GroupStore::new(runtime.clone(), tenant(), deadline()).await;
        // Restore before asserting so a failing case cannot contaminate later tests.
        admin(restore);
        assert!(
            matches!(result, Err(rss_mdm_group_postgres::Error::RolledBack(ref e)) if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant),
            "accepted or unrelated drift failure: {mutation}"
        );
        GroupStore::new(runtime.clone(), tenant(), deadline())
            .await
            .unwrap_or_else(|e| panic!("restore {restore}: {e:?}"));
    }
    runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn standalone_delete_requires_companion_transaction() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group: id,
                presentation: serde_json::json!({"name":"delete-boundary","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
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
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn distinct_runs_compete_on_one_revision_and_preserve_event_contract() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    assert_event(&created, "created");
    let a = builds::request(&created, None);
    let b = builds::request(&created, None);
    builds::prepare(&runtime, &s, &a, &page).await.unwrap();
    builds::prepare(&runtime, &s, &b, &page).await.unwrap();
    let (locked, wait_locked) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let holding = runtime.local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
        Box::pin(async move {
            s.lock_reference_target_in(tx, id).await?.unwrap();
            let pid = tx
                .with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            locked.send(pid).unwrap();
            wait_release.await.unwrap();
            Ok(())
        })
    });
    let competing = async {
        let holder = wait_locked.await.unwrap();
        let observe = async {
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    if admin(&format!("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND {holder}=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked")).parse::<usize>().unwrap() >= 2 { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("both operations must wait on the target row");
            release.send(()).unwrap();
        };
        let (a, b, ()) = tokio::join!(
            builds::publish(&runtime, &s, &a),
            builds::publish(&runtime, &s, &b),
            observe
        );
        (a, b)
    };
    let (held, (first, second)) = tokio::join!(holding, competing);
    held.fold(
        |_| (),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let (saved, rejected) = match first {
        Ok(winner) => (winner, second),
        Err(error) => (second.unwrap(), Err(error)),
    };
    assert!(matches!(
        rejected,
        Err(rss_mdm_group_postgres::Error::Rejected(
            Rejection::VersionConflict
        ))
    ));
    assert_event(&saved, "members_changed");
    assert_eq!(event_count(a.id) + event_count(b.id), 1);
    let changed = s
        .execute(
            op(),
            at(),
            &Command::Edit {
                group: id,
                expected: saved.group.revision,
                presentation: serde_json::json!({"name":"edited","description":"","vendor":{"help":"retained"}}).as_object().unwrap().clone(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_event(&changed, "edited");
    assert_eq!(changed.group.member_version, saved.group.member_version);
    assert_eq!(changed.group.presentation["vendor"]["help"], "retained");

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
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn concurrent_inputs_rule_changes_and_kind_boundaries() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    let request = builds::request(&created, None);
    let (locked, wait_locked) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let holding = runtime.local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
        Box::pin(async move {
            s.lock_reference_target_in(tx, id).await?.unwrap();
            let pid = tx
                .with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            locked.send(pid).unwrap();
            wait_release.await.unwrap();
            Ok(())
        })
    });
    let competing = async {
        let holder = wait_locked.await.unwrap();
        let observe = async {
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    if admin(&format!("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND {holder}=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked")).parse::<usize>().unwrap() >= 2 { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("both operations must wait on the target row");
            release.send(()).unwrap();
        };
        let (a, b, ()) = tokio::join!(
            builds::begin(&runtime, &s, &request),
            builds::begin(&runtime, &s, &request),
            observe
        );
        (a, b)
    };
    let (held, (a, b)) = tokio::join!(holding, competing);
    held.fold(
        |_| (),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
        |e| panic!("{e:?}"),
    );
    for build in [a.unwrap(), b.unwrap()] {
        assert_eq!(build.request.id, request.id);
        assert_eq!(build.objects, 0);
        assert!(!build.input_sealed && !build.ready && build.receipt.is_none());
    }
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
            sources: vec![],
            id: op(),
            input_version: String::new(),
            ..request.clone()
        },
        BuildRequest {
            sources: vec![],
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
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn atomic_event_failure_rls_and_large_member_ids() {
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let created = s
        .execute(
            op(),
            at(),
            &Command::Create {
                asset_context: rss_mdm_group::AssetContext::Endpoint,
                group: id,
                presentation: serde_json::json!({"name":"static","description":""})
                    .as_object()
                    .unwrap()
                    .clone(),
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
    assert!(
        matches!(failed, Err(rss_mdm_group_postgres::Error::RolledBack(ref e)) if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Permanent),
        "{failed:?}"
    );
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
    for (bound, expected) in [(tenant(), 1_i64), (foreign(), 0)] {
        let visible = runtime
            .local_tx_with_context(bound, deadline(), &s, |_, tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, i64>(
                                "SELECT count(*) FROM mdm_group.groups WHERE id=$1::uuid",
                            )
                            .bind(id.to_string())
                            .fetch_one(c)
                            .await
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                |v| v,
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
                |e| panic!("{e:?}"),
            );
        assert_eq!(
            visible, expected,
            "RLS must hide the row without a tenant predicate"
        );
    }
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
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn admitted_input_and_command_commit_unknown_recover_by_original_identity() {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let runtime = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let id = group_id();
    let operation = op();
    let command = Command::Create {
        asset_context: rss_mdm_group::AssetContext::Endpoint,
        group: id,
        presentation: serde_json::json!({"name":"unknown","description":""})
            .as_object()
            .unwrap()
            .clone(),
        definition: Definition::Static,
    };
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        s.execute(operation, at(), &command, deadline()).await,
        Err(rss_mdm_group_postgres::Error::CommitUnknown { .. })
    ));
    assert_eq!(s.get(id, deadline()).await.unwrap().unwrap().id, id);
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
    let stored = builds::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.build_in(tx, request.id).await })
            })
            .await,
        request.id,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&stored.request).unwrap(),
        serde_json::to_value(&request).unwrap()
    );
    assert!(!stored.input_sealed && !stored.ready && stored.receipt.is_none());
    let request = stored.request.clone();
    builds::resume(&runtime, &s, stored, &page).await.unwrap();
    let first = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(
        first,
        builds::publish(&runtime, &s, &request).await.unwrap()
    );
    assert_eq!(event_count(request.id), 1);
    assert_eq!(
        builds::members(&runtime, &s, request.id).await.unwrap(),
        vec!["a"]
    );
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
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
    runtime.local_tx(tenant(), deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.groups(tenant_id,id,kind,presentation,revision,member_version,member_count,deleted,calculation_revision,asset_context) VALUES($1::uuid,$2::uuid,'static',$3,1,0,0,false,0,'endpoint')")
                .bind(tenant().to_string()).bind(id.to_string()).bind(serde_json::json!({"name":"restart","description":""})).execute(c).await?;
            Ok(())
        })).await
    })).await.fold(|_| (), |e| panic!("{e}"), |e| panic!("{e}"), |e| panic!("{e}"), |e| panic!("{e}"), |e| panic!("{e}"));
    let snapshot = s.get(id, deadline()).await.unwrap().unwrap();
    let request = builds::request(
        &Receipt {
            operation: op(),
            group: snapshot,
            added: 0,
            removed: 0,
        },
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
    let stored = builds::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), &s, |s, tx| {
                Box::pin(async move { s.build_in(tx, request.id).await })
            })
            .await,
        request.id,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&stored.request).unwrap(),
        serde_json::to_value(&request).unwrap()
    );
    assert!(stored.input_sealed && stored.receipt.is_none());
    assert_eq!(stored.request.patch.as_ref().unwrap().add, vec!["a", "b"]);
    let request = stored.request.clone();
    builds::resume(&runtime, &s, stored, &page).await.unwrap();
    let saved = builds::publish(&runtime, &s, &request).await.unwrap();
    assert_eq!(saved.group.member_count, 2);
    assert_eq!(
        builds::members(&runtime, &s, request.id).await.unwrap(),
        vec!["a", "b"]
    );
    assert_eq!(event_count(request.id), 1);
    runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; executed by make t2 MODULE=group.persistence"]
async fn borrowed_entries_reject_same_tenant_foreign_runtime_without_events() {
    let runtime = connect_runtime().await;
    let other = connect_runtime().await;
    let s = store(runtime.clone(), tenant()).await;
    let (id, created, page) = dynamic_group(&s).await;
    let request = builds::request(&created, None);
    for entry in 0..12 {
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
                        10 => ctx
                            .0
                            .affected_groups_in(tx, &[], true, None, 1)
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
            |e| {
                assert!(
                    e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Invariant,
                    "{e:?}"
                );
                true
            },
            |_| false,
            |_| false,
            |_| false
        ));
    }
    assert_eq!(event_count(request.id), 0);
    assert_eq!(
        admin(&format!(
            "SELECT count(*) FROM mdm_group.member_runs WHERE tenant_id='{}' AND id='{}'",
            tenant(),
            request.id
        )),
        "0"
    );
    assert_eq!(
        builds::begin(&runtime, &s, &request)
            .await
            .unwrap()
            .request
            .id,
        request.id
    );
    other.close().await;
    runtime.close().await;
}

use rss_mdm_group::{GroupId, OperationId};
