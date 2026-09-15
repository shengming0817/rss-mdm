use rss_mdm_policy_postgres::{core::*, *};
mod support;
use support::*;
fn pid() -> PolicyId {
    PolicyId::new(tenant(), unique()).unwrap()
}
fn req(p: &PolicyId, rev: u64, command: Command) -> Request {
    let r = Request {
        id: RequestId::new(tenant(), unique()).unwrap(),
        expected_storage_revision: rev,
        as_of: at(10),
        command,
    };
    assert_eq!(r.policy(), p);
    r
}
fn version(p: &PolicyId, n: u64) -> Version {
    Version::new(
        p.clone(),
        n,
        PayloadRef::new(
            PayloadId::new(tenant(), format!("{}-payload", p.value())).unwrap(),
            n,
            [n as u8; 32],
        )
        .unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap()
}
fn targets(p: &PolicyId, revision: u64, members: &[&str]) -> TargetSnapshot {
    TargetSnapshot::new(
        TargetSnapshotId::new(tenant(), p.value()).unwrap(),
        revision,
        SnapshotCompleteness::Complete,
        members
            .iter()
            .map(|s| DeviceId::new(tenant(), *s).unwrap())
            .collect(),
    )
    .unwrap()
}
async fn setup(s: &PolicyStore, p: &PolicyId) -> u64 {
    let c = req(p, 0, Command::Create { policy: p.clone() });
    s.execute(&c, deadline()).await.unwrap();
    assert_event(p.value(), c.id.value(), 1, 10);
    let a = req(
        p,
        1,
        Command::Transition {
            policy: p.clone(),
            transition: Transition::Activate(version(p, 1)),
        },
    );
    s.execute(&a, deadline()).await.unwrap();
    let t = req(
        p,
        2,
        Command::SelectTargets {
            policy: p.clone(),
            snapshot: targets(p, 1, &["a"]),
            references: vec![AssignmentReference {
                id: "assignment".into(),
                revision: 1,
            }],
        },
    );
    s.execute(&t, deadline()).await.unwrap();
    3
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn persistence_replay_aba_and_old_facts() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let p = pid();
    let mut rev = setup(&s, &p).await;
    for _ in 0..2 {
        rev = s
            .execute(
                &req(&p, rev, Command::Replan { policy: p.clone() }),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
    }
    assert_eq!(
        s.version(&p, 1, deadline()).await.unwrap(),
        Some(version(&p, 1))
    );
    assert_eq!(
        s.target_snapshot(
            &TargetSnapshotId::new(tenant(), p.value()).unwrap(),
            1,
            deadline()
        )
        .await
        .unwrap(),
        Some(targets(&p, 1, &["a"]))
    );
    let before = s.get(&p, deadline()).await.unwrap().unwrap();
    let old_id = before.current_plan_id().unwrap();
    assert!(before.plan_is_fresh());
    for (n, m) in [(2, vec!["b"]), (1, vec!["a"])] {
        rev = s
            .execute(
                &req(
                    &p,
                    rev,
                    Command::SelectTargets {
                        policy: p.clone(),
                        snapshot: targets(&p, n, &m),
                        references: before.references().to_vec(),
                    },
                ),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
    }
    assert!(
        !s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .plan_is_fresh()
    );
    let r = req(&p, rev, Command::Replan { policy: p.clone() });
    let receipt = s.execute(&r, deadline()).await.unwrap();
    assert_eq!(receipt, s.execute(&r, deadline()).await.unwrap());
    rev = receipt.storage_revision;
    assert_eq!(
        s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .current_plan_id(),
        Some(old_id)
    );
    let mut wrong = r.clone();
    wrong.as_of = at(11);
    assert!(matches!(
        s.execute(&wrong, deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    assert_eq!(
        s.execute(
            &req(&p, rev, Command::Replan { policy: p.clone() }),
            deadline()
        )
        .await
        .unwrap()
        .storage_revision,
        rev
    );
    let plan = s.plan(&p, &r.id, deadline()).await.unwrap().unwrap();
    assert_eq!(plan.request(), &r.id);
    assert_eq!(plan.as_of(), r.as_of);
    assert_eq!(
        s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .current_plan_request(),
        Some(&r.id)
    );
    assert_eq!(plan.id(), old_id);
    for progress in [Progress::Running, Progress::Planned] {
        let fact = ExecutionRecord::new(
            version(&p, 1),
            DeviceId::new(tenant(), "a").unwrap(),
            progress,
            Effect::Unverified,
        )
        .unwrap();
        rev = s
            .execute(
                &req(
                    &p,
                    rev,
                    Command::ReplaceFacts {
                        policy: p.clone(),
                        facts: vec![fact],
                    },
                ),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
        assert!(
            !s.get(&p, deadline())
                .await
                .unwrap()
                .unwrap()
                .plan_is_fresh()
        );
    }
    let before_refresh = rev;
    rev = s
        .execute(
            &req(&p, rev, Command::Replan { policy: p.clone() }),
            deadline(),
        )
        .await
        .unwrap()
        .storage_revision;
    let refreshed = s.get(&p, deadline()).await.unwrap().unwrap();
    assert_eq!(refreshed.current_plan_id(), Some(old_id));
    assert!(refreshed.plan_is_fresh());
    assert_eq!(rev, before_refresh + 1);
    rev = s
        .execute(
            &req(
                &p,
                rev,
                Command::Transition {
                    policy: p.clone(),
                    transition: Transition::Activate(version(&p, 2)),
                },
            ),
            deadline(),
        )
        .await
        .unwrap()
        .storage_revision;
    rev = s
        .execute(
            &req(&p, rev, Command::Replan { policy: p.clone() }),
            deadline(),
        )
        .await
        .unwrap()
        .storage_revision;
    let current = s
        .get(&p, deadline())
        .await
        .unwrap()
        .unwrap()
        .current_plan_id();
    let late = ExecutionRecord::new(
        version(&p, 1),
        DeviceId::new(tenant(), "a").unwrap(),
        Progress::Succeeded,
        Effect::VerifiedPresent,
    )
    .unwrap();
    s.execute(
        &req(
            &p,
            rev,
            Command::ReplaceFacts {
                policy: p.clone(),
                facts: vec![late],
            },
        ),
        deadline(),
    )
    .await
    .unwrap();
    let after = s.get(&p, deadline()).await.unwrap().unwrap();
    assert_eq!(after.current_plan_id(), current);
    assert!(!after.plan_is_fresh());
    let page = s.execution_facts(&p, None, 1, deadline()).await.unwrap();
    assert_eq!(page.records.len(), 1);
    let next = s
        .execution_facts(&p, page.next.clone(), 1, deadline())
        .await
        .unwrap();
    assert_eq!(next.records.len(), 1);
    assert_ne!(page.records[0].key(), next.records[0].key());
    let facts = s
        .execution_facts(&p, None, 100, deadline())
        .await
        .unwrap()
        .records;
    assert_eq!(
        facts
            .iter()
            .find(|f| f.version().number() == 2)
            .unwrap()
            .progress(),
        Progress::Planned
    );
    let mut refresh = req(
        &p,
        after.storage_revision(),
        Command::Replan { policy: p.clone() },
    );
    refresh.as_of = at(100);
    s.execute(&refresh, deadline()).await.unwrap();
    let installed = s.plan(&p, &refresh.id, deadline()).await.unwrap().unwrap();
    assert_eq!(installed.request(), &refresh.id);
    assert_eq!(installed.as_of(), at(100));
    let restarted = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    assert_eq!(
        restarted.operation(&r.id, deadline()).await.unwrap(),
        Some(receipt)
    );
    let foreign_store = PolicyStore::new(runtime, foreign(), deadline())
        .await
        .unwrap();
    assert!(
        foreign_store
            .get(&PolicyId::new(foreign(), p.value()).unwrap(), deadline())
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn concurrent_cas_borrowed_rollback_and_runtime_owner() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let p = pid();
    let rev = setup(&s, &p).await;
    let a = req(
        &p,
        rev,
        Command::Transition {
            policy: p.clone(),
            transition: Transition::Activate(version(&p, 2)),
        },
    );
    let b = req(
        &p,
        rev,
        Command::Transition {
            policy: p.clone(),
            transition: Transition::Activate(version(&p, 3)),
        },
    );
    let (a, b) = tokio::join!(s.execute(&a, deadline()), s.execute(&b, deadline()));
    assert_ne!(a.is_ok(), b.is_ok());
    let revision = s
        .get(&p, deadline())
        .await
        .unwrap()
        .unwrap()
        .storage_revision();
    let r = req(
        &p,
        revision,
        Command::Transition {
            policy: p.clone(),
            transition: Transition::Pause,
        },
    );
    let result = runtime
        .local_tx_with_context(tenant(), deadline(), (&s, &r), |(s, r), tx| {
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
    assert!(s.operation(&r.id, deadline()).await.unwrap().is_none());
    let other = support::runtime().await;
    let result = other
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
}
#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn outbox_failure_and_immutable_inputs() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let p = pid();
    let rev = setup(&s, &p).await;
    let bad = req(
        &p,
        rev,
        Command::SelectTargets {
            policy: p.clone(),
            snapshot: targets(&p, 1, &["different"]),
            references: vec![],
        },
    );
    assert!(matches!(
        s.execute(&bad, deadline()).await,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    sql("REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_policy_runtime");
    let r = req(&p, rev, Command::Replan { policy: p.clone() });
    let result = s.execute(&r, deadline()).await;
    sql("GRANT INSERT ON rss_transactional_messaging.outbox TO mdm_policy_runtime");
    assert!(result.is_err());
    assert!(s.operation(&r.id, deadline()).await.unwrap().is_none());
    assert_eq!(
        s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .storage_revision(),
        rev
    );
    sql("ALTER TABLE mdm_policy.aggregates NO FORCE ROW LEVEL SECURITY");
    let result = PolicyStore::new(runtime, tenant(), deadline()).await;
    sql("ALTER TABLE mdm_policy.aggregates FORCE ROW LEVEL SECURITY");
    assert!(result.is_err());
    assert_eq!(
        sql(
            "SELECT count(*) FROM mdm_policy.aggregates WHERE tenant_id='22222222-2222-2222-2222-222222222222'"
        ),
        "0"
    );
}

fn assert_event(id: &str, request: &str, revision: u64, occurred_at: i64) {
    use sha2::{Digest, Sha256};
    let message_id = format!("policy.v1:{request}");
    let envelope: serde_json::Value = serde_json::from_str(&sql(&format!(
        "SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id='{}' AND message_id='{}'",
        tenant(), message_id
    ))).unwrap();
    assert_eq!(envelope["tenant"], tenant().to_string());
    assert_eq!(envelope["occurred_at"], occurred_at);
    assert_eq!(envelope["domain"], "mdm-policy");
    assert_eq!(envelope["route"], "policy.changed");
    assert_eq!(envelope["contract"], "mdm.policy.changed");
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
#[ignore = "real PostgreSQL: backend-t2"]
async fn fact_pages_preserve_boundaries_and_reject_foreign_documents() {
    use sha2::{Digest, Sha256};
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let p = pid();
    s.execute(
        &req(&p, 0, Command::Create { policy: p.clone() }),
        deadline(),
    )
    .await
    .unwrap();
    let empty = s.execution_facts(&p, None, 2, deadline()).await.unwrap();
    assert!(empty.records.is_empty() && empty.next.is_none());
    s.execute(
        &req(
            &p,
            1,
            Command::Transition {
                policy: p.clone(),
                transition: Transition::Activate(version(&p, 1)),
            },
        ),
        deadline(),
    )
    .await
    .unwrap();
    let mut rev = 2;
    for count in 1..=3 {
        let devices = (0..count).map(|n| format!("d{n}")).collect::<Vec<_>>();
        let members = devices.iter().map(String::as_str).collect::<Vec<_>>();
        rev = s
            .execute(
                &req(
                    &p,
                    rev,
                    Command::SelectTargets {
                        policy: p.clone(),
                        snapshot: targets(&p, count as u64, &members),
                        references: vec![],
                    },
                ),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
        rev = s
            .execute(
                &req(&p, rev, Command::Replan { policy: p.clone() }),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
        let page = s.execution_facts(&p, None, 2, deadline()).await.unwrap();
        assert_eq!(page.records.len(), count.min(2));
        assert_eq!(page.next.is_some(), count > 2);
    }
    let all = s.execution_facts(&p, None, 1000, deadline()).await.unwrap();
    let mut next = None;
    let mut keys = Vec::new();
    loop {
        let page = s.execution_facts(&p, next, 1, deadline()).await.unwrap();
        keys.extend(page.records.iter().map(|r| r.key().clone()));
        next = page.next;
        if next.is_none() {
            break;
        }
    }
    assert_eq!(
        keys,
        all.records
            .iter()
            .map(|r| r.key().clone())
            .collect::<Vec<_>>()
    );
    assert!(
        s.execution_facts(&p, Some("zzzz".into()), 2, deadline())
            .await
            .unwrap()
            .records
            .is_empty()
    );
    for limit in [0, 1001] {
        assert!(matches!(
            s.execution_facts(&p, None, limit, deadline()).await,
            Err(Error::Rejected(Rejection::InvalidInput))
        ));
    }
    assert!(
        s.execution_facts(&p, Some("x".repeat(513)), 2, deadline())
            .await
            .is_err()
    );
    assert!(
        s.execution_facts(
            &PolicyId::new(foreign(), p.value()).unwrap(),
            None,
            2,
            deadline()
        )
        .await
        .is_err()
    );
    let foreign_store = PolicyStore::new(runtime, foreign(), deadline())
        .await
        .unwrap();
    assert!(
        foreign_store
            .execution_facts(
                &PolicyId::new(foreign(), p.value()).unwrap(),
                None,
                2,
                deadline()
            )
            .await
            .unwrap()
            .records
            .is_empty()
    );
    // Corrupt the lookahead record with valid JSON/core data and a matching digest.
    // It must be checked before truncation, even though it is not returned on this page.
    let original = sql(&format!(
        "SELECT convert_from(document,'UTF8') FROM mdm_policy.facts WHERE tenant_id='{}' AND owner='{}' AND key='1/d2'",
        tenant(),
        p.value()
    ));
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    for (field, value) in [(0, foreign().to_string()), (1, "other-policy".into())] {
        let mut document: serde_json::Value = serde_json::from_str(&original).unwrap();
        document[0][field] = serde_json::Value::String(value);
        let bytes = serde_json::to_vec(&document).unwrap();
        sql(&format!(
            "UPDATE mdm_policy.facts SET document=decode('{}','hex'),digest=decode('{}','hex') WHERE tenant_id='{}' AND owner='{}' AND key='1/d2'",
            hex(&bytes),
            hex(&Sha256::digest(&bytes)),
            tenant(),
            p.value()
        ));
        let result = s.execution_facts(&p, None, 2, deadline()).await;
        sql(&format!(
            "UPDATE mdm_policy.facts SET document=decode('{}','hex'),digest=decode('{}','hex') WHERE tenant_id='{}' AND owner='{}' AND key='1/d2'",
            hex(original.as_bytes()),
            hex(&Sha256::digest(original.as_bytes())),
            tenant(),
            p.value()
        ));
        assert!(result.is_err());
    }
    // Policy-specific column grants must remain exact after sharing admission.
    sql("REVOKE UPDATE(document) ON mdm_policy.facts FROM mdm_policy_runtime");
    let bad = PolicyStore::new(support::runtime().await, tenant(), deadline()).await;
    sql("GRANT UPDATE(document) ON mdm_policy.facts TO mdm_policy_runtime");
    assert!(bad.is_err());
}
