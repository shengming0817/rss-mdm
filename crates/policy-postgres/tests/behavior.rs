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
async fn setup(s: &PolicyStore, p: &PolicyId) -> u64 {
    s.execute(
        &req(p, 0, Command::Create { policy: p.clone() }),
        deadline(),
    )
    .await
    .unwrap();
    s.execute(
        &req(
            p,
            1,
            Command::Transition {
                policy: p.clone(),
                transition: Transition::Activate(version(p, 1)),
            },
        ),
        deadline(),
    )
    .await
    .unwrap()
    .storage_revision
}
#[path = "support/planning.rs"]
mod planning;
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
                tx.prepare_outbox_partitions(&[s.partition(r.policy().value())?])
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
async fn admission_rejects_noninherited_switchable_privileges() {
    let runtime = runtime().await;
    let role = format!("acl_{}", unique().replace('-', "_"));
    let bridge = format!("{role}_bridge");
    sql(&format!(
        "CREATE ROLE {role} NOLOGIN; CREATE ROLE {bridge} NOLOGIN; GRANT {role} TO {bridge} WITH INHERIT FALSE, SET TRUE; GRANT {bridge} TO mdm_policy_runtime WITH INHERIT FALSE, SET TRUE; GRANT USAGE ON SCHEMA mdm_policy TO {role};"
    ));
    for membership in ["INHERIT FALSE, SET TRUE", "INHERIT TRUE, SET FALSE"] {
        sql(&format!("GRANT {role} TO {bridge} WITH {membership}"));
        for privilege in [
            "TRUNCATE ON mdm_policy.requests",
            "DELETE ON mdm_policy.immutable",
            "UPDATE(document) ON mdm_policy.immutable",
            "UPDATE ON mdm_policy.aggregates",
            "REFERENCES ON mdm_policy.aggregates",
            "TRIGGER ON mdm_policy.aggregates",
        ] {
            sql(&format!("GRANT {privilege} TO {role}"));
            let result = PolicyStore::new(runtime.clone(), tenant(), deadline()).await;
            sql(&format!("REVOKE {privilege} FROM {role}"));
            assert!(
                result.is_err(),
                "admitted switchable privilege: {privilege}"
            );
        }
    }
    // Permitted column privileges in a switchable role remain admissible.
    sql(&format!(
        "GRANT UPDATE(document) ON mdm_policy.aggregates TO {role}"
    ));
    PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    sql(&format!(
        "REVOKE UPDATE(document) ON mdm_policy.aggregates FROM {role}"
    ));
    // A role with neither inheritance nor SET permission is not executable.
    sql(&format!(
        "GRANT {bridge} TO mdm_policy_runtime WITH INHERIT FALSE, SET FALSE; GRANT TRUNCATE ON mdm_policy.requests TO {role}"
    ));
    let dormant = PolicyStore::new(runtime, tenant(), deadline()).await;
    sql(&format!(
        "REVOKE {bridge} FROM mdm_policy_runtime; REVOKE {role} FROM {bridge}; DROP OWNED BY {role}; DROP ROLE {bridge}; DROP ROLE {role};"
    ));
    dormant.unwrap();
}

#[tokio::test]
#[ignore = "real PostgreSQL: backend-t2"]
async fn saving_intents_does_not_create_execution_facts() {
    let runtime = runtime().await;
    let s = PolicyStore::new(runtime.clone(), tenant(), deadline())
        .await
        .unwrap();
    let p = pid();
    let rev = setup(&s, &p).await;
    let candidate = planning::prepare(&runtime, &s, &p, rev, &["a"]).await;
    let reference = planning::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &candidate), |ctx, tx| {
                Box::pin(async move {
                    let candidate = ctx.0.candidate_in(tx, ctx.1).await?.unwrap();
                    let reference = candidate.request.references[0].id.clone();
                    assert!(!ctx.0.has_saved_reference_in(tx, &reference).await?.unwrap());
                    Ok(Ok(reference))
                })
            })
            .await,
    )
    .unwrap();
    let operation = RequestId::new(tenant(), unique()).unwrap();
    let saved = planning::save(&runtime, &s, &p, &operation, &candidate, rev, deadline())
        .await
        .unwrap();
    assert_eq!(
        saved,
        planning::save(&runtime, &s, &p, &operation, &candidate, rev, deadline())
            .await
            .unwrap()
    );
    assert!(
        planning::settle(
            runtime
                .local_tx_with_context(tenant(), deadline(), (&s, &reference), |ctx, tx| Box::pin(
                    async move { ctx.0.has_saved_reference_in(tx, ctx.1).await }
                ))
                .await
        )
        .unwrap()
    );
    assert_event(p.value(), operation.value(), saved.storage_revision, 10);
    assert!(
        s.execution_facts(&p, None, 1000, deadline())
            .await
            .unwrap()
            .records
            .is_empty()
    );
    let intents = planning::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &candidate), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .candidate_intents_in(tx, ctx.1, IntentKind::Add, None, 1000)
                        .await
                })
            })
            .await,
    )
    .unwrap();
    assert_eq!(intents.len(), 1);
    assert!(
        matches!(&intents[0].intent,CandidateIntent::Desired {device,supersedes:false,version:1} if device.value()=="a")
    );
    runtime.close().await;
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
    let old = ExecutionRecord::new(
        version(&p, 1),
        DeviceId::new(tenant(), "a").unwrap(),
        Progress::Running,
        Effect::VerifiedPresent,
    )
    .unwrap();
    let request = req(
        &p,
        rev,
        Command::RecordExecutions {
            policy: p.clone(),
            facts: vec![old.clone()],
        },
    );
    let receipt = s.execute(&request, deadline()).await.unwrap();
    rev = receipt.storage_revision;
    assert_eq!(receipt, s.execute(&request, deadline()).await.unwrap());
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
    let candidate = planning::prepare(&runtime, &s, &p, rev, &["a"]).await;
    let intents = planning::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &candidate), |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .candidate_intents_in(tx, ctx.1, IntentKind::Supersede, None, 1000)
                        .await
                })
            })
            .await,
    )
    .unwrap();
    assert!(matches!(
        intents[0].intent,
        CandidateIntent::Desired {
            version: 2,
            supersedes: true,
            ..
        }
    ));
    let mut after = None;
    for expected in [1, 0] {
        let rows = planning::settle(
            runtime
                .local_tx_with_context(
                    tenant(),
                    deadline(),
                    (&s, &candidate, after.clone()),
                    |ctx, tx| {
                        Box::pin(async move {
                            ctx.0
                                .candidate_intents_in(
                                    tx,
                                    ctx.1,
                                    IntentKind::Predecessors,
                                    ctx.2.clone(),
                                    1,
                                )
                                .await
                        })
                    },
                )
                .await,
        )
        .unwrap();
        assert_eq!(rows.len(), expected);
        if let Some(row) = rows.first() {
            assert!(
                matches!(&row.intent, CandidateIntent::Predecessor { execution, successor_version: 2 } if execution == &old)
            );
            after = Some(row.position.clone());
        }
    }
    let operation = RequestId::new(tenant(), unique()).unwrap();
    let saved = planning::save(&runtime, &s, &p, &operation, &candidate, rev, deadline())
        .await
        .unwrap();
    rev = saved.storage_revision;
    assert_eq!(
        s.execution_facts(&p, None, 1000, deadline())
            .await
            .unwrap()
            .records,
        vec![old.clone()]
    );
    let stale = planning::prepare(&runtime, &s, &p, rev, &["a"]).await;
    for transition in [Transition::Pause, Transition::Resume] {
        rev = s
            .execute(
                &req(
                    &p,
                    rev,
                    Command::Transition {
                        policy: p.clone(),
                        transition,
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
    assert!(matches!(
        planning::save(
            &runtime,
            &s,
            &p,
            &RequestId::new(tenant(), unique()).unwrap(),
            &stale,
            rev,
            deadline()
        )
        .await,
        Err(Error::Rejected(Rejection::Conflict))
    ));
    assert_eq!(
        s.operation(&operation, deadline()).await.unwrap(),
        Some(saved)
    );
    assert_eq!(
        s.version(&p, 1, deadline()).await.unwrap(),
        Some(version(&p, 1))
    );
    let incompatible = Version::new(
        p.clone(),
        1,
        PayloadRef::new(
            PayloadId::new(tenant(), "incompatible").unwrap(),
            1,
            [9; 32],
        )
        .unwrap(),
        RemovalRule::CancelOutstandingRetainEffects,
    )
    .unwrap();
    let bad = ExecutionRecord::new(
        incompatible,
        old.device().clone(),
        Progress::Failed,
        Effect::Unknown,
    )
    .unwrap();
    assert!(
        s.execute(
            &req(
                &p,
                rev,
                Command::RecordExecutions {
                    policy: p.clone(),
                    facts: vec![bad]
                }
            ),
            deadline()
        )
        .await
        .is_err()
    );
    assert_eq!(
        s.execution_facts(&p, None, 1000, deadline())
            .await
            .unwrap()
            .records,
        vec![old]
    );
    runtime.close().await;
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
    let candidate = planning::prepare(&runtime, &s, &p, rev, &["a"]).await;
    let mut original = planning::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &candidate), |ctx, tx| {
                Box::pin(async move { ctx.0.candidate_in(tx, ctx.1).await })
            })
            .await,
    )
    .unwrap()
    .request;
    original.target_revision += 1;
    let conflict = planning::settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (&s, &original), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_candidate_in(tx, ctx.1).await })
            })
            .await,
    );
    assert!(matches!(
        conflict,
        Err(Error::Rejected(Rejection::IdentityConflict))
    ));
    sql(
        "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) FROM mdm_policy_runtime",
    );
    let operation = RequestId::new(tenant(), unique()).unwrap();
    let failed = planning::save(&runtime, &s, &p, &operation, &candidate, rev, deadline()).await;
    sql(
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_policy_runtime",
    );
    assert!(failed.is_err());
    assert!(s.operation(&operation, deadline()).await.unwrap().is_none());
    assert_eq!(
        s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .storage_revision(),
        rev
    );
    assert!(
        s.get(&p, deadline())
            .await
            .unwrap()
            .unwrap()
            .current_plan_id()
            .is_none()
    );
    sql("ALTER TABLE mdm_policy.aggregates NO FORCE ROW LEVEL SECURITY");
    let rejected = PolicyStore::new(runtime.clone(), tenant(), deadline()).await;
    sql("ALTER TABLE mdm_policy.aggregates FORCE ROW LEVEL SECURITY");
    assert!(rejected.is_err());
    runtime.close().await;
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
    let rev = setup(&s, &p).await;
    let facts = (0..5)
        .map(|n| {
            ExecutionRecord::new(
                version(&p, 1),
                DeviceId::new(tenant(), format!("d{n}")).unwrap(),
                Progress::Running,
                Effect::Unknown,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    s.execute(
        &req(
            &p,
            rev,
            Command::RecordExecutions {
                policy: p.clone(),
                facts: facts.clone(),
            },
        ),
        deadline(),
    )
    .await
    .unwrap();
    let mut after = None;
    let mut all = vec![];
    loop {
        let page = s.execution_facts(&p, after, 2, deadline()).await.unwrap();
        all.extend(page.records);
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(all, facts);
    let mut revision = s
        .get(&p, deadline())
        .await
        .unwrap()
        .unwrap()
        .storage_revision();
    for number in [2, 10] {
        revision = s
            .execute(
                &req(
                    &p,
                    revision,
                    Command::Transition {
                        policy: p.clone(),
                        transition: Transition::Activate(version(&p, number)),
                    },
                ),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
        revision = s
            .execute(
                &req(
                    &p,
                    revision,
                    Command::RecordExecutions {
                        policy: p.clone(),
                        facts: vec![
                            ExecutionRecord::new(
                                version(&p, number),
                                DeviceId::new(tenant(), "d0").unwrap(),
                                Progress::Succeeded,
                                Effect::VerifiedPresent,
                            )
                            .unwrap(),
                        ],
                    },
                ),
                deadline(),
            )
            .await
            .unwrap()
            .storage_revision;
    }
    let page = s
        .execution_facts(&p, Some("1/d4".into()), 1, deadline())
        .await
        .unwrap();
    assert_eq!(page.records[0].version().number(), 2);
    let page = s
        .execution_facts(&p, page.next, 1, deadline())
        .await
        .unwrap();
    assert_eq!(page.records[0].version().number(), 10);
    assert!(page.next.is_none());
    for invalid in ["zero", "0/d0", "01/d0", "1/"] {
        assert!(
            s.execution_facts(&p, Some(invalid.into()), 2, deadline())
                .await
                .is_err()
        );
    }

    for limit in [0, 1001] {
        assert!(
            s.execution_facts(&p, None, limit, deadline())
                .await
                .is_err()
        );
    }
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
    let foreign_store = PolicyStore::new(runtime.clone(), foreign(), deadline())
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
    let original = sql(&format!(
        "SELECT convert_from(document,'UTF8') FROM mdm_policy.facts WHERE tenant_id='{}' AND owner='{}' AND key='1/d2'",
        tenant(),
        p.value()
    ));
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for (field, value) in [(0, foreign().to_string()), (1, "other-policy".into())] {
        let mut doc: serde_json::Value = serde_json::from_str(&original).unwrap();
        doc[0][field] = value.into();
        let bytes = serde_json::to_vec(&doc).unwrap();
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
    sql("REVOKE UPDATE(document) ON mdm_policy.facts FROM mdm_policy_runtime");
    let bad = PolicyStore::new(runtime.clone(), tenant(), deadline()).await;
    sql("GRANT UPDATE(document) ON mdm_policy.facts TO mdm_policy_runtime");
    assert!(bad.is_err());
    runtime.close().await;
}
