#![allow(
    clippy::cognitive_complexity,
    reason = "integration scenarios assert the complete transaction result"
)]
use super::*;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
use serde_json::json;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
fn fixture() -> Value {
    serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG").unwrap()).unwrap())
        .unwrap()
}
fn sql(statement: &str) -> String {
    use std::io::Write;
    let config = fixture();
    let mut child = std::process::Command::new("docker")
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
            "backend",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(statement.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}
async fn management(t: TenantId) -> Management {
    let c = fixture();
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new(
                "localhost",
                c["port"].as_u64().unwrap() as u16,
                "backend",
                "mdm_management_runtime",
                PgPassword::new("backend-fixture"),
                PgPrivateCa::from_pem(std::fs::read(c["ca"].as_str().unwrap()).unwrap()).unwrap(),
            ),
            crate::lifecycle::RuntimeTimer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                vec![(t, Epoch::new(1).unwrap())],
            )
            .unwrap(),
        )
        .await
        .unwrap(),
    );
    Management::new(runtime, t, Arc::new(crate::clock::SystemClock))
        .await
        .unwrap()
}
async fn execute(m: &Management, c: &Command) -> std::result::Result<Value, Error> {
    let audit = Audit::new(m.tenant.to_string(), "management_write");
    audit.identify_fixture("operator", "mdm");
    let result = m.execute(c, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result
}
fn operation<T>(expected_revision: u64, input: T) -> Operation<T> {
    Operation {
        operation_id: Uuid::new_v4(),
        expected_revision,
        input,
    }
}
fn scope(group: Uuid) -> ScopeDefinition {
    ScopeDefinition {
        targets: [Reference::Group(group)].into(),
        limitations: None,
        exclusions: Default::default(),
    }
}
fn seed_device(device: &str) -> String {
    let registration = Uuid::new_v4().to_string();
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let t = tenant();
    sql(&format!(
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES('{t}','{request}','{grant}');INSERT INTO mdm_access.devices VALUES('{t}','{device}');INSERT INTO mdm_access.registrations VALUES('{t}','{registration}','{device}','mdm',1,'{request}','active');INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{t}','{registration}','mdm.windows','{epoch}','{{}}',true);"
    ));
    registration
}
#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn group_scope_plan_replay_stale_and_audit_atomicity() {
    let mut m = management(tenant()).await;
    struct CountingClock(std::sync::atomic::AtomicI64);
    impl crate::clock::Clock for CountingClock {
        fn unix_seconds(&self) -> std::result::Result<i64, crate::Error> {
            Ok(self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        }
    }
    let clock = Arc::new(CountingClock(std::sync::atomic::AtomicI64::new(
        1_700_000_000,
    )));
    m.clock = clock.clone();
    let device = format!("设备-{}", Uuid::new_v4());
    seed_device(&device);
    let group = Uuid::new_v4();
    let c = Command::Group {
        id: group,
        change: operation(
            0,
            GroupChange::Create {
                name: "fleet".into(),
                description: "".into(),
                criteria: None,
            },
        ),
    };
    let first = execute(&m, &c).await.unwrap();
    assert_eq!(first, execute(&m, &c).await.unwrap());
    execute(
        &m,
        &Command::Group {
            id: group,
            change: operation(
                1,
                GroupChange::Members {
                    add: vec![device.clone()],
                    remove: vec![],
                },
            ),
        },
    )
    .await
    .unwrap();
    let scope_id = Uuid::new_v4();
    let before = clock.0.load(std::sync::atomic::Ordering::SeqCst);
    execute(
        &m,
        &Command::Scope {
            id: scope_id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(group),
                },
            ),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        clock.0.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "one clock read per transaction"
    );
    let policy = Uuid::new_v4().to_string();
    execute(
        &m,
        &Command::Policy {
            id: policy.clone(),
            change: operation(0, PolicyChange::Create),
        },
    )
    .await
    .unwrap();
    let preview = Uuid::new_v4();
    let c = Command::Preview {
        id: policy.clone(),
        request: Operation {
            operation_id: preview,
            expected_revision: 0,
            input: PreviewInput {
                scope: scope_id,
                expected_revision: 0,
            },
        },
    };
    // The durable policy create starts at its adapter's first storage revision.
    let state = execute(&m, &Command::PolicyRead { id: policy.clone() })
        .await
        .unwrap();
    let revision = state["storage_revision"].as_u64().unwrap();
    let Command::Preview { mut request, .. } = c else {
        unreachable!()
    };
    request.expected_revision = revision;
    request.input.expected_revision = revision;
    let result = execute(
        &m,
        &Command::Preview {
            id: policy.clone(),
            request,
        },
    )
    .await
    .unwrap();
    assert_eq!(result["devices"], json!([device]));
    let save = Command::Save {
        id: policy.clone(),
        request: operation(revision, SavePlan { preview }),
    };
    let saved = execute(&m, &save).await.unwrap();
    assert_eq!(saved, execute(&m, &save).await.unwrap());
    let previous = execute(&m, &Command::ScopeRead { id: scope_id })
        .await
        .unwrap();
    m.runtime.close().await;
    drop(m);
    let m = management(tenant()).await;
    assert_eq!(saved, execute(&m, &save).await.unwrap());
    assert_eq!(
        previous,
        execute(&m, &Command::ScopeRead { id: scope_id })
            .await
            .unwrap()
    );
    let historical = execute(&m, &Command::PlanRead { id: preview })
        .await
        .unwrap();
    assert_eq!(historical["plan"], saved["plan"]);

    assert_eq!(saved["plan"]["dispatch"], "not_requested");
    assert!(matches!(
        execute(
            &m,
            &Command::Group {
                id: group,
                change: operation(2, GroupChange::Delete)
            }
        )
        .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        execute(
            &m,
            &Command::Scope {
                id: scope_id,
                change: operation(1, ScopeChange::Delete)
            }
        )
        .await,
        Err(Error::Conflict)
    ));
    let state = execute(&m, &Command::PolicyRead { id: policy.clone() })
        .await
        .unwrap();
    let revision = state["storage_revision"].as_u64().unwrap();
    let stale = Uuid::new_v4();
    execute(
        &m,
        &Command::Preview {
            id: policy.clone(),
            request: Operation {
                operation_id: stale,
                expected_revision: revision,
                input: PreviewInput {
                    scope: scope_id,
                    expected_revision: revision,
                },
            },
        },
    )
    .await
    .unwrap();
    execute(
        &m,
        &Command::Group {
            id: group,
            change: operation(
                2,
                GroupChange::Members {
                    add: vec![],
                    remove: vec![device],
                },
            ),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        execute(
            &m,
            &Command::Save {
                id: policy,
                request: operation(revision, SavePlan { preview: stale })
            }
        )
        .await,
        Err(Error::Plan(crate::PlanFailure {
            reason: crate::PlanFailureReason::StalePlan,
            ..
        }))
    ));
    let denied = Uuid::new_v4();
    sql("REVOKE INSERT ON mdm_access.audit FROM mdm_management_runtime;");
    assert!(matches!(
        execute(
            &m,
            &Command::Group {
                id: denied,
                change: operation(
                    0,
                    GroupChange::Create {
                        name: "rollback".into(),
                        description: "".into(),
                        criteria: None
                    }
                )
            }
        )
        .await,
        Err(Error::Unavailable(Failure::Audit))
    ));
    sql("GRANT INSERT ON mdm_access.audit TO mdm_management_runtime;");
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.groups WHERE id='{denied}'"
        )),
        "0"
    );
    let foreign =
        management(TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap()).await;
    assert!(
        execute(&foreign, &Command::ScopeRead { id: scope_id })
            .await
            .is_err()
    );
    foreign.runtime.close().await;
    m.runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn initial_empty_group_scope_and_revision_competition() {
    let m = management(tenant()).await;
    let g = Uuid::new_v4();
    execute(
        &m,
        &Command::Group {
            id: g,
            change: operation(
                0,
                GroupChange::Create {
                    name: "empty".into(),
                    description: "".into(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    let s = Uuid::new_v4();
    execute(
        &m,
        &Command::Scope {
            id: s,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(g),
                },
            ),
        },
    )
    .await
    .unwrap();
    let a = Command::Scope {
        id: s,
        change: operation(
            1,
            ScopeChange::Put {
                definition: ScopeDefinition {
                    targets: Default::default(),
                    limitations: Some(Default::default()),
                    exclusions: Default::default(),
                },
            },
        ),
    };
    let b = Command::Scope {
        id: s,
        change: operation(1, ScopeChange::Delete),
    };
    let (a, b) = tokio::join!(execute(&m, &a), execute(&m, &b));
    assert_ne!(a.is_ok(), b.is_ok());
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn management_admission_rejects_schema_and_privilege_drift() {
    let service = management(tenant()).await;
    for (change, restore) in [
        (
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact DROP NOT NULL",
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact SET NOT NULL",
        ),
        (
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(true)",
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(revision>0)",
        ),
        (
            "GRANT SELECT ON mdm_access.credentials TO mdm_management_runtime",
            "REVOKE SELECT ON mdm_access.credentials FROM mdm_management_runtime; GRANT SELECT(tenant_id,registration,state) ON mdm_access.credentials TO mdm_management_runtime",
        ),
        (
            "ALTER TABLE mdm_management.scopes DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_management.scopes ENABLE ROW LEVEL SECURITY",
        ),
        (
            "GRANT DELETE ON mdm_management.previews TO mdm_management_runtime",
            "REVOKE DELETE ON mdm_management.previews FROM mdm_management_runtime",
        ),
        (
            "GRANT SELECT ON mdm_access.authorization_rules TO mdm_management_runtime",
            "REVOKE SELECT ON mdm_access.authorization_rules FROM mdm_management_runtime",
        ),
    ] {
        sql(change);
        let rejected = storage::admit(&service.runtime, tenant()).await.is_err();
        sql(restore);
        assert!(rejected);
    }
    for (table, column) in [
        ("mdm_access.devices", "id"),
        ("mdm_access.registrations", "state"),
        ("mdm_access.report_sources", "enabled"),
        ("mdm.inventory", "value"),
    ] {
        assert_eq!(
            sql(&format!(
                "SELECT has_column_privilege('mdm_management_runtime','{table}','{column}','UPDATE')"
            )),
            "f"
        );
        sql(&format!(
            "GRANT UPDATE({column}) ON {table} TO mdm_management_runtime"
        ));
        let rejected = storage::admit(&service.runtime, tenant()).await.is_err();
        sql(&format!(
            "REVOKE UPDATE({column}) ON {table} FROM mdm_management_runtime"
        ));
        assert!(rejected);
    }
    storage::admit(&service.runtime, tenant()).await.unwrap();
    let denied = service
        .runtime
        .local_tx(tenant(), deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT locator FROM mdm_access.credentials")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await?;
                Ok(())
            })
        })
        .await;
    assert!(denied.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    service.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn registration_replacement_invalidates_direct_and_group_previews() {
    let m = management(tenant()).await;
    let device = format!("device-{}", Uuid::new_v4());
    let old = seed_device(&device);
    let group = Uuid::new_v4();
    execute(
        &m,
        &Command::Group {
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "registration".into(),
                    description: "".into(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    execute(
        &m,
        &Command::Group {
            id: group,
            change: operation(
                1,
                GroupChange::Members {
                    add: vec![device.clone()],
                    remove: vec![],
                },
            ),
        },
    )
    .await
    .unwrap();
    let mut pending = Vec::new();
    for reference in [Reference::Device(device.clone()), Reference::Group(group)] {
        let scope = Uuid::new_v4();
        let policy = Uuid::new_v4().to_string();
        execute(
            &m,
            &Command::Scope {
                id: scope,
                change: operation(
                    0,
                    ScopeChange::Put {
                        definition: ScopeDefinition {
                            targets: [reference].into(),
                            limitations: None,
                            exclusions: Default::default(),
                        },
                    },
                ),
            },
        )
        .await
        .unwrap();
        let created = execute(
            &m,
            &Command::Policy {
                id: policy.clone(),
                change: operation(0, PolicyChange::Create),
            },
        )
        .await
        .unwrap();
        let revision = created["storage_revision"].as_u64().unwrap();
        let preview = Uuid::new_v4();
        execute(
            &m,
            &Command::Preview {
                id: policy.clone(),
                request: Operation {
                    operation_id: preview,
                    expected_revision: revision,
                    input: PreviewInput {
                        scope,
                        expected_revision: revision,
                    },
                },
            },
        )
        .await
        .unwrap();
        pending.push((policy, revision, preview));
    }
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    let t = tenant();
    sql(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{old}';INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES('{t}','{request}','{grant}');INSERT INTO mdm_access.registrations VALUES('{t}','{replacement}','{device}','mdm',2,'{request}','active');"
    ));
    for (id, revision, preview) in pending.clone() {
        assert!(matches!(
            execute(
                &m,
                &Command::Save {
                    id,
                    request: operation(revision, SavePlan { preview })
                }
            )
            .await,
            Err(Error::Plan(crate::PlanFailure {
                reason: crate::PlanFailureReason::StalePlan,
                ..
            }))
        ));
    }
    sql(&format!(
        "UPDATE mdm_access.registrations SET state='revoked' WHERE id='{replacement}'"
    ));
    for (id, revision, preview) in pending {
        let result = execute(
            &m,
            &Command::Save {
                id,
                request: operation(revision, SavePlan { preview }),
            },
        )
        .await;
        assert!(
            matches!(
                result,
                Err(Error::Plan(crate::PlanFailure {
                    reason: crate::PlanFailureReason::StalePlan,
                    ..
                }))
            ),
            "lost registration must stale preview: {result:?}"
        );
    }
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn group_delete_scope_reference_compete_without_dangling_references() {
    let first = management(tenant()).await;
    let second = management(tenant()).await;
    for reverse in [false, true] {
        let group = Uuid::new_v4();
        let scope_id = Uuid::new_v4();
        execute(
            &first,
            &Command::Group {
                id: group,
                change: operation(
                    0,
                    GroupChange::Create {
                        name: "reference-race".into(),
                        description: "".into(),
                        criteria: None,
                    },
                ),
            },
        )
        .await
        .unwrap();
        let delete = Command::Group {
            id: group,
            change: operation(1, GroupChange::Delete),
        };
        let reference = Command::Scope {
            id: scope_id,
            change: operation(
                0,
                ScopeChange::Put {
                    definition: scope(group),
                },
            ),
        };
        let (a, b) = if reverse {
            tokio::join!(execute(&first, &reference), execute(&second, &delete))
        } else {
            tokio::join!(execute(&first, &delete), execute(&second, &reference))
        };
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM mdm_management.scopes s JOIN mdm_management.scope_versions v USING(tenant_id,id,revision) JOIN mdm_group.groups g ON g.tenant_id=s.tenant_id AND g.id='{group}' WHERE s.id='{scope_id}' AND g.deleted AND NOT s.deleted"
            )),
            "0"
        );
    }
    first.runtime.close().await;
    second.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn corrupt_scope_is_a_storage_failure_not_a_client_error() {
    let m = management(tenant()).await;
    let id = Uuid::new_v4();
    let command = Command::Scope {
        id,
        change: operation(
            0,
            ScopeChange::Put {
                definition: ScopeDefinition {
                    targets: Default::default(),
                    limitations: None,
                    exclusions: Default::default(),
                },
            },
        ),
    };
    let receipt = execute(&m, &command).await.unwrap();
    sql(&format!(
        "UPDATE mdm_management.scope_versions SET definition='[]' WHERE id='{id}'"
    ));
    assert!(matches!(
        execute(&m, &Command::ScopeRead { id }).await,
        Err(Error::Unavailable(Failure::ManagementStorage))
    ));
    sql(&format!(
        "UPDATE mdm_management.scope_versions SET definition='{{\"targets\":[],\"limitations\":null,\"exclusions\":[]}}' WHERE id='{id}'"
    ));
    let operation = match &command {
        Command::Scope { change, .. } => change.operation_id,
        _ => unreachable!(),
    };
    sql(&format!(
        "UPDATE mdm_management.operations SET response='[]' WHERE id='{operation}'"
    ));
    let before = sql("SELECT count(*) FROM mdm_access.audit");
    assert!(
        matches!(
            execute(&m, &command).await,
            Err(Error::Unavailable(Failure::ManagementStorage))
        ),
        "corrupt replay receipt must fail before success audit"
    );
    assert_eq!(before, sql("SELECT count(*) FROM mdm_access.audit"));
    let document = serde_json::to_string(&receipt).unwrap().replace('\'', "''");
    sql(&format!(
        "UPDATE mdm_management.operations SET response='{document}' WHERE id='{operation}'"
    ));
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn expired_guard_after_lock_rejects_mutation_and_replay() {
    use sqlx::{
        Connection,
        postgres::{PgConnectOptions, PgSslMode},
    };
    let m = management(tenant()).await;
    let config = fixture();
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database("backend")
        .username("postgres")
        .password("admin-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut holder = sqlx::PgConnection::connect_with(&options).await.unwrap();
    for replay in [false, true] {
        let id = Uuid::new_v4();
        let command = Command::Group {
            id,
            change: operation(
                0,
                GroupChange::Create {
                    name: "guarded".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        };
        if replay {
            execute(&m, &command).await.unwrap();
        }
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2390))")
            .bind(tenant().to_string())
            .execute(&mut holder)
            .await
            .unwrap();
        let audit = Audit::new(tenant().to_string(), "management_write");
        audit.identify_fixture("operator", "mdm");
        let expires = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_millis(150);
        let authorize = || {
            if rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < expires {
                Ok(())
            } else {
                Err(Error::Forbidden)
            }
        };
        let release = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2390))")
                .bind(tenant().to_string())
                .execute(&mut holder)
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(m.execute(&command, &audit, &authorize), release);
        audit.finalize(None);
        assert!(matches!(result, Err(Error::Forbidden)));
        let read = execute(&m, &Command::GroupRead { id }).await;
        assert_eq!(
            read.is_ok(),
            replay,
            "expired new write must leave no group"
        );
    }
    holder.close().await.unwrap();
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn asset_commit_unknown_recovers_original_receipts() {
    use assets::{
        Command as AssetCommand, FieldKey, ManualChange, Owner, Query, SavedChange,
        SavedDefinition, Scalar,
    };
    let m = management(tenant()).await;
    let device = format!("unknown-{}", Uuid::new_v4());
    seed_device(&device);
    let owner = Owner {
        instance: Uuid::new_v4().to_string(),
        principal: Uuid::new_v4().to_string(),
    };
    let id = Uuid::new_v4();
    let commands = [
        Command::Asset {
            command: AssetCommand::Manual {
                device: device.clone(),
                field: FieldKey::AssetTag,
                change: operation(
                    0,
                    ManualChange::Set {
                        value: Scalar::String("retained".into()),
                    },
                ),
                owner: owner.clone(),
            },
        },
        Command::Asset {
            command: AssetCommand::SavedWrite {
                id,
                owner,
                change: operation(
                    0,
                    SavedChange::Put {
                        definition: SavedDefinition {
                            name: "mine".into(),
                            query: Query::default(),
                        },
                    },
                ),
            },
        },
    ];
    for command in commands {
        m.runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        assert!(matches!(
            execute(&m, &command).await,
            Err(Error::CommitUnknown)
        ));
        let recovered = execute(&m, &command).await.unwrap();
        assert_eq!(execute(&m, &command).await.unwrap(), recovered);
    }
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{}' AND device='{device}'",
            tenant()
        )),
        "1"
    );
    assert_eq!(
        sql(&format!(
            "SELECT revision FROM mdm_management.saved_queries WHERE tenant_id='{}' AND id='{id}'",
            tenant()
        )),
        "1"
    );
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn asset_storage_stages_and_capacity_are_not_malformed() {
    let m = management(tenant()).await;
    let command = Command::Asset {
        command: assets::Command::Search {
            query: assets::Query::default(),
            scope: assets::ReadScope {
                subject: "fixture-operator".into(),
                devices: None,
            },
        },
    };
    for (table, expected) in [
        ("mdm.inventory", "inventory_query"),
        ("mdm.manual_assignments", "manual_query"),
        ("mdm_access.collection_runs", "collection_query"),
    ] {
        sql(&format!(
            "REVOKE SELECT ON {table} FROM mdm_management_runtime"
        ));
        let error = execute(&m, &command).await.unwrap_err();
        sql(&format!(
            "GRANT SELECT ON {table} TO mdm_management_runtime"
        ));
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"kind":"unavailable","reason":expected})
        );
    }
    let prefix = format!("asset-limit-{}-", Uuid::new_v4());
    sql(&format!(
        "INSERT INTO mdm_access.devices(tenant_id,id) SELECT '{}','{prefix}'||i FROM generate_series(1,10001) i",
        tenant()
    ));
    let error = execute(&m, &command).await.unwrap_err();
    sql(&format!(
        "DELETE FROM mdm_access.devices WHERE tenant_id='{}' AND id LIKE '{prefix}%'",
        tenant()
    ));
    assert!(matches!(
        error,
        Error::Unavailable(Failure::AssetObjectLimit)
    ));
    m.runtime.close().await;
}
