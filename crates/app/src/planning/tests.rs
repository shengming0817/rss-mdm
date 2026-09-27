#![allow(
    clippy::cognitive_complexity,
    reason = "integration scenarios assert the complete transaction result"
)]
use super::*;
use rss_request_context::Deadline;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
use serde_json::json;
#[path = "recovery_tests.rs"]
mod recovery;
#[path = "resource_archive_tests.rs"]
mod resource_archive;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
fn fixture() -> Value {
    serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG").unwrap()).unwrap())
        .unwrap()
}
#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn asset_history_rollback_replay_and_frozen_watermark() {
    let t = tenant();
    let device = format!("history-{}", Uuid::new_v4());
    let read = || {
        sql(&format!(
            "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id='{t}'"
        ))
        .parse::<i64>()
        .unwrap()
    };
    let before = read();
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}'); ROLLBACK;"
    ));
    assert_eq!(read(), before, "rollback cannot leave a durable trigger");
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}'); COMMIT;"
    ));
    let created = read();
    assert!(created > before);
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}') ON CONFLICT DO NOTHING; COMMIT;"
    ));
    assert_eq!(
        read(),
        created,
        "idempotent writes cannot manufacture a new input version"
    );
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; DELETE FROM mdm_access.devices WHERE tenant_id='{t}' AND id='{device}'; COMMIT;"
    ));
    assert!(read() > created);
    assert_eq!(
        sql(&format!(
            "SELECT document->>'id' FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' AND revision<={created} ORDER BY revision DESC LIMIT 1"
        )),
        device
    );
    assert_eq!(
        sql(&format!(
            "SELECT document IS NULL FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' ORDER BY revision DESC LIMIT 1"
        )),
        "t"
    );
    let service = planning(t).await;
    let scope_device = device.clone();
    let frozen = service
        .runtime
        .local_tx_with_context(t, deadline(), &service, move |s, tx| {
            Box::pin(async move {
                s.asset_reader
                    .asset_page_in(
                        tx,
                        created,
                        None,
                        1,
                        &assets::ReadScope {
                            subject: "history".into(),
                            devices: Some([scope_device.clone()].into()),
                        },
                    )
                    .await
                    .map_err(|_| sqlx::Error::Protocol("frozen page rejected".into()).into())
            })
        })
        .await
        .fold(
            |p| p,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    assert_eq!(frozen.devices.len(), 1);
    assert_eq!(frozen.devices[0].device, device);
    assert!(frozen.next.is_none());
    assert_eq!(service.forward_asset_changes().await.unwrap(), 2);
    assert_eq!(service.forward_asset_changes().await.unwrap(), 0);
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM rss_reconcile.targets WHERE tenant_id='{t}' AND reconciler='mdm.assets' AND entity='changes'"
        )),
        "1"
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm.asset_changes WHERE tenant_id='{t}' AND revision>{before}"
        )),
        "2",
        "forwarding must retain the durable input"
    );
    service.runtime.close().await;
}
fn audit_records() -> Vec<crate::audit_test_support::Record> {
    crate::audit_test_support::decode_hex(&sql(
        "SELECT encode(canonical,'hex') FROM rss_audit.records ORDER BY tenant_id,position",
    ))
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
            "-qAt",
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
        .write_all(format!("SET rss.tenant_id='{}';\n{statement}", tenant()).as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}
async fn runtime(t: TenantId) -> Arc<PgRuntime> {
    runtime_role(t, "mdm_flow_runtime").await
}
async fn runtime_role(t: TenantId, role: &str) -> Arc<PgRuntime> {
    let c = fixture();
    let config = PgConfig::new(
        "localhost",
        c["port"].as_u64().unwrap() as u16,
        "backend",
        role,
        PgPassword::new("backend-fixture"),
        PgPrivateCa::from_pem(std::fs::read(c["ca"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let binding = ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16]).unwrap(),
        vec![(t, Epoch::new(1).unwrap())],
    )
    .unwrap();
    Arc::new(if role == "mdm_command_runtime" {
        PgRuntime::connect(config, crate::lifecycle::RuntimeTimer, binding)
            .await
            .unwrap()
    } else {
        PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
            .await
            .unwrap()
    })
}
async fn planning(t: TenantId) -> Planning {
    let audit = audit_store().await;
    let runtime = runtime(t).await;
    let clock = Arc::new(crate::clock::SystemClock);
    let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), t, clock.clone())
        .await
        .unwrap();
    crate::flow::storage::admit(&runtime, t).await.unwrap();
    let key = crate::flow::storage::cursor_key(&runtime, t).await.unwrap();
    Planning::new(audit, runtime, t, clock, catalog, &key)
        .await
        .unwrap()
}
async fn execute(m: &Planning, c: &Command) -> std::result::Result<Value, Error> {
    let audit = RequestAudit::new(m.tenant.to_string(), "management_write");
    audit.set_principal("operator", "mdm");
    let result = m.execute(c, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result
}
async fn execute_asset(m: &Planning, c: &assets::Command) -> std::result::Result<Value, Error> {
    let service = assets(m).await;
    execute_asset_service(m, &service, c).await
}
async fn execute_asset_service(
    m: &Planning,
    service: &assets::AssetService,
    c: &assets::Command,
) -> std::result::Result<Value, Error> {
    let audit = RequestAudit::new(m.tenant.to_string(), "management_write");
    audit.set_principal("operator", "mdm");
    let result = service.execute(c, &audit, &|| Ok(())).await;
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
    seed_device_in(tenant(), device)
}
fn seed_device_in(t: TenantId, device: &str) -> String {
    let registration = Uuid::new_v4().to_string();
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    sql(&format!(
        "SET rss.tenant_id='{t}'; INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{t}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.devices VALUES('{t}','{device}');INSERT INTO mdm_access.registrations VALUES('{t}','{registration}','{device}','mdm',1,'{request}','active');INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES('{t}',gen_random_uuid(),'{registration}','mdm',encode(sha256(convert_to('{registration}','UTF8')),'hex'),'active');INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{t}','{registration}','mdm.windows','{epoch}','{{}}',true);"
    ));
    registration
}

async fn wait_task(
    m: &Planning,
    id: Uuid,
    family: crate::automation::TaskKind,
    target: &str,
) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let result = execute(
                m,
                &Command::TaskRead {
                    id,
                    target: target.into(),
                    family,
                },
            )
            .await;
            let value = match result {
                Ok(value) => value,
                Err(Error::Unavailable(Failure::PlanningStorage) | Error::CommitUnknown) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => panic!("task status failed: {error:?}"),
            };
            if value["status"] == "completed" {
                return value;
            }
            assert!(value["failure"].is_null(), "task failed: {value}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded fixture task did not complete")
}

struct RunningAutomation {
    stack: rss_runtime::ShutdownStack,
    automation: Arc<crate::automation::Automation>,
}
impl RunningAutomation {
    async fn start(service: Arc<Planning>) -> Self {
        let config = fixture();
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("localhost")
            .port(config["port"].as_u64().unwrap() as u16)
            .database("backend")
            .username("mdm_flow_runtime")
            .password("backend-fixture")
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(config["ca"].as_str().unwrap());
        let automation = crate::automation::Automation::connect(
            service.clone(),
            assets(&service).await,
            options,
        )
        .await
        .unwrap();
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(10)).unwrap(),
            Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .unwrap();
        let mut launch = stack.startup().unwrap().commit();
        launch.stage_deferred_task_with_token(automation.clone().registration().critical());
        launch.finish();
        Self { stack, automation }
    }
    async fn stop(self) {
        assert!(self.stack.shutdown().join().await.unwrap().is_clean());
        rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(self.automation))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn durable_asset_group_scope_pipeline() {
    let service = Arc::new(planning(tenant()).await);
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database("backend")
        .username("mdm_flow_runtime")
        .password("backend-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let automation =
        crate::automation::Automation::connect(service.clone(), assets(&service).await, options)
            .await
            .unwrap();
    let device = format!("automation-{}", Uuid::new_v4());
    seed_device(&device);
    let owner = assets::Owner {
        instance: Uuid::new_v4().to_string(),
        principal: Uuid::new_v4().to_string(),
    };
    execute_asset(
        &service,
        &assets::Command::Manual {
            device: device.clone(),
            field: assets::FieldKey::IsLoaner,
            owner: owner.clone(),
            change: operation(
                0,
                assets::ManualChange::Set {
                    value: assets::Scalar::Boolean(true),
                },
            ),
        },
    )
    .await
    .unwrap();
    let group = Uuid::new_v4();
    let created = execute(
        &service,
        &Command::Group {
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "automation".into(),
                    description: String::new(),
                    criteria: Some(assets::Criteria::Predicate {
                        field: assets::FieldKey::IsLoaner,
                        op: assets::Operator::Eq,
                        value: Some(assets::Scalar::Boolean(true)),
                        values: None,
                    }),
                },
            ),
        },
    )
    .await
    .unwrap();
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10)).unwrap(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    )
    .unwrap();
    let mut launch = stack.startup().unwrap().commit();
    launch.stage_deferred_task_with_token(automation.clone().registration().critical());
    launch.finish();
    let task = Uuid::parse_str(created["task"].as_str().unwrap()).unwrap();
    assert_eq!(
        wait_task(
            &service,
            task,
            crate::automation::TaskKind::Group,
            &group.to_string()
        )
        .await["members"],
        1
    );
    let page_command = Command::GroupPage {
        group,
        result: task,
        projection: pages::GroupPageKind::Members,
        query: pages::PageQuery {
            limit: 1,
            cursor: None,
        },
    };
    let page = execute(&service, &page_command).await.unwrap();
    assert_eq!(page["page"]["items"], serde_json::json!([device]));
    assert_eq!(page["current"], true);
    assert!(wire::Response::decode(page.clone()).is_ok());
    let continuation = execute(
        &service,
        &Command::GroupPage {
            group,
            result: task,
            projection: pages::GroupPageKind::Members,
            query: pages::PageQuery {
                limit: 1,
                cursor: Some(page["nextCursor"].as_str().unwrap().into()),
            },
        },
    )
    .await
    .unwrap();
    assert_eq!(continuation["page"]["items"], serde_json::json!([]));
    let denied_audit = RequestAudit::new(tenant().to_string(), "management_read");
    assert!(matches!(
        service
            .execute(&page_command, &denied_audit, &|| Err(Error::Forbidden))
            .await,
        Err(Error::Forbidden)
    ));
    denied_audit.finalize(None);
    let query_scope = assets::ReadScope {
        subject: "query-owner".into(),
        devices: Some([device.clone()].into()),
    };
    let query = execute_asset(
        &service,
        &assets::Command::Search {
            request: operation(
                0,
                assets::Query {
                    criteria: Some(assets::Criteria::Predicate {
                        field: assets::FieldKey::IsLoaner,
                        op: assets::Operator::Eq,
                        value: Some(assets::Scalar::Boolean(true)),
                        values: None,
                    }),
                    select: vec![assets::FieldKey::IsLoaner],
                    sort: Some(assets::Sort {
                        field: assets::FieldKey::IsLoaner,
                        descending: true,
                    }),
                },
            ),
            scope: query_scope.clone(),
        },
    )
    .await
    .unwrap();
    let query_task = Uuid::parse_str(query["asset"]["task"].as_str().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = execute_asset(
                &service,
                &assets::Command::QueryStatus {
                    task: query_task,
                    scope: query_scope.clone(),
                },
            )
            .await
            .unwrap();
            assert!(status["asset"]["failure"].is_null(), "{status}");
            if status["asset"]["status"] == "completed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let query_items = execute_asset(
        &service,
        &assets::Command::QueryItems {
            task: query_task,
            scope: query_scope.clone(),
            limit: 1,
            cursor: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(query_items["asset"]["summary"]["matched"], 1);
    assert_eq!(query_items["asset"]["items"][0]["device"], device);
    assert_eq!(
        query_items["asset"]["items"][0]["fields"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        execute_asset(
            &service,
            &assets::Command::QueryItems {
                task: query_task,
                scope: assets::ReadScope::all(),
                limit: 1,
                cursor: None
            }
        )
        .await,
        Err(Error::Forbidden)
    ));
    let facets = execute_asset(
        &service,
        &assets::Command::QueryFacets {
            task: query_task,
            scope: query_scope.clone(),
            facet: assets::Facet::AssetStates,
            limit: 1,
            cursor: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(facets["asset"]["items"][0]["label"], "known");
    assert_eq!(facets["asset"]["items"][0]["total"], 1);
    let scope_id = Uuid::new_v4();
    let scoped = execute(
        &service,
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
    let scope_task = Uuid::parse_str(scoped["task"].as_str().unwrap()).unwrap();
    assert_eq!(
        wait_task(
            &service,
            scope_task,
            crate::automation::TaskKind::Scope,
            &scope_id.to_string()
        )
        .await["members"],
        1
    );
    for projection in [
        pages::ScopePageKind::Members,
        pages::ScopePageKind::Decisions,
    ] {
        let page = execute(
            &service,
            &Command::ScopePage {
                scope: scope_id,
                result: scope_task,
                projection,
                query: pages::PageQuery {
                    limit: 1000,
                    cursor: None,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(page["totalMembers"], 1);
        assert!(wire::Response::decode(page).is_ok());
    }
    assert!(stack.shutdown().join().await.unwrap().is_clean());
    rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(automation))
        .await
        .unwrap();
    service.runtime.close().await;
}
#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn group_scope_replay_and_audit_atomicity() {
    let m = Arc::new(planning(tenant()).await);
    let device = format!("设备-{}", Uuid::new_v4());
    seed_device(&device);
    let group = Uuid::new_v4();
    let create = Command::Group {
        id: group,
        change: operation(
            0,
            GroupChange::Create {
                name: "fleet".into(),
                description: String::new(),
                criteria: None,
            },
        ),
    };
    let first = execute(&m, &create).await.unwrap();
    assert_eq!(first, execute(&m, &create).await.unwrap());
    let running = RunningAutomation::start(m.clone()).await;
    let members = execute(
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
    wait_task(
        &m,
        Uuid::parse_str(members["task"].as_str().unwrap()).unwrap(),
        crate::automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    let scope_id = Uuid::new_v4();
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
    running.stop().await;
    let denied = Uuid::new_v4();
    sql("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime");
    let result = execute(
        &m,
        &Command::Group {
            id: denied,
            change: operation(
                0,
                GroupChange::Create {
                    name: "denied".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        },
    )
    .await;
    sql("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime");
    assert!(matches!(
        result,
        Err(Error::Unavailable(Failure::AuditAdmission))
    ));
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm_group.groups WHERE id='{denied}'"
        )),
        "0"
    );
    let foreign = planning(TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap()).await;
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
    let m = planning(tenant()).await;
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
    let service = planning(tenant()).await;
    for (change, restore) in [
        (
            "GRANT DELETE ON mdm_commands.action_runs TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_commands.action_runs FROM mdm_flow_runtime",
        ),
        (
            "REVOKE INSERT ON mdm_policy.versions FROM mdm_policy_runtime",
            "GRANT INSERT ON mdm_policy.versions TO mdm_policy_runtime",
        ),
        (
            "GRANT UPDATE(number) ON mdm_policy.versions TO mdm_flow_runtime",
            "REVOKE UPDATE(number) ON mdm_policy.versions FROM mdm_flow_runtime",
        ),
        (
            "REVOKE SELECT ON mdm_access.agent_bindings FROM mdm_flow_runtime",
            "GRANT SELECT ON mdm_access.agent_bindings TO mdm_flow_runtime",
        ),
        (
            "CREATE ROLE flow_drift NOLOGIN; GRANT UPDATE(number) ON mdm_policy.versions TO flow_drift; GRANT flow_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE flow_drift FROM mdm_flow_runtime; DROP OWNED BY flow_drift; DROP ROLE flow_drift",
        ),
        (
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact DROP NOT NULL",
            "ALTER TABLE mdm.manual_assignments ALTER COLUMN fact SET NOT NULL",
        ),
        (
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(true)",
            "ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_revision_check; ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_revision_check CHECK(revision>0)",
        ),
        (
            "GRANT SELECT ON mdm_access.credentials TO mdm_flow_runtime",
            "REVOKE SELECT ON mdm_access.credentials FROM mdm_flow_runtime; GRANT SELECT(tenant_id,registration,state) ON mdm_access.credentials TO mdm_flow_runtime",
        ),
        (
            "ALTER TABLE mdm_planning.scopes DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_planning.scopes ENABLE ROW LEVEL SECURITY",
        ),
        (
            "GRANT DELETE ON mdm_automation.automation_jobs TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_automation.automation_jobs FROM mdm_flow_runtime",
        ),
        (
            "GRANT UPDATE ON mdm_access.authorization_rules TO mdm_flow_runtime",
            "REVOKE UPDATE ON mdm_access.authorization_rules FROM mdm_flow_runtime",
        ),
    ] {
        sql(change);
        let rejected = crate::flow::storage::admit(&service.runtime, tenant())
            .await
            .is_err()
            || rss_mdm_policy_postgres::PolicyStore::new(
                service.runtime.clone(),
                tenant(),
                deadline(),
            )
            .await
            .is_err();
        sql(restore);
        assert!(rejected, "accepted privilege drift: {change}");
    }
    for (table, column) in [
        ("mdm_access.devices", "id"),
        ("mdm_access.registrations", "state"),
        ("mdm_access.report_sources", "enabled"),
        ("mdm.inventory", "value"),
    ] {
        assert_eq!(
            sql(&format!(
                "SELECT has_column_privilege('mdm_flow_runtime','{table}','{column}','UPDATE')"
            )),
            "f"
        );
        sql(&format!(
            "GRANT UPDATE({column}) ON {table} TO mdm_flow_runtime"
        ));
        let rejected = crate::flow::storage::admit(&service.runtime, tenant())
            .await
            .is_err()
            || rss_mdm_policy_postgres::PolicyStore::new(
                service.runtime.clone(),
                tenant(),
                deadline(),
            )
            .await
            .is_err();
        sql(&format!(
            "REVOKE UPDATE({column}) ON {table} FROM mdm_flow_runtime"
        ));
        assert!(rejected);
    }
    crate::flow::storage::admit(&service.runtime, tenant())
        .await
        .unwrap();
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
async fn registration_replacement_invalidates_direct_and_group_admission() {
    let m = Arc::new(planning(tenant()).await);
    let running = RunningAutomation::start(m.clone()).await;
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
    let membership = execute(
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
    wait_task(
        &m,
        Uuid::parse_str(membership["task"].as_str().unwrap()).unwrap(),
        crate::automation::TaskKind::Group,
        &group.to_string(),
    )
    .await;
    let mut pending = Vec::new();
    for reference in [Reference::Device(device.clone()), Reference::Group(group)] {
        let id = Uuid::new_v4();
        let receipt = execute(
            &m,
            &Command::Scope {
                id,
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
        wait_task(
            &m,
            Uuid::parse_str(receipt["task"].as_str().unwrap()).unwrap(),
            crate::automation::TaskKind::Scope,
            &id.to_string(),
        )
        .await;
        pending.push(id);
    }
    running.stop().await;
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    let t = tenant();
    sql(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{old}';INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{t}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.registrations VALUES('{t}','{replacement}','{device}','mdm',2,'{request}','active');"
    ));
    for id in pending {
        assert_eq!(
            sql(&format!(
                "SELECT mdm_planning.scope_admission('{id}','{device}')->>'state'"
            )),
            "pending"
        );
    }
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn group_delete_scope_reference_compete_without_dangling_references() {
    let first = planning(tenant()).await;
    let second = planning(tenant()).await;
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
                "SELECT count(*) FROM mdm_planning.scopes s JOIN mdm_planning.scope_versions v USING(tenant_id,id,revision) JOIN mdm_group.groups g ON g.tenant_id=s.tenant_id AND g.id='{group}' WHERE s.id='{scope_id}' AND g.deleted AND NOT s.deleted"
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
    let m = planning(tenant()).await;
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
        "UPDATE mdm_planning.scope_versions SET definition='[]' WHERE id='{id}'"
    ));
    assert!(matches!(
        execute(&m, &Command::ScopeRead { id }).await,
        Err(Error::Unavailable(Failure::PlanningStorage))
    ));
    sql(&format!(
        "UPDATE mdm_planning.scope_versions SET definition='{{\"targets\":[],\"limitations\":null,\"exclusions\":[]}}' WHERE id='{id}'"
    ));
    let operation = match &command {
        Command::Scope { change, .. } => change.operation_id,
        _ => unreachable!(),
    };
    sql(&format!(
        "UPDATE mdm_planning.operations SET response='[]' WHERE id='{operation}'"
    ));
    let before = sql("SELECT count(*) FROM rss_audit.records");
    assert!(
        matches!(
            execute(&m, &command).await,
            Err(Error::Unavailable(Failure::PlanningStorage))
        ),
        "corrupt replay receipt must fail before success audit"
    );
    assert_eq!(before, sql("SELECT count(*) FROM rss_audit.records"));
    let document = serde_json::to_string(&receipt).unwrap().replace('\'', "''");
    sql(&format!(
        "UPDATE mdm_planning.operations SET response='{document}' WHERE id='{operation}'"
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
    let m = planning(tenant()).await;
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
        let audit = RequestAudit::new(tenant().to_string(), "management_write");
        audit.set_principal("operator", "mdm");
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
    let m = planning(tenant()).await;
    let device = format!("unknown-{}", Uuid::new_v4());
    seed_device(&device);
    let owner = Owner {
        instance: Uuid::new_v4().to_string(),
        principal: Uuid::new_v4().to_string(),
    };
    let id = Uuid::new_v4();
    let execution = [
        AssetCommand::Manual {
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
        AssetCommand::SavedWrite {
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
    ];
    let service = assets(&m).await;
    for command in execution {
        m.runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        assert!(matches!(
            execute_asset_service(&m, &service, &command).await,
            Err(Error::CommitUnknown)
        ));
        let recovered = execute_asset_service(&m, &service, &command).await.unwrap();
        assert_eq!(
            execute_asset_service(&m, &service, &command).await.unwrap(),
            recovered
        );
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
            "SELECT revision FROM mdm_assets.saved_queries WHERE tenant_id='{}' AND id='{id}'",
            tenant()
        )),
        "1"
    );
    m.runtime.close().await;
}

#[tokio::test]
#[ignore = "real PostgreSQL; hack/management-t2.py"]
async fn asset_storage_failures_are_not_malformed() {
    let m = planning(tenant()).await;
    let device = format!("storage-stages-{}", Uuid::new_v4());
    seed_device(&device);
    let command = assets::Command::Detail {
        device,
        scope: assets::ReadScope::all(),
    };
    for (table, expected) in [
        ("mdm.inventory", "inventory_query"),
        ("mdm.manual_assignments", "manual_query"),
        ("mdm_access.collection_runs", "collection_query"),
    ] {
        sql(&format!("REVOKE SELECT ON {table} FROM mdm_flow_runtime"));
        let outcome = execute_asset(&m, &command).await;
        sql(&format!("GRANT SELECT ON {table} TO mdm_flow_runtime"));
        let error = outcome.unwrap_err();
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"kind":"unavailable","reason":expected})
        );
    }
    m.runtime.close().await;
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "real PG: independently constructed asset service, no Planning or App"]
async fn asset_capability_owns_execution_and_receipt_recovery() {
    for (tenant, ledger) in [
        (tenant(), false),
        (
            TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            true,
        ),
    ] {
        let runtime = runtime(tenant).await;
        let key = crate::flow::storage::cursor_key(&runtime, tenant)
            .await
            .unwrap();
        let service = assets::AssetService::new(
            audit_store_with_integrity(if ledger {
                rss_audit_postgres::Integrity::Ledger(Arc::new(
                    rss_ledger::Authenticator::new(
                        rss_ledger::KeyId::parse("asset-test").unwrap(),
                        vec![19; 32],
                    )
                    .unwrap(),
                ))
            } else {
                rss_audit_postgres::Integrity::Plain
            })
            .await,
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
        );
        let device = format!("independent-{}", Uuid::new_v4());
        seed_device_in(tenant, &device);
        let command = assets::Command::Manual {
            device: device.clone(),
            field: assets::FieldKey::AssetTag,
            change: operation(
                0,
                assets::ManualChange::Set {
                    value: assets::Scalar::String("independent".into()),
                },
            ),
            owner: assets::Owner {
                instance: "mdm".into(),
                principal: "operator".into(),
            },
        };
        let audit = || {
            let audit = RequestAudit::new(tenant.to_string(), "management_write");
            audit.set_principal("operator", "mdm");
            audit
        };
        runtime.inject_next_transaction_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        let first = audit();
        assert!(matches!(
            service.execute(&command, &first, &|| Ok(())).await,
            Err(Error::CommitUnknown)
        ));
        first.finalize(None);
        let canonical = || {
            sql(&format!(
                "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{tenant}' ORDER BY position"
            ))
        };
        let original = canonical();
        assert!(!original.is_empty());
        let replay = audit();
        let receipt = service
            .execute(&command, &replay, &|| Ok(()))
            .await
            .unwrap();
        replay.finalize(None);
        assert_eq!(canonical(), original);
        assert_eq!(receipt["asset"]["revision"], 1);
        let denied = audit();
        assert!(matches!(
            service
                .execute(&command, &denied, &|| Err(Error::Forbidden))
                .await,
            Err(Error::Forbidden)
        ));
        denied.finalize(None);
        let competing = |value: &str| assets::Command::Manual {
            device: device.clone(),
            field: assets::FieldKey::AssetTag,
            change: operation(
                1,
                assets::ManualChange::Set {
                    value: assets::Scalar::String(value.into()),
                },
            ),
            owner: assets::Owner {
                instance: "mdm".into(),
                principal: "operator".into(),
            },
        };
        let left = competing("left");
        let right = competing("right");
        let a = audit();
        let b = audit();
        let (a_result, b_result) = tokio::join!(
            service.execute(&left, &a, &|| Ok(())),
            service.execute(&right, &b, &|| Ok(()))
        );
        assert_eq!(
            usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()),
            1
        );
        assert!(
            matches!(a_result, Err(Error::Conflict)) || matches!(b_result, Err(Error::Conflict))
        );
        a.finalize(None);
        b.finalize(None);
        assert_eq!(canonical().lines().count(), original.lines().count() + 1);
        assert_eq!(
            sql(&format!(
                "SELECT count(*) FROM rss_ledger.entries WHERE tenant_id='{tenant}'"
            )),
            if ledger { "2" } else { "0" }
        );
        runtime.close().await;
    }
}

async fn audit_store() -> Arc<rss_mdm_audit_integration::AuditStore> {
    audit_store_with_integrity(rss_audit_postgres::Integrity::Plain).await
}
async fn audit_store_with_integrity(
    integrity: rss_audit_postgres::Integrity,
) -> Arc<rss_mdm_audit_integration::AuditStore> {
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database("backend")
        .username("mdm_access")
        .password("access-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2)).unwrap();
    let control = rss_audit_postgres::Control::new(&timer, deadline, &cancel);
    Arc::new(
        rss_mdm_audit_integration::AuditStore::new(pool, integrity, &control)
            .await
            .unwrap(),
    )
}

#[tokio::test]
#[ignore = "real PostgreSQL: management-t2"]
async fn audit_startup_rejects_each_borrowed_owner_snapshot_isolation() {
    let store = audit_store().await;
    for role in [
        "mdm_flow_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        sql(&format!(
            "ALTER ROLE {role} SET default_transaction_isolation='repeatable read'"
        ));
        let runtime = runtime_role(tenant(), role).await;
        let result = crate::database::admit_audit_runtime(&runtime, &store, tenant()).await;
        runtime.close().await;
        sql(&format!(
            "ALTER ROLE {role} RESET default_transaction_isolation"
        ));
        assert!(
            matches!(result, Err(Error::Unavailable(Failure::AuditIsolation))),
            "{role}: {result:?}"
        );
        let runtime = runtime_role(tenant(), role).await;
        crate::database::admit_audit_runtime(&runtime, &store, tenant())
            .await
            .unwrap();
        runtime.close().await;
    }
}

async fn assets(service: &Planning) -> Arc<assets::AssetService> {
    let key = crate::flow::storage::cursor_key(&service.runtime, service.tenant)
        .await
        .unwrap();
    Arc::new(assets::AssetService::new(
        service.audit_store.clone(),
        service.runtime.clone(),
        service.tenant,
        service.clock.clone(),
        &key,
    ))
}
