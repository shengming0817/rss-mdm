//! Capability preparation shared by planning, asset and audit storage tests.
pub(crate) use crate::planning::Planning;
use crate::planning::automation;
pub(crate) use crate::{Error, assets};
pub(crate) use rss_mdm_audit_integration::RequestAudit;
pub(crate) use rss_mdm_flow_service::transaction::deadline;
pub(crate) use rss_mdm_inventory_service::groups::{Command as GroupCommand, GroupChange};
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_mdm_scope_service::Command;
pub(crate) use rss_request_context::{Deadline, TenantId};
pub(crate) use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
pub(crate) use rss_transactional_messaging_postgres::{
    PgConfig, PgPassword, PgPrivateCa, PgRuntime,
};
pub(crate) use serde_json::{Value, json};
pub(crate) use std::{sync::Arc, time::Duration};
pub(crate) use uuid::Uuid;

pub(crate) fn tenant() -> TenantId {
    TenantId::parse(crate::test_support::case::tenant()).unwrap()
}

pub(crate) fn fixture() -> Value {
    serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG").unwrap()).unwrap())
        .unwrap()
}

pub(crate) async fn audit_records() -> Vec<crate::audit_test_support::Record> {
    crate::audit_test_support::audit_records().await.unwrap()
}

pub(crate) fn sql(statement: &str) -> String {
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
            config["database"].as_str().unwrap(),
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

pub(crate) async fn runtime(t: TenantId) -> Arc<PgRuntime> {
    runtime_role(t, "mdm_flow_runtime").await
}

pub(crate) async fn runtime_role(t: TenantId, role: &str) -> Arc<PgRuntime> {
    let c = fixture();
    let config = PgConfig::new(
        "localhost",
        c["port"].as_u64().unwrap() as u16,
        c["database"].as_str().unwrap(),
        role,
        PgPassword::new("runtime-fixture"),
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

pub(crate) async fn planning(t: TenantId) -> Planning {
    let audit = audit_store().await;
    let runtime = runtime(t).await;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        audit
            .on_runtime(runtime.clone(), t, &budget.control())
            .await
            .unwrap(),
    );
    let clock = Arc::new(crate::clock::SystemClock);
    let key = crate::cursor_keys::load(&runtime, t).await.unwrap();
    Planning::new(
        audit.clone(),
        runtime,
        t,
        clock,
        &key,
        Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
            audit,
        )),
    )
    .await
    .unwrap()
}

pub(crate) struct ScopeClock(pub Arc<dyn rss_mdm_flow_service::clock::Clock>);
impl rss_mdm_scope_service::clock::Clock for ScopeClock {
    fn unix_seconds(&self) -> std::result::Result<i64, rss_mdm_scope_service::Error> {
        self.0.unix_seconds().map_err(|_| {
            rss_mdm_scope_service::Error::Unavailable(rss_mdm_scope_service::Failure::Clock)
        })
    }
}
pub(crate) async fn scopes(m: &Planning) -> Arc<rss_mdm_scope_service::Scopes> {
    let key = crate::cursor_keys::load(&m.runtime, m.tenant)
        .await
        .unwrap();
    Arc::new(
        rss_mdm_scope_service::Scopes::new(
            m.runtime.clone(),
            m.tenant,
            Arc::new(ScopeClock(m.clock.clone())),
            rss_mdm_scope_service::Dependencies {
                audit_store: m.audit_store.clone(),
                reconcile_messaging: m.reconcile_messaging.clone(),
                objects: m.objects.clone(),
                groups: m.groups.clone(),
                cursor_key: key,
                projection: Arc::new(rss_mdm_execution_service::scope::ScopeProjection::new(
                    m.runtime.clone(),
                    m.tenant,
                )),
                dependents: Arc::new(
                    rss_mdm_flow_service::planning::policies::scope_changes::ScopeChanges::new(
                        m.runtime.clone(),
                        m.tenant,
                    ),
                ),
            },
        )
        .await
        .unwrap(),
    )
}
pub(crate) fn scope_operation<T>(
    expected_revision: u64,
    input: T,
) -> rss_mdm_scope_service::operation::Operation<T> {
    rss_mdm_scope_service::operation::Operation {
        operation_id: Uuid::new_v4(),
        expected_revision,
        input,
    }
}
pub(crate) trait FixtureCommand {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error>;
}
impl FixtureCommand for Command {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error> {
        scopes(m)
            .await
            .execute(self, audit, &|| Ok(()))
            .await
            .map_err(Into::into)
    }
}
impl FixtureCommand for GroupCommand {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error> {
        let proof = group_proof(m).await;
        groups(m)
            .await
            .execute(self, audit, &proof)
            .await
            .map_err(Into::into)
    }
}
pub(crate) async fn execute(
    m: &Planning,
    c: &impl FixtureCommand,
) -> std::result::Result<Value, Error> {
    let audit = RequestAudit::new(
        m.tenant.to_string(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.set_principal("operator", crate::test_support::INSTANCE);
    let result = c.run(m, &audit).await;
    audit.finalize(None);
    result
}
pub(crate) async fn groups(m: &Planning) -> rss_mdm_inventory_service::groups::Groups {
    let key = crate::cursor_keys::load(&m.runtime, m.tenant)
        .await
        .unwrap();
    rss_mdm_inventory_service::groups::Groups::new(
        rss_mdm_inventory_service::groups::Dependencies {
            reconcile_messaging: m.reconcile_messaging.clone(),
            objects: m.objects.clone(),
            tenant: m.tenant,
            groups: m.groups.clone(),
            runtime: m.runtime.clone(),
            audit_store: m.audit_store.clone(),
            clock: Arc::new(rss_mdm_flow_service::clock::InventoryClock(m.clock.clone())),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
        },
    )
    .await
    .unwrap()
}
pub(crate) async fn compliance(
    m: &Planning,
) -> Arc<rss_mdm_inventory_service::compliance::Compliance> {
    let key = crate::cursor_keys::load(&m.runtime, m.tenant)
        .await
        .unwrap();
    Arc::new(rss_mdm_inventory_service::compliance::Compliance::new(
        rss_mdm_inventory_service::compliance::Dependencies {
            tenant: m.tenant,
            groups: m.groups.clone(),
            runtime: m.runtime.clone(),
            audit_store: m.audit_store.clone(),
            clock: Arc::new(rss_mdm_flow_service::clock::InventoryClock(m.clock.clone())),
            reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(
                m.runtime.clone(),
                m.tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
        },
    ))
}
pub(crate) fn group_operation(
    expected_revision: u64,
    input: GroupChange,
) -> rss_mdm_inventory_service::operation::Operation<GroupChange> {
    rss_mdm_inventory_service::operation::Operation {
        operation_id: Uuid::new_v4(),
        expected_revision,
        input,
    }
}

pub(crate) async fn execute_asset(
    m: &Planning,
    c: &assets::Command,
) -> std::result::Result<Value, Error> {
    let service = assets(m).await;
    execute_asset_service(m, &service, c).await
}

pub(crate) async fn execute_asset_service(
    m: &Planning,
    service: &assets::AssetService,
    c: &assets::Command,
) -> std::result::Result<Value, Error> {
    let audit = RequestAudit::new(
        m.tenant.to_string(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.set_principal("operator", crate::test_support::INSTANCE);
    let result = service
        .execute(c, &audit, &|| Ok(()))
        .await
        .map(|v| serde_json::to_value(v).expect("asset response serializes"));
    audit.finalize(None);
    result.map_err(Error::from)
}

pub(crate) fn scope(group: Uuid) -> ScopeDefinition {
    ScopeDefinition {
        targets: [Reference::Group(group)].into(),
        limitations: None,
        exclusions: Default::default(),
    }
}

pub(crate) fn seed_device(device: &str) -> String {
    seed_device_in(tenant(), device)
}

pub(crate) fn seed_device_in(t: TenantId, device: &str) -> String {
    let registration = Uuid::new_v4().to_string();
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    sql(&format!(
        "SET rss.tenant_id='{t}'; INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{t}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) VALUES('{t}','{request}','{grant}','mdm.windows','Device');INSERT INTO mdm_access.devices VALUES('{t}','{device}');INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES('{t}','{registration}','{device}','mdm',1,'{request}','active','primary',gen_random_uuid());INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES('{t}',gen_random_uuid(),'{registration}','mdm',encode(sha256(convert_to('{registration}','UTF8')),'hex'),'active');INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{t}','{registration}','mdm.windows','{epoch}',true);"
    ));
    registration
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TaskFamily {
    Group,
    Scope,
}

pub(crate) async fn wait_task(m: &Planning, id: Uuid, family: TaskFamily, target: &str) -> Value {
    wait_task_with_budget(m, id, family, target, Duration::from_secs(30)).await
}

pub(crate) async fn wait_task_with_budget(
    m: &Planning,
    id: Uuid,
    family: TaskFamily,
    target: &str,
    budget: Duration,
) -> Value {
    let group_owner = groups(m).await;
    let group_actor = if matches!(family, TaskFamily::Group) {
        Some(group_proof(m).await)
    } else {
        None
    };
    let mut last = None;
    tokio::time::timeout(budget, async {
        loop {
            let result=match family {
                TaskFamily::Group=>{
                    let audit=RequestAudit::new(m.tenant.to_string(),"management_read",rss_mdm_audit_integration::AuditIntent::Routine);
                    let result=group_owner.execute(&GroupCommand::TaskRead{id,target:target.into()},&audit,group_actor.as_ref().unwrap()).await.map_err(Error::from);
                    audit.finalize(None);result
                },
                TaskFamily::Scope=>execute(m,&Command::TaskRead{id,target:target.into()}).await,
            };
            let value = match result {
                Ok(value) => value,
                Err(
                    Error::Flow(rss_mdm_flow_service::Error::Unavailable(
                        rss_mdm_flow_service::Failure::PlanningStorage,
                    ))
                    | Error::Flow(rss_mdm_flow_service::Error::CommitUnknown)
                    | Error::Scope(rss_mdm_scope_service::Error::Unavailable(_) | rss_mdm_scope_service::Error::CommitUnknown),
                ) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => panic!("task status failed: {error:?}"),
            };
            last = Some(value.clone());
            if value["status"] == "completed" {
                return value;
            }
            assert!(value["failure"].is_null(), "task failed: {value}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|error| panic!("bounded fixture {family:?} task {id} for {target} did not complete: {error}; last={last:?}; health={:?}", m.automation_health()))
}

pub(crate) async fn audit_store() -> Arc<rss_mdm_audit_integration::AuditStore> {
    audit_store_with_integrity(rss_audit_postgres::Integrity::Plain).await
}

pub(crate) async fn audit_store_with_integrity(
    integrity: rss_audit_postgres::Integrity,
) -> Arc<rss_mdm_audit_integration::AuditStore> {
    let config = fixture();
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_access")
        .password("access-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let runtime = crate::audit_test_support::source_runtime(&pool, tenant())
        .await
        .unwrap();
    // Audit admission owns this budget; producer initialization has its own control.
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2)).unwrap();
    let control = {
        let cutoff = deadline;
        rss_audit_postgres::Control::new(&timer, cutoff, cutoff, &cancel)
    };
    Arc::new(
        rss_mdm_audit_integration::AuditStore::new(pool, integrity, runtime, tenant(), &control)
            .await
            .unwrap(),
    )
}

pub(crate) async fn assets(service: &Planning) -> Arc<assets::AssetService> {
    let key = crate::cursor_keys::load(&service.runtime, service.tenant)
        .await
        .unwrap();
    Arc::new(assets::AssetService::new(
        inventory_runtime(service.tenant).await,
        service.audit_store.clone(),
        service.runtime.clone(),
        service.tenant,
        Arc::new(rss_mdm_flow_service::clock::InventoryClock(
            service.clock.clone(),
        )),
        &key,
        rss_reconcile_postgres::PgMessagingStore::new(
            service.runtime.clone(),
            service.tenant,
            rss_mdm_inventory_service::transaction::deadline(),
        )
        .await
        .unwrap(),
    ))
}

pub(crate) fn options() -> sqlx::postgres::PgConnectOptions {
    let config = fixture();
    sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_flow_runtime")
        .password("runtime-fixture")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap())
}

pub(crate) async fn query_job(service: &Planning, count: usize) -> Uuid {
    let prefix = Uuid::new_v4();
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect_with(
        &crate::device::test_support::options("postgres").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant().to_string())
        .execute(&mut connection)
        .await
        .unwrap();
    let inserted = sqlx::query("INSERT INTO mdm_access.devices SELECT $1::uuid,$2||lpad(n::text,4,'0') FROM generate_series(1,$3) n")
        .bind(tenant().to_string()).bind(format!("resume-{prefix}-"))
        .bind(i32::try_from(count).unwrap()).execute(&mut connection).await;
    let closed = connection.close().await;
    inserted.unwrap();
    closed.unwrap();
    let task = Uuid::new_v4();
    execute_asset(
        service,
        &assets::Command::Search {
            request: rss_mdm_inventory_service::operation::Operation {
                operation_id: task,
                expected_revision: 0,
                input: assets::rsql::QueryInput::default(),
            }
            .into(),
            scope: assets::ReadScope {
                authority: "internal".into(),
                collection_scope: rss_mdm_inventory::CollectionScope::Device,

                subject: prefix.to_string(),
                devices: Some(
                    (1..=count)
                        .map(|n| format!("resume-{prefix}-{n:04}"))
                        .collect(),
                ),
            },
        },
    )
    .await
    .unwrap();
    task
}

pub(crate) fn snapshot(task: Uuid) -> String {
    sql(&format!(
        "SELECT jsonb_build_array(j.cursor,j.completed,j.failure,j.total,(SELECT count(*) FROM mdm_assets.asset_query_results WHERE run='{task}')) FROM mdm_assets.asset_query_runs j WHERE j.id='{task}'"
    ))
}

pub(crate) async fn frozen_device(service: &Planning, device: &str, watermark: i64) -> Value {
    let device = device.to_owned();
    service
        .runtime
        .local_tx_with_context(tenant(), deadline(), service, move |m, tx| {
            Box::pin(async move {
                let page = m
                    .asset_reader
                    .asset_page_in(
                        tx,
                        watermark,
                        None,
                        1,
                        &assets::ReadScope {
                            authority: "internal".into(),
                            collection_scope: rss_mdm_inventory::CollectionScope::Device,

                            subject: "history-evidence".into(),
                            devices: Some([device].into()),
                        },
                    )
                    .await
                    .map_err(|_| sqlx::Error::Protocol("history fixture read failed".into()))?;
                Ok(serde_json::to_value(&page.devices[0].scalars).unwrap())
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
        )
}
pub(crate) struct RunningAutomation {
    stack: rss_runtime::ShutdownStack,
    automation: Arc<crate::automation::Automation>,
    pub(crate) assets: Arc<assets::AssetService>,
    inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
}
impl RunningAutomation {
    pub(crate) async fn start(service: Arc<Planning>) -> Self {
        Self::start_with_execution(service, None).await
    }
    pub(crate) async fn start_with_execution(
        service: Arc<Planning>,
        execution: Option<Arc<rss_mdm_execution_service::ExecutionService>>,
    ) -> Self {
        let config = fixture();
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("localhost")
            .port(config["port"].as_u64().unwrap() as u16)
            .database(config["database"].as_str().unwrap())
            .username("mdm_flow_runtime")
            .password("runtime-fixture")
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(config["ca"].as_str().unwrap());
        let inventory = inventory_runtime(service.tenant).await;
        let key = crate::cursor_keys::load(&service.runtime, service.tenant)
            .await
            .unwrap();
        let assets = Arc::new(assets::AssetService::new(
            inventory.clone(),
            service.audit_store.clone(),
            service.runtime.clone(),
            service.tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            rss_reconcile_postgres::PgMessagingStore::new(
                service.runtime.clone(),
                service.tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
        ));
        let work = match execution {
            Some(execution) => {
                crate::automation::PlanningWork::connect(service.clone(), execution, options)
                    .await
                    .unwrap()
            }
            None => crate::automation::PlanningWork::connect_planning(service.clone(), options)
                .await
                .unwrap(),
        };
        let automation = crate::automation::Automation::connect(work).await.unwrap();
        let query_work = Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
            assets.clone(),
            automation.work.scheduler(),
        ));
        let compliance_work = Arc::new(
            rss_mdm_inventory_service::compliance::runtime::ComplianceWork::new(
                compliance(&service).await,
                automation.work.scheduler(),
            ),
        );
        let (group_work, scope_work, scope_delivery) =
            scope_group_components(&service, automation.work.scheduler()).await;
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(10)).unwrap(),
            Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .unwrap();
        let notifications = crate::worker_wake::Listener::new(
            crate::device::test_support::options("mdm_access").unwrap(),
            service.tenant,
        );
        let signals = notifications.signals.clone();
        let mut startup = stack.startup().unwrap();
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            notifications.clone(),
        ));
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::scope_group_changes::Resource(scope_delivery.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_deferred_task_with_token(
            scope_work
                .registration(signals.handle(crate::worker_wake::Work::Scopes))
                .critical(),
        );
        launch.stage_task_with_token(notifications.registration().critical());
        launch.stage_deferred_task_with_token(
            query_work
                .registration(signals.handle(crate::worker_wake::Work::AssetQueries))
                .critical(),
        );
        launch.stage_deferred_task_with_token(
            compliance_work
                .registration(signals.handle(crate::worker_wake::Work::Compliance))
                .critical(),
        );

        launch.stage_deferred_task_with_token(
            automation.clone().registration(signals.flow()).critical(),
        );
        launch.stage_deferred_task_with_token(
            group_work
                .registration(signals.handle(crate::worker_wake::Work::Groups))
                .critical(),
        );
        launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
        launch.finish();
        Self {
            stack,
            automation,
            assets,
            inventory,
        }
    }
    pub(crate) async fn stop(self) {
        assert!(self.stack.shutdown().join().await.unwrap().is_clean());
        self.inventory.close_fixture().await.unwrap();
        rss_runtime::ManagedResource::shutdown(&crate::automation::Resource(
            self.automation.work.clone(),
        ))
        .await
        .unwrap();
    }
}

pub(crate) fn inventory_operation<T>(
    expected_revision: u64,
    input: T,
) -> rss_mdm_inventory_service::operation::Operation<T> {
    rss_mdm_inventory_service::operation::Operation {
        operation_id: Uuid::new_v4(),
        expected_revision,
        input,
    }
}

pub(crate) async fn scope_admission(
    service: &Planning,
    scope: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &str,
) -> rss_mdm_execution_service::source_authority::ScopeAdmission {
    use rss_mdm_execution_service::source_authority::SourceAuthority;
    let source =
        rss_mdm_flow_service::planning::policies::source::execution(service.objects.clone());
    let tenant = service.tenant;
    let device = device.to_owned();
    service
        .runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .admission_on(c, tenant, scope, channel, &device)
                            .await)
                    })
                })
                .await
            })
        })
        .await
        .fold(
            |v| v.unwrap(),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |_| panic!("unknown"),
            |_| panic!("unknown"),
            |e| panic!("{e:?}"),
        )
}

pub(crate) async fn inventory_runtime(
    tenant: TenantId,
) -> Arc<crate::inventory_runtime::InventoryRuntime> {
    let options = crate::device::test_support::options;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(options("mdm_access").unwrap());
    let access = Arc::new(rss_mdm_inventory_service::Store::from_pool(pool));
    crate::inventory_runtime::InventoryRuntime::fixture(
        options("mdm_runtime").unwrap(),
        access,
        tenant,
        crate::test_support::runtime::monotonic(),
        audit_store_with_integrity(rss_audit_postgres::Integrity::Plain).await,
    )
    .await
    .unwrap()
}

/// Legal definition baseline for tests of membership/Scope rather than definition authoring.
pub(crate) async fn seed_group(
    m: &Planning,
    command: &GroupCommand,
) -> std::result::Result<Value, Error> {
    let GroupCommand::Group { id, change } = command else {
        panic!("group baseline requires a mutation");
    };
    let owner = groups(m).await;
    m.runtime
        .local_tx_with_context(
            m.tenant,
            deadline(),
            (&owner, m, *id, change.as_ref()),
            |(owner, m, id, change), tx| {
                Box::pin(async move {
                    m.audit_store
                        .bind_in(tx)
                        .await
                        .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                    let partition = m.groups.partition(&id.to_string())?;
                    tx.prepare_outbox_partitions(&[partition]).await?;
                    rss_mdm_inventory_service::transaction::lock(tx)
                        .await
                        .map_err(|e| {
                            sqlx::Error::Protocol(format!("group baseline lock: {e:?}"))
                        })?;
                    let tenant = m.tenant.to_string();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("SELECT mdm_devices.lock_query_revision($1::uuid)")
                                .bind(tenant)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;

                    owner
                        .publish_change_in(
                            tx,
                            *id,
                            change,
                            rss_contract::Timepoint::try_from(m.clock.unix_seconds().unwrap())
                                .unwrap(),
                            &[],
                        )
                        .await
                        .map_err(|e| sqlx::Error::Protocol(format!("group baseline: {e:?}")).into())
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |_| panic!("unknown baseline commit"),
            |_| panic!("unknown baseline rollback"),
            |e| panic!("{e:?}"),
        )
}

pub(crate) fn group_page_query(
    limit: usize,
    cursor: Option<String>,
) -> rss_mdm_query::window::Query {
    let mut raw = url::form_urlencoded::Serializer::new(String::new());
    raw.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        raw.append_pair("cursor", &cursor);
    }
    rss_mdm_inventory_service::groups::pages::SCHEMA
        .parse(&raw.finish())
        .unwrap()
        .0
}
pub(crate) fn scope_page_query(
    limit: usize,
    cursor: Option<String>,
) -> rss_mdm_scope_service::pages::ResultQuery {
    let mut raw = url::form_urlencoded::Serializer::new(String::new());
    raw.append_pair("limit", &limit.to_string())
        .append_pair("channel", "mdm");
    if let Some(cursor) = cursor {
        raw.append_pair("cursor", &cursor);
    }
    rss_mdm_scope_service::pages::ResultQuery::parse(&raw.finish()).unwrap()
}

#[path = "group_support.rs"]
mod group_support;
pub(crate) use group_support::{
    GroupWorker, claim_group, finish_group_claim, group_proof, scope_group_components,
};

pub(crate) struct QueryWorker {
    worker: rss_mdm_inventory_service::assets::runtime::QueryWork,
    schedule: rss_reconcile_postgres::PgStore,
}
impl std::ops::Deref for QueryWorker {
    type Target = rss_mdm_inventory_service::assets::runtime::QueryWork;
    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}
impl QueryWorker {
    pub(crate) async fn open(service: &Planning) -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options())
            .await
            .unwrap();
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let schedule = rss_reconcile_postgres::PgStore::new(pool, &control)
            .await
            .unwrap();
        Self {
            worker: rss_mdm_inventory_service::assets::runtime::QueryWork::new(
                assets(service).await,
                schedule.clone(),
            ),
            schedule,
        }
    }
    pub(crate) fn as_ref(&self) -> &rss_mdm_inventory_service::assets::runtime::QueryWork {
        &self.worker
    }
    pub(crate) async fn close(&self) {
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        assert!(matches!(
            self.schedule.close(&control).await,
            rss_reconcile_postgres::CloseOutcome::Drained
        ));
    }
}
pub(crate) async fn claim_query(
    worker: &QueryWorker,
    task: Uuid,
    lease: Duration,
) -> rss_reconcile_postgres::PgClaim {
    use rss_reconcile::DurableStore;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let claims = worker
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.asset-queries").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap();
    let mut selected = None;
    for claim in claims {
        if claim.target().entity() == format!("task:{task}") {
            selected = Some(claim);
        } else {
            worker.release(&claim, &control).await.unwrap();
        }
    }
    selected.expect("query must be claimable")
}

pub(crate) struct ScopeWorker {
    worker: rss_mdm_scope_service::runtime::ScopeWork,
    schedule: rss_reconcile_postgres::PgStore,
}
impl std::ops::Deref for ScopeWorker {
    type Target = rss_mdm_scope_service::runtime::ScopeWork;
    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}
impl ScopeWorker {
    pub(crate) async fn open(service: &Planning) -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options())
            .await
            .unwrap();
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let schedule = rss_reconcile_postgres::PgStore::new(pool, &control)
            .await
            .unwrap();
        Self {
            worker: rss_mdm_scope_service::runtime::ScopeWork::new(
                scopes(service).await,
                schedule.clone(),
            ),
            schedule,
        }
    }
    pub(crate) async fn close(&self) {
        let timer = automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        assert!(matches!(
            self.schedule.close(&control).await,
            rss_reconcile_postgres::CloseOutcome::Drained
        ));
    }
}
pub(crate) async fn claim_scope(
    worker: &ScopeWorker,
    task: Uuid,
    lease: Duration,
) -> rss_reconcile_postgres::PgClaim {
    use rss_reconcile::DurableStore;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let claims = worker
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.scopes").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap();
    let mut selected = None;
    for claim in claims {
        if claim.target().entity() == format!("task:{task}") {
            selected = Some(claim);
        } else {
            worker.release(&claim, &control).await.unwrap();
        }
    }
    selected.expect("Scope must be claimable")
}
