//! Capability preparation shared by planning, asset and audit storage tests.
use crate::planning::{Command, automation};
pub(crate) use crate::planning::{Planning, model::*};
pub(crate) use crate::{Error, assets};
pub(crate) use rss_mdm_audit_integration::RequestAudit;
pub(crate) use rss_mdm_flow_service::operation::Operation;
pub(crate) use rss_mdm_flow_service::transaction::deadline;
pub(crate) use rss_mdm_inventory_service::groups::{Command as GroupCommand, GroupChange};
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
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, t)
        .await
        .unwrap();
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

pub(super) trait FixtureCommand {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error>;
}
impl FixtureCommand for Command {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error> {
        m.execute(self, audit, &|| Ok(())).await.map_err(Into::into)
    }
}
impl FixtureCommand for GroupCommand {
    async fn run(&self, m: &Planning, audit: &RequestAudit) -> std::result::Result<Value, Error> {
        groups(m)
            .await
            .execute(self, audit, &|| Ok(()), m)
            .await
            .map_err(Into::into)
    }
}
pub(super) async fn execute(
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
    let key = rss_mdm_flow_service::storage::cursor_key(&m.runtime, m.tenant)
        .await
        .unwrap();
    rss_mdm_inventory_service::groups::Groups {
        reconcile_messaging: m.reconcile_messaging.clone(),
        objects: m.objects.clone(),
        tenant: m.tenant,
        groups: m.groups.clone(),
        runtime: m.runtime.clone(),
        audit_store: m.audit_store.clone(),
        clock: Arc::new(rss_mdm_flow_service::clock::InventoryClock(m.clock.clone())),
        cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
    }
}
pub(crate) async fn compliance(
    m: &Planning,
) -> Arc<rss_mdm_inventory_service::compliance::Compliance> {
    let key = rss_mdm_flow_service::storage::cursor_key(&m.runtime, m.tenant)
        .await
        .unwrap();
    Arc::new(rss_mdm_inventory_service::compliance::Compliance::new(
        rss_mdm_inventory_service::compliance::Dependencies {
            tenant: m.tenant,
            groups: m.groups.clone(),
            runtime: m.runtime.clone(),
            audit_store: m.audit_store.clone(),
            clock: Arc::new(rss_mdm_flow_service::clock::InventoryClock(m.clock.clone())),
            tasks: Arc::new(crate::automation::inventory_tasks::InventoryTasks),
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
    let result = service.execute(c, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result.map_err(Error::from)
}

pub(crate) fn operation<T>(expected_revision: u64, input: T) -> Operation<T> {
    Operation {
        operation_id: Uuid::new_v4(),
        expected_revision,
        input,
    }
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

pub(crate) async fn wait_task(
    m: &Planning,
    id: Uuid,
    family: crate::automation::TaskKind,
    target: &str,
) -> Value {
    wait_task_with_budget(m, id, family, target, Duration::from_secs(30)).await
}

pub(crate) async fn wait_task_with_budget(
    m: &Planning,
    id: Uuid,
    family: crate::automation::TaskKind,
    target: &str,
    budget: Duration,
) -> Value {
    let mut last = None;
    tokio::time::timeout(budget, async {
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
                Err(
                    Error::Flow(rss_mdm_flow_service::Error::Unavailable(
                        rss_mdm_flow_service::Failure::PlanningStorage,
                    ))
                    | Error::Flow(rss_mdm_flow_service::Error::CommitUnknown),
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
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2)).unwrap();
    let control = {
        let cutoff = deadline;
        rss_audit_postgres::Control::new(&timer, cutoff, cutoff, &cancel)
    };
    let runtime = crate::audit_test_support::source_runtime(&pool, tenant())
        .await
        .unwrap();
    Arc::new(
        rss_mdm_audit_integration::AuditStore::new(pool, integrity, runtime, tenant(), &control)
            .await
            .unwrap(),
    )
}

pub(crate) async fn assets(service: &Planning) -> Arc<assets::AssetService> {
    let key = rss_mdm_flow_service::storage::cursor_key(&service.runtime, service.tenant)
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
        Arc::new(crate::automation::inventory_tasks::InventoryTasks),
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
    sql(&format!(
        "INSERT INTO mdm_access.devices SELECT '{}','resume-{prefix}-'||lpad(n::text,4,'0') FROM generate_series(1,{count}) n",
        tenant()
    ));
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
    crate::automation::jobs::forward_jobs(
        &service.reconcile_messaging,
        &service.runtime,
        service.tenant,
        &service.audit_store,
    )
    .await
    .unwrap();
    task
}

pub(crate) async fn claim_job(
    worker: &crate::automation::PlanningWork,
    task: Uuid,
    lease: Duration,
) -> rss_reconcile_postgres::PgClaim {
    use rss_reconcile::DurableStore;
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let claims = worker
        .claim_due(
            &rss_reconcile::Scope::new(tenant(), "mdm.assets").unwrap(),
            64,
            lease,
            &control,
        )
        .await
        .unwrap();
    let mut selected = None;
    for claim in claims {
        if claim.target().entity() == format!("job:{task}") {
            selected = Some(claim);
        } else {
            worker.release(&claim, &control).await.unwrap();
        }
    }
    selected.expect("job must be claimable")
}

pub(crate) fn snapshot(task: Uuid) -> String {
    sql(&format!(
        "SELECT jsonb_build_array(j.cursor,j.completed,j.failure,r.total,(SELECT count(*) FROM mdm_assets.asset_query_results WHERE run='{task}')) FROM mdm_automation.automation_jobs j JOIN mdm_assets.asset_query_runs r ON r.id=j.id AND r.tenant_id=j.tenant_id WHERE j.id='{task}'"
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
                Ok(serde_json::to_value(&page.devices[0]).unwrap())
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
        let key = rss_mdm_flow_service::storage::cursor_key(&service.runtime, service.tenant)
            .await
            .unwrap();
        let assets = Arc::new(assets::AssetService::new(
            inventory.clone(),
            service.audit_store.clone(),
            service.runtime.clone(),
            service.tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            Arc::new(crate::automation::inventory_tasks::InventoryTasks),
        ));
        let automation = crate::automation::Automation::connect(
            crate::automation::PlanningWork::connect(service.clone(), options)
                .await
                .unwrap(),
            assets.clone(),
            compliance(&service).await,
        )
        .await
        .unwrap();
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
        let mut launch = startup.commit();
        launch.stage_task_with_token(notifications.registration().critical());
        launch.stage_deferred_task_with_token(
            automation.clone().registration(signals.flow()).critical(),
        );
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
    let source = crate::planning::execution_source::ExecutionSource::new(service.objects.clone());
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
                    owner
                        .audit_store
                        .bind_in(tx)
                        .await
                        .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                    rss_mdm_inventory_service::transaction::lock(tx)
                        .await
                        .map_err(|e| {
                            sqlx::Error::Protocol(format!("group baseline lock: {e:?}"))
                        })?;
                    let partition = owner.groups.partition(&id.to_string())?;
                    tx.prepare_outbox_partitions(&[partition]).await?;

                    owner
                        .publish_change_in(
                            tx,
                            *id,
                            change,
                            rss_contract::Timepoint::try_from(m.clock.unix_seconds().unwrap())
                                .unwrap(),
                            *m,
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

pub(crate) async fn finish_claim(
    worker: &crate::automation::Automation,
    claim: &rss_reconcile_postgres::PgClaim,
) {
    use rss_reconcile::{DurableStore, Reconciler};
    let timer = automation::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let diff = worker.observe(claim, &control).await.unwrap();
            if diff.drift() == rss_reconcile::DriftKind::Converged {
                break;
            }
            worker.apply(claim, diff, &control).await.unwrap();
        }
        worker
            .finish(claim, rss_reconcile::Completion::Converged, &control)
            .await
            .unwrap();
    })
    .await
    .expect("fixture task must finish");
}
