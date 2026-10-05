//! Real Policy publication, lazy device admission, delivery, result intake and recovery.
use crate::test_support::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub(crate) fn case_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| crate::test_support::credential("agent_execution-CREDENTIAL"))
}
pub(crate) fn case_inventory_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| crate::test_support::credential("agent_execution-INVENTORY_CREDENTIAL"))
}
pub(crate) fn case_task_scope() -> Uuid {
    Uuid::from_u128(crate::test_support::case::id("TASK_SCOPE"))
}
pub(crate) fn case_empty_scope() -> Uuid {
    Uuid::from_u128(crate::test_support::case::id("EMPTY_SCOPE"))
}
pub(crate) fn case_device_id() -> &'static str {
    crate::test_support::agent::device(
        case_credential(),
        crate::test_support::case::name("enterprise-device"),
    )
}

pub(crate) async fn post(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    body: Value,
) -> Result<Value> {
    let response = browser.call(router, Method::POST, path, Some(body)).await?;
    ensure!(response.0.is_success(), "{path}: {response:?}");
    Ok(response.1)
}
pub(crate) async fn resource(
    browser: &mut Browser,
    router: &Router,
    id: Uuid,
    revision: u64,
    input: Value,
) -> Result<Value> {
    post(
        browser,
        router,
        &format!("/api/v1/resources/{id}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input}),
    )
    .await
}
pub(crate) async fn upload(
    browser: &Browser,
    router: &Router,
    id: Uuid,
    bytes: &[u8],
) -> Result<StatusCode> {
    upload_for(browser, router, id, bytes, "macos", "aarch64").await
}
pub(crate) async fn upload_for(
    browser: &Browser,
    router: &Router,
    id: Uuid,
    bytes: &[u8],
    platform: &str,
    architecture: &str,
) -> Result<StatusCode> {
    let _guard = super::software::content_setup_guard().await?;
    let request=Request::builder().method(Method::POST).uri(format!("/api/v1/resources/{id}/content?version=v1&variant=default&platform={platform}&architecture={architecture}&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",browser.csrf.as_ref().unwrap())
        .header("cookie",browser.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
    Ok(router.clone().oneshot(request).await?.status())
}
pub(crate) async fn task_event(router: &Router, task: &Value, mut kind: Value) -> Result<Value> {
    let response = task_event_request(router, task, Uuid::new_v4(), &mut kind).await?;
    ensure!(response.0 == StatusCode::OK, "event: {response:?}");
    Ok(response.1)
}
pub(crate) async fn task_event_request(
    router: &Router,
    task: &Value,
    operation: Uuid,
    kind: &mut Value,
) -> Result<(StatusCode, Value)> {
    if kind["kind"] == "result" && kind.get("collectedAt").is_none() {
        kind["collectedAt"] = json!(2);
    }
    if kind["kind"] == "result" && kind.get("diagnostics").is_none() {
        let failure = match kind["quality"].as_str() {
            Some("truncated") => json!("output_limit"),
            Some("failed") => json!("capture_failed"),
            _ => Value::Null,
        };
        kind["diagnostics"] = json!({"stdout":"captured stdout","stderr":"captured stderr","durationMs":1,"executedAt":1,"failure":failure});
    }
    agent_call(router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{}/events",task["payload"]["taskId"].as_str().unwrap()),Some(case_credential()),Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":operation,"attemptId":task["payload"]["attemptId"],"event":kind}))).await
}
pub(crate) async fn claim_request(router: &Router, operation: Uuid) -> Result<(StatusCode, Value)> {
    agent_call(
        router,
        Method::POST,
        "/api/v1/agent/runtime/tasks/claim",
        Some(case_credential()),
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":operation})),
    )
    .await
}
pub(crate) async fn claim(router: &Router) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = claim_request(router, Uuid::new_v4()).await?;
            ensure!(response.0 == StatusCode::OK, "claim: {response:?}");
            let _: rss_mdm_agent_wire::runtime::TaskClaimResponse =
                serde_json::from_value(response.1.clone())?;
            if !response.1["task"].is_null() {
                return Ok::<_, anyhow::Error>(response.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
pub(crate) fn policy_definition(resource: Uuid, scope: Uuid) -> Value {
    json!({"scope":scope,"action": {"resource": {"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"execution","parameters":{},"runLifetimeSeconds":300}})
}
pub(crate) struct Fixture {
    pub(crate) base: Value,
    pub(crate) builtin_collections: Vec<Value>,
    pub(crate) router: Router,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) plan_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) author: Browser,
    pub(crate) author_id: String,
    pub(crate) grants: Vec<crate::authorization::Grant>,
    pub(crate) key: ring::signature::Ed25519KeyPair,
}
impl Fixture {
    pub(crate) async fn new() -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        Self::from_config(base).await
    }
    pub(crate) async fn from_config(base: Value) -> Result<Self> {
        let fixture_config: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let key_file = base["task_signing"]["private_key_file"]
            .as_str()
            .or_else(|| fixture_config["task_signing"]["private_key_file"].as_str())
            .ok_or_else(|| anyhow::anyhow!("fixture task key missing"))?;
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(&std::fs::read(key_file)?).unwrap();
        // Store startup recovery and fixture uploads share the content directory.
        let content_setup = super::software::content_setup_guard().await?;
        let (router, execution, plan_runtime) = crate::api::application_fixture(
            serde_json::from_value(base.clone())?,
            Arc::new(crate::clock::SystemClock),
            monotonic(),
            database(&base).await?,
            None,
            database(&base)
                .await?
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await
        .map_err(|error| anyhow::anyhow!("application fixture rejected: {error:?}"))?;
        drop(content_setup);
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        let mut author = Browser::default();
        ensure!(author.login(&router, "other").await? == StatusCode::OK);
        let author_id = browser_subject(&author, &router).await?;
        let mut grants = crate::test_support::identity::device_grants(
            Some(case_device_id()),
            &[
                "enrollment",
                "inventory_read",
                "script_execute",
                "operation_read",
                "operation_cancel",
            ],
        )?;
        for operation in [
            crate::authorization::Permission::PolicyWrite,
            crate::authorization::Permission::PolicyRead,
            crate::authorization::Permission::ResourceWrite,
            crate::authorization::Permission::ResourceRead,
            crate::authorization::Permission::GroupRead,
            crate::authorization::Permission::GroupWrite,
            crate::authorization::Permission::GroupRecompute,
            crate::authorization::Permission::ScopeRead,
            crate::authorization::Permission::ScopeWrite,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
        grants.push(crate::authorization::Grant {
            operation: crate::authorization::Permission::InventoryRead,
            scope: crate::authorization::Scope::AllDevices,
        });
        grants.extend(crate::test_support::identity::device_grants(
            None,
            &["script_execute"],
        )?);
        crate::test_support::identity::set_grants(case_tenant(), &author_id, grants.clone())
            .await?;
        Ok(Self {
            builtin_collections: Vec::new(),
            base,
            router,
            queries: execution.queries,
            content: execution.content,
            execution: execution.service,
            plan_runtime,
            author,
            author_id,
            grants,
            key,
        })
    }
    pub(crate) async fn register(&mut self) -> Result<Value> {
        self.register_profile(json!(["inventory.collect.v1", "task.execute.v1"]))
            .await
    }
    pub(crate) async fn register_profile(&mut self, capabilities: Value) -> Result<Value> {
        let old_device = case_device_id();
        let (_,registration)=crate::test_support::agent::enroll_profile(&self.router,&mut self.author,case_credential(),json!({"capabilities":capabilities,"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
        for grant in &mut self.grants {
            if let crate::authorization::Scope::Device { id } = &mut grant.scope
                && id == old_device
            {
                *id = registration["deviceId"].as_str().unwrap().into()
            }
        }
        crate::test_support::identity::set_grants(
            case_tenant(),
            &self.author_id,
            self.grants.clone(),
        )
        .await?;
        self.builtin_collections = registration["collections"].as_array().unwrap().clone();
        Ok(registration)
    }
    pub(crate) async fn scope(&mut self, scope: Uuid, targets: Value) -> Result<()> {
        let base = &self.base;
        let router = &self.router;
        let author = &mut self.author;
        let setup_automation = start_automation(base).await?;
        let created=post(author,router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":targets,"limitations":null,"exclusions":[]}}})).await?;
        await_task(
            author,
            router,
            &format!(
                "/api/v1/scopes/{scope}/tasks/{}",
                created["task"].as_str().unwrap()
            ),
        )
        .await?;
        crate::test_support::stop_worker(setup_automation).await?;
        Ok(())
    }
    pub(crate) async fn resource(&mut self) -> Result<(Uuid, &'static [u8], Value)> {
        self.resource_with_output_limit(4096).await
    }
    pub(crate) async fn resource_with_output_limit(
        &mut self,
        output_bytes: u32,
    ) -> Result<(Uuid, &'static [u8], Value)> {
        self.script_resource(output_bytes, false).await
    }
    pub(crate) async fn script_resource(
        &mut self,
        output_bytes: u32,
        inputs: bool,
    ) -> Result<(Uuid, &'static [u8], Value)> {
        let router = &self.router;
        let author = &mut self.author;
        let id = Uuid::new_v4();
        let bytes = b"#!/bin/sh\nprintf '{\"version\":\"1.2\",\"healthy\":true}\n'\n";
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"},"padding":{"type":"string"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"collection","mappings":{"custom.corporate_agent.version":"/version","custom.corporate_agent.healthy":"/healthy"}},"timeoutSeconds":60,"outputBytes":output_bytes,"maxRows":1});
        if inputs {
            definition["parameters"] = json!({"type":"object","properties":{"name":{"type":"string","maxLength":32},"path":{"type":"string","maxLength":64,"enum":["/Applications","/Library"]}},"required":["name","path"],"additionalProperties":false});
            definition["bindings"] = json!({"name":{"kind":"positional","index":0},"path":{"kind":"environment","name":"RSS_PARAM_PATH"}});
        }
        resource(
            author,
            router,
            id,
            0,
            json!({"action":"create","kind":"script"}),
        )
        .await?;
        resource(author,router,id,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"fixture-script","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
        ensure!(upload(author, router, id, bytes).await? == StatusCode::CREATED);
        resource(
            author,
            router,
            id,
            2,
            json!({"action":"activate","version":"v1"}),
        )
        .await?;
        Ok((id, bytes, definition))
    }
}
pub(crate) async fn publish(author: &mut Browser, router: &Router, resource: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    Ok(id)
}
pub(crate) async fn worker(base: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let config: Config = serde_json::from_value(base.clone())?;
    let service = crate::execution_assembly::open(
        &config,
        config.native_protector()?,
        crate::test_support::identity::audit_store(&config).await?,
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?,
        std::collections::BTreeMap::new(),
        rss_device_command_postgres::CommandClock::Postgres,
        crate::test_support::identity::session_authority(&config).await?,
    )
    .await?
    .service;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        rss_mdm_execution_service::Resource(service.clone()),
    ));
    let notifications = crate::worker_wake::Listener::new(
        config.access_database.options()?,
        rss_request_context::TenantId::parse(&config.identity.tenant_id)?,
    );
    let signals = notifications.signals.clone();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.registration().critical());
    launch.stage_deferred_task_with_token(service.registration(signals.execution()).critical());
    launch.finish();
    Ok(Some(owner))
}
pub(crate) async fn complete(router: &Router, task: &Value) -> Result<()> {
    task_event(router, task, json!({"kind":"received"})).await?;
    task_event(router, task, json!({"kind":"start"})).await?;
    task_event(router,task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    Ok(())
}

pub(crate) fn run_count(policy: Uuid) -> Result<String> {
    pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{policy}'",
        case_tenant()
    ))
}

/// Prepare historical ownership before exercising the current retirement/recovery paths.
pub(crate) async fn historical_remote_run(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    run: Uuid,
    parent: Uuid,
) -> Result<()> {
    sqlx::query("INSERT INTO mdm_planning.remote_operations(tenant_id,id,resource,resource_version,frozen,snapshot,created_at,deadline,author,staged) SELECT r.tenant_id,$3,p.definition->'action'->'resource'->>'id',p.definition->'action'->'resource'->>'version',v.frozen,jsonb_build_object('kind','devices','devices',jsonb_build_array(r.device)),r.created_at,r.deadline,'{}',true FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE r.tenant_id=$1::uuid AND r.id=$2")
        .bind(tenant).bind(run).bind(parent).execute(&mut *c).await?;
    sqlx::query("INSERT INTO mdm_planning.remote_operation_targets(tenant_id,operation,device,status,delivery_id) SELECT tenant_id,$3,device,'accepted',id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(run).bind(parent).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_commands.action_runs SET source_kind='remote_operation',remote_operation=$3,policy_version=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(run).bind(parent).execute(&mut *c).await?;
    Ok(())
}

/// Reconstruct a predecessor Remote record from complete production-owned script material.
/// This fixture writes historical coordinates directly; no current execution entrance invokes it.
pub(crate) async fn historical_remote(f: &Fixture, task: &Value, parent: Uuid) -> Result<Value> {
    use sqlx::Connection;
    let run = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    historical_remote_run(&mut c, case_tenant(), run, parent).await?;
    let config: crate::task_signing::Config =
        serde_json::from_value(f.base["task_signing"].clone())?;
    let signer = crate::task_signing::open(&config)?;
    let sign = |value: Value| -> Result<Value> {
        let mut value = value;
        value["payload"]["authorization"] = json!({"kind":"remote_operation","operationId":parent});
        Ok(serde_json::to_value(signer.sign(
            serde_json::from_value(value["payload"].clone())?,
        )?)?)
    };
    let attempts:Vec<(Uuid,Value,Option<Value>)>=sqlx::query_as("SELECT id,offer,permit FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND run=$2").bind(case_tenant()).bind(run).fetch_all(&mut c).await?;
    for (id, offer, permit) in attempts {
        sqlx::query("UPDATE mdm_commands.action_attempts SET offer=$3,permit=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).bind(sign(offer)?).bind(permit.map(sign).transpose()?).execute(&mut c).await?;
    }
    c.close().await?;
    sign(task.clone())
}
