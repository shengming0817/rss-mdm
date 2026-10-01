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
    crate::test_support::case::name("enterprise-device")
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
        &format!("/api/v3/resources/{id}"),
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
    let _guard = super::software::content_setup_guard().await?;
    let request=Request::builder().method(Method::POST).uri(format!("/api/v3/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
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
    if kind["kind"] == "result" && kind.get("diagnostics").is_none() {
        let failure = match kind["quality"].as_str() {
            Some("truncated") => json!("output_limit"),
            Some("failed") => json!("capture_failed"),
            _ => Value::Null,
        };
        kind["diagnostics"] = json!({"stdout":"captured stdout","stderr":"captured stderr","durationMs":1,"executedAt":1,"failure":failure});
    }
    agent_call(router,Method::POST,&format!("/api/agent/v4/tasks/{}/events",task["payload"]["taskId"].as_str().unwrap()),Some(case_credential()),Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":operation,"attemptId":task["payload"]["attemptId"],"event":kind}))).await
}
pub(crate) async fn claim_request(router: &Router, operation: Uuid) -> Result<(StatusCode, Value)> {
    agent_call(
        router,
        Method::POST,
        "/api/agent/v4/tasks/claim",
        Some(case_credential()),
        Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":operation})),
    )
    .await
}
pub(crate) async fn claim(router: &Router) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = claim_request(router, Uuid::new_v4()).await?;
            ensure!(response.0 == StatusCode::OK, "claim: {response:?}");
            let _: rss_mdm_agent_wire::TaskClaimResponse =
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
    pub(crate) router: Router,
    pub(crate) execution: Arc<crate::execution::ExecutionService>,
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
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(&std::fs::read(
            base["task_signing"]["private_key_file"].as_str().unwrap(),
        )?)
        .unwrap();
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
        .await?;
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
            base,
            router,
            execution,
            plan_runtime,
            author,
            author_id,
            grants,
            key,
        })
    }
    pub(crate) async fn register(&mut self) -> Result<Value> {
        self.register_profile(json!(["inventory.basic.v4", "task.execute.v4"]))
            .await
    }
    pub(crate) async fn register_profile(&mut self, capabilities: Value) -> Result<Value> {
        let router = &self.router;
        let author = &mut self.author;
        author.operation = Some(Uuid::new_v4());
        let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let enrollment = post(
            author,
            router,
            "/api/v3/enrollments",
            json!({"deviceId":case_device_id(),"password":password,"source":"agent.builtin"}),
        )
        .await?;
        author.operation = None;
        let registration=agent_call(router,Method::POST,"/api/agent/v4/registrations",None,Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":case_credential(),"platform":"macos","architecture":"aarch64","capabilities":capabilities}))).await?;
        ensure!(
            registration.0 == StatusCode::CREATED && registration.1["capabilities"] == capabilities,
            "task registration: {registration:?}"
        );
        Ok(registration.1)
    }
    pub(crate) async fn scope(&mut self, scope: Uuid, targets: Value) -> Result<()> {
        let base = &self.base;
        let router = &self.router;
        let author = &mut self.author;
        let setup_automation = start_automation(base).await?;
        let created=post(author,router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":targets,"limitations":null,"exclusions":[]}}})).await?;
        await_task(
            author,
            router,
            &format!(
                "/api/v2/scopes/{scope}/tasks/{}",
                created["task"].as_str().unwrap()
            ),
        )
        .await?;
        crate::test_support::stop_worker(setup_automation).await?;
        Ok(())
    }
    pub(crate) async fn resource(&mut self) -> Result<(Uuid, &'static [u8], Value)> {
        let router = &self.router;
        let author = &mut self.author;
        let id = Uuid::new_v4();
        let bytes = b"#!/bin/sh\nprintf '{\"version\":\"1.2\",\"healthy\":true}\n'\n";
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"collection","mappings":{"custom.corporate_agent.version":"/version","custom.corporate_agent.healthy":"/healthy"}},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
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
    post(author,router,&format!("/api/v2/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    Ok(id)
}
pub(crate) async fn worker(base: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let config: Config = serde_json::from_value(base.clone())?;
    let service = crate::flow::execution::open(
        &config,
        crate::test_support::identity::audit_store(&config).await?,
        crate::flow::execution::open_content(&config)?,
        std::collections::BTreeMap::new(),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(service.clone()),
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
    launch.stage_deferred_task_with_token(service.registration(signals.flow()).critical());
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
