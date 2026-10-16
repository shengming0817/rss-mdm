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
    agent_call(router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{}/events",task["payload"]["task"]["taskId"].as_str().unwrap()),Some(case_credential()),Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":operation,"attemptId":task["payload"]["task"]["attemptId"],"event":kind}))).await
}
pub(crate) async fn claim_request(router: &Router, operation: Uuid) -> Result<(StatusCode, Value)> {
    agent_call(
        router,
        Method::POST,
        "/api/v1/agent/runtime/tasks/claim",
        Some(case_credential()),
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":operation})),
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
    pub(crate) resources: super::Resources,
    pub(crate) base: Value,
    pub(crate) builtin_collections: Vec<Value>,
    pub(crate) router: Router,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) planning: Arc<rss_mdm_flow_service::planning::Planning>,
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
        let (resources, mut fixture) = crate::test_support::Resources::build(move |resources| {
            Box::pin(async move {
                let fixture_config: Value =
                    serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
                let key_file = base["task_signing"]["private_key_file"]
                    .as_str()
                    .or_else(|| fixture_config["task_signing"]["private_key_file"].as_str())
                    .ok_or_else(|| anyhow::anyhow!("fixture task key missing"))?;
                let key =
                    ring::signature::Ed25519KeyPair::from_pkcs8(&std::fs::read(key_file)?).unwrap();
                // Store startup recovery and fixture uploads share the content directory.
                let content_setup = super::software::content_setup_guard().await?;
                let access = database(&base).await?;
                let audit = access
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await?;
                let (router, execution, plan_runtime, planning, application_resources) =
                    crate::api::application_fixture(
                        serde_json::from_value(base.clone())?,
                        Arc::new(crate::clock::SystemClock),
                        monotonic(),
                        access,
                        None,
                        audit,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("application fixture rejected: {error:?}"))?;
                resources.extend(application_resources);
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
                crate::test_support::identity::set_grants(
                    case_tenant(),
                    &author_id,
                    grants.clone(),
                )
                .await?;
                Ok(Self {
                    resources: Default::default(),
                    builtin_collections: Vec::new(),
                    base,
                    router,
                    queries: execution.queries,
                    content: execution.content,
                    execution: execution.service,
                    plan_runtime,
                    planning,
                    author,
                    author_id,
                    grants,
                    key,
                })
            })
        })
        .await?;
        fixture.resources = resources;
        Ok(fixture)
    }
    pub(crate) async fn register(&mut self) -> Result<Value> {
        self.register_profile(json!(["inventory.collect.v1", "task.execute.v1"]))
            .await
    }
    pub(crate) async fn register_profile(&mut self, capabilities: Value) -> Result<Value> {
        let old_device = case_device_id();
        let registration = crate::test_support::agent::seed_profile(&self.base, self.execution.clone(),
            case_credential(), old_device, json!({"capabilities":capabilities,"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
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
        seed_scope(&self.planning, scope, targets).await
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
        let mut definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"},"padding":{"type":"string"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":{"custom.corporate_agent.version":{"pointer":"/version","conversion":{"kind":"identity"},"columns":{}},"custom.corporate_agent.healthy":{"pointer":"/healthy","conversion":{"kind":"identity"},"columns":{}}}},"timeoutSeconds":60,"outputBytes":output_bytes,"maxRows":1});
        if inputs {
            definition["parameters"] = json!({"type":"object","properties":{"name":{"type":"string","maxLength":32},"path":{"type":"string","maxLength":64,"enum":["/Applications","/Library"]}},"required":["name","path"],"additionalProperties":false});
            definition["bindings"] = json!({"name":{"kind":"positional","index":0},"path":{"kind":"environment","name":"RSS_PARAM_PATH"}});
        }
        use rss_mdm_resource::{
            Architecture, Artifact, Declaration, Digest, Id, Kind, Platform, Variant, Version,
        };
        let tenant = rss_request_context::TenantId::parse(case_tenant())?;
        let version = Version::new(
            tenant,
            Id::new(id.to_string())?,
            Id::new("v1")?,
            Kind::Script,
            vec![Variant::new(
                Platform::MacOS,
                Architecture::Aarch64,
                Id::new("default")?,
                Declaration::Script {
                    artifact: Artifact::new(
                        Id::new("fixture-script")?,
                        bytes.len() as u64,
                        Digest::from_bytes(digest),
                    )?,
                    definition: serde_json::from_value(definition.clone())?,
                },
            )],
        )?;
        let at = rss_contract::Timepoint::try_from(1_i64)?;
        self.plan_runtime
            .local_tx(tenant, crate::identity::deadline(), move |tx| {
                Box::pin(async move {
                    rss_mdm_resource_postgres::fixture::active_version_in(tx, version, at).await
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(anyhow::anyhow!(e)),
                |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("resource fixture rollback unconfirmed")),
                |_| Err(anyhow::anyhow!("resource fixture commit unconfirmed")),
                |e| Err(anyhow::anyhow!(e)),
            )?;
        ensure!(upload(author, router, id, bytes).await? == StatusCode::CREATED);
        Ok((id, bytes, definition))
    }
}
pub(crate) async fn publish(author: &mut Browser, router: &Router, resource: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    Ok(id)
}
pub(crate) async fn worker(base: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    super::software_execution::worker(base, None).await
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

pub(crate) async fn seed_scope(
    planning: &rss_mdm_flow_service::planning::Planning,
    scope: Uuid,
    targets: Value,
) -> Result<()> {
    let definition =
        serde_json::from_value(json!({"targets":targets,"limitations":null,"exclusions":[]}))?;
    planning
        .runtime
        .local_tx_with_context(
            planning.tenant,
            crate::identity::deadline(),
            planning,
            |planning, tx| {
                Box::pin(async move {
                    planning
                        .seed_scope_in(tx, scope, definition)
                        .await
                        .map_err(|error| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol(error.to_string()),
                            )
                        })
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("scope fixture rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("scope fixture commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )
}
