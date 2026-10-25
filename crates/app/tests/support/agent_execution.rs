//! Real Policy publication, lazy device admission, delivery, result intake and recovery.
use crate::test_support::{agent::*, http::*, process::*, runtime::*, *};
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub(crate) fn case_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| crate::test_support::runtime::credential("agent_execution-CREDENTIAL"))
}
pub(crate) fn case_inventory_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| {
        crate::test_support::runtime::credential("agent_execution-INVENTORY_CREDENTIAL")
    })
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
    pub(crate) authority: authority::Authority,
    pub(crate) enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    pub(crate) command_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) resources: super::runtime::Resources,
    pub(crate) base: Value,
    pub(crate) builtin_collections: Vec<Value>,
    pub(crate) router: Router,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) inputs: Arc<rss_mdm_execution_service::Inputs>,
    pub(crate) planning: Arc<rss_mdm_flow_service::planning::Planning>,
    pub(crate) plan_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) author: Browser,
    pub(crate) access_authenticator: Option<
        webauthn_authenticator_rs::WebauthnAuthenticator<
            webauthn_authenticator_rs::softpasskey::SoftPasskey,
        >,
    >,
    pub(crate) author_id: String,
    pub(crate) grants: Vec<crate::authorization::Grant>,
    pub(crate) key: ring::signature::Ed25519KeyPair,
}
impl Fixture {
    pub(crate) async fn new() -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let fixture = Self::from_config(base).await?;
        if let Err(error) = crate::test_support::identity::seed_grants(
            case_tenant(),
            &fixture.author_id,
            fixture.grants.clone(),
        )
        .await
        {
            return fixture.resources.finish(async { Err(error) }).await;
        }
        Ok(fixture)
    }
    pub(crate) async fn from_config(base: Value) -> Result<Self> {
        let (resources, mut fixture) =
            crate::test_support::runtime::Resources::build(move |resources| {
                Box::pin(async move {
                    let fixture_config = crate::test_support::agent::fixture_signing_input()?;
                    let key_file = fixture_config["private_key_file"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("fixture task key missing"))?;
                    let key =
                        ring::signature::Ed25519KeyPair::from_pkcs8(&std::fs::read(key_file)?)
                            .unwrap();
                    // Store startup recovery and fixture uploads share the content directory.
                    let config: Config = serde_json::from_value(base.clone())?;
                    let mut authority = authority::Authority::from_config(base.clone()).await?;
                    resources.extend(std::mem::take(&mut authority.resources));
                    let tenant = authority.identity.tenant;
                    let protection = config.native_protector()?;
                    let content_setup = super::software::content_setup_guard().await?;
                    let content = crate::execution_assembly::open_content(&config, protection.clone()).await?;
                    drop(content_setup);
                    if let Some(store) = &content { resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
                    let plan_runtime = crate::planning::test_support::runtime(tenant).await;
                    resources.resource(SourceResource(plan_runtime.clone()));
                    let cursor_key = rss_mdm_flow_service::storage::cursor_key(&plan_runtime, tenant).await?;
                    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
                    let plan_audit = Arc::new(authority.audit.on_runtime(plan_runtime.clone(), tenant, &budget.control()).await?);
                    let clock = Arc::new(crate::clock::SystemClock);
                    let planning = Arc::new(rss_mdm_flow_service::planning::Planning::new(
                        plan_audit.clone(), plan_runtime.clone(), tenant, clock.clone(), &cursor_key,
                        Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(plan_audit.clone())),
                    ).await?);
                    let mut publications = rss_mdm_software_service::management::publication::service::PublicationDirectory {
                        cursor: rss_mdm_query::cursor::CursorCodec::new(&cursor_key)?, services: Default::default(), tenant,
                        runtime: plan_runtime.clone(), audit_store: plan_audit.clone(), clock: Arc::new(crate::clock::FlowClock(clock.clone())),
                    };
                    config.flow.open_publications(tenant, &mut publications, content.clone(), &mut |resource| resources.resource(resource)).await?;
                    let publications = Arc::new(publications);
                    let runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
                    let built = async {
                    let channels = Arc::new(crate::channel_status::Channels::new(&config));
                    let signer = crate::task_signing::prepare(config.task_signing.as_ref(), &config.access_database, tenant, &protection, &channels).await?.map(|loaded| Arc::new(loaded.task));
                    let sessions = Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), tenant));
                    let (service, inputs, queries) = crate::execution_assembly::assemble(
                        &config, protection.clone(), authority.audit.clone(), content.clone(),
                        publications.services.clone(), runtime.clone(), channels, signer, None, sessions,
                        config.recovery_credentials.as_ref().map(crate::recovery_credentials::Config::open).transpose()?,
                        rss_device_command_postgres::CommandClock::Postgres,
                        cursor_key.clone(),
                    ).await?;
                    Ok::<_, anyhow::Error>((service, queries, inputs))
                    }.await;
                    let (service, queries, inputs) = match built {
                        Ok(value) => value,
                        Err(error) => { runtime.close().await; return Err(error); }
                    };
                    resources.resource(rss_mdm_execution_service::Resource(service.clone()));
                    authority.identity.enterprise_platform.bind(service.clone())?;
                    let pki = config.agent_pki.load(&config.identity.instance_id, authority.audit.clone(), clock.clone(), crate::device_pki::providers(&config.device_pki)?, None)?.ok_or_else(|| anyhow::anyhow!("Agent PKI missing"))?;
                    crate::test_support::pki::seed_trust(&authority.pool, &[pki.issuer.trust().trust.clone()]).await?;
                    let access_audit = Arc::new(authority.audit.on_runtime(authority.identity.runtime.clone(), tenant, &budget.control()).await?);
                    let enrollment = application_service(access_audit, &pki, authority.registration.clone(), authority.audit.clone(), service.clone())?;
                    let agent_store = Arc::new(rss_mdm_agent_channel::Store::from_pool(authority.pool.clone()));
                    let native = rss_mdm_agent_channel::task_router(Arc::new(crate::agent::TaskState {
                        access: agent_store, enrollment: enrollment.clone(), execution: service.clone(),
                        identity: Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), tenant)),
                        authorization: authority.authorization.clone(),
                    }), rss_mdm_agent_channel::boundary::Envelope {
                        admission: Arc::new(tokio::sync::Semaphore::new(32)), requests: Arc::new(tokio::sync::Semaphore::new(32)),
                        host: "mdm.example.test:9445".into(), clock: monotonic(), audit_store: authority.audit.clone(), tenant: tenant.to_string(),
                    });
                    let content_access = Arc::new(rss_mdm_content_service::service::Access {
                        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), tenant),
                        authorization: authority.authorization.clone(), catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
                        runtime: plan_runtime.clone(), audit_store: plan_audit.clone(), tenant, content: content.clone(),
                        clock: Arc::new(crate::clock::ContentClock(clock.clone())),
                    });
        let resources_store = Arc::new(rss_mdm_resource_postgres::ResourceStore::new(plan_runtime.clone(), tenant, crate::identity::deadline()).await?);
        let software = Arc::new(rss_mdm_software_service::management::catalog::Access {
            runtime: plan_runtime.clone(), cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &cursor_key)),
            audit: plan_audit.clone(), tenant,
            catalog: rss_mdm_software_service::catalog::Catalog::new(plan_runtime.clone(), tenant, plan_audit.clone()),
            resources: resources_store, clock: Arc::new(crate::clock::ContentClock(clock.clone())),
            content: content.as_ref().map(|store| Arc::new(rss_mdm_content_service::software::SoftwareContent::new(store.clone(), Arc::new(crate::clock::ContentClock(clock.clone()))))),
            imports: rss_mdm_software_service::management::catalog::ImportConfig {
                sources: content.as_ref().map(|store| store.config.imports.clone()).unwrap_or_default(),
                transfer_seconds: content.as_ref().map_or(0, |store| store.config.transfer_seconds),
            },
        });
                    let catalog = crate::flow::catalog(plan_audit.clone(), plan_runtime.clone(), tenant, clock.clone()).await?;
                    let policies = Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(&cursor_key, plan_runtime.clone(), rss_reconcile_postgres::PgMessagingStore::new(plan_runtime.clone(), tenant, crate::identity::deadline()).await?, plan_audit, tenant, Arc::new(rss_mdm_policy_postgres::PolicyStore::new(plan_runtime.clone(), tenant, crate::identity::deadline()).await?), inputs.clone()));
                    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
                    let mut routes = Router::new().nest("/api/v1",
                        rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { planning: planning.clone(), groups })).into_axum()
                        .merge(rss_mdm_management_http::planning::policies::http::routes(queries.clone()).with_state(policies).into_axum())
                        .merge(rss_mdm_management_http::execution::actions::http::routes().with_state(queries.clone()).into_axum())
                        .merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog, content: content_access.clone() })).into_axum())
                        .merge(rss_mdm_management_http::software_catalog::routes().with_state(software).into_axum())
                        .merge(rss_mdm_management_http::content::http::routes().with_state(content_access).into_axum())
                        .merge(rss_mdm_management_http::execution::http::routes(queries.clone(), rss_mdm_query::cursor::CursorCodec::new(&cursor_key)?).with_state(Arc::new(rss_mdm_management_http::execution::http::HttpState { execution: service.clone(), apple: false, windows: false })).into_axum()),
                    ).merge(authority.authorization()).merge(authority.enrollment());
                    let mut public = Router::new().nest("/api/v1/agent/runtime", native.into_axum());
                    if !publications.services.is_empty() {
                        routes = routes.merge(Router::new().nest("/api/v1", rss_mdm_management_http::software_publication::http::routes().with_state(Arc::new(rss_mdm_management_http::software_publication::http::HttpState { publications: publications.clone(), access: authority.authorization.clone() })).into_axum()));
                        public = public.merge(rss_mdm_management_http::software_native::routes().with_state(Arc::new(rss_mdm_management_http::software_native::StateData { directory: publications, content: content.clone(), requests: Arc::new(tokio::sync::Semaphore::new(8)) })).into_axum());
                    }
                    let router = authority.router_with_public(routes, public)?;
                    let author = crate::test_support::authority::Authority::prepared_browser("other")?;
                    let author_id = prepared_subject(&author)?;
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
                    Ok(Self {
                        resources: Default::default(),
                        builtin_collections: Vec::new(),
                        base,
                        router,
                        queries,
                        content,
                        execution: service,
                        authority,
                        enrollment,
                        command_runtime: runtime,
                        plan_runtime,
                        planning,
                        inputs,
                        author,
                        access_authenticator: None,
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
        let registration = crate::test_support::agent::seed_service(&self.enrollment,
            case_credential(), old_device, json!({"capabilities":capabilities,"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
        for grant in &mut self.grants {
            if let crate::authorization::Scope::Device { id } = &mut grant.scope
                && id == old_device
            {
                *id = registration["deviceId"].as_str().unwrap().into()
            }
        }
        crate::test_support::identity::seed_grants(
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
        let id = Uuid::new_v4();
        let bytes = b"#!/bin/sh\nprintf '{\"version\":\"1.2\",\"healthy\":true}\n'\n";
        let mut definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"},"padding":{"type":"string"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":{"custom.corporate_agent.version":{"pointer":"/version","conversion":{"kind":"identity"},"columns":{}},"custom.corporate_agent.healthy":{"pointer":"/healthy","conversion":{"kind":"identity"},"columns":{}}}},"timeoutSeconds":60,"outputBytes":output_bytes,"maxRows":1});
        if inputs {
            definition["parameters"] = json!({"type":"object","properties":{"name":{"type":"string","maxLength":32},"path":{"type":"string","maxLength":64,"enum":["/Applications","/Library"]}},"required":["name","path"],"additionalProperties":false});
            definition["bindings"] = json!({"name":{"kind":"positional","index":0},"path":{"kind":"environment","name":"RSS_PARAM_PATH"}});
        }
        self.seed_script_resource(id, bytes, definition.clone())
            .await?;
        Ok((id, bytes, definition))
    }
    pub(crate) async fn seed_script_resource(
        &mut self,
        id: Uuid,
        bytes: &[u8],
        definition: Value,
    ) -> Result<()> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
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
        let artifact = Artifact::new(
            Id::new("fixture-script")?,
            bytes.len() as u64,
            Digest::from_bytes(digest),
        )?;
        rss_mdm_content_service::fixture::artifact(
            self.content.as_deref().expect("script content"),
            &artifact,
            bytes.to_vec(),
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
        )
        .await?;
        Ok(())
    }
}
pub(crate) async fn publish(author: &mut Browser, router: &Router, resource: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    Ok(id)
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

pub(crate) async fn seed_script_result(
    f: &Fixture,
    run: Uuid,
    output: Value,
    canary: &str,
) -> Result<()> {
    use rss_mdm_execution_service::actions::state::{Cancellation, Delivery, Execution, RunState};
    let result = rss_mdm_agent_wire::runtime::ScriptRunResult {
        collected_at: 1,
        received_at: 2,
        exit_code: Some(0),
        quality: rss_mdm_agent_wire::runtime::OutputQuality::Complete,
        schema_valid: true,
        budget_valid: true,
        output,
        output_reference: None,
        diagnostics: serde_json::from_value(
            json!({"stdout":canary,"stderr":canary,"durationMs":1,"executedAt":1,"failure":null}),
        )?,
        trusted: true,
    };
    let mut result = serde_json::to_value(result)?;
    let tenant = f.authority.identity.tenant;
    f.command_runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |c| Box::pin(async move {
            let (deadline, created): (i64, i64) = sqlx::query_as("SELECT deadline, created_at FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant.to_string()).bind(run).fetch_one(&mut *c).await?;
            result["collectedAt"] = json!(created);
            result["receivedAt"] = json!(created + 1);
            result["diagnostics"]["executedAt"] = json!(created);
            let state = RunState { delivery: Delivery::Received {attempt: Uuid::new_v4(), lease_until: deadline}, execution: Execution::Succeeded, cancellation: Cancellation::None, deadline, started_at: Some(created) };
            sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,result=$4,gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant.to_string()).bind(run).bind(serde_json::to_value(state).expect("run state")).bind(result).execute(c).await?;
            Ok(())
        })).await
    })).await.fold(Ok, |e|Err(anyhow::anyhow!(e)), |e|Err(anyhow::anyhow!(e)), |_|Err(anyhow::anyhow!("seed rollback unconfirmed")), |_|Err(anyhow::anyhow!("seed commit unconfirmed")), |e|Err(anyhow::anyhow!(e)))
}

pub(crate) async fn seed_script_policy(f: &Fixture, resource: Uuid) -> Result<Uuid> {
    use rss_mdm_execution_service::input_preparation::{PublicationAuthority, PublicationInput};
    let id = Uuid::new_v4();
    let change = rss_mdm_policy::Change::Put {
        definition: Box::new(serde_json::from_value(policy_definition(
            resource,
            case_task_scope(),
        ))?),
        enabled: true,
    };
    let policy = rss_mdm_policy::Policy::apply(id, None, 0, &change, Uuid::new_v4(), None)?.policy;
    let input = PublicationInput::try_from(&policy.definition.action)?;
    let verified = f.inputs.prepare_resource(input.resource()).await?;
    let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    f.plan_runtime
        .local_tx_with_context(
            f.authority.identity.tenant,
            crate::identity::deadline(),
            (&f.inputs, &proof, &policy, &change, verified.as_ref()),
            |(inputs, proof, policy, change, verified), tx| {
                Box::pin(async move {
                    let frozen = inputs
                        .publish_in(
                            tx,
                            &PublicationInput::try_from(&policy.definition.action)
                                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                            *verified,
                            &PublicationAuthority {
                                proof,
                                snapshot: proof
                                    .authorization()
                                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                                owner: rss_mdm_execution_service::configuration::Owner::Policy {
                                    policy: policy.id,
                                    version: policy.version,
                                },
                                devices: None,
                            },
                        )
                        .await
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                    let publication = rss_mdm_policy_postgres::Publication {
                        change: (*change).clone(),
                        policy: (*policy).clone(),
                        frozen: Some(serde_json::to_value(frozen).expect("frozen script")),
                        author: serde_json::to_value(proof.actor()).expect("author"),
                        at: 1,
                    };
                    rss_mdm_policy_postgres::fixture::published_in(tx, &publication).await
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(id)
}

pub(crate) async fn seed_script_run(f: &Fixture, policy: Uuid) -> Result<Uuid> {
    let task_id = Uuid::new_v4();
    let mut tx = f.authority.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let object = f
        .planning
        .objects
        .endpoint(&mut tx, f.authority.identity.tenant, case_device_id())
        .await?;
    tx.rollback().await?;
    let source_objects = serde_json::to_value(vec![object])?;
    let tenant = f.authority.identity.tenant;
    f.command_runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                let state = rss_mdm_execution_service::actions::state::RunState::new(300, 1).expect("valid run horizon");
                sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects) SELECT p.tenant_id,$2,p.current_version,r.device,r.id,r.generation,'retained-sensitive-result',1,1,300,$4,true,$5,$6 FROM mdm_policy.policies p JOIN mdm_access.registrations r ON r.tenant_id=p.tenant_id AND r.device=$3 AND r.channel='agent' AND r.state='active' WHERE p.tenant_id=$1::uuid AND p.id=$7")
                    .bind(tenant.to_string()).bind(task_id).bind(case_device_id()).bind(serde_json::to_value(state).expect("run state"))
                    .bind(vec![7u8;32]).bind(source_objects).bind(policy).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok, |e|Err(anyhow::anyhow!(e)), |e|Err(anyhow::anyhow!(e)), |_|Err(anyhow::anyhow!("seed rollback unconfirmed")), |_|Err(anyhow::anyhow!("seed commit unconfirmed")), |e|Err(anyhow::anyhow!(e)))?;
    Ok(task_id)
}
