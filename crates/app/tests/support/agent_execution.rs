//! Real Policy publication, lazy device admission, delivery, result intake and recovery.
use crate::test_support::*;
use base64::Engine;
use ring::signature::KeyPair;
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub(crate) const CREDENTIAL: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
pub(crate) const INVENTORY_CREDENTIAL: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
pub(crate) const TASK_SCOPE: Uuid = Uuid::from_u128(0x90101010_1234_4321_8123_101010101010);
pub(crate) const EMPTY_SCOPE: Uuid = Uuid::from_u128(0x90101010_1234_4321_8123_202020202020);
pub(crate) const DEVICE_ID: &str = "enterprise-device";

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
    agent_call(router,Method::POST,&format!("/api/agent/v3/tasks/{}/events",task["payload"]["taskId"].as_str().unwrap()),Some(CREDENTIAL),Some(json!({"wireVersion":3,"operationId":operation,"attemptId":task["payload"]["attemptId"],"event":kind}))).await
}
pub(crate) async fn claim_request(router: &Router, operation: Uuid) -> Result<(StatusCode, Value)> {
    agent_call(
        router,
        Method::POST,
        "/api/agent/v3/tasks/claim",
        Some(CREDENTIAL),
        Some(json!({"wireVersion":3,"operationId":operation})),
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
    json!({"resource":{"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"scope":scope,"behavior":{"kind":"execution","parameters":{},"runLifetimeSeconds":300}})
}
pub(crate) struct Fixture {
    _temp: tempfile::TempDir,
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
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let keyfile = temp.path().join("signing.pk8");
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        std::fs::write(&keyfile, pkcs8.as_ref())?;
        std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600))?;
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        base["content"] = json!({"directory":temp.path(),"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":67108864,"max_bundle_entries":100,"max_expansion_ratio":100});
        base["task_signing"] = json!({"private_key_file":keyfile,"key_id":"fixture","trusted_keys":{"fixture":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
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
            Some(DEVICE_ID),
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
        crate::test_support::identity::set_grants(TENANT, &author_id, grants.clone()).await?;
        Ok(Self {
            _temp: temp,
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
        let router = &self.router;
        let author = &mut self.author;
        author.operation = Some(Uuid::new_v4());
        let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let enrollment = post(
            author,
            router,
            "/api/v3/enrollments",
            json!({"deviceId":DEVICE_ID,"password":password,"source":"agent.builtin"}),
        )
        .await?;
        author.operation = None;
        let registration=agent_call(router,Method::POST,"/api/agent/v3/registrations",None,Some(json!({"wireVersion":3,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":CREDENTIAL,"platform":"macos","architecture":"aarch64","capabilities":["inventory.basic.v3","task.execute.v3"]}))).await?;
        ensure!(
            registration.0 == StatusCode::CREATED
                && registration.1["capabilities"]
                    == json!(["inventory.basic.v3", "task.execute.v3"]),
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
        ensure!(setup_automation.shutdown().join().await?.is_clean());
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
    post(author,router,&format!("/api/v2/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,TASK_SCOPE)}})).await?;
    Ok(id)
}
pub(crate) async fn worker(base: &Value) -> Result<rss_runtime::ShutdownStack> {
    let config: Config = serde_json::from_value(base.clone())?;
    let service = crate::flow::execution::open(
        &config,
        crate::test_support::identity::audit_store(&config).await?,
    )
    .await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(service.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(service.registration().critical());
    launch.finish();
    Ok(owner)
}
pub(crate) async fn complete(router: &Router, task: &Value) -> Result<()> {
    task_event(router, task, json!({"kind":"received"})).await?;
    task_event(router, task, json!({"kind":"start"})).await?;
    task_event(router,task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    Ok(())
}
