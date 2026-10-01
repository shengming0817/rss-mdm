#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
//! Real enterprise software Policy through Agent Offer, content, Start and detection.
use crate::test_support::software::write;
use crate::test_support::*;
use sha2::{Digest, Sha256};

pub(crate) fn case_device() -> &'static str {
    crate::test_support::case::name("software-deployment-device")
}
pub(crate) fn case_windows_device() -> &'static str {
    crate::test_support::case::name("windows-software-deployment-device")
}
pub(crate) fn case_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| crate::test_support::credential("software_execution-CREDENTIAL"))
}

pub(crate) async fn agent(
    router: &Router,
    path: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    agent_call(router, Method::POST, path, Some(case_credential()), body).await
}
pub(crate) async fn event(
    router: &Router,
    task: &Value,
    event: Value,
) -> Result<(StatusCode, Value)> {
    event_with(router, case_credential(), task, event).await
}
pub(crate) async fn event_with(
    router: &Router,
    credential: &str,
    task: &Value,
    mut event: Value,
) -> Result<(StatusCode, Value)> {
    if event["kind"] == "software_result" {
        event["definitionDigest"] = task["payload"]["definitionDigest"].clone();
        event["evidenceDigest"] = json!(Sha256::digest(b"controlled detector evidence").to_vec());
        event["observedVersion"] = if event["detection"] == "present" {
            task["payload"]["steps"]
                .as_array()
                .and_then(|steps| steps.last())
                .ok_or_else(|| anyhow::anyhow!("missing executable step"))?["action"]["version"]
                .clone()
        } else {
            Value::Null
        };
    }
    agent_call(router,Method::POST,&format!("/api/agent/v5/tasks/{}/events", task["payload"]["taskId"].as_str().unwrap()),Some(credential),
        Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["attemptId"],"event":event}))).await
}
pub(crate) async fn claim(router: &Router) -> Result<Value> {
    claim_with(router, case_credential()).await
}
pub(crate) async fn claim_with(router: &Router, credential: &str) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = agent_call(
                router,
                Method::POST,
                "/api/agent/v5/tasks/claim",
                Some(credential),
                Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"profiles":["posix_sh","bash","power_shell7","osquery"]})),
            )
            .await?;
            ensure!(response.0 == StatusCode::OK, "claim: {response:?}");
            if !response.1["task"].is_null() {
                return Ok::<_, anyhow::Error>(response.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}
async fn upload_fixture(router: &Router, request: Request<Body>) -> Result<()> {
    let _guard = super::software::content_setup_guard().await?;
    let status = router.clone().oneshot(request).await?.status();
    ensure!(status == StatusCode::CREATED, "fixture upload: {status}");
    Ok(())
}
pub(crate) async fn upload_windows(
    author: &Browser,
    router: &Router,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    let request=Request::builder().method(Method::POST)
        .uri(format!("{path}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
    upload_fixture(router, request).await?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    MacOs,
    Windows,
}

/// A real authorized session, one Agent/Scope, and an approved dependency/root pair.
/// Action assertions belong to callers; only the requested platform is prepared.
pub(crate) struct Fixture {
    pub(crate) base: Value,
    pub(crate) router: Router,
    pub(crate) author: Browser,
    pub(crate) resource: Uuid,
    pub(crate) scope: Uuid,
    pub(crate) dependency_bytes: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) removal: Vec<u8>,
    pub(crate) windows_bytes: Vec<u8>,
    pub(crate) credential: String,
    pub(crate) first_operation: Value,
}
impl Fixture {
    pub(crate) async fn approved(platform: Platform) -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let (router, _, _) = crate::api::application_fixture(
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
        let subject = browser_subject(&author, &router).await?;
        let mut grants = crate::test_support::identity::device_grants(
            None,
            &[
                "enrollment",
                "inventory_read",
                "software_deploy",
                "operation_read",
            ],
        )?;
        for name in [
            "resource_read",
            "resource_write",
            "software_read",
            "software_write",
            "software_approve",
            "software_withdraw",
            "policy_read",
            "policy_write",
            "scope_read",
            "scope_write",
        ] {
            grants.push(crate::authorization::Grant {
                operation: serde_json::from_value(json!(name))?,
                scope: crate::authorization::Scope::Tenant,
            });
        }
        crate::test_support::identity::set_grants(case_tenant(), &subject, grants).await?;
        let (device, platform_name, architecture, credential) = match platform {
            Platform::MacOs => (
                case_device(),
                "macos",
                "aarch64",
                case_credential().to_owned(),
            ),
            Platform::Windows => (
                case_windows_device(),
                "windows",
                "x86_64",
                crate::test_support::credential("windows-software"),
            ),
        };
        author.operation = Some(Uuid::new_v4());
        let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let enrollment = author
            .call(
                &router,
                Method::POST,
                "/api/v3/enrollments",
                Some(json!({"deviceId":device,"password":password,"source":"agent.builtin"})),
            )
            .await?;
        ensure!(enrollment.0.is_success(), "enrollment: {enrollment:?}");
        author.operation = None;
        let registration=agent_call(&router,Method::POST,"/api/agent/v5/registrations",None,
            Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"enrollmentId":enrollment.1["enrollmentId"],"password":password,"credential":credential,"platform":platform_name,"architecture":architecture,"capabilities":["inventory.collect.v5","software.execute.v5"]}))).await?;
        ensure!(
            registration.0 == StatusCode::CREATED,
            "registration: {registration:?}"
        );
        let scope = prepared_scope(&base, &mut author, &router, &[device]).await?;
        let source = Uuid::new_v4().to_string();
        let source_path = format!("/api/v3/software/sources/{source}/revisions/1");
        let registered=write(&mut author,&router,&source_path,0,json!({"action":"register","definition":{"id":source,"revision":"1","kind":"private","location":null,"publishers":[]}})).await?;
        write(
            &mut author,
            &router,
            &source_path,
            1,
            json!({"action":"approve","evidence":["enterprise-source"]}),
        )
        .await?;
        let dependency = Uuid::new_v4();
        let dependency_path = format!("/api/v3/resources/{dependency}");
        write(
            &mut author,
            &router,
            &dependency_path,
            0,
            json!({"action":"create","kind":"software"}),
        )
        .await?;
        let dependency_bytes = format!("controlled dependency package {dependency}").into_bytes();
        let dependency_digest: [u8; 32] = Sha256::digest(&dependency_bytes).into();
        let dependency_definition = json!({"source":registered["snapshot"],"package":"Private.Dependency","version":"1","format":"pkg","primary":"scripts/install.sh","artifacts":{"scripts/install.sh":{"reference":"dep-installer","length":dependency_bytes.len(),"sha256":dependency_digest}},"install":{"executor":"package_installer","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.private.dependency","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":null});
        let windows_dependency_bytes =
            format!("controlled windows dependency msi {dependency}").into_bytes();
        let windows_dependency_digest: [u8; 32] = Sha256::digest(&windows_dependency_bytes).into();
        let windows_dependency_definition = json!({"source":registered["snapshot"],"package":"Private.WindowsDependency","version":"1","format":"msi","primary":"package","artifacts":{"package":{"reference":"dep-win-installer","length":windows_dependency_bytes.len(),"sha256":windows_dependency_digest}},"install":{"executor":"msi","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":null});
        write(&mut author,&router,&dependency_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform_name,"architecture":architecture,"key":"default","declaration":{"kind":"software","definition":if platform == Platform::MacOs { dependency_definition } else { windows_dependency_definition }}}]})).await?;
        if platform == Platform::MacOs {
            let request=Request::builder().method(Method::POST).uri(format!("{dependency_path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(dependency_bytes.to_vec()))?;
            upload_fixture(&router, request).await?;
        } else {
            upload_windows(
                &author,
                &router,
                &dependency_path,
                &windows_dependency_bytes,
            )
            .await?;
        }
        write(
            &mut author,
            &router,
            &dependency_path,
            2,
            json!({"action":"activate","version":"v1"}),
        )
        .await?;
        write(
            &mut author,
            &router,
            &format!("/api/v3/software/resources/{dependency}/versions/v1"),
            0,
            json!({"action":"approve","evidence":["fixed-prerequisite"]}),
        )
        .await?;
        let dependency_version = author
            .call(
                &router,
                Method::GET,
                &format!("/api/v3/software/resources/{dependency}/versions/v1"),
                None,
            )
            .await?;
        ensure!(dependency_version.0 == StatusCode::OK);
        let resource = Uuid::new_v4();
        let path = format!("/api/v3/resources/{resource}");
        write(
            &mut author,
            &router,
            &path,
            0,
            json!({"action":"create","kind":"software"}),
        )
        .await?;
        let bytes = format!("controlled software package {resource}").into_bytes();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let removal = format!("#!/bin/sh\n# {resource}\nexit 0\n").into_bytes();
        let removal_digest: [u8; 32] = Sha256::digest(&removal).into();
        let definition = json!({"source":registered["snapshot"],"package":"Private.Controlled","version":"1","format":"pkg","primary":"package","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":digest},"remove":{"reference":"remover","length":removal.len(),"sha256":removal_digest}},"install":{"executor":"package_installer","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":{"executor":"posix_sh","entry":"remove","runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"detect":{"kind":"pkg_receipt","receipt":"com.private.controlled","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[{"resource":dependency,"version":"v1","sha256":dependency_version.1["resourceDigest"]}],"bundle":null});
        let windows_bytes = format!("controlled windows root msi {resource}").into_bytes();
        let windows_digest: [u8; 32] = Sha256::digest(&windows_bytes).into();
        let windows_definition = json!({"source":registered["snapshot"],"package":"Private.WindowsControlled","version":"1","format":"msi","primary":"package","artifacts":{"package":{"reference":"win-installer","length":windows_bytes.len(),"sha256":windows_digest}},"install":{"executor":"msi","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[{"resource":dependency,"version":"v1","sha256":dependency_version.1["resourceDigest"]}],"bundle":null});
        write(&mut author,&router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform_name,"architecture":architecture,"key":"default","declaration":{"kind":"software","definition":if platform == Platform::MacOs { definition } else { windows_definition }}}]})).await?;
        if platform == Platform::MacOs {
            let request=Request::builder().method(Method::POST).uri(format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
            upload_fixture(&router, request).await?;
            let request=Request::builder().method(Method::POST).uri(format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&artifact=remover&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(removal.to_vec()))?;
            upload_fixture(&router, request).await?;
        } else {
            upload_windows(&author, &router, &path, &windows_bytes).await?;
        }
        write(
            &mut author,
            &router,
            &path,
            2,
            json!({"action":"activate","version":"v1"}),
        )
        .await?;
        let first_approval = write(
            &mut author,
            &router,
            &format!("/api/v3/software/resources/{resource}/versions/v1"),
            0,
            json!({"action":"approve","evidence":["enterprise-version"]}),
        )
        .await?;
        let first_operation = first_approval["admission"]["operation"].clone();
        Ok(Self {
            base,
            router,
            author,
            resource,
            scope,
            dependency_bytes,
            bytes,
            removal,
            windows_bytes,
            credential,
            first_operation,
        })
    }
}
pub(crate) async fn prepared_scope(
    base: &Value,
    author: &mut Browser,
    router: &Router,
    devices: &[&str],
) -> Result<Uuid> {
    let scope = Uuid::new_v4();
    let automation = start_automation(base).await?;
    let targets = devices
        .iter()
        .map(|device| json!({"kind":"device","id":device}))
        .collect::<Vec<_>>();
    let created = write(
        author,
        router,
        &format!("/api/v2/scopes/{scope}"),
        0,
        json!({"action":"put","definition":{"targets":targets,"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    crate::test_support::stop_worker(automation).await?;
    Ok(scope)
}

pub(crate) async fn worker(base: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let config: Config = serde_json::from_value(base.clone())?;
    let worker = crate::flow::execution::open(
        &config,
        crate::test_support::identity::audit_store(&config).await?,
    )
    .await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(worker.clone()),
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
    launch.stage_deferred_task_with_token(worker.registration(signals.flow()).critical());
    launch.finish();
    Ok(Some(stack))
}
pub(crate) fn authored(resource: Uuid, scope: Uuid, intent: &str, operation: &Value) -> Value {
    json!({"scope":scope,"action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":intent,"admissionOperation":operation,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":scope,"opensAt":0}]}}})
}
