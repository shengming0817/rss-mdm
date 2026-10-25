#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
//! Real enterprise software Policy through Agent Offer, content, Start and detection.
use crate::test_support::{agent::*, http::*, runtime::*, *};
use sha2::{Digest, Sha256};

pub(crate) fn context(platform: Platform) -> Value {
    let os = match platform {
        Platform::Windows => [10, 0, 22621, 0],
        Platform::MacOs => [14, 0, 0, 0],
    };
    json!({"revision":1,"osVersion":os,"userHelper":true,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false})
}
pub(crate) fn case_device() -> &'static str {
    crate::test_support::agent::device(
        case_credential(),
        crate::test_support::case::name("software-deployment-device"),
    )
}
pub(crate) fn case_windows_device() -> &'static str {
    crate::test_support::agent::device(
        &crate::test_support::runtime::credential("windows-software"),
        crate::test_support::case::name("windows-software-deployment-device"),
    )
}
pub(crate) fn case_credential() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| crate::test_support::runtime::credential("software_execution-CREDENTIAL"))
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
    event: Value,
) -> Result<(StatusCode, Value)> {
    agent_call(router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{}/events", task["payload"]["task"]["taskId"].as_str().unwrap()),Some(credential),
        Some(json!({"wireVersion":1,"executionContext":task["payload"]["task"]["executionContext"],"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"event":event}))).await
}
pub(crate) fn result_event(
    task: &Value,
    intent: &str,
    exit_code: Option<i32>,
    state: &str,
    reboot: bool,
) -> Result<Value> {
    use rss_mdm_agent_wire::runtime as wire;
    let spec: wire::SoftwareTaskSpec = serde_json::from_value(task["payload"]["task"].clone())?;
    let observed_at = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let mut steps = Vec::new();
    for (index, step) in spec.steps.iter().enumerate() {
        let after = match state {
            "present" => wire::SoftwareDetectionObservation::Present {
                version: rss_mdm_software_service::preparation::evidence::detected_version(
                    &step.action,
                ),
                evidence_sha256: Sha256::digest(b"controlled present observation").into(),
                observed_at,
            },
            "absent" => wire::SoftwareDetectionObservation::Absent {
                evidence_sha256: Sha256::digest(b"controlled absent observation").into(),
                observed_at,
            },
            "unknown" => wire::SoftwareDetectionObservation::Unknown {
                diagnostic: "controlled detector unavailable".into(),
            },
            _ => anyhow::bail!("unsupported test observation"),
        };
        steps.push(wire::SoftwareStepResult {
            step_id: step.step_id,
            index: index.try_into()?,
            step_digest: step.digest()?,
            target: step.target.clone(),
            package: step.action.package.clone(),
            identity: rss_mdm_software_service::preparation::evidence::observed_identity(
                &step.action,
            ),
            before: wire::SoftwareDetectionObservation::Absent {
                evidence_sha256: Sha256::digest(b"controlled prior observation").into(),
                observed_at,
            },
            after,
            process: exit_code.map_or(wire::SoftwareProcessObservation::NotRun, |code| {
                wire::SoftwareProcessObservation::Exited { code }
            }),
            reboot_required: reboot,
            diagnostics: wire::TaskDiagnostics::new("".into(), "".into(), 1, observed_at, None)?,
        });
    }
    let result = wire::SoftwareTaskResult {
        intent: match intent {
            "install" => wire::SoftwareTaskIntent::Install,
            "uninstall" => wire::SoftwareTaskIntent::Uninstall,
            _ => anyhow::bail!("unsupported test intent"),
        },
        definition_digest: spec.definition_digest,
        steps,
    };
    let mut value = serde_json::to_value(result)?;
    value["kind"] = json!("software_result");
    Ok(value)
}
pub(crate) async fn claim(router: &Router) -> Result<Value> {
    claim_with(router, case_credential(), Platform::MacOs).await
}
pub(crate) async fn claim_with(
    router: &Router,
    credential: &str,
    platform: Platform,
) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = agent_call(
                router,
                Method::POST,
                "/api/v1/agent/runtime/tasks/claim",
                Some(credential),
                Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(platform),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
    resource: Uuid,
    bytes: &[u8],
) -> Result<()> {
    let request=Request::builder().method(Method::POST)
        .uri(format!("/api/v1/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={}",Uuid::new_v4()))
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

/// A real authorized session, one Agent/Scope, and an authorized dependency/root pair.
/// Action assertions belong to callers; only the requested platform is prepared.
pub(crate) struct Fixture {
    pub(crate) resources: super::runtime::Resources,
    pub(crate) enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    platform: Platform,
    pub(crate) source_snapshot: Value,
    pub(crate) dependency: Uuid,
    pub(crate) dependency_digest: Value,
    pub(crate) base: Value,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) router: Router,
    pub(crate) author: Browser,
    pub(crate) resource: Uuid,
    pub(crate) scope: Uuid,
    pub(crate) planning: Arc<rss_mdm_flow_service::planning::Planning>,
    pub(crate) dependency_bytes: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) removal: Vec<u8>,
    pub(crate) windows_bytes: Vec<u8>,
    pub(crate) credential: String,
    pub(crate) registration: Value,
}
impl Fixture {
    pub(crate) async fn authorized(platform: Platform) -> Result<Self> {
        let capabilities = match platform {
            Platform::Windows => json!(["inventory.collect.v1", "software.msi.system.v1"]),
            Platform::MacOs => json!(["inventory.collect.v1", "software.pkg.system.v1"]),
        };
        let mut fixture = Self::with_profiles(platform, capabilities, context(platform)).await?;
        let dependency = fixture.seed_dependency().await?;
        fixture.seed_root(json!([dependency])).await?;
        Ok(fixture)
    }
    pub(crate) async fn seed_dependency(&mut self) -> Result<Value> {
        let platform = self.platform;
        let (platform_name, architecture) = match platform {
            Platform::MacOs => ("macos", "aarch64"),
            Platform::Windows => ("windows", "x86_64"),
        };
        let planning = &self.planning;
        let registered = json!({"snapshot":self.source_snapshot});
        let dependency = self.dependency;
        let dependency_bytes = &self.dependency_bytes;
        let dependency_digest: [u8; 32] = Sha256::digest(dependency_bytes).into();
        let dependency_definition = json!({"material":{"format":"pkg","installer":"scripts/install.sh"},"source":registered["snapshot"],"package":"Private.Dependency","version":"1","artifacts":{"scripts/install.sh":{"reference":"dep-installer","length":dependency_bytes.len(),"sha256":dependency_digest}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"pkg","installer":"scripts/install.sh","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.private.dependency","version":"1"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
        let windows_dependency_bytes =
            format!("controlled windows dependency msi {dependency}").into_bytes();
        let windows_dependency_digest: [u8; 32] = Sha256::digest(&windows_dependency_bytes).into();
        let windows_dependency_definition = json!({"material":{"format":"msi","installer":"package"},"source":registered["snapshot"],"package":"Private.WindowsDependency","version":"1","artifacts":{"package":{"reference":"dep-win-installer","length":windows_dependency_bytes.len(),"sha256":windows_dependency_digest}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
        let dependency_resource = seed_resource(
            &planning.runtime,
            planning.tenant,
            dependency,
            platform_name,
            architecture,
            if platform == Platform::MacOs {
                dependency_definition
            } else {
                windows_dependency_definition
            },
        )
        .await?;
        let bytes = if platform == Platform::MacOs {
            dependency_bytes.as_slice()
        } else {
            windows_dependency_bytes.as_slice()
        };
        let artifact = rss_mdm_resource::Artifact::new(
            rss_mdm_resource::Id::new("dep-installer")?,
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(bytes),
        )?;
        rss_mdm_content_service::fixture::artifact(
            self.content.as_deref().expect("software content"),
            &artifact,
            bytes.to_vec(),
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
        )
        .await?;
        seed_enabled(
            &planning.runtime,
            self.content
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("software fixture requires content"))?,
            &dependency_resource,
        )
        .await?;
        self.dependency_digest = json!(dependency_resource.digest().bytes());
        Ok(json!({"resource":dependency,"version":"v1","sha256":self.dependency_digest}))
    }
    pub(crate) async fn seed_root(&mut self, dependencies: Value) -> Result<()> {
        let platform = self.platform;
        let (platform_name, architecture) = match platform {
            Platform::MacOs => ("macos", "aarch64"),
            Platform::Windows => ("windows", "x86_64"),
        };
        let planning = &self.planning;
        let registered = json!({"snapshot":self.source_snapshot});
        let resource = self.resource;
        let bytes = &self.bytes;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let removal = &self.removal;
        let removal_digest: [u8; 32] = Sha256::digest(removal).into();
        let definition = json!({"material":{"format":"pkg","installer":"package"},"source":registered["snapshot"],"package":"Private.Controlled","version":"1","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":digest},"remove":{"reference":"remover","length":removal.len(),"sha256":removal_digest}},"reboot":"report","downgrade":"deny","dependencies":dependencies,"behavior":{"kind":"pkg","installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":{"installer":"remove","invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"detect":{"kind":"pkg_receipt","receipt":"com.private.controlled","version":"1"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
        let windows_bytes = format!("controlled windows root msi {resource}").into_bytes();
        let windows_digest: [u8; 32] = Sha256::digest(&windows_bytes).into();
        let windows_definition = json!({"material":{"format":"msi","installer":"package"},"source":registered["snapshot"],"package":"Private.WindowsControlled","version":"1","artifacts":{"package":{"reference":"win-installer","length":windows_bytes.len(),"sha256":windows_digest}},"reboot":"report","downgrade":"deny","dependencies":dependencies,"behavior":{"kind":"msi","installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}","version":"1"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
        let root_resource = seed_resource(
            &planning.runtime,
            planning.tenant,
            resource,
            platform_name,
            architecture,
            if platform == Platform::MacOs {
                definition
            } else {
                windows_definition
            },
        )
        .await?;
        let materials: Vec<(&str, &[u8])> = if platform == Platform::MacOs {
            vec![
                ("installer", bytes.as_slice()),
                ("remover", removal.as_slice()),
            ]
        } else {
            vec![("win-installer", windows_bytes.as_slice())]
        };
        for (reference, bytes) in materials {
            let artifact = rss_mdm_resource::Artifact::new(
                rss_mdm_resource::Id::new(reference)?,
                bytes.len() as u64,
                rss_mdm_resource::Digest::of(bytes),
            )?;
            rss_mdm_content_service::fixture::artifact(
                self.content.as_deref().expect("software content"),
                &artifact,
                bytes.to_vec(),
                crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
            )
            .await?;
        }
        seed_enabled(
            &planning.runtime,
            self.content
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("software fixture requires content"))?,
            &root_resource,
        )
        .await?;
        Ok(())
    }
    pub(crate) async fn with_profiles(
        platform: Platform,
        capabilities: Value,
        execution_context: Value,
    ) -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        Self::with_config(platform, capabilities, execution_context, base).await
    }
    pub(crate) async fn with_config(
        platform: Platform,
        capabilities: Value,
        execution_context: Value,
        base: Value,
    ) -> Result<Self> {
        let (resources, mut fixture) = crate::test_support::runtime::Resources::build(move |resources| Box::pin(async move {
        let mut agent = super::agent_execution::Fixture::from_config(base.clone()).await?;
        resources.extend(std::mem::take(&mut agent.resources));
        let router = agent.router.merge(agent.authority.protect(rss_mdm_http_contract::Router::new().nest("/api/v1", rss_mdm_management_http::planning::policies::http::previews(agent.queries.clone(), None)))?);
        let planning = agent.planning;
        let author = crate::test_support::authority::Authority::prepared_browser("other")?;
        let subject = prepared_subject(&author)?;
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
        crate::test_support::identity::seed_grants(case_tenant(), &subject, grants).await?;
        let (_device, platform_name, architecture, credential) = match platform {
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
                crate::test_support::runtime::credential("windows-software"),
            ),
        };
        let registration=crate::test_support::agent::seed_service(&agent.enrollment,&credential,_device,json!({"capabilities":capabilities,"platform":platform_name,"architecture":architecture,"executionContext":execution_context})).await?;
        let device = registration["deviceId"].as_str().unwrap();
        let scope = prepared_scope(&planning, &[device])
            .await
            .map_err(|e| anyhow::anyhow!("software fixture scope: {e:#}"))?;
        let source = Uuid::new_v4().to_string();
        let tenant = rss_request_context::TenantId::parse(case_tenant())?;
        let source_definition = rss_mdm_software_service::catalog::SourceDefinition {
            id: source,
            revision: "1".into(),
            protocol: rss_mdm_software_service::catalog::SourceProtocol::Private,
        };
        let snapshot = planning
            .runtime
            .local_tx(tenant, crate::identity::deadline(), move |tx| {
                Box::pin(async move {
                    rss_mdm_software_service::catalog::fixture::source_in(tx, source_definition)
                        .await
                        .map_err(|e| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol(e.to_string()),
                            )
                        })
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(anyhow::anyhow!(e)),
                |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("software source rollback unconfirmed")),
                |_| Err(anyhow::anyhow!("software source commit unconfirmed")),
                |e| Err(anyhow::anyhow!(e)),
            )?;
        let registered = json!({"snapshot": snapshot});
        let dependency = Uuid::new_v4();
        let dependency_bytes = format!("controlled dependency package {dependency}").into_bytes();
        let resource = Uuid::new_v4();
        let bytes = format!("controlled software package {resource}").into_bytes();
        let removal = format!("#!/bin/sh\n# {resource}\nexit 0\n").into_bytes();
        let windows_bytes = format!("controlled windows root msi {resource}").into_bytes();

        Ok(Self {
            resources: Default::default(),
            platform,
            source_snapshot: registered["snapshot"].clone(),
            dependency,
            dependency_digest: Value::Null,
            base,
            enrollment: agent.enrollment,
            queries: agent.queries,
            content: agent.content,
            execution: agent.execution,
            router,
            author,
            resource,
            scope,
            planning,
            dependency_bytes,
            bytes,
            removal,
            windows_bytes,
            credential,
            registration,
        })

        })).await?;
        fixture.resources = resources;
        Ok(fixture)
    }
}
pub(crate) async fn prepared_scope(
    planning: &rss_mdm_flow_service::planning::Planning,
    devices: &[&str],
) -> Result<Uuid> {
    let scope = Uuid::new_v4();
    let targets = devices
        .iter()
        .map(|device| json!({"kind":"device","id":device}))
        .collect::<Vec<_>>();
    super::agent_execution::seed_scope(planning, scope, json!(targets)).await?;
    Ok(scope)
}

pub(crate) async fn worker(
    base: &Value,
    worker: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Result<Option<rss_runtime::ShutdownStack>> {
    crate::test_support::case::require_worker();
    let config: Config = serde_json::from_value(base.clone())?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    let notifications = crate::worker_wake::Listener::new(
        config.access_options()?,
        rss_request_context::TenantId::parse(&config.identity.tenant_id)?,
    );
    let signals = notifications.signals.clone();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.registration().critical());
    launch.stage_deferred_task_with_token(worker.registration(signals.execution()).critical());
    launch.finish();
    Ok(Some(stack))
}
pub(crate) fn authored(resource: Uuid, scope: Uuid, intent: &str) -> Value {
    json!({"scope":scope,"action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":intent,"delivery":{"kind":"direct"},"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":scope,"opensAt":0}]}}})
}

// Statistics are published by policy recovery. Await readiness, then preserve each
// caller's assertions over the actual reported effect and fixed membership denominator.
pub(crate) async fn ready_rollout(
    author: &mut Browser,
    router: &Router,
    policy: Uuid,
) -> Result<(StatusCode, Value)> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let reply = author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v1/policies/{policy}/software/rollout"),
                    None,
                )
                .await?;
            ensure!(reply.0 == StatusCode::OK, "rollout read failed: {reply:?}");
            let stages = reply.1["stages"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("rollout stages missing"))?;
            if !stages.is_empty() && stages.iter().all(|stage| stage["ready"] == true) {
                ensure!(
                    stages.iter().all(|stage| stage["asOf"].as_i64().is_some()),
                    "ready rollout has no timestamp: {reply:?}"
                );
                return Ok(reply);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("rollout statistics did not become ready for {policy}"))?
}

pub(crate) async fn seed_resource(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    tenant: rss_request_context::TenantId,
    id: Uuid,
    platform: &str,
    architecture: &str,
    definition: Value,
) -> Result<rss_mdm_resource::Version> {
    use rss_mdm_resource::{Declaration, Id, Kind, Variant, Version};
    let version = Version::new(
        tenant,
        Id::new(id.to_string())?,
        Id::new("v1")?,
        Kind::Software,
        vec![Variant::new(
            serde_json::from_value(json!(platform))?,
            serde_json::from_value(json!(architecture))?,
            Id::new("default")?,
            Declaration::Software {
                definition: serde_json::from_value(definition)?,
            },
        )],
    )?;
    let stored = version.clone();
    runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(
                    tx,
                    stored,
                    rss_contract::Timepoint::try_from(1_i64).expect("fixture time"),
                )
                .await
            })
        })
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("software resource rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("software resource commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )?;
    Ok(version)
}
pub(crate) async fn seed_enabled(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    content: &rss_mdm_content_service::Store,
    version: &rss_mdm_resource::Version,
) -> Result<()> {
    use rss_mdm_software_service::catalog::ContentPort;
    let verified = content.verify(version).await?;
    let version = version.clone();
    runtime
        .local_tx(version.tenant(), crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_software_service::catalog::fixture::enabled_in(
                    tx,
                    &version,
                    verified.as_ref(),
                )
                .await
                .map_err(|e| {
                    rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                        e.to_string(),
                    ))
                })
            })
        })
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("software lifecycle rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("software lifecycle commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )
}
