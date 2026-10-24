//! Fixture peers use real signed certificates and a real TLS handshake.
use super::{http::*, process::*, runtime::*, *};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_registration_service::agent::{Assembly, NativeAdmission, Pending, Service};
use std::sync::{Mutex, OnceLock};
static PEERS: OnceLock<Mutex<BTreeMap<String, (ClientCertificateEvidence, &'static str)>>> =
    OnceLock::new();
pub(crate) fn evidence(label: &str) -> Option<ClientCertificateEvidence> {
    PEERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(label)
        .map(|p| p.0.clone())
}
pub(crate) fn device(label: &str, fallback: &'static str) -> &'static str {
    PEERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(label)
        .map_or(fallback, |p| p.1)
}
pub(crate) fn remember(label: &str, peer: ClientCertificateEvidence, device: String) {
    PEERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(label.into(), (peer, Box::leak(device.into_boxed_str())));
}
struct NoNative;
impl NativeAdmission for NoNative {
    fn bootstrap<'a>(
        &'a self,
        _: &'a mut sqlx::PgConnection,
        _: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> Pending<'a, ()> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }
    fn grant<'a>(
        &'a self,
        _: &'a mut sqlx::PgConnection,
        _: &'a rss_mdm_registration_service::agent::native::Source,
        _: &'a rss_mdm_agent_wire::enroll::NativeGrantRequest,
    ) -> Pending<'a, (rss_mdm_agent_wire::enroll::GrantReceipt, bool)> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }

    fn validate<'a>(
        &'a self,
        _c: &'a mut sqlx::PgConnection,
        _source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> Pending<'a, ()> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }
}
pub(crate) async fn service(fixture: &authority::Authority) -> Result<Arc<Service>> {
    let config: crate::agent_pki::Config =
        serde_json::from_value(fixture.base["agent_pki"].clone())?;
    let providers = crate::device_pki::providers(&serde_json::from_value::<
        Vec<crate::device_pki::Provider>,
    >(fixture.base["device_pki"].clone())?)?;
    let pki = config
        .load(
            fixture.base["identity"]["instance_id"].as_str().unwrap(),
            fixture.audit.clone(),
            Arc::new(crate::clock::SystemClock),
            providers.clone(),
            config.bootstrap_materials(
                fixture.base["identity"]["instance_id"].as_str().unwrap(),
                &providers,
                crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
            )?,
        )?
        .ok_or_else(|| anyhow::anyhow!("Agent PKI fixture missing"))?;
    let registry = rss_mdm_pki_service::registry::Registry::new(
        fixture.pool.clone(),
        fixture.audit.clone(),
        vec![pki.issuer.trust().trust.clone()],
        providers,
    );
    super::pki::seed_trust(&fixture.pool.clone(), registry.bindings()).await?;
    Ok(Arc::new(Service::new(Assembly {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[29; 32]).unwrap(),
        tenant: fixture.identity.tenant,
        store: fixture.registration.clone(),
        audit: fixture.audit.clone(),
        access_audit: Arc::new(
            fixture
                .audit
                .on_runtime(
                    fixture.identity.runtime.clone(),
                    fixture.identity.tenant,
                    &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                        .control(),
                )
                .await?,
        ),
        issuer: pki.issuer.clone(),
        clock: pki.pki_clock.clone(),
        protection: crate::test_support::identity::config(case_tenant())?.native_protector()?,
        installations: Arc::new(crate::agent_configurations::Installations),
        bootstrap: None,
        binding: Arc::new(crate::agent::Bindings),
        native: Arc::new(NoNative),
    })?))
}
pub(crate) async fn complete_grant(
    service: &Service,
    grant: &Value,
    input: &Value,
    label: &str,
) -> Result<Value> {
    let request: rss_mdm_agent_wire::enroll::CertificateRequest = serde_json::from_value(json!({
        "wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant["grantId"],
        "secret":input["secret"],"csr":input["csr"],"runtime":input["runtime"]
    }))?;
    let audit = || {
        rss_mdm_audit_integration::RequestAudit::new(
            case_tenant().into(),
            "agent_certificate_activate",
        )
    };
    let candidate = service.issue(&request, &audit()).await?;
    let chain = candidate
        .certificate_chain
        .iter()
        .map(|v| STANDARD.decode(v))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let peer = crate::test_support::agent_tls::peer(
        service.trust(),
        &chain,
        &std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?),
    )
    .await?;
    let receipt = service
        .activate(
            &peer,
            &rss_mdm_agent_wire::enroll::ActivationRequest {
                wire_version: 1,
                issuance_id: candidate.issuance_id,
                operation_id: Uuid::new_v4(),
            },
            &audit(),
        )
        .await?;
    super::task_signing::acknowledge(service, &peer).await?;
    remember(label, peer, receipt.runtime.device_id.clone());
    Ok(serde_json::to_value(receipt.runtime)?)
}

pub(crate) fn application_service(
    access_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pki: &crate::agent_pki::AgentPki,
    access: Arc<rss_mdm_registration_service::Store>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Result<Arc<Service>> {
    Ok(Arc::new(Service::new(Assembly {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[29; 32]).unwrap(),
        tenant: rss_request_context::TenantId::parse(case_tenant())?,
        store: access,
        access_audit,
        audit,
        issuer: pki.issuer.clone(),
        clock: pki.pki_clock.clone(),
        protection: crate::test_support::identity::config(case_tenant())?.native_protector()?,
        installations: Arc::new(crate::agent_configurations::Installations),
        bootstrap: pki.bootstrap.clone(),
        binding: Arc::new(crate::agent::Bindings),
        native: execution,
    })?))
}

pub(crate) struct Agent {
    pub(crate) password: &'static str,
    pub(crate) credential: &'static str,
    pub(crate) request: Value,
    pub(crate) candidate: Value,
    pub(crate) registration: Value,
}
pub(crate) fn csr() -> Result<String> {
    Ok(STANDARD.encode(std::fs::read(
        std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?).join("agent.der"),
    )?))
}
pub(crate) async fn seed_service(
    service: &Service,
    label: &str,
    device: &str,
    profile: Value,
) -> Result<Value> {
    seed_service_with_ack(service, label, device, profile, true).await
}
/// A real active mTLS registration that has not yet installed task signing trust.
pub(crate) async fn seed_unacknowledged(
    service: &Service,
    label: &str,
    device: &str,
    profile: Value,
) -> Result<Value> {
    seed_service_with_ack(service, label, device, profile, false).await
}
async fn seed_service_with_ack(
    service: &Service,
    label: &str,
    device: &str,
    profile: Value,
    acknowledge: bool,
) -> Result<Value> {
    let root = std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?);
    use crate::clock::Clock;
    let now = crate::clock::SystemClock.unix_seconds()?;
    let csr = std::fs::read(root.join("agent.der"))?;
    let identity =
        rss_mdm_certificate::agent::identity(uuid::Uuid::parse_str(case_tenant())?, device)?;
    let chain = super::pki::leaf(&root, &csr, "rss-mdm-agent", &[identity], now, now + 86400)?;
    let validity = super::pki::validity(&chain[0])?;
    let (issued, runtime) = service
        .seed_peer(
            device,
            serde_json::from_value(profile)?,
            csr,
            chain,
            validity,
        )
        .await?;
    let peer = crate::test_support::agent_tls::peer(service.trust(), &issued.chain, &root).await?;
    service.authenticate(&peer).await?;
    if acknowledge {
        super::task_signing::acknowledge(service, &peer).await?;
    }
    remember(label, peer, runtime.device_id.clone());
    Ok(serde_json::to_value(runtime)?)
}

/// Enrollment and credential-lifecycle specialties retain the complete public operation chain.
pub(crate) async fn enroll_profile(
    router: &Router,
    browser: &mut Browser,
    label: &str,
    profile: Value,
) -> Result<(Value, Value, Value)> {
    let secret = super::runtime::credential(&Uuid::new_v4().to_string());
    let op = Uuid::new_v4();
    let (status,pending)=agent_call(router,Method::POST,"/api/v1/agent/enroll/requests",None,Some(json!({"wireVersion":1,"operationId":op,"secret":secret,"platform":profile["platform"],"csr":csr()?}))).await?;
    ensure!(status.is_success(), "request {status} {pending}");
    let (status, grant) = browser
        .call(
            router,
            Method::POST,
            &format!(
                "/api/v1/agent-requests/{}/authorize",
                pending["grantId"].as_str().unwrap()
            ),
            Some(json!({"operationId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(status.is_success(), "grant {status} {grant}");
    let request = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant["grantId"],"secret":secret,"csr":csr()?,"runtime":profile});
    let (status, candidate) = agent_call(
        router,
        Method::POST,
        "/api/v1/agent/enroll/certificates",
        None,
        Some(request.clone()),
    )
    .await?;
    ensure!(status.is_success(), "candidate {status} {candidate}");
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: crate::agent_pki::Config = serde_json::from_value(base["agent_pki"].clone())?;
    let db = database(&base).await?;
    let pki = config
        .load(
            base["identity"]["instance_id"].as_str().unwrap(),
            db.audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
            Arc::new(crate::clock::SystemClock),
            crate::device_pki::providers(&serde_json::from_value::<
                Vec<crate::device_pki::Provider>,
            >(base["device_pki"].clone())?)?,
            None,
        )?
        .unwrap();
    let chain = candidate["certificateChain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| STANDARD.decode(v.as_str().unwrap()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let peer = crate::test_support::agent_tls::peer(
        pki.issuer.trust(),
        &chain,
        &std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?),
    )
    .await?;
    remember(label, peer, "candidate".into());
    let activation =
        json!({"wireVersion":1,"issuanceId":candidate["issuanceId"],"operationId":Uuid::new_v4()});
    let (status, receipt) = agent_call(
        router,
        Method::POST,
        "/api/v1/agent/enroll/activate",
        Some(label),
        Some(activation),
    )
    .await?;
    ensure!(status.is_success(), "activate {status} {receipt}");
    let registration = receipt["runtime"].clone();
    remember(
        label,
        evidence(label).unwrap(),
        registration["deviceId"].as_str().unwrap().into(),
    );
    Ok((request, candidate, registration))
}
pub(crate) async fn register(router: &Router, browser: &mut Browser) -> Result<Agent> {
    let label = Box::leak(super::runtime::credential(&Uuid::new_v4().to_string()).into_boxed_str());
    let (request,candidate,registration)=enroll_profile(router,browser,label,json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":software_execution::context(software_execution::Platform::MacOs)})).await?;
    let device = registration["deviceId"].as_str().unwrap();
    change_device_grants(browser, device, &["inventory_read", "credentials"]).await?;
    Ok(Agent {
        password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        credential: label,
        request,
        candidate,
        registration,
    })
}
pub(crate) async fn router(fixture: &mut authority::Authority) -> Result<Router> {
    let service = service(fixture).await?;
    let runtime = agent_runtime(fixture).await?;
    fixture.resources.resource(InventoryFixtureResource(runtime.clone()));
    let envelope = rss_mdm_agent_channel::boundary::Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(32)),
        host: "mdm.example.test:9445".into(),
        clock: monotonic(),
        audit_store: fixture.audit.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
        tenant: case_tenant().into(),
    };
    let public = Router::new()
        .nest(
            "/api/v1/agent/runtime",
            crate::agent::router(
                Arc::new(crate::agent::HttpState {
                    content: None,
                    telemetry: None,
                    enrollment: service.clone(),
                    audit_store: fixture.audit.clone(),
                    access: Arc::new(rss_mdm_agent_channel::Store::from_pool(
                        fixture.pool.clone(),
                    )),
                    inventory: runtime,
                }),
                envelope.clone(),
            )
            .into_axum(),
        )
        .nest(
            "/api/v1/agent/enroll",
            crate::agent::enroll::router(service.clone(), envelope).into_axum(),
        );
    let browser = fixture.authorization().merge(fixture.enrollment()).nest(
        "/api/v1",
        rss_mdm_management_http::agent_enrollment::routes(Some(service)).into_axum(),
    );
    fixture.router_with_public(browser, public)
}

/// Prepare additional task-capable targets from one real HTTP registration.
/// Only access prerequisites are cloned; remote targets, commands, receipts and
/// audit remain exclusively the output of the production operation under test.
pub(crate) fn bulk_task_agents(canonical: &str, count: usize) -> Result<Vec<String>> {
    ensure!(count <= 1000);
    // Keep the one live HTTP peer first in target order; the remaining peers
    // exercise fanout checkpoints without making this a relay-throughput test.
    let canonical_sql = canonical.replace('\'', "''");
    pg(&format!(
        r#"
BEGIN;
CREATE TEMP TABLE task_targets ON COMMIT DROP AS
 SELECT 'restart-agent-' || lpad(n::text,3,'0') AS device, gen_random_uuid() AS grant_id,
        gen_random_uuid() AS request, gen_random_uuid() AS registration
 FROM generate_series(1,{count}) n;
INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at)
 SELECT '{TENANT}',grant_id,request,'download','bulk-fixture','{INSTANCE}',device,'macos',repeat('0',64),repeat('0',64),'consumed',clock_timestamp()+interval '24 hours' FROM task_targets;
INSERT INTO mdm_access.devices(tenant_id,id) SELECT '{TENANT}',device FROM task_targets;
INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch)
 SELECT '{TENANT}',registration,device,'agent',1,grant_id,'active','primary',gen_random_uuid() FROM task_targets;
INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state)
 SELECT '{TENANT}',gen_random_uuid(),registration,'agent',
        md5(registration::text)||md5(registration::text),'active' FROM task_targets;
INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled)
 SELECT '{TENANT}',t.registration,s.source,gen_random_uuid(),true
 FROM task_targets t CROSS JOIN mdm_access.report_sources s
 JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration)
 WHERE r.tenant_id='{TENANT}' AND r.device='{canonical_sql}' AND r.channel='agent' AND r.state='active' AND s.enabled;
INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context)
 SELECT '{TENANT}',registration,1,'["inventory.collect.v1","task.execute.v1"]','macos','aarch64','{execution_context}'::jsonb FROM task_targets;
INSERT INTO mdm_commands.action_polls(tenant_id,registration,profiles) SELECT '{TENANT}',registration,'{{"profiles":["posix_sh"],"environment":{{"osVersion":"14.0.0.0","build":0,"edition":null,"tools":{{}}}}}}'::jsonb FROM task_targets;
DO $$ BEGIN
 IF (SELECT count(*) FROM task_targets t JOIN mdm_access.registrations r ON r.id=t.registration
     JOIN mdm_agent.bindings b ON b.registration=r.id
     JOIN mdm_access.credentials c ON c.registration=r.id
     JOIN mdm_access.agent_grants q ON q.id=r.agent_grant_id
     JOIN mdm_access.devices d ON (d.tenant_id,d.id)=(r.tenant_id,r.device)
     WHERE r.state='active' AND c.state='active'
       AND b.capabilities='["inventory.collect.v1","task.execute.v1"]'
       AND (SELECT count(*) FROM mdm_access.report_sources s WHERE s.registration=r.id AND s.enabled
            AND s.source IN ('agent.builtin','agent.script','agent.osquery'))=3) <> {count}
 THEN RAISE EXCEPTION 'incomplete task target fixture'; END IF;
END $$;
COMMIT;
"#,
        TENANT = case_tenant(),
        execution_context = serde_json::json!({"revision":1,"osVersion":[14,0,0,0],"userHelper":true,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}),
    ))?;
    let mut devices = vec![canonical.to_owned()];
    devices.extend((1..=count).map(|n| format!("restart-agent-{n:03}")));
    Ok(devices)
}

pub(crate) fn fixture_signing_input() -> Result<Value> {
    let config = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    Ok(serde_json::from_slice(&std::fs::read(
        config.parent().unwrap().join("task-signing-fixture.json"),
    )?)?)
}

pub(crate) async fn agent_call(
    router: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test:9445");
    if let Some(label) = bearer {
        if let Some(peer) = agent::evidence(label) {
            request = request.extension(peer)
        } else {
            request = request.header("authorization", format!("Bearer {label}"))
        }
    }
    let body = if let Some(value) = body {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    let response = tokio::spawn(router.clone().oneshot(request.body(body)?)).await??;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response.into_body().collect().await?.to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    if status.is_client_error() || status.is_server_error() {
        ensure!(
            content_type.as_deref() == Some("application/json"),
            "Agent error escaped JSON content type: {status} {content_type:?}"
        );
        if path.starts_with("/api/v1/agent/enroll/") {
            let _: rss_mdm_agent_wire::enroll::ErrorBody = serde_json::from_value(value.clone())?;
        } else {
            let _: rss_mdm_agent_wire::runtime::ErrorBody = serde_json::from_value(value.clone())?;
        }
    }
    Ok((status, value))
}

pub(crate) async fn wait_agent_status(
    router: &Router,
    credential: &str,
    report_id: uuid::Uuid,
    observation: &str,
    projection: &str,
) -> Result<Value> {
    let mut last = Value::Null;
    let settled = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (status, body) = agent_call(
                router,
                Method::GET,
                &format!("/api/v1/agent/runtime/reports/{report_id}"),
                Some(credential),
                None,
            )
            .await?;
            ensure!(
                status == StatusCode::OK,
                "Agent status failed: {status} {body}"
            );
            if body["observation"] == observation && body["projection"] == projection {
                return Ok::<_, anyhow::Error>(body);
            }
            last = body;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    settled.map_err(|_| {
        anyhow::anyhow!(
            "Agent report {report_id} did not settle at {observation}/{projection}; last={last}"
        )
    })?
}

pub(crate) async fn agent_runtime(
    authority: &authority::Authority,
) -> Result<Arc<crate::inventory_runtime::InventoryRuntime>> {
    let config: Config = serde_json::from_value(authority.base.clone())?;
    Ok(crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        Arc::new(rss_mdm_inventory_service::Store::from_pool(authority.pool.clone())),
        authority.identity.tenant, monotonic(), authority.audit.clone(),
    ).await?)
}
