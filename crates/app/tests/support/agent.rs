//! Fixture peers use real signed certificates and a real TLS handshake.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_certificate::HandshakePeer;
use rss_mdm_registration_service::agent::{Assembly, NativeAdmission, Pending, Service};
use std::sync::{Mutex, OnceLock};
static PEERS: OnceLock<Mutex<BTreeMap<String, (HandshakePeer, &'static str)>>> = OnceLock::new();
pub(crate) fn evidence(label: &str) -> Option<HandshakePeer> {
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
pub(crate) fn remember(label: &str, peer: HandshakePeer, device: String) {
    PEERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(label.into(), (peer, Box::leak(device.into_boxed_str())));
}
struct NoNative;
impl NativeAdmission for NoNative {
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
            fixture.audit.clone(),
            Arc::new(crate::clock::SystemClock),
            providers.clone(),
        )?
        .ok_or_else(|| anyhow::anyhow!("Agent PKI fixture missing"))?;
    let registry = rss_mdm_pki_service::registry::Registry::new(
        fixture.access.archive_pool(),
        fixture.audit.clone(),
        vec![pki.issuer.trust().trust.clone()],
        providers,
    );
    super::pki::seed_trust(&fixture.access.archive_pool(), registry.bindings()).await?;
    Ok(Arc::new(Service::new(Assembly {
        tenant: fixture.identity.tenant,
        store: fixture.access.registration(),
        audit: fixture.audit.clone(),
        issuer: pki.issuer.clone(),
        clock: pki.pki_clock.clone(),
        origin: pki.origin.clone(),
        configuration_signer: Arc::new(fixture_signer()?),
        installations: Arc::new(crate::agent_configurations::Installations),
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
    remember(label, peer, receipt.runtime.device_id.clone());
    Ok(serde_json::to_value(receipt.runtime)?)
}

pub(crate) fn application_service(
    pki: &crate::agent_pki::AgentPki,
    access: &crate::Database,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Result<Arc<Service>> {
    Ok(Arc::new(Service::new(Assembly {
        tenant: rss_request_context::TenantId::parse(case_tenant())?,
        store: access.registration(),
        audit,
        issuer: pki.issuer.clone(),
        clock: pki.pki_clock.clone(),
        origin: pki.origin.clone(),
        configuration_signer: Arc::new(fixture_signer()?),
        installations: Arc::new(crate::agent_configurations::Installations),
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
/// Seed current credentials while preserving certificate, TLS, and request verification.
pub(crate) async fn seed_profile(
    base: &Value,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    label: &str,
    device: &str,
    profile: Value,
) -> Result<Value> {
    let config: crate::agent_pki::Config = serde_json::from_value(base["agent_pki"].clone())?;
    let access = database(base).await?;
    let result = async {
        let audit = access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?;
        let pki = config
            .load(
                audit.clone(),
                Arc::new(crate::clock::SystemClock),
                crate::device_pki::providers(&serde_json::from_value::<
                    Vec<crate::device_pki::Provider>,
                >(base["device_pki"].clone())?)?,
            )?
            .ok_or_else(|| anyhow::anyhow!("agent fixture PKI missing"))?;
        let service = application_service(&pki, &access, audit, execution)?;
        seed_service(&service, label, device, profile).await
    }
    .await;
    access.close().await;
    result
}

pub(crate) async fn seed_service(
    service: &Service,
    label: &str,
    device: &str,
    profile: Value,
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
    let secret = super::credential(&Uuid::new_v4().to_string());
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
            db.audit_store(&crate::config::AuditConfig::Plain).await?,
            Arc::new(crate::clock::SystemClock),
            crate::device_pki::providers(&serde_json::from_value::<
                Vec<crate::device_pki::Provider>,
            >(base["device_pki"].clone())?)?,
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
    let label = Box::leak(super::credential(&Uuid::new_v4().to_string()).into_boxed_str());
    let (request,candidate,registration)=enroll_profile(router,browser,label,json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":software_execution::context(software_execution::Platform::MacOs)})).await?;
    let device = registration["deviceId"].as_str().unwrap();
    set_device_grants(browser, router, device, &["inventory_read", "credentials"]).await?;
    Ok(Agent {
        password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        credential: label,
        request,
        candidate,
        registration,
    })
}
pub(crate) async fn router(fixture: &authority::Authority) -> Result<Router> {
    let service = service(fixture).await?;
    let runtime = agent_runtime(&fixture.base).await?;
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
                    enrollment: service.clone(),
                    audit_store: fixture.audit.clone(),
                    access: Arc::new(fixture.access.agent_store()),
                    inventory: runtime,
                }),
                envelope.clone(),
            ),
        )
        .nest(
            "/api/v1/agent/enroll",
            crate::agent::enroll::router(service.clone(), envelope),
        );
    let browser = fixture.authorization().merge(fixture.enrollment()).nest(
        "/api/v1",
        rss_mdm_management_http::agent_enrollment::routes(Some(service)),
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

pub(crate) fn fixture_signer() -> Result<rss_mdm_registration_service::agent::configurations::Signer>
{
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: crate::task_signing::Config = serde_json::from_value(base["task_signing"].clone())?;
    Ok(crate::agent_configurations::signer(&config)?)
}
