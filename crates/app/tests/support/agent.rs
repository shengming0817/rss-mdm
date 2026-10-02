use super::*;
pub(crate) struct Agent {
    pub(crate) password: &'static str,
    pub(crate) credential: &'static str,
    pub(crate) request: Value,
    pub(crate) registration: Value,
}
pub(crate) async fn register(router: &Router, browser: &mut Browser) -> Result<Agent> {
    let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static CREDENTIAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let credential = CREDENTIAL
        .get_or_init(|| super::credential("registration"))
        .as_str();
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, enrollment) = browser
        .call(
            router,
            Method::POST,
            "/api/v3/enrollments",
            Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":password,"source":"agent.builtin"})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK && enrollment["source"] == "agent.builtin",
        "Agent enrollment failed: {status} {enrollment}"
    );
    let operation = uuid::Uuid::new_v4();
    let registration_request = json!({
        "wireVersion":5,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":operation,
        "enrollmentId":enrollment["enrollmentId"],
        "password":password,
        "credential":credential,
        "platform":"macos",
        "architecture":"aarch64",
        "capabilities":["inventory.collect.v5"]
    });
    let (status, registration) = agent_call(
        router,
        Method::POST,
        "/api/agent/v5/registrations",
        None,
        Some(registration_request.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::CREATED && registration["source"] == "agent.builtin",
        "Agent registration failed: {status} {registration}"
    );
    Ok(Agent {
        password,
        credential,
        request: registration_request,
        registration,
    })
}

/// Registration and report routes consume only authority, device and observation services.
pub(crate) async fn router(fixture: &authority::Authority) -> Result<Router> {
    let runtime = agent_runtime(&fixture.base).await?;
    let devices = Arc::new(crate::device::DeviceService::new(
        fixture.access.registration(),
        case_tenant().into(),
        fixture.audit.clone(),
    ));
    let collection = Arc::new(crate::assets::collection::CollectionService::new(
        devices.clone(),
        fixture.access.inventory(),
        runtime,
    ));
    let agent = crate::agent::router(
        Arc::new(crate::agent::HttpState {
            mount: crate::device::ChannelMount::new(
                fixture.identity.tenant,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            ),
            audit_store: fixture.audit.clone(),
            access: Arc::new(fixture.access.agent_store()),
            identity: Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    fixture.identity.authority.clone(),
                    fixture.identity.tenant,
                ),
            ),
            credentials: fixture.credentials.clone(),
            devices,
            collection,
        }),
        rss_mdm_agent_channel::boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: "mdm.example.test".into(),
            clock: monotonic(),
            audit_store: fixture.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
            tenant: case_tenant().into(),
        },
    );
    let fallback = Router::new()
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(axum::middleware::from_fn_with_state(
            "mdm.example.test".to_owned(),
            crate::http_host::guard,
        ));
    Ok(fixture
        .router_with_public(
            fixture.authorization().merge(fixture.enrollment()),
            Router::new().nest("/api/agent/v5", agent),
        )?
        .merge(fallback))
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
INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at)
 SELECT '{TENANT}',grant_id,'bulk-fixture','{INSTANCE}',device,'enrollment','consumed',
        clock_timestamp()+interval '200 seconds' FROM task_targets;
INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile)
 SELECT '{TENANT}',request,grant_id,'agent.builtin',NULL FROM task_targets;
INSERT INTO mdm_access.devices(tenant_id,id) SELECT '{TENANT}',device FROM task_targets;
INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state)
 SELECT '{TENANT}',registration,device,'agent',1,request,'active' FROM task_targets;
INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state)
 SELECT '{TENANT}',gen_random_uuid(),registration,'agent',
        md5(registration::text)||md5(registration::text),'active' FROM task_targets;
INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled)
 SELECT '{TENANT}',t.registration,s.source,gen_random_uuid(),true
 FROM task_targets t CROSS JOIN mdm_access.report_sources s
 JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration)
 WHERE r.tenant_id='{TENANT}' AND r.device='{canonical_sql}' AND r.channel='agent' AND r.state='active' AND s.enabled;
INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context)
 SELECT '{TENANT}',registration,5,'["inventory.collect.v5","task.execute.v5"]','macos','aarch64','{execution_context}'::jsonb FROM task_targets;
DO $$ BEGIN
 IF (SELECT count(*) FROM task_targets t JOIN mdm_access.registrations r ON r.id=t.registration
     JOIN mdm_agent.bindings b ON b.registration=r.id
     JOIN mdm_access.credentials c ON c.registration=r.id
     JOIN mdm_access.requests q ON q.id=r.request_id
     JOIN mdm_access.devices d ON (d.tenant_id,d.id)=(r.tenant_id,r.device)
     WHERE r.state='active' AND c.state='active'
       AND b.capabilities='["inventory.collect.v5","task.execute.v5"]'
       AND (SELECT count(*) FROM mdm_access.report_sources s WHERE s.registration=r.id AND s.enabled
            AND s.source IN ('agent.builtin','agent.script','agent.osquery'))=3) <> {count}
 THEN RAISE EXCEPTION 'incomplete task target fixture'; END IF;
END $$;
COMMIT;
"#,
        TENANT = case_tenant(),
        execution_context = serde_json::json!({"revision":1,"osVersion":[14,0,0,0],"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}),
    ))?;
    let mut devices = vec![canonical.to_owned()];
    devices.extend((1..=count).map(|n| format!("restart-agent-{n:03}")));
    Ok(devices)
}
