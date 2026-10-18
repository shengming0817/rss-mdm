//! Controlled PKG and real Apple mTLS, observation, dynamic Group and independent enrollment.
use super::*;
use crate::test_support::{channel_onboarding as setup, credential, pg};
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: real native peer and durable Policy"]
async fn absent_agent_group_installs_fixed_package_and_registers_independently() -> Result<()> {
    let mut f = Fixture::with_agent(None).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        f.app.flow.planning.clone(),
        f.app.flow.assets.clone(),
        f.app.flow.compliance.clone(),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(automation.registration(f.signals.flow()).critical());
    launch.finish();
    let policy = setup::publish(&mut f.browser, &f.router, case_device(), &f.app, false).await?;
    let (platform, payload) = peer.next("DeviceInformation").await?;
    ensure!(
        payload["Queries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_string() == Some("IsAppleSilicon"))
    );
    let bytes = peer
        .manage(
            "Acknowledged",
            Some(platform),
            Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsAppleSilicon", true.into()),
                ])
                .into(),
            )),
        )
        .await?;
    let (query, payload) = lifecycle::command(&bytes, "InstalledApplicationList")?;
    ensure!(payload["Identifiers"] == plist::Value::Array(vec!["com.rss.agent".into()]));
    peer.manage(
        "Acknowledged",
        Some(query),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    let operation = setup::operation(policy).await?;
    let state = setup::diagnosis(&mut f.browser, &f.router, policy, case_device()).await?;
    ensure!(
        state["taskAdmission"]["state"] == "eligible"
            && state["operationIds"] == json!([operation]),
        "{state}"
    );
    let (install, payload) = peer.next("InstallEnterpriseApplication").await?;
    ensure!(
        payload["Configuration"].as_dictionary().unwrap()["RSSInstallationOperation"].as_string()
            == Some(operation.to_string().as_str())
    );
    ensure!(!payload.contains_key("RemoveAppUponMDMProfileRemoval"));
    let manifest = payload["Manifest"].as_dictionary().unwrap();
    let item = manifest["items"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    let asset = item["assets"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    let generated = url::Url::parse(asset["url"].as_string().unwrap())?;
    ensure!(
        generated
            .path()
            .starts_with("/api/v1/agent/enroll/installations/")
    );
    let package = f
        .router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(generated.path())
                .header(
                    "host",
                    generated[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
                )
                .header("range", "bytes=0-3")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    ensure!(package.status() == StatusCode::PARTIAL_CONTENT);
    ensure!(
        axum::body::to_bytes(package.into_body(), 1024)
            .await?
            .as_ref()
            == &setup::bytes()[..4]
    );

    ensure!(peer.manage("NotNow", Some(install), None).await?.is_empty());
    ensure!(f.operation(operation).await?["agentInstallation"]["delivery"] == "deferred");
    let (retry, _) = next_after_cooldown(&peer, install, "InstallEnterpriseApplication").await?;
    ensure!(retry == install, "NotNow retries the same native identity");
    // The reference server receives the ACK; the product loses this transport message.
    // Both then continue on the same device, so the oracle still checks query syntax.
    peer.oracle
        .compare(
            "/mdm",
            &protocol::xml(protocol::dictionary([
                ("Status", "Acknowledged".into()),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
                ("CommandUUID", install.to_string().into()),
            ]))?,
            &[],
        )
        .await?;
    // An unacknowledged install is queried; it is never sent again as a new install.
    let (observe, _) = peer.next("InstalledApplicationList").await?;
    // Error responses cannot claim installed even if an extraneous list is present.
    peer.manage(
        "Error",
        Some(observe),
        Some((
            "InstalledApplicationList",
            plist::Value::Array(vec![
                protocol::dictionary([
                    ("Identifier", "com.rss.agent".into()),
                    ("Version", "1.2.3".into()),
                ])
                .into(),
            ]),
        )),
    )
    .await?;
    let state = f.operation(operation).await?;
    ensure!(
        state["agentInstallation"]["installation"] == "unknown"
            && state["commandStatus"] != "applied",
        "{state}"
    );
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":operation,"secret":credential("managed-apple-agent"),"csr":crate::test_support::agent::csr()?,"runtime":{"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v1","mdm.enrollment.v1"]}});
    let (bootstrap_delivery, bootstrap_payload) = peer.next("InstallProfile").await?;
    ensure!(
        bootstrap_payload.contains_key("Payload"),
        "native bootstrap must deliver a profile"
    );
    peer.manage("Acknowledged", Some(bootstrap_delivery), None)
        .await?;
    let bootstrap_peer = crate::test_support::bootstrap::issue_apple(
        &f.app,
        &f.router,
        &f.root,
        operation,
        &bootstrap_payload,
    )
    .await?;
    // The native daily identity is no longer mounted as an Agent authorization endpoint.
    ensure!(
        peer.client
            .post(format!("{}/api/v1/agent/enroll/native-grants", peer.origin))
            .json(&input)
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    let response =
        crate::test_support::bootstrap::grant(&f.router, &bootstrap_peer, &input).await?;
    let status = response.status();
    let receipt: serde_json::Value = response.json().await?;
    ensure!(status == StatusCode::OK, "register {status}: {receipt}");
    ensure!(receipt["state"] == "available");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_apple.attempts WHERE tenant_id='{}' AND operation='{operation}' AND phase='execute'",case_tenant()))?.trim()=="1");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_grants WHERE tenant_id='{}' AND source='native' AND (native_authority ? 'secret' OR native_authority ? 'input')",case_tenant()))?.trim()=="0", "native authority must not persist bootstrap secrets");
    let receipt = crate::test_support::agent::complete_grant(
        f.app.agent_enrollment.as_ref().unwrap(),
        &receipt,
        &input,
        &credential("managed-apple-agent"),
    )
    .await?;
    ensure!(receipt["deviceId"] != case_device());
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='agent'",case_tenant()))?.trim()=="1");
    let state = f.operation(operation).await?;
    ensure!(
        state["agentInstallation"]["installation"] == "unknown"
            && !state["agentInstallation"]["agentRegistration"].is_null(),
        "{state}"
    );
    let _ = install;
    ensure!(owner.shutdown().join().await?.is_clean());
    drop(device);
    f.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: Agent publication retains bound attempt identity"]
async fn agent_publication_preserves_bound_attempt_identity() -> Result<()> {
    use sqlx::{Connection, Row};
    let mut f = Fixture::start().await?;
    let (device, der) = f.seed_local_identity().await?;
    let peer = f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    let mut config: config::Config =
        serde_json::from_slice(&std::fs::read(f.root.join("apple.json"))?)?;
    config.management.origin = f.app.apple()?.config.management.origin.clone();
    config.management.listen = f.app.apple()?.config.management.listen;
    config.trust_file = f.app.apple()?.config.trust_file.clone();
    setup::publish_macos_release(&mut f.browser, &f.router, &f.app).await?;
    let original_rights: i32 = pg(&format!(
        "SELECT access_rights FROM mdm_apple.devices WHERE tenant_id='{}' AND state='active'",
        case_tenant()
    ))?
    .trim()
    .parse()?;
    let updated = Apple::load(
        f.app.protection.clone(),
        config,
        f.app.clock.unix_seconds()?,
        super::fixture_providers(&f.root)?,
    )?;
    let trust = rss_mdm_device_trust::apple::AppleDeviceTrust::from_trust(
        f.app.apple()?.channel.device_trust().clone(),
    )?;
    let leaf = trust.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(der)],
        f.app.clock.unix_seconds()?,
    )?;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let attempt =
        rss_mdm_apple_channel::enrollment::attempt(&mut tx, case_tenant(), &updated.channel, &leaf)
            .await?;
    ensure!(attempt.try_get::<String, _>("state")? == "bound");
    let rights: i32 = sqlx::query_scalar(
        "SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active'",
    )
    .bind(case_tenant())
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        rights == original_rights,
        "deployment config must not invent device consent"
    );
    tx.rollback().await?;
    f.close().await
}

async fn next_after_cooldown(
    peer: &lifecycle::Peer,
    attempt: Uuid,
    kind: &str,
) -> Result<(Uuid, plist::Dictionary)> {
    use sqlx::Connection;
    let mut db =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let future: bool = sqlx::query_scalar("SELECT next_attempt>clock_timestamp() FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(attempt).fetch_one(&mut db).await?;
    ensure!(future, "current attempt has no future cooldown");
    ensure!(
        peer.manage("Idle", None, None).await?.is_empty(),
        "cooldown allowed an early retry"
    );
    let changed = sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(attempt).execute(&mut db).await?;
    ensure!(changed.rows_affected() == 1);
    db.close().await?;
    peer.next(kind).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: native bundle evidence never verifies the publisher"]
async fn collected_bundle_presence_remains_unknown() -> Result<()> {
    let mut f = Fixture::with_agent(None).await?;
    let (peer, device) = f.ready_local_peer().await?;
    setup::publish_macos_release(&mut f.browser, &f.router, &f.app).await?;
    let (platform, _) = peer.next("DeviceInformation").await?;
    let bytes = peer
        .manage(
            "Acknowledged",
            Some(platform),
            Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsAppleSilicon", true.into()),
                ])
                .into(),
            )),
        )
        .await?;
    let (query, _) = lifecycle::command(&bytes, "InstalledApplicationList")?;
    peer.manage(
        "Acknowledged",
        Some(query),
        Some((
            "InstalledApplicationList",
            plist::Value::Array(vec![
                protocol::dictionary([
                    ("Identifier", "com.rss.agent".into()),
                    ("Version", "1.2.3".into()),
                    ("TeamID", "RSS1234567".into()),
                ])
                .into(),
            ]),
        )),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let value = pg(&format!("SELECT value FROM mdm.inventory WHERE tenant_id='{}' AND source='mdm.apple' AND field='channel.agent.installation'", case_tenant()))?;
            if !value.trim().is_empty() {
                ensure!(serde_json::from_str::<serde_json::Value>(value.trim())? == json!({"kind":"string","value":"unknown"}), "unverified native observation: {value}");
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await??;
    drop(device);
    f.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: started Agent handoff completes real SCEP and native check-in"]
async fn agent_handoff_completes_native_registration_and_token_update() -> Result<()> {
    let mut f = Fixture::start().await?;
    let handoff =
        crate::test_support::native_handoff::Handoff::new(rss_mdm_resource::Platform::MacOS)
            .await?;
    let id = Uuid::parse_str(handoff.receipt["enrollmentId"].as_str().unwrap())?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/enrollments/{id}/profile"))
        .header("host", "mdm.example.test")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"password":credential("wrong-native-handoff")}).to_string(),
        ))?;
    ensure!(f.router.clone().oneshot(request).await?.status() == StatusCode::UNAUTHORIZED);
    let (enrollment, attempt, password) = f.profile_request(id, handoff.password.clone()).await?;
    let device = scep_client::Device::new(enrollment, attempt, &password)?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    let der = device
        .enroll(
            &f.client()?,
            &f.app.apple()?.channel.scep_fixture()?.0,
            &request,
        )
        .await?;
    let peer = f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    let linked = pg(&format!(
        "SELECT count(*) FROM mdm_access.agent_native_enrollments l JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(l.tenant_id,l.request) JOIN mdm_access.registrations r ON(r.tenant_id,r.request_id)=(q.tenant_id,q.id) JOIN mdm_apple.devices a ON(a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE l.tenant_id='{}' AND l.request='{id}' AND l.source_registration='{}' AND q.state='bound' AND r.state='active' AND a.state='active' AND r.id<>l.source_registration",
        case_tenant(),
        handoff.source["registrationId"].as_str().unwrap()
    ))?;
    ensure!(
        linked.trim() == "1",
        "native registration must follow its exact Agent task"
    );
    crate::test_support::identity::set_grants(case_tenant(), &handoff.fixture.author_id, vec![])
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/enrollments/{id}/profile"))
        .header("host", "mdm.example.test")
        .header("content-type", "application/json")
        .body(Body::from(json!({"password":handoff.password}).to_string()))?;
    ensure!(
        f.router.clone().oneshot(request).await?.status() == StatusCode::FORBIDDEN,
        "withdrawn Agent task authority must not enroll MDM"
    );
    handoff.close().await?;
    drop(device);
    f.close().await
}
