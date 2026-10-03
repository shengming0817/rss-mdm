//! Controlled PKG and real Apple mTLS, observation, dynamic Group and independent enrollment.
use super::*;
use crate::test_support::{channel_onboarding as setup, credential, pg};
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: real native peer and durable Policy"]
async fn absent_agent_group_installs_fixed_package_and_registers_independently() -> Result<()> {
    let mut f = Fixture::with_agent(Some(setup::pin(false))).await?;
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
    let policy = setup::publish(&mut f.browser, &f.router, case_device(), false).await?;
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
                    ("OSVersion", "14.0".into()),
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
    ensure!(peer.manage("NotNow", Some(install), None).await?.is_empty());
    ensure!(f.operation(operation).await?["agentInstallation"]["delivery"] == "deferred");
    let (retry, _) = next_after_cooldown(&peer, "InstallEnterpriseApplication").await?;
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
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "InstalledApplicationList",
            plist::Value::Array(vec![
                protocol::dictionary([
                    ("Identifier", "com.rss.agent".into()),
                    ("Version", "1.2.3".into()),
                    ("Installing", true.into()),
                ])
                .into(),
            ]),
        )),
    )
    .await?;
    ensure!(f.operation(operation).await?["agentInstallation"]["installation"] == "installing");
    let (observe, _) = next_after_cooldown(&peer, "InstalledApplicationList").await?;
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
    let (observe, _) = next_after_cooldown(&peer, "InstalledApplicationList").await?;
    peer.manage(
        "Acknowledged",
        Some(observe),
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
    let state = f.operation(operation).await?;
    ensure!(
        state["agentInstallation"]["installation"] == "unknown"
            && state["commandStatus"] != "applied",
        "unverified bundle promoted to installed: {state}"
    );
    let input = json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4(),"installationOperation":operation,"credential":credential("managed-apple-agent"),"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v6","mdm.enrollment.v6"]});
    let url = format!("{}/api/agent/v6/managed-registrations", peer.origin);
    for (field, value, code) in [
        ("wireVersion", json!(3), "unsupported_wire"),
        (
            "capabilities",
            json!(["inventory.basic.v3"]),
            "unsupported_capability",
        ),
        (
            "capabilities",
            json!(["inventory.collect.v6", "inventory.collect.v6"]),
            "unsupported_capability",
        ),
        ("deviceId", json!("untrusted"), "malformed_request"),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        let response = peer.client.post(&url).json(&invalid).send().await?;
        ensure!(response.status() == StatusCode::BAD_REQUEST);
        ensure!(response.json::<serde_json::Value>().await?["code"] == code);
    }
    let response = peer.client.post(&url).json(&input).send().await?;
    let status = response.status();
    let receipt: serde_json::Value = response.json().await?;
    ensure!(
        status == StatusCode::CREATED,
        "register {status}: {receipt}"
    );
    ensure!(receipt["deviceId"] != case_device());
    let response = peer.client.post(&url).json(&input).send().await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(response.json::<serde_json::Value>().await? == receipt);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_apple.attempts WHERE tenant_id='{}' AND operation='{operation}' AND phase='execute'",case_tenant()))?.trim()=="1");
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
#[ignore = "MODULE=apple.onboarding: actual issued peer survives optional feature changes"]
async fn enabling_agent_installation_preserves_existing_native_identity_and_rights() -> Result<()> {
    use sqlx::{Connection, Row};
    let mut f = Fixture::start().await?;
    let (_peer, device) = f.ready_local_peer().await?;
    let mut config: config::Config =
        serde_json::from_slice(&std::fs::read(f.root.join("apple.json"))?)?;
    config.management.origin = f.app.apple()?.config.management.origin.clone();
    config.management.listen = f.app.apple()?.config.management.listen;
    let pin: rss_mdm_execution_service::agent_install::Config =
        serde_json::from_value(setup::pin(false))?;
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
        pin.identity(rss_mdm_policy::Platform::Macos).cloned(),
    )?;
    let trust = rss_mdm_certificate::apple::AppleDeviceTrust::from_bytes(
        &std::fs::read(f.root.join("apple-issuer.pem"))?,
        f.app.clock.unix_seconds()?,
    )?;
    let leaf = trust.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            std::fs::read(device.root.path().join("leaf.der"))?,
        )],
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
    kind: &str,
) -> Result<(Uuid, plist::Dictionary)> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let bytes = peer.manage("Idle", None, None).await?;
            if !bytes.is_empty() {
                return lifecycle::command(&bytes, kind);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.onboarding: native bundle evidence never verifies the publisher"]
async fn collected_bundle_presence_remains_unknown() -> Result<()> {
    let mut f = Fixture::with_agent(Some(setup::pin(false))).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let (platform, _) = peer.next("DeviceInformation").await?;
    let bytes = peer
        .manage(
            "Acknowledged",
            Some(platform),
            Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "14.0".into()),
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
