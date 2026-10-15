use crate::api::Assembly;
use crate::windows::test_support::*;
use anyhow::ensure;
use axum::http::StatusCode;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use uuid::Uuid;
#[tokio::test]
#[ignore = "make t2 MODULE=windows.enrollment"]
async fn discovery_wstep_replay_and_tls_identity() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let app = &host.app;
    let client = &host.client;
    ensure!(
        client
            .get(format!(
                "{}/accepted-peer",
                app.windows()?.config.enrollment.origin
            ))
            .header("x-forwarded-for", "198.51.100.23")
            .send()
            .await?
            .text()
            .await?
            == "127.0.0.1",
        "TLS requests lost the RSS-owned accepted peer"
    );
    let peer = host.enrolled_peer().await?;
    let token = peer
        .issue
        .header
        .security
        .as_ref()
        .unwrap()
        .username
        .as_ref()
        .unwrap();
    discover_and_policy(
        client,
        app,
        peer.receipt.enrollment_id,
        token.password.0.as_str(),
    )
    .await?;
    rejected_csrs(client, &peer.path, &peer.issue).await?;
    let retry = client
        .post(&peer.path)
        .header("content-type", "application/soap+xml")
        .body(peer.wire.clone())
        .send()
        .await?;
    ensure!(retry.status() == StatusCode::OK);
    let replay =
        soap::decode_response(&peer.issue, &retry.bytes().await?, &CodecLimits::default())?;
    let Body::IssueResponse(replay) = replay.body else {
        anyhow::bail!("missing issuance replay");
    };
    ensure!(replay.provisioning.0 == peer.provisioning);
    let mut admin = crate::test_support::Browser {
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            host.secret.expose().into(),
        )]),
        csrf: Some(host.secret.csrf()),
        ..Default::default()
    };
    let (status, timeline) = admin
        .call(
            &host.browser,
            axum::http::Method::GET,
            &format!(
                "/api/v1/devices/{}/timeline",
                crate::test_support::case::name("tls-device")
            ),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK);
    ensure!(
        timeline["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["source"] == "mdm.business"
                && v["action"] == "enrollment_issue"
                && !v["registrationId"].is_null())
    );
    let root = &host.root;
    let root_cert = &host.root_cert;
    let url = &peer.url;
    ensure!(
        client
            .post(url)
            .body("no certificate")
            .send()
            .await
            .is_err(),
        "management accepted an anonymous TLS handshake"
    );
    let rogue_identity = reqwest::Identity::from_pem(
        &[
            std::fs::read(root.join("rogue-client.pem"))?,
            std::fs::read(root.join("device.key"))?,
        ]
        .concat(),
    )?;
    let rogue = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert.clone())
        .identity(rogue_identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    ensure!(
        rogue
            .post(url)
            .body("untrusted chain")
            .send()
            .await
            .is_err(),
        "management accepted an untrusted client CA"
    );
    let reference = host.reference;
    let secret = rss_identity_core::session::SessionSecret::parse(host.secret.expose().into())?;
    let actor = app
        .identity
        .authority
        .authenticate_session(app.identity.tenant, secret, crate::identity::deadline())
        .await?;
    app.identity
        .authority
        .revoke_current_session(actor, crate::identity::deadline())
        .await?;
    ensure!(
        app.identity
            .authenticate(app.credentials.get(reference)?)
            .await
            .is_err()
    );
    host.close().await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "integration matrix keeps actual Discovery/XCEP success and denial assertions together"
)]
async fn discover_and_policy(
    client: &reqwest::Client,
    app: &Assembly,
    enrollment: Uuid,
    password: &str,
) -> anyhow::Result<()> {
    let origin = &app.windows()?.config.enrollment.origin;
    let mut discovery = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    let discovery_url = format!("{origin}/EnrollmentServer/Discovery.svc");
    for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
        let probe = client.request(method, &discovery_url).send().await?;
        ensure!(probe.status() == StatusCode::OK && probe.bytes().await?.is_empty());
    }
    discovery.header.to = Some(discovery_url.clone());
    let response = client
        .post(&discovery_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&discovery, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let discovery_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded = soap::decode_response(
        &discovery,
        &response.bytes().await?,
        &CodecLimits::default(),
    )?;
    let Body::DiscoverResponse(found) = decoded.body else {
        anyhow::bail!("not Discovery response")
    };
    ensure!(found.enrollment_version == "4.0");
    ensure!(found.policy_url == format!("{origin}/EnrollmentServer/Policy.svc"));
    ensure!(found.enrollment_url == format!("{origin}/EnrollmentServer/Enrollment.svc"));
    let mut policy = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/policy-request.xml"),
        Operation::GetPolicies,
        &CodecLimits::default(),
    )?;
    policy.header.to = Some(found.policy_url.clone());
    let token = policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap();
    token.username = Secret(app.windows()?.channel.enrollment_username(enrollment)?);
    token.password = Secret(password.to_owned());
    let response = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let policy_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded =
        soap::decode_response(&policy, &response.bytes().await?, &CodecLimits::default())?;
    let Body::GetPoliciesResponse(found_policy) = decoded.body else {
        anyhow::bail!("not XCEP response")
    };
    ensure!(found_policy.minimum_key_length == 2048 && found_policy.validity_seconds == 90 * 86400);
    for (request, url) in [(&discovery, &discovery_url), (&policy, &found.policy_url)] {
        let mut bad = request.clone();
        bad.header.to = Some("https://outside.invalid/EnrollmentServer/Policy.svc".into());
        for (message, host) in [(&bad, None), (request, Some("outside.invalid"))] {
            let mut call = client
                .post(url)
                .header("content-type", "application/soap+xml")
                .body(soap::encode(message, &CodecLimits::default())?);
            if let Some(host) = host {
                call = call.header("host", host);
            }
            let response = call.send().await?;
            ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
            let fault = soap::decode(
                &response.bytes().await?,
                Operation::Fault,
                &CodecLimits::default(),
            )?;
            ensure!(matches!(
                fault.body,
                Body::Fault(soap::FaultKind::MessageFormat)
            ));
        }
    }
    for username in [
        enrollment.to_string(),
        format!("{enrollment}@wrong.invalid"),
        format!("{}@localhost", enrollment.to_string().to_uppercase()),
    ] {
        let mut invalid = policy.clone();
        invalid
            .header
            .security
            .as_mut()
            .unwrap()
            .username
            .as_mut()
            .unwrap()
            .username = Secret(username);
        let denied = client
            .post(&found.policy_url)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&invalid, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(denied.status() == StatusCode::INTERNAL_SERVER_ERROR);
        let fault = soap::decode(
            &denied.bytes().await?,
            Operation::Fault,
            &CodecLimits::default(),
        )?;
        ensure!(matches!(
            fault.body,
            Body::Fault(soap::FaultKind::Authentication)
        ));
    }
    policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap()
        .password = Secret(crate::enrollment::random());
    let denied = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(denied.status() == StatusCode::INTERNAL_SERVER_ERROR);
    let fault = soap::decode(
        &denied.bytes().await?,
        Operation::Fault,
        &CodecLimits::default(),
    )?;
    ensure!(matches!(
        fault.body,
        Body::Fault(soap::FaultKind::Authentication)
    ));
    let mut pg =
        PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    for (request, action) in [
        (discovery_audit, "windows_discovery"),
        (policy_audit, "windows_policy"),
    ] {
        let count = crate::audit_test_support::read(&mut pg)
            .await?
            .iter()
            .filter(|r| {
                r.request() == Some(request.as_str())
                    && r.action() == action
                    && r.result() == "success"
            })
            .count();
        ensure!(count == 1);
    }
    pg.close().await?;
    Ok(())
}
async fn rejected_csrs(
    client: &reqwest::Client,
    path: &str,
    issue: &soap::Message,
) -> anyhow::Result<()> {
    let Body::Issue(original) = &issue.body else {
        anyhow::bail!("expected Issue")
    };
    let mut trailing = original.request.bytes().to_vec();
    trailing.push(0);
    let mut bad_proof = original.request.bytes().to_vec();
    *bad_proof.last_mut().unwrap() ^= 1;
    for csr in [trailing, bad_proof] {
        let mut request = issue.clone();
        let Body::Issue(body) = &mut request.body else {
            unreachable!()
        };
        body.request = soap::CertificateRequest::Pkcs10(Secret(csr));
        let response = client
            .post(path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&request, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
        let fault = soap::decode(
            &response.bytes().await?,
            Operation::Fault,
            &CodecLimits::default(),
        )?;
        ensure!(matches!(
            fault.body,
            Body::Fault(soap::FaultKind::CertificateRequest)
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=windows.enrollment: ordinary user self enrollment over real Windows TLS"]
async fn self_enrollment_preserves_server_identity_and_terminal_protocol_id() -> anyhow::Result<()>
{
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.self_peer().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let _server = crate::test_support::software::HttpServer::start(listener, host.browser.clone());
    let secret = crate::test_support::identity::credential(&host.app.identity, "other")?;
    let mut browser = crate::test_support::Browser {
        network: Some((
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(12))
                .build()?,
            origin,
        )),
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            secret.expose().into(),
        )]),
        csrf: Some(secret.csrf()),
        ..Default::default()
    };
    let path = format!("/api/v1/enrollments/{}", peer.receipt.enrollment_id);
    let (status, options) = browser
        .call(
            &host.browser,
            axum::http::Method::GET,
            "/api/v1/self-enrollments",
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK && options["channels"].as_array().unwrap().len() == 1);
    ensure!(options["channels"][0]["source"] == "mdm.windows");
    let (status, before) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(status == StatusCode::OK && before["progress"]["certificateIssued"] == true);
    ensure!(
        before["progress"]["managementReady"] == false
            && before["progress"]["diagnostic"] == "awaiting_first_check_in"
    );
    ensure!(
        before["instructions"]["username"]
            == host
                .app
                .windows()?
                .channel
                .enrollment_username(peer.receipt.enrollment_id)?
    );
    ensure!(before["progress"]["systemConfirmation"] == "unknown");
    use rss_mdm_windows_mdm::syncml;
    ensure!(
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(syncml::encode(&peer.message, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    let (_, challenged) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(
        challenged["progress"]["managementReady"] == false
            && challenged["progress"]["firstAuthenticatedCheckIn"] == false
    );
    authenticate_self_peer(&peer).await?;
    let (status, ready) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(
        status == StatusCode::OK && ready["progress"]["managementReady"] == true,
        "{ready}"
    );
    let mut tx = host.store.begin(case_tenant()).await?;
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).execute(&mut *tx).await?;
    tx.commit().await?;
    let (_, disabled) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(
        disabled["progress"]["managementReady"] == false
            && disabled["progress"]["diagnostic"] == "channel_unavailable"
    );
    let mut tx = host.store.begin(case_tenant()).await?;
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=true WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).execute(&mut *tx).await?;
    tx.commit().await?;
    // Expire the fixture through the test administrator, then use the actual owner pruner.
    let mut pg =
        PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    ensure!(sqlx::query("UPDATE mdm_access.management_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).execute(&mut pg).await?.rows_affected() == 1);
    ensure!(
        rss_mdm_windows_channel::retention::prune_management(
            &host.store.windows_store(),
            host.app.audit_store.as_ref(),
            case_tenant()
        )
        .await?
            == 1
    );
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    let messages: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(peer.intent.registration).fetch_one(&mut pg).await?;
    ensure!(sessions == 0 && messages == 0);
    let (_, retained) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(
        retained["progress"]["managementReady"] == true
            && retained["progress"]["firstAuthenticatedCheckIn"] == true
    );
    let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let quotas = rss_mdm_registration_service::quotas::Quotas::new(
        host.store.registration(),
        host.app.audit_store.clone(),
    );
    let usage = quotas.usage(&proof, None).await?;
    let usage = usage
        .channels
        .iter()
        .find(|c| c.channel == rss_mdm_registration_service::quotas::Channel::WindowsMdm)
        .unwrap();
    ensure!(usage.active == 1 && usage.reserved == 0 && usage.used == 1);
    let mut tx = host.store.begin(case_tenant()).await?;
    let device:String=sqlx::query_scalar("SELECT g.device FROM mdm_access.requests q JOIN mdm_access.grants g ON(q.tenant_id,q.grant_id)=(g.tenant_id,g.id) WHERE q.tenant_id=$1::uuid AND q.id=$2 AND q.self_service").bind(case_tenant()).bind(peer.receipt.enrollment_id).fetch_one(&mut *tx).await?;
    ensure!(device.starts_with("self:") && device != crate::test_support::case::name("tls-device"));
    tx.rollback().await?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        crate::test_support::identity::device_grants(Some(&device), &["credentials"])?,
    )
    .await?;
    let admin = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    host.app
        .devices
        .revoke(&admin, &device, peer.intent.registration, Uuid::new_v4())
        .await?;
    let (_, revoked) = browser
        .call(&host.browser, axum::http::Method::GET, &path, None)
        .await?;
    ensure!(
        revoked["progress"]["managementReady"] == false
            && revoked["progress"]["diagnostic"] == "revoked"
    );
    host.close().await
}

async fn authenticate_self_peer(peer: &Peer) -> anyhow::Result<()> {
    ensure!(
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(rss_mdm_windows_mdm::syncml::encode(
                &peer.ack,
                &CodecLimits::default()
            )?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    Ok(())
}
