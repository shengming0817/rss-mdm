use super::{
    Browser, Fixture, Method, StatusCode, case_tenant, lifecycle, oracle, protocol, scep_client,
};
use anyhow::{Result, ensure};
use serde_json::json;
use sqlx::Connection;
use std::time::Duration;
use uuid::Uuid;

pub(super) async fn issuer_state(pg: &mut sqlx::PgConnection, state: &str) -> Result<()> {
    let changed = sqlx::query("UPDATE mdm_pki.issuers SET state=$2 WHERE tenant_id=$1::uuid AND purpose='apple' AND state<>$2")
        .bind(super::case_tenant()).bind(state).execute(pg).await?.rows_affected();
    ensure!(changed == 1, "expected one fixture issuer");
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=apple.scep: stale process snapshot must not authorize new issuance"]
async fn stale_issuer_rejects_new_profiles_but_preserves_frozen_attempts() -> Result<()> {
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use serde_json::json;
    use tower::ServiceExt;
    let mut f = Fixture::start().await?;
    let (enrollment, attempt, password) = f.enrollment().await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    // A different process has withdrawn this issuer; this channel keeps its old in-memory snapshot.
    issuer_state(&mut pg, "verify_only").await?;
    let profile = |id| {
        Request::post(format!("/api/v1/enrollments/{id}/profile"))
            .header("host", "mdm.example.test")
            .header("content-type", "application/json")
            .body(Body::from(json!({"password":password}).to_string()))
            .unwrap()
    };
    let replay = f.router.clone().oneshot(profile(enrollment)).await?;
    ensure!(
        replay.status() == StatusCode::OK,
        "frozen attempt was re-authorized"
    );
    let old: Uuid = sqlx::query_scalar(
        "SELECT id FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2",
    )
    .bind(super::case_tenant())
    .bind(enrollment)
    .fetch_one(&mut pg)
    .await?;
    ensure!(old == attempt);
    f.browser.operation = Some(Uuid::new_v4());
    let created = f
        .browser
        .call(
            &f.router,
            Method::POST,
            "/api/v1/enrollments",
            Some(json!({"source":"mdm.apple","password":password,"deviceId":super::case_device()})),
        )
        .await?;
    f.browser.operation = None;
    ensure!(created.0 == StatusCode::OK, "create enrollment {created:?}");
    let next = Uuid::parse_str(created.1["enrollmentId"].as_str().unwrap())?;
    let denied = f.router.clone().oneshot(profile(next)).await?;
    ensure!(
        denied.status() == StatusCode::CONFLICT,
        "stale issuer authorized new profile"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$2",
    )
    .bind(super::case_tenant())
    .bind(next)
    .fetch_one(&mut pg)
    .await?;
    ensure!(count == 0, "stale authorization escaped rollback");
    issuer_state(&mut pg, "active").await?;
    ensure!(f.router.clone().oneshot(profile(next)).await?.status() == StatusCode::OK);
    pg.close().await?;
    f.close().await
}
pub(super) async fn unbound_leaf_and_replay(
    f: &Fixture,
    device: &scep_client::Device,
    request: &[u8],
    attempt: Uuid,
) -> Result<()> {
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let row: (String, bool) = sqlx::query_as(
        "SELECT state,fingerprint IS NULL FROM mdm_apple.scep_attempts WHERE id=$1::uuid",
    )
    .bind(attempt.to_string())
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        row == ("consumed".into(), true),
        "lost notify fabricated a certificate binding"
    );
    ensure!(
        device
            .enroll(
                &f.client()?,
                &f.app.apple()?.channel.scep_fixture()?.0,
                request
            )
            .await
            .is_err(),
        "identical SCEP request reauthorized"
    );
    pg.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Apple T2: real step-ca SCEP, PostgreSQL and native mTLS"]
async fn external_scep_issuance_and_lost_notify() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (enrollment, attempt, password) = f.enrollment().await?;
    let device = scep_client::Device::new(enrollment, attempt, &password)?;
    let apple = f.app.apple()?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    f.lose_notify
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let der = device
        .enroll(&f.client()?, &apple.channel.scep_fixture()?.0, &request)
        .await?;
    f.lose_notify
        .store(false, std::sync::atomic::Ordering::SeqCst);
    unbound_leaf_and_replay(&f, &device, &request, attempt).await?;
    let checked = apple.channel.trust_fixture().verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            der.clone(),
        )],
        f.app.clock.unix_seconds()?,
    )?;
    ensure!(checked.enrollment() == enrollment && checked.attempt() == attempt);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(40))
        .identity(device.identity(&der)?)
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            f.root.join("ca.crt"),
        )?)?)
        .build()?;
    let body = protocol::xml(protocol::dictionary([
        ("MessageType", "Authenticate".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("Topic", apple.config.apns_topic.clone().into()),
    ]))?;
    let oracle = oracle::Oracle::new(&der)?;
    let response = client
        .put(format!("{}/checkin", apple.config.management.origin))
        .body(body.clone())
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "native Authenticate {}",
        response.status()
    );
    oracle.compare("/checkin", &body, &[]).await?;
    let peer = lifecycle::Peer {
        pending_replies: Default::default(),
        installed_trust: Default::default(),
        client,
        oracle,
        origin: apple.config.management.origin.clone(),
        topic: apple.config.apns_topic.clone(),
    };
    peer.token().await?;
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.scep: ordinary user self enrollment and real native activation"]
async fn self_enrollment_uses_current_user_and_one_macos_allocation() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (client, origin, control) = f.https_browser().await?;
    f.browser.network = Some((client, origin));
    let (enrollment, attempt, password) = f.self_enrollment().await?;
    let prepared = f.self_progress(enrollment).await?;
    ensure!(
        prepared["progress"]["profilePrepared"] == "observed"
            && prepared["progress"]["managementReady"] == false
    );
    ensure!(prepared["progress"]["diagnostic"] == "awaiting_certificate");
    let device = scep_client::Device::new(enrollment, attempt, &password)?;
    let apple = f.app.apple()?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    device
        .enroll(&f.client()?, &apple.channel.scep_fixture()?.0, &request)
        .await?;
    let issued = f.self_progress(enrollment).await?;
    ensure!(
        issued["progress"]["certificateIssued"] == true
            && issued["progress"]["managementReady"] == false
    );
    ensure!(issued["progress"]["systemConfirmation"] == "unknown");
    // A signed old certificate must not advance a newly resumed, still-unbound handoff.
    let password = rss_mdm_registration_service::enrollment::random();
    let secret = crate::test_support::identity::credential(&f.app.identity, "other")?;
    let mut browser = Browser {
        network: f.browser.network.clone(),
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            secret.expose().into(),
        )]),
        csrf: Some(secret.csrf()),
        operation: Some(Uuid::new_v4()),
    };
    let (status, resumed) = browser
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/enrollments/{enrollment}/resume"),
            Some(json!({"password":password})),
        )
        .await?;
    ensure!(status == StatusCode::OK, "resume {status} {resumed}");
    let pending = f.self_progress(enrollment).await?;
    ensure!(
        pending["progress"]["profilePrepared"] == "unknown"
            && pending["progress"]["certificateIssued"] == false
            && pending["progress"]["managementReady"] == false,
        "{pending}"
    );
    let (client, origin) = f.browser.network.as_ref().unwrap();
    let profile = client
        .post(format!("{origin}/api/v1/enrollments/{enrollment}/profile"))
        .header("host", "mdm.example.test")
        .json(&json!({"password":password}))
        .send()
        .await?;
    ensure!(profile.status() == StatusCode::OK);
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let current: Uuid = sqlx::query_scalar("SELECT s.id FROM mdm_apple.scep_attempts s JOIN mdm_access.requests q ON(q.tenant_id,q.id,q.password_version)=(s.tenant_id,s.enrollment,s.authorization_version) WHERE s.tenant_id=$1::uuid AND s.enrollment=$2 AND s.state='prepared'")
        .bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    ensure!(current != attempt);
    pg.close().await?;
    let device = scep_client::Device::new(enrollment, current, &password)?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    let der = device
        .enroll(&f.client()?, &apple.channel.scep_fixture()?.0, &request)
        .await?;
    ensure!(f.self_progress(enrollment).await?["progress"]["certificateIssued"] == true);
    let peer = f.authenticate_peer(&device, &der).await?;
    let authenticated = f.self_progress(enrollment).await?;
    ensure!(
        authenticated["progress"]["firstAuthenticatedCheckIn"] == true
            && authenticated["progress"]["managementReady"] == false
    );
    ensure!(
        authenticated["progress"]["diagnostic"] == "awaiting_device_token",
        "{authenticated}"
    );
    peer.token().await?;
    let ready = f.self_progress(enrollment).await?;
    ensure!(ready["progress"]["managementReady"] == true, "{ready}");
    let proof = crate::device::test_support::admin(super::case_tenant(), "other-a").await?;
    let quotas = rss_mdm_registration_service::quotas::Quotas::new(
        f.app.access.registration(),
        f.app.audit_store.clone(),
    );
    let usage = quotas.usage(&proof, None).await?;
    let usage = usage
        .channels
        .iter()
        .find(|c| c.channel == rss_mdm_registration_service::quotas::Channel::MacosMdm)
        .unwrap();
    ensure!(usage.active == 1 && usage.reserved == 0 && usage.used == 1);
    ensure!(control.shutdown().join().await?.is_clean());
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.scep: pause after CA acceptance preserves completion and gates first activation"]
async fn pause_during_signing_preserves_result_and_managed_continuity() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (enrollment, attempt, password) = f.enrollment().await?;
    let device = scep_client::Device::new(enrollment, attempt, &password)?;
    let request = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    f.pause_before_notify
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let der = device
        .enroll(
            &f.client()?,
            &f.app.apple()?.channel.scep_fixture()?.0,
            &request,
        )
        .await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let paused: bool = sqlx::query_scalar("SELECT paused FROM mdm_access.registration_admission WHERE tenant_id=$1::uuid AND channel='macos_mdm'").bind(case_tenant()).fetch_one(&mut pg).await?;
    ensure!(paused, "notify hook must pause after CA acceptance");
    let pending = f.peer_identity(&device, &der)?;
    let rejected = pending
        .send(
            "/checkin",
            protocol::dictionary([
                ("MessageType", "Authenticate".into()),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
                ("Topic", pending.topic.clone().into()),
            ]),
        )
        .await?;
    ensure!(
        rejected.0 == StatusCode::CONFLICT,
        "first activation returned the wrong rejection: {}",
        rejected.0
    );
    let unbound: bool = sqlx::query_scalar("SELECT certificate IS NOT NULL AND fingerprint IS NOT NULL AND registration IS NULL AND state='consumed' FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(attempt).fetch_one(&mut pg).await?;
    ensure!(
        unbound,
        "paused first activation lost the signed result or bound the credential"
    );
    sqlx::query("UPDATE mdm_access.registration_admission SET paused=false,revision=2 WHERE tenant_id=$1::uuid AND channel='macos_mdm'").bind(case_tenant()).execute(&mut pg).await?;
    let peer = f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    sqlx::query("UPDATE mdm_access.registration_admission SET paused=true,revision=3 WHERE tenant_id=$1::uuid AND channel='macos_mdm'").bind(case_tenant()).execute(&mut pg).await?;
    f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    f.close().await
}
