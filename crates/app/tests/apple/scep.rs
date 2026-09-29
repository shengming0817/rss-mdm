use super::{Fixture, StatusCode, lifecycle, oracle, protocol, scep_client};
use anyhow::{Result, ensure};
use sqlx::Connection;
use std::time::Duration;
use uuid::Uuid;
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
            .enroll(&f.client()?, &f.app.apple()?.config.scep_url, request)
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
        .enroll(&f.client()?, &apple.config.scep_url, &request)
        .await?;
    f.lose_notify
        .store(false, std::sync::atomic::Ordering::SeqCst);
    unbound_leaf_and_replay(&f, &device, &request, attempt).await?;
    let checked = apple.authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            der.clone(),
        )],
        f.app.clock.unix_seconds()?,
    )?;
    ensure!(checked.enrollment == enrollment && checked.attempt == attempt);
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
        client,
        oracle,
        origin: apple.config.management.origin.clone(),
        topic: apple.config.apns_topic.clone(),
    };
    peer.token().await?;
    f.close().await
}
