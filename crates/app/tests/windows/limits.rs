use crate::windows::test_support::*;
use anyhow::ensure;
use axum::http::StatusCode;
use rss_mdm_windows_mdm::{
    CodecLimits,
    soap::{self, Operation},
};
use std::{sync::Arc, time::Duration};
#[tokio::test]
#[ignore = "make t2 MODULE=windows.limits"]
async fn accepted_peer_rate_limit_and_refill() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let url = format!("{origin}/EnrollmentServer/Discovery.svc");
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let clock = IngressClock::new();
    let requests = Arc::new(tokio::sync::Semaphore::new(32));
    let router = rss_mdm_windows_channel::boundary::wrap(
        rss_mdm_windows_channel::discovery_routes(
            origin.clone(),
            Some(soap::DiscoverResponse {
                auth_policy: soap::AuthPolicy::OnPremise,
                enrollment_version: "4.0".into(),
                policy_url: format!("{origin}/EnrollmentServer/Policy.svc"),
                enrollment_url: format!("{origin}/EnrollmentServer/Enrollment.svc"),
            }),
        ),
        rss_mdm_windows_channel::boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: origin.strip_prefix("https://").unwrap().into(),
            clock: clock.clone(),
            audit_store: audit,
            requests: requests.clone(),
            tenant: case_tenant().into(),
        },
    );
    let channel = crate::native::ChannelRouter {
        origins: vec![origin],
        router: router
            .layer(axum::middleware::from_fn(crate::native::admission::admit))
            .into_checked_axum(rss_mdm_http_contract::catalog::WINDOWS_LISTENER),
        admission: crate::native::admission::Admission::new(
            clock.clone(),
            requests,
            "windows-enrollment",
        ),
    };
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::test_support::runtime::PoolResource(pool),
    ));
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::test_support::runtime::SourceResource(source),
    ));
    let registration = crate::test_support::gateway::registration(
        listener,
        channel,
        crate::native::ChannelKind::WindowsEnrollment,
    )
    .await?;
    let mut launch = startup.commit();
    launch.stage_task_with_token(registration.critical());
    launch.finish();
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root()?.join("ca.crt"),
        )?)?)
        .build()?;
    let result = ingress_burst(&client, &url, &clock).await;
    let receipt = owner.shutdown().join().await?;
    ensure!(
        receipt.is_clean(),
        "discovery fixture shutdown: {receipt:?}"
    );
    result
}
async fn ingress_burst(
    client: &reqwest::Client,
    url: &str,
    clock: &IngressClock,
) -> anyhow::Result<()> {
    let mut request = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    request.header.to = Some(url.to_owned());
    let bytes = soap::encode(&request, &CodecLimits::default())?;
    let before = crate::audit_test_support::audit_records()
        .await?
        .iter()
        .filter(|r| r.action() == "windows_discovery")
        .count();
    // Freeze refill time only for the deterministic burst assertions.
    clock.advance();
    let mut accepted = 0i64;
    let mut refused = 0;
    for index in 0..128 {
        let response = client
            .post(url)
            .header("content-type", "application/soap+xml")
            .header("x-forwarded-for", format!("198.51.100.{}", index + 1))
            .body(bytes.clone())
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => {
                accepted += 1;
                let _ = response.bytes().await?;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                refused += 1;
                ensure!(response.headers()["cache-control"] == "no-store");
                ensure!(response.json::<serde_json::Value>().await?["code"] == "request_limited");
            }
            code => anyhow::bail!("unexpected burst response: {code}"),
        }
    }
    ensure!(
        refused == 64 && accepted == 64,
        "forwarded headers bypassed peer admission"
    );
    let after = crate::audit_test_support::audit_records()
        .await?
        .iter()
        .filter(|r| r.action() == "windows_discovery")
        .count();
    ensure!(
        after == before,
        "capacity denials amplified persistent audit"
    );
    clock.advance();
    ensure!(
        client
            .post(url)
            .header("content-type", "application/soap+xml")
            .body(bytes)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    Ok(())
}
