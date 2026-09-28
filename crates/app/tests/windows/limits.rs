use crate::windows::test_support::*;
use crate::windows::*;
use crate::{api::Assembly, device::test_support::options};
use anyhow::ensure;
use sqlx::{Connection, PgConnection};
#[tokio::test]
#[ignore = "make t2 MODULE=windows.limits"]
async fn accepted_peer_rate_limit_and_refill() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    ingress_burst(&host.client, &host.app, &host.ingress_clock).await?;
    host.close().await?;
    Ok(())
}
async fn ingress_burst(
    client: &reqwest::Client,
    app: &Assembly,
    clock: &IngressClock,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/EnrollmentServer/Discovery.svc",
        app.windows()?.config.enrollment.origin
    );
    let mut request = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    request.header.to = Some(url.clone());
    let bytes = soap::encode(&request, &CodecLimits::default())?;
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let before = crate::audit_test_support::read(&mut pg)
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
            .post(&url)
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
        refused >= 64 && accepted <= 64,
        "forwarded headers bypassed peer admission"
    );
    let after = crate::audit_test_support::read(&mut pg)
        .await?
        .iter()
        .filter(|r| r.action() == "windows_discovery")
        .count();
    ensure!(
        after - before == usize::try_from(accepted)?,
        "capacity denials amplified persistent audit"
    );
    clock.advance();
    ensure!(
        client
            .post(&url)
            .header("content-type", "application/soap+xml")
            .body(bytes)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    pg.close().await?;
    Ok(())
}
