//! Real host composition and owned resource shutdown, with no enrollment journey.
use crate::authority_t2_support::*;
use anyhow::{Result, bail};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

async fn ready(client: &reqwest::Client, url: &str) -> Result<Value> {
    loop {
        if let Ok(response) = client
            .get(url)
            .header("host", "mdm.example.test")
            .header("x-rss-public-origin", "https://mdm.example.test")
            .header("x-forwarded-for", "127.0.0.1")
            .send()
            .await
            && response.status() == reqwest::StatusCode::OK
        {
            return Ok(response.json().await?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "T2: real App, PostgreSQL connections and TCP listener lifecycle"]
#[allow(
    clippy::disallowed_methods,
    reason = "test composition supplies the production monotonic clock"
)]
async fn host_reports_its_binding_then_releases_listener_and_database_resources() -> Result<()> {
    let inputs = Inputs::load()?;
    let operator = inputs.pool("lifecycle", "postgres").await?;
    let management = crate::identity::management_tenant(
        &inputs.database("lifecycle", "mdm_identity_runtime"),
        rss_identity_core::InstanceId::parse(&inputs.installation.instance_id)?,
    )
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(management.to_string())
    .execute(&operator)
    .await?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let host = Uuid::new_v4();
    let configuration =
        crate::host_t2_support::configuration(&inputs, "lifecycle", address, host).await?;
    let config = serde_json::from_value(configuration)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    drop(reservation);
    let mut server = Box::pin(crate::serve(
        config,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop sender closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    ));
    let readiness_url = format!("http://{address}/readyz");
    let observation = tokio::select! {
        result = &mut server => bail!("host exited before readiness: {result:?}"),
        response = tokio::time::timeout(Duration::from_secs(90), ready(&client, &readiness_url)) => response??,
    };
    assert_eq!(observation["ready"], true);
    assert_eq!(observation["observation"]["hostId"], host.to_string());
    assert_eq!(
        observation["observation"]["instanceId"],
        inputs.installation.instance_id
    );
    let count = || {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename<>'postgres' AND backend_type='client backend'").fetch_one(&operator)
    };
    assert!(
        count().await? > 0,
        "startup must actually open owned database resources"
    );
    stop.send(())
        .map_err(|_| anyhow::anyhow!("host lost its stop receiver"))?;
    tokio::time::timeout(Duration::from_secs(70), &mut server).await??;
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "listener remains open after shutdown"
    );
    assert_eq!(
        count().await?,
        0,
        "owned database sessions leaked after successful shutdown"
    );
    operator.close().await;
    Ok(())
}

#[path = "lifecycle_installation.rs"]
mod installation;

pub(super) use installation::shared_telemetry;
