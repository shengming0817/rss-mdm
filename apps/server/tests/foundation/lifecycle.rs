//! Real host composition and owned resource shutdown, with no enrollment journey.
use super::support::*;
use anyhow::{Result, bail};
use rss_request_context::TenantId;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

async fn ready(client: &reqwest::Client, url: &str) -> Result<Value> {
    loop {
        if let Ok(response) = client
            .get(url)
            .header("host", "mdm.example.test")
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
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    seed_tenant(&operator, tenant).await?;
    let management = crate::identity::management_tenant(
        &inputs.database("lifecycle", "mdm_identity_runtime"),
        rss_identity_core::InstanceId::parse(&inputs.installation.instance_id)?,
    )
    .await?;
    assert_ne!(tenant, management);
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(management.to_string())
    .execute(&operator)
    .await?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let mut configuration: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    configuration["listen"] = json!(address.to_string());
    configuration["identity"]["tenant_id"] = json!(tenant.to_string());
    configuration["identity"]["database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_identity_runtime"))?;
    configuration["access_database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_access"))?;
    configuration["runtime_database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_runtime"))?;
    configuration["execution"]["database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_command_runtime"))?;
    configuration["scope_group_database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_scope_group_consumer"))?;
    configuration["webhooks"]["recovery_database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_webhook_operator"))?;
    configuration["publication"]["database"] =
        serde_json::to_value(inputs.database("lifecycle", "mdm_software_driver"))?;
    for (owner, role) in [
        ("inventory", "mdm_inventory_runtime"),
        ("scope", "mdm_scope_runtime"),
        ("policy", "mdm_policy_runtime"),
        ("resource", "mdm_resource_runtime"),
        ("software", "mdm_software_runtime"),
        ("content", "mdm_content_runtime"),
        ("telemetry", "mdm_telemetry_runtime"),
        ("scheduler", "mdm_scheduler_runtime"),
    ] {
        configuration["business_databases"][owner] =
            serde_json::to_value(inputs.database("lifecycle", role))?;
    }
    configuration["native_protocols"] = json!({});
    configuration["device_pki"] = json!([]);
    configuration["native_protection"] = json!({"active_file":inputs.directory.join("native.key"),
        "historical_files":[], "fingerprint_file":inputs.directory.join("fingerprint.key")});
    let host = Uuid::new_v4();
    configuration["runtime_binding"]["host_id"] = json!(host);
    let config = serde_json::from_value(configuration)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    drop(reservation);
    let server = crate::serve(
        config,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop sender closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    );
    tokio::pin!(server);
    let readiness_url = format!("http://{address}/readyz");
    let observation = tokio::select! {
        result = &mut server => bail!("host exited before readiness: {result:?}"),
        response = tokio::time::timeout(Duration::from_secs(90), ready(&client, &readiness_url)) => response??,
    };
    assert_eq!(observation["ready"], true);
    assert_eq!(observation["observation"]["hostId"], host.to_string());
    assert_eq!(observation["observation"]["tenantId"], tenant.to_string());
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
