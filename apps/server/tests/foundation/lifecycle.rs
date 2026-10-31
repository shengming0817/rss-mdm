//! Real host composition and owned resource shutdown, with no enrollment journey.
use crate::authority_t2_support::*;
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
    // A retained configuration-input failure must revoke the real public probe,
    // even though every managed task is still running. Use the legal persisted
    // suspended state, fencing any in-flight checkpoint attempt in the same transaction.
    let mut tx = operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let changed=sqlx::query("UPDATE rss_reconcile.targets SET token=NULL,lease_until=NULL,next_run=NULL,queue_ticket=NULL,result='suspended',epoch=epoch+1 WHERE tenant_id=$1::uuid AND reconciler='mdm.policy' AND entity='configuration-inputs'").bind(tenant.to_string()).execute(&mut *tx).await?;
    assert_eq!(changed.rows_affected(), 1);
    sqlx::query("INSERT INTO mdm_planning.configuration_source_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=configuration_source_dispatch.failure_generation+1").bind(tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let paused = tokio::select! {
        result=&mut server=>bail!("host exited during input suspension: {result:?}"),
        response=client.get(&readiness_url).header("host","mdm.example.test").header("x-rss-public-origin","https://mdm.example.test").header("x-forwarded-for","127.0.0.1").send()=>response?,
    };
    assert_eq!(paused.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(paused.json::<Value>().await?["ready"], false);
    let mut tx = operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET failure=NULL WHERE tenant_id=$1::uuid").bind(tenant.to_string()).execute(&mut *tx).await?;
    sqlx::query(
        "SELECT rss_reconcile.wake($1::uuid,'mdm.policy','configuration-inputs',ARRAY[]::text[])",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let recovered = tokio::select! {
        result=&mut server=>bail!("host exited during input recovery: {result:?}"),
        response=tokio::time::timeout(Duration::from_secs(30),ready(&client,&readiness_url))=>response??,
    };
    assert_eq!(recovered["ready"], true);
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
