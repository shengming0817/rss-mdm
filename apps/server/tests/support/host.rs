//! Shared real App configuration for lifecycle and HTTP consumer proofs.
use crate::authority_t2_support::Inputs;
use anyhow::Result;
use serde_json::{Value, json};
use uuid::Uuid;
pub(crate) async fn configuration(
    inputs: &Inputs,
    profile: &str,
    address: std::net::SocketAddr,
    host: Uuid,
) -> Result<Value> {
    let mut configuration: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    configuration["listen"] = json!(address.to_string());
    let management = crate::identity::management_tenant(
        &inputs.database(profile, "mdm_identity_runtime"),
        rss_identity_core::InstanceId::parse(&inputs.installation.instance_id)?,
    )
    .await?;
    configuration["identity"]["management_tenant"] = json!(management.to_string());
    configuration["identity"]["database"] =
        serde_json::to_value(inputs.database(profile, "mdm_identity_runtime"))?;
    configuration["access_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_access"))?;
    configuration["device_access"]["database"] =
        serde_json::to_value(inputs.database(profile, "da_access"))?;
    configuration["runtime_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_runtime"))?;
    configuration["command_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_command_runtime"))?;
    configuration["scope_group_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_scope_group_consumer"))?;
    configuration["command_projection_password_files"] = serde_json::to_value(
        crate::assembly::task_relay::lanes::LANES
            .iter()
            .map(|lane| (lane.role, inputs.database(profile, lane.role).password_file))
            .collect::<std::collections::BTreeMap<_, _>>(),
    )?;
    configuration["asset_input_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_asset_ingress_consumer"))?;
    configuration["webhooks"]["recovery_database"] =
        serde_json::to_value(inputs.database(profile, "mdm_webhook_operator"))?;
    configuration["publication"]["database"] =
        serde_json::to_value(inputs.database(profile, "mdm_software_driver"))?;
    for (owner, role) in [
        ("inventory", "mdm_inventory_runtime"),
        ("scope", "mdm_scope_runtime"),
        ("policy", "mdm_policy_runtime"),
        ("resource", "mdm_resource_runtime"),
        ("software", "mdm_software_runtime"),
        ("content", "mdm_content_runtime"),
        ("telemetry", "mdm_telemetry_runtime"),
        ("scheduler", "mdm_scheduler_runtime"),
        ("wns", "mdm_wns_runtime"),
    ] {
        configuration["business_databases"][owner] =
            serde_json::to_value(inputs.database(profile, role))?;
    }
    configuration["native_protocols"] = json!({});
    configuration["device_pki"] = json!([]);
    configuration["native_protection"] = json!({"active_file":inputs.directory.join("native.key"),
        "historical_files":[], "fingerprint_file":inputs.directory.join("fingerprint.key")});
    configuration["storage_binding"] = json!({"target":inputs.installation.target,"lineage":inputs.installation.lineage,"epoch":1});
    configuration["runtime_binding"]["host_id"] = json!(host);
    configuration["identity"]["instance_id"] = json!(inputs.installation.instance_id);
    Ok(configuration)
}

/// Exercise the final production App over TCP, and drain it even when the proof fails.
#[allow(
    clippy::disallowed_methods,
    reason = "host proof supplies the production monotonic clock"
)]
pub(crate) async fn run<F, Fut>(configuration: Value, proof: F) -> Result<()>
where
    F: FnOnce(reqwest::Client, String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    run_with_drain(configuration, proof, || async { Ok(()) }).await
}

#[allow(clippy::disallowed_methods, reason = "production host clock")]
pub(crate) async fn run_with_drain<F, Fut, D, Drain>(
    configuration: Value,
    proof: F,
    drain: D,
) -> Result<()>
where
    F: FnOnce(reqwest::Client, String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
    D: FnOnce() -> Drain,
    Drain: std::future::Future<Output = Result<()>>,
{
    use std::{sync::Arc, time::Duration};
    let address = configuration["listen"].as_str().unwrap().to_owned();
    let config = serde_json::from_value(configuration)?;
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("host", "mdm.example.test"),
        ("x-rss-public-origin", "https://mdm.example.test"),
        ("x-forwarded-for", "127.0.0.1"),
    ] {
        headers.insert(name, value.parse()?);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()?;
    let base = format!("http://{address}");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(crate::serve(
        config,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop sender closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    ));
    let exercise = async {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(response) = client.get(format!("{base}/readyz")).send().await
                    && response.status().is_success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?;
        Box::pin(proof(client, base)).await
    };
    let result = tokio::select! {
        result = &mut server => anyhow::bail!("host exited during HTTP proof: {result:?}"),
        result = exercise => result,
    };
    stop.send(())
        .map_err(|_| anyhow::anyhow!("host lost stop receiver"))?;
    let drain_result = drain().await;
    tokio::time::timeout(Duration::from_secs(70), &mut server).await???;
    drain_result?;
    result
}

pub(crate) async fn reject(response: reqwest::Response, status: u16, code: &str) -> Result<Value> {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    Uuid::parse_str(response.headers()["x-request-id"].to_str()?)?;
    let body: Value = response.json().await?;
    assert_eq!(body, json!({"code":code}));
    Ok(body)
}
