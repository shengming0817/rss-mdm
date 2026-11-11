//! Shared real App configuration for lifecycle and HTTP consumer proofs.
use crate::authority_t2_support::Inputs;
use anyhow::Result;
use rss_request_context::TenantId;
use serde_json::{Value, json};
use uuid::Uuid;
pub(crate) fn configuration(
    inputs: &Inputs,
    profile: &str,
    tenant: TenantId,
    address: std::net::SocketAddr,
    host: Uuid,
) -> Result<Value> {
    let mut configuration: Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    configuration["listen"] = json!(address.to_string());
    configuration["identity"]["tenant_id"] = json!(tenant.to_string());
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
