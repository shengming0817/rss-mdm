//! Real host command-runtime composition reused by channel consumer proofs.
use super::authority_t2_support::Context;
use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
pub async fn open(c: &Context, signing: bool) -> Result<crate::assembly::execution::Assembly> {
    open_with(c, signing, |_| {}).await
}
pub async fn open_with(
    c: &Context,
    signing: bool,
    configure: fn(&mut serde_json::Value),
) -> Result<crate::assembly::execution::Assembly> {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    config["identity"]["tenant_id"] = json!(c.tenant.to_string());
    config["identity"]["instance_id"] = json!(c.inputs.installation.instance_id);
    config["identity"]["database"] =
        serde_json::to_value(c.inputs.database("shared", "mdm_identity_runtime"))?;
    config["access_database"] = serde_json::to_value(c.inputs.database("shared", "mdm_access"))?;
    config["execution"]["database"] =
        serde_json::to_value(c.inputs.database("shared", "mdm_command_runtime"))?;
    config["storage_binding"] = json!({"target":c.inputs.installation.target,"lineage":c.inputs.installation.lineage,"epoch":1});
    config["native_protocols"] = json!({});
    config["device_pki"] = json!([]);
    config["agent_pki"] = json!({"mode":"disabled"});
    config["task_signing"] = if signing {
        json!({"revision":1})
    } else {
        serde_json::Value::Null
    };
    config["content"] = serde_json::Value::Null;
    config["recovery_credentials"] = serde_json::Value::Null;
    configure(&mut config);
    let config = serde_json::from_value(config)?;
    let protection = super::device_material_support::protection(c)?;
    Ok(crate::assembly::execution::open(
        &config,
        protection,
        c.audit.clone(),
        None,
        Default::default(),
        rss_device_command_postgres::CommandClock::Postgres,
        Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                c.authority.clone(),
                c.tenant,
            ),
        ),
        vec![7; 32],
    )
    .await?)
}
pub async fn close(a: crate::assembly::execution::Assembly) -> Result<()> {
    use rss_runtime::ManagedResource;
    rss_mdm_device_service::control::Resource(a.service.clone())
        .shutdown()
        .await?;
    drop(a);
    Ok(())
}

/// Triggers and security-definer functions require the same tenant coordinate as production.
pub async fn seed_transaction(c: &Context) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
