//! Shared host resources and signing materials; tests compose their concrete owners locally.
use super::authority_t2_support::Context;
use crate::assembly::host_storage::Storage;
use anyhow::Result;
use serde_json::json;
use std::{sync::Arc, time::Duration};
pub struct Prepared {
    pub config: crate::config::Config,
    pub storage: Storage,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub signing: Arc<rss_mdm_task_trust::Signing>,
    pub channels: Arc<crate::channel_status::Channels>,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    lifecycle: rss_runtime::ShutdownStack,
}
impl Prepared {
    pub async fn open(
        c: &Context,
        signing: bool,
        configure: fn(&mut serde_json::Value),
    ) -> Result<Self> {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
        config["identity"]["tenant_id"] = json!(c.tenant.to_string());
        config["identity"]["instance_id"] = json!(c.inputs.installation.instance_id);
        config["identity"]["database"] =
            serde_json::to_value(c.inputs.database("shared", "mdm_identity_runtime"))?;
        config["access_database"] =
            serde_json::to_value(c.inputs.database("shared", "mdm_access"))?;
        config["device_access"]["database"] =
            serde_json::to_value(c.inputs.database("shared", "da_access"))?;
        config["command_database"] =
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

        let config: crate::config::Config = serde_json::from_value(config)?;
        let protection = super::device_material_support::protection(c)?;
        let channels = Arc::new(crate::channel_status::Channels::new(&config));
        let (signing, _) = crate::assembly::task_trust::signing(
            &config,
            c.tenant,
            protection.clone(),
            c.audit.clone(),
            &channels,
        )
        .await?;
        let mut lifecycle = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = lifecycle.startup()?;
        let storage = Storage::open(&config, c.audit.clone(), &protection, |resource| {
            startup.stage_resource(resource)
        })
        .await;
        startup.commit().finish();
        let storage = match storage {
            Ok(storage) => storage,
            Err(error) => {
                let receipt = lifecycle.shutdown().join().await?;
                anyhow::ensure!(
                    receipt.is_clean(),
                    "command resource cleanup failed after {error}"
                );
                return Err(error.into());
            }
        };
        Ok(Self {
            config,
            storage,
            protection,
            signing,
            channels,
            source: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
            )),
            sessions: Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    c.authority.clone(),
                    c.tenant,
                ),
            ),
            lifecycle,
        })
    }
    /// Failed domain composition still drains every acquired host resource.
    pub async fn finish<T>(self, result: Result<T>) -> Result<(Self, T)> {
        match result {
            Ok(value) => Ok((self, value)),
            Err(error) => {
                self.close().await?;
                Err(error)
            }
        }
    }
    pub async fn close(self) -> Result<()> {
        let receipt = self.lifecycle.shutdown().join().await?;
        anyhow::ensure!(receipt.is_clean(), "command resource cleanup failed");
        Ok(())
    }
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
