//! Shared host resources and signing materials; tests compose their concrete owners locally.
use super::authority_t2_support::Context;
use crate::assembly::host_storage::Storage;
use anyhow::Result;
use serde_json::json;
use std::{sync::Arc, time::Duration};
pub struct Prepared {
    pub(crate) background: crate::background::Compiled,
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
    pub async fn open(c: &Context, configure: fn(&mut serde_json::Value)) -> Result<Self> {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
        let management: uuid::Uuid =
            sqlx::query_scalar("SELECT management_tenant_id FROM public.mdm_installation")
                .fetch_one(&c.operator)
                .await?;
        config["identity"]["management_tenant"] = json!(management);
        config["identity"]["instance_id"] = json!(c.inputs.installation.instance_id);
        config["identity"]["database"] =
            serde_json::to_value(c.inputs.database(&c.profile, "mdm_identity_runtime"))?;
        config["access_database"] =
            serde_json::to_value(c.inputs.database(&c.profile, "mdm_access"))?;
        config["device_access"]["database"] =
            serde_json::to_value(c.inputs.database(&c.profile, "da_access"))?;
        config["command_database"] =
            serde_json::to_value(c.inputs.database(&c.profile, "mdm_command_runtime"))?;
        config["storage_binding"] = json!({"target":c.inputs.installation.target,"lineage":c.inputs.installation.lineage,"epoch":1});
        config["native_protocols"] = json!({});
        config["device_pki"] = json!([]);
        config["agent_pki"] = json!({"mode":"disabled"});
        config["content"] = serde_json::Value::Null;
        config["recovery_credentials"] = serde_json::Value::Null;
        configure(&mut config);

        let config: crate::config::Config = serde_json::from_value(config)?;
        let background = config.background.compile(&config)?;
        let protection = super::device_material_support::protection(c)?;
        let channels = Arc::new(crate::channel_status::Channels::new(
            &config,
            protection.clone(),
        ));
        let (signing, _) =
            crate::assembly::task_trust::signing(protection.clone(), c.audit.clone())?;
        let mut lifecycle = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = lifecycle.startup()?;
        let storage = Storage::open(
            &config,
            c.database.archive_pool(),
            &background,
            c.audit.clone(),
            &protection,
            |resource| startup.stage_resource(resource),
        )
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
            background,
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
                rss_mdm_authorization_service::session::SessionAuthority::new(c.authority.clone()),
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
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.execution_epoch',$2,true),set_config('rss.storage_target',$3,true),set_config('rss.storage_lineage',$4,true)")
        .bind(c.tenant.to_string()).bind(c.execution().epoch().get().to_string()).bind(c.execution().storage().target().iter().map(|b|format!("{b:02x}")).collect::<String>()).bind(c.execution().storage().lineage().iter().map(|b|format!("{b:02x}")).collect::<String>())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

pub(crate) async fn recovery_fact(
    c: &Context,
    id: uuid::Uuid,
    version: i64,
) -> Result<Option<serde_json::Value>> {
    use sha2::{Digest, Sha256};
    let event_id = format!(
        "e-{:x}",
        Sha256::digest(format!("command:{id}:recover:{version}"))
    );
    let bytes: Option<Vec<u8>> = sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business' AND event_id=$2")
        .bind(c.tenant.to_string()).bind(event_id).fetch_optional(&c.operator).await?;
    bytes
        .map(|bytes| {
            let event = rss_audit_core::decode_untrusted(&bytes)?;
            Ok(serde_json::from_slice(
                event.event().context().payload().as_bytes(),
            )?)
        })
        .transpose()
}

/// The first append fails after inserting the fact. The second reaches the commit boundary.
/// PostgreSQL sequence values survive both rollbacks and identify the exact attempted fact.
pub(crate) async fn check_uncommitted_command(
    c: &Context,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    event_key: &str,
    exercise: impl AsyncFn(rss_mdm_audit_integration::WriteOutcome) -> Result<()>,
) -> Result<()> {
    use rss_mdm_audit_integration::WriteOutcome;
    use rss_transactional_messaging_postgres::PgTransactionFault;
    use sha2::{Digest, Sha256};
    let event = format!("e-{:x}", Sha256::digest(event_key.as_bytes()));
    let probe = format!("t2_command_{}", uuid::Uuid::new_v4().simple());
    let install = format!(
        "CREATE SEQUENCE public.{probe};
         GRANT USAGE ON SEQUENCE public.{probe} TO mdm_audit_owner;
         CREATE FUNCTION public.{probe}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             IF nextval('public.{probe}') = 1 THEN RAISE EXCEPTION 'test audit failure'; END IF;
             RETURN NEW;
         END; $$;
         CREATE TRIGGER {probe} AFTER INSERT ON rss_audit.records FOR EACH ROW
         WHEN (NEW.tenant_id='{}'::uuid AND NEW.source_id='mdm.business' AND NEW.event_id='{event}')
         EXECUTE FUNCTION public.{probe}()",
        c.tenant
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(install))
        .execute(&c.operator)
        .await?;
    let checked = async {
        for (attempt, fault, outcome) in [
            (
                1,
                PgTransactionFault::RollbackFailedAfterAck,
                WriteOutcome::RollbackFailed,
            ),
            (2, PgTransactionFault::CommitPending, WriteOutcome::Unknown),
        ] {
            runtime.inject_next_transaction_fault(fault);
            exercise(outcome).await?;
            let witnessed: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM public.{probe}"
            )))
            .fetch_one(&c.operator)
            .await?;
            anyhow::ensure!(
                witnessed == attempt,
                "expected {attempt} audit appends, found {witnessed}"
            );
        }
        Ok(())
    }
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {probe} ON rss_audit.records; DROP FUNCTION public.{probe}(); DROP SEQUENCE public.{probe}"
    ))).execute(&c.operator).await?;
    checked
}
