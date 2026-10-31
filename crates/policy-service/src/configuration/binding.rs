use super::*;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore};
use std::time::Duration;
impl Transactions {
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        channels: Arc<dyn channels::Channels>,
        changes: Arc<dyn crate::inputs::ExecutionChanges>,
    ) -> std::result::Result<Self, Error> {
        let caller = runtime.clone();
        let audit = audit_store.clone();
        let fingerprint_id = protection.fingerprint_id().to_owned();
        let (outbox, store) = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    rss_mdm_native_protection::binding::bind_in(tx, &fingerprint_id).await?;
                    let admitted = tx
                        .with_connection(|c| {
                            Box::pin(async move {
                                super::verify_authority(c).await?;
                                let policy: bool =
                                    sqlx::query_scalar("SELECT current_user='mdm_policy_runtime'")
                                        .fetch_one(&mut *c)
                                        .await?;
                                if policy {
                                    super::source_changes::verify_storage(c).await?;
                                }
                                sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                                    .fetch_one(c)
                                    .await
                            })
                        })
                        .await?;
                    if !admitted {
                        return Err(sqlx::Error::Protocol(
                            "configuration participant admission".into(),
                        )
                        .into());
                    }
                    let budget = rss_transactional_messaging::policy::DeliveryBudget::new(
                        Duration::from_secs(60),
                        Duration::from_secs(6),
                        Duration::from_secs(6),
                        Duration::from_secs(6),
                    )
                    .map_err(|_| sqlx::Error::Protocol("configuration delivery budget".into()))?;
                    let outbox = Arc::new(PgOutboxStore::new(caller, messaging_domain(), budget)?);
                    let roles = rss_device_command_postgres::CallerRoles::new(&[
                        "mdm_command_runtime",
                        "mdm_policy_runtime",
                    ])
                    .map_err(|_| sqlx::Error::Protocol("configuration caller profile".into()))?;
                    let store = rss_device_command_postgres::PgStore::new(
                        tx,
                        outbox.clone(),
                        rss_device_command_postgres::CommandClock::Postgres,
                        &roles,
                    )
                    .await?;
                    Ok((outbox, store))
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::PolicyAdmission)),
                |_| Err(Error::Unavailable(Failure::PolicyAdmission)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::PolicyAdmission)),
            )?;
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::PolicyAdmission))?;
        Ok(Self {
            outbox,
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime,
            tenant,
            audit_store,
            source,
            protection,
            content,
            channels,
            changes,
            store,
            reconcile_messaging,
        })
    }
}
