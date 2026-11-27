use super::*;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore};
use std::time::Duration;
pub struct Dependencies {
    pub supersede_batch: rss_device_command::BatchLimit,
    pub recovery_batch: rss_device_command::BatchLimit,
    pub runtime: Arc<PgRuntime>,
    pub probe: rss_transactional_messaging::fence::ExecutionBinding,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub channels: Arc<dyn channels::Channels>,
    pub changes: Arc<dyn crate::inputs::ConfigurationDependents>,
}
impl Transactions {
    pub async fn bind(dependencies: Dependencies) -> std::result::Result<Self, Error> {
        let Dependencies {
            supersede_batch,
            recovery_batch,
            runtime,
            probe,
            audit_store,
            source,
            protection,
            content,
            channels,
            changes,
        } = dependencies;

        if source.profile() != rss_mdm_install_support::StorageProfile::Mdm
            || source.objects.is_none()
        {
            return Err(Error::Unsupported);
        }
        let caller = runtime.clone();
        let audit = audit_store.clone();
        let access = channels.clone();
        let fingerprint_id = protection.fingerprint_id().to_owned();
        let store = runtime
            .local_tx(probe, deadline(), move |tx| {
                Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    rss_mdm_native_protection::binding::bind_in(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        tx,
                        &fingerprint_id,
                    )
                    .await?;
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
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            access.verify_access(c).await.map_err(|_| {
                                sqlx::Error::Protocol(
                                    "configuration channel access rejected".into(),
                                )
                            })
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
                        outbox,
                        rss_device_command_postgres::CommandClock::Postgres,
                        &roles,
                        supersede_batch,
                    )
                    .await?;
                    Ok(store)
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
        let reconcile_messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            probe,
            deadline(),
        ))
        .await
        .map_err(|_| Error::Unavailable(Failure::PolicyAdmission))?;
        Ok(Self {
            recovery_batch,
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                rss_mdm_install_support::StorageProfile::Mdm,
                runtime.clone(),
            ),
            runtime,

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
