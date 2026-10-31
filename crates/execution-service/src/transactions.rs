//! Transaction resources bind to the initiating runtime; workers stay with ExecutionService.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (one connection, one settlement owner).
use crate::*;

/// Immutable configuration and channel ports shared without sharing a transaction identity.
pub struct ExecutionMaterials {
    pub capacity: Arc<dyn crate::capacity::DeviceCapacity>,
    pub task_cleanup: Arc<dyn crate::task_cleanup::TaskCleanup>,
    pub configuration_cleanup: Arc<dyn crate::configuration_cleanup::ConfigurationCleanup>,
    pub recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub inputs: Arc<InputMaterials>,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub windows_results: Arc<dyn crate::windows_results::Store>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
    pub instance: String,
    pub command_clock: rss_device_command_postgres::CommandClock,
}
pub(crate) struct ExecutionTransactions {
    pub(crate) capacity: Arc<dyn crate::capacity::DeviceCapacity>,
    pub(crate) task_cleanup: Arc<dyn crate::task_cleanup::TaskCleanup>,
    pub(crate) configuration_cleanup: Arc<dyn crate::configuration_cleanup::ConfigurationCleanup>,
    pub(crate) recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub(crate) source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub(crate) windows_results: Arc<dyn crate::windows_results::Store>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
}
impl ExecutionTransactions {
    pub(crate) async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<ExecutionMaterials>,
    ) -> std::result::Result<Self, Error> {
        let invalid = || Error::Unavailable(Failure::CommandInvariant);
        #[allow(
            unreachable_patterns,
            reason = "dependency feature unification may expose a controlled clock without this caller opting in"
        )]
        let clock = match &materials.command_clock {
            rss_device_command_postgres::CommandClock::Postgres => {
                rss_device_command_postgres::CommandClock::Postgres
            }

            _ => return Err(Error::Unavailable(Failure::CommandInvariant)),
        };
        let audit = audit_store.clone();
        let caller = runtime.clone();
        let (_, store) = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    storage::admit_policy_participant(tx).await?;
                    storage::bind_command_in(caller, tx, clock).await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(invalid()),
                |_| Err(invalid()),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(invalid()),
            )?;
        storage::bind_native_key(&runtime, tenant, materials.protection.fingerprint_id()).await?;
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| invalid())?;
        Ok(Self {
            capacity: materials.capacity.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime,
            tenant,
            audit_store,
            store,
            reconcile_messaging,
            recovery_credentials: materials.recovery_credentials.clone(),
            source: materials.source.clone(),
            protection: materials.protection.clone(),
            agent_store: materials.agent_store.clone(),
            apple_profiles: materials.apple_profiles.clone(),
            task_cleanup: materials.task_cleanup.clone(),
            configuration_cleanup: materials.configuration_cleanup.clone(),
            windows_results: materials.windows_results.clone(),
            apple_results: materials.apple_results.clone(),
            instance: materials.instance.clone(),
        })
    }
}
