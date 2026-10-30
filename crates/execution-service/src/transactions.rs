//! Transaction resources bind to the initiating runtime; workers stay with ExecutionService.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (one connection, one settlement owner).
use crate::*;

/// Immutable configuration and channel ports shared without sharing a transaction identity.
pub struct ExecutionMaterials {
    pub recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub inputs: Arc<InputMaterials>,
    pub source: Arc<dyn source_authority::SourceAuthority>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_store: Arc<dyn channels::Agent>,
    pub apple_profiles: Arc<dyn channels::AppleProfiles>,
    pub apple_collections: Arc<dyn channels::AppleCollections>,
    pub apple_results: Arc<dyn channels::AppleResults>,
    pub signer: Option<Arc<crate::task_signing::Signer>>,
    pub instance: String,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub command_clock: rss_device_command_postgres::CommandClock,
}
pub(crate) struct ExecutionTransactions {
    pub(crate) recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub(crate) inputs: Arc<Inputs>,
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) apple_profiles: Arc<dyn channels::AppleProfiles>,
    pub(crate) apple_collections: Arc<dyn channels::AppleCollections>,
    pub(crate) apple_results: Arc<dyn channels::AppleResults>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) signer: Option<Arc<crate::task_signing::Signer>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    #[cfg(feature = "integration")]
    pub(crate) installation_authorization_floor: std::sync::atomic::AtomicI64,
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
            #[cfg(feature = "integration")]
            rss_device_command_postgres::CommandClock::Controlled(clock) => {
                rss_device_command_postgres::CommandClock::Controlled(clock.clone())
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
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            inputs: Arc::new(Inputs::bind(
                runtime.clone(),
                tenant,
                materials.inputs.clone(),
            )),
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
            apple_collections: materials.apple_collections.clone(),
            apple_results: materials.apple_results.clone(),
            signer: materials.signer.clone(),
            instance: materials.instance.clone(),
            content: materials.content.clone(),
            #[cfg(feature = "integration")]
            installation_authorization_floor: Default::default(),
        })
    }
}
