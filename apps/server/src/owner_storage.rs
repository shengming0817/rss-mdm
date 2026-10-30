//! Host-owned connection resources. Business capabilities perform their own admission.
use crate::{ConfigIssue, Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{sync::Arc, time::Duration};

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageBinding {
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Databases {
    pub inventory: crate::config::Database,
    pub scope: crate::config::Database,
    pub policy: crate::config::Database,
    pub resource: crate::config::Database,
    pub software: crate::config::Database,
    pub content: crate::config::Database,
    pub telemetry: crate::config::Database,
    pub scheduler: crate::config::Database,
}
impl Databases {
    pub(crate) fn validate(&self, base: &crate::config::Database) -> Result<(), Error> {
        for (database, role) in [
            (&self.inventory, "mdm_inventory_runtime"),
            (&self.scope, "mdm_scope_runtime"),
            (&self.policy, "mdm_policy_runtime"),
            (&self.resource, "mdm_resource_runtime"),
            (&self.software, "mdm_software_runtime"),
            (&self.content, "mdm_content_runtime"),
            (&self.telemetry, "mdm_telemetry_runtime"),
            (&self.scheduler, "mdm_scheduler_runtime"),
        ] {
            if database.user != role
                || database.host != base.host
                || database.port != base.port
                || database.name != base.name
            {
                return Err(Error::Configuration(ConfigIssue::BusinessDatabase));
            }
        }
        Ok(())
    }
}
pub(crate) struct OwnerRuntime {
    pub runtime: Arc<PgRuntime>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl OwnerRuntime {
    pub(crate) async fn open(
        database: &crate::config::Database,
        binding: &StorageBinding,
        tenant: TenantId,
        connections: u32,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        name: &'static str,
        mut acquire: impl FnMut(Resource),
    ) -> Result<Self, Error> {
        let invalid = || Error::Configuration(ConfigIssue::BusinessDatabase);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(binding.target, binding.lineage).map_err(|_| invalid())?,
            vec![(tenant, Epoch::new(binding.epoch).map_err(|_| invalid())?)],
        )
        .map_err(|_| invalid())?;
        let pg = PgConfig::new(
            &database.host,
            database.port,
            &database.name,
            &database.user,
            PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
            PgPrivateCa::from_pem(
                crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec(),
            )
            .map_err(|_| invalid())?,
        )
        .with_pool_limits(0, connections);
        let runtime = Arc::new(
            PgRuntime::connect_producer(pg, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::Database))?,
        );
        acquire(Resource::new(runtime.clone(), name));
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(
            audit
                .on_runtime(runtime.clone(), tenant, &budget.control())
                .await?,
        );
        runtime
            .local_tx(tenant, crate::identity::deadline(), |tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            if !sqlx::query_scalar::<_, bool>(include_str!(
                                "../schema/installation-reader-admission.sql"
                            ))
                            .fetch_one(c)
                            .await?
                            {
                                return Err(sqlx::Error::Protocol(
                                    "installation reader admission rejected".into(),
                                ));
                            }
                            Ok(())
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::AccessAdmission)),
                |_| Err(Error::Unavailable(Failure::AccessAdmission)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::AccessAdmission)),
            )?;
        Ok(Self { runtime, audit })
    }
}
pub(crate) struct Resource {
    runtime: Arc<PgRuntime>,
    name: &'static str,
}
impl Resource {
    pub(crate) fn new(runtime: Arc<PgRuntime>, name: &'static str) -> Self {
        Self { runtime, name }
    }
}
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        self.name
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.runtime.close().await;
        Ok(())
    }
}
