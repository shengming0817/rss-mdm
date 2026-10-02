use crate::planning::Planning;
use crate::{Error, Failure};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{sync::Arc, time::Duration};

use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub storage: StorageBinding,
    pub publication: crate::publication_config::Config,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageBinding {
    pub database: crate::config::Database,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
}
pub(crate) const SOURCE_STARTUP_SECONDS: u64 = 6;
impl Config {
    pub(crate) fn startup_budget(&self) -> Duration {
        Duration::from_secs(
            45 + if self.publication.sources.is_empty() {
                0
            } else {
                5 + SOURCE_STARTUP_SECONDS * self.publication.sources.len() as u64
            },
        )
    }

    pub(crate) fn validate(
        &self,
        database: &crate::config::Database,
    ) -> std::result::Result<(), Error> {
        if self.storage.database.user != "mdm_flow_runtime"
            || self.storage.database.host != database.host
            || self.storage.database.port != database.port
            || self.storage.database.name != database.name
        {
            return Err(Error::Configuration(crate::ConfigIssue::Flow));
        }
        if self.publication.database.user != "mdm_software_driver"
            || self.publication.database.host != database.host
            || self.publication.database.port != database.port
            || self.publication.database.name != database.name
            || self.publication.sources.len() > 16
        {
            return Err(Error::Configuration(crate::ConfigIssue::Publication));
        }
        Ok(())
    }
    pub(crate) async fn open(
        &self,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        mut acquire: impl FnMut(Resource),
    ) -> std::result::Result<Arc<Flow>, Error> {
        let invalid = || Error::Configuration(crate::ConfigIssue::Flow);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.storage.target, self.storage.lineage)
                .map_err(|_| invalid())?,
            vec![(
                tenant,
                Epoch::new(self.storage.epoch).map_err(|_| invalid())?,
            )],
        )
        .map_err(|_| invalid())?;
        let database = &self.storage.database;
        let config = PgConfig::new(
            &database.host,
            database.port,
            &database.name,
            &database.user,
            PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
            PgPrivateCa::from_pem(
                crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec(),
            )
            .map_err(|_| invalid())?,
        );
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Storage,
        });
        admit_audit_runtime(&runtime, &audit_store, tenant).await?;
        storage::admit(&runtime, tenant).await?;
        let key = storage::cursor_key(&runtime, tenant).await?;
        let catalog = catalog(audit_store.clone(), runtime.clone(), tenant, clock.clone()).await?;
        let software_resources = Arc::new(
            rss_mdm_resource_postgres::ResourceStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_flow_service::transaction::deadline(),
            )
            .await
            .map_err(|_| invalid())?,
        );
        match Planning::new(
            audit_store.clone(),
            runtime.clone(),
            tenant,
            Arc::new(crate::clock::FlowClock(clock.clone())),
            &key,
        )
        .await
        {
            Ok(service) => {
                let assets = Arc::new(crate::assets::AssetService::new(
                    audit_store.clone(),
                    runtime.clone(),
                    tenant,
                    Arc::new(crate::clock::InventoryClock(clock.clone())),
                    &key,
                    Arc::new(crate::automation::inventory_tasks::InventoryTasks),
                ));
                let groups = Arc::new(rss_mdm_inventory_service::groups::Groups {
                    tenant,
                    groups: service.groups.clone(),
                    cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
                    audit_store: audit_store.clone(),
                    runtime: runtime.clone(),
                    clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
                });
                let compliance = Arc::new(rss_mdm_inventory_service::compliance::Compliance::new(
                    rss_mdm_inventory_service::compliance::Dependencies {
                        audit_store: audit_store.clone(),
                        runtime: runtime.clone(),
                        tenant,
                        clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
                        groups: service.groups.clone(),
                        tasks: Arc::new(crate::automation::inventory_tasks::InventoryTasks),
                        cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
                    },
                ));
                let mut service = Flow { groups, compliance,
                    cursor_key: key,
                    runtime: runtime.clone(),
                    planning: Arc::new(service),
                    catalog,
                    software_resources,
                    assets,
                    publications: Arc::new(
                        rss_mdm_software_service::management::publication::service::PublicationDirectory {
                            services: Default::default(),
                            tenant,
                            runtime: runtime.clone(),
                            audit_store,
                            clock: Arc::new(crate::clock::FlowClock(clock)),
                        },
                    ),
                    publication_runtime: None,
                };
                let setup = self
                    .open_publications(tenant, &mut service, content, &mut acquire)
                    .await;
                if let Err(error) = setup {
                    if let Some(p) = &service.publication_runtime {
                        p.close().await;
                    }
                    runtime.close().await;
                    return Err(error);
                }
                Ok(Arc::new(service))
            }
            Err(error) => {
                runtime.close().await;
                Err(error.into())
            }
        }
    }
    async fn open_publications(
        &self,
        tenant: TenantId,
        planning: &mut Flow,
        content: Option<Arc<rss_mdm_content_service::Store>>,
        acquire: &mut impl FnMut(Resource),
    ) -> std::result::Result<(), Error> {
        if self.publication.sources.is_empty() {
            return Ok(());
        }
        use rss_mdm_software_service::publication as p;
        let invalid = || Error::Configuration(crate::ConfigIssue::Publication);
        let db = &self.publication.database;
        let binding = ExecutionBinding::new(
            StorageIdentity::new(self.storage.target, self.storage.lineage)
                .map_err(|_| invalid())?,
            vec![(
                tenant,
                Epoch::new(self.storage.epoch).map_err(|_| invalid())?,
            )],
        )
        .map_err(|_| invalid())?;
        let config = PgConfig::new(
            &db.host,
            db.port,
            &db.name,
            &db.user,
            PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
            PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())
                .map_err(|_| invalid())?,
        );
        let runtime = Arc::new(
            PgRuntime::connect_producer(config, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        acquire(Resource {
            runtime: runtime.clone(),
            role: Role::Publication,
        });
        planning.publication_runtime = Some(runtime.clone());
        crate::database::admit_audit_runtime(&runtime, &planning.publications.audit_store, tenant)
            .await?;
        for source in &self.publication.sources {
            let service = p::PublicationService::connect(
                rss_mdm_software_service::Host {
                    content: content.clone().ok_or_else(invalid)?,
                    runtime: runtime.clone(),
                    audit: planning.publications.audit_store.clone(),
                    credentials: Arc::new(crate::source_credentials::SourceCredentials::load(
                        tenant,
                        &source.name,
                        &source.credentials,
                    )?),
                },
                tenant,
                source.name.clone(),
                source.rings.clone(),
                p::ServiceIdentity {
                    backend: rss_mdm_software_release::ActorId::new(tenant, "mdm-software-backend")
                        .map_err(|_| invalid())?,
                },
                Deadline::from_timeout(
                    &crate::lifecycle::RuntimeTimer,
                    Duration::from_secs(SOURCE_STARTUP_SECONDS),
                )
                .map_err(|_| invalid())?,
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::FlowSource))?;
            if Arc::get_mut(&mut planning.publications)
                .expect("unshared startup directory")
                .services
                .insert(source.name.clone(), Arc::new(service))
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Role {
    Storage,
    Publication,
}
pub(crate) struct Resource {
    runtime: Arc<PgRuntime>,
    role: Role,
}
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        match self.role {
            Role::Storage => "flow-runtime-postgres",
            Role::Publication => "software-driver-postgres",
        }
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.runtime.close().await;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/flow/unit.rs"]
mod tests;

pub(crate) struct Flow {
    pub(crate) cursor_key: Vec<u8>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) catalog: Arc<crate::resource_catalog::ResourceCatalog>,
    pub(crate) software_resources: Arc<rss_mdm_resource_postgres::ResourceStore>,
    pub(crate) planning: Arc<Planning>,
    pub(crate) assets: Arc<crate::assets::AssetService>,
    pub(crate) groups: Arc<rss_mdm_inventory_service::groups::Groups>,
    pub(crate) compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    pub(crate) publications:
        Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    publication_runtime: Option<Arc<PgRuntime>>,
}

pub(crate) async fn catalog(
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
) -> std::result::Result<Arc<crate::resource_catalog::ResourceCatalog>, Error> {
    Ok(Arc::new(
        crate::resource_catalog::ResourceCatalog::new(
            audit,
            runtime,
            tenant,
            Arc::new(crate::clock::FlowClock(clock)),
            Arc::new(rss_mdm_flow_service::resource_catalog::StoredReferences),
        )
        .await?,
    ))
}

use rss_mdm_flow_service::storage;

async fn admit_audit_runtime(
    runtime: &PgRuntime,
    audit: &rss_mdm_audit_integration::AuditStore,
    tenant: TenantId,
) -> std::result::Result<(), Error> {
    if let Err(error) = crate::database::admit_audit_runtime(runtime, audit, tenant).await {
        runtime.close().await;
        return Err(error);
    }
    Ok(())
}
